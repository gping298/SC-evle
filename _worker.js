// --- DynamicUUID  ---

/**
 * Dynamic, Self-Verifying UUID Generator
 * 
 * This module creates UUIDs that embed a timestamp and a signature,
 * allowing for stateless validation of both authenticity and expiration.
 * It uses the standard Web Crypto API.
 */
class DynamicUUID {
	/**
	 * @param {string} secretKey A long, random, and secret string used for signing.
	 * @param {number} [expirationInSeconds=86400] The validity period for a UUID, in seconds. Defaults to 24 hours.
	 */
	constructor(secretKey, expirationInSeconds = 24 * 60 * 60) {
		if (!secretKey) {
			throw new Error('A secretKey is required.');
		}
		this.secretKey = secretKey;
		this.expirationInSeconds = expirationInSeconds;
		this.encoder = new TextEncoder();
	}

	/**
	 * Imports the secret key for cryptographic operations.
	 * @private
	 */
	async _getImportedKey() {
		if (!this._importedKey) {
			this._importedKey = await crypto.subtle.importKey(
				'raw',
				this.encoder.encode(this.secretKey), {
					name: 'HMAC',
					hash: 'SHA-256'
				},
				false,
				['sign', 'verify']
			);
		}
		return this._importedKey;
	}

	/**
	 * Signs a given data payload.
	 * @private
	 * @param {Uint8Array} data The data to sign.
	 * @returns {Promise<ArrayBuffer>} The HMAC-SHA256 signature.
	 */
	async _sign(data) {
		const key = await this._getImportedKey();
		return crypto.subtle.sign('HMAC', key, data);
	}

	/**
	 * Converts a 16-byte array into a standard UUID string format.
	 * @private
	 */
	_bytesToUUID(bytes) {
		const hex = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
		return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20,32)}`;
	}

	/**
	 * Converts a UUID string back into a 16-byte array. Returns null if invalid format.
	 * @private
	 */
	_uuidToBytes(uuidString) {
		const hex = uuidString.replace(/-/g, '');
		if (hex.length !== 32) return null;
		const bytes = new Uint8Array(16);
		for (let i = 0; i < 16; i++) {
			bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
		}
		return bytes;
	}

	/**
	 * Generates a new, self-contained dynamic UUID.
	 * The UUID contains a timestamp, a nonce, and a signature.
	 * @returns {Promise<string>} A promise that resolves to the new UUID string.
	 */
	async generate() {
		const nowInSeconds = Math.floor(Date.now() / 1000);
		const randomBytes = crypto.getRandomValues(new Uint8Array(4)); // 4-byte nonce

		// Payload: 4-byte timestamp + 4-byte nonce
		const payload = new Uint8Array(8);
		const view = new DataView(payload.buffer);
		view.setUint32(0, nowInSeconds, false); // Big-endian
		payload.set(randomBytes, 4);

		// Signature: Sign the payload and take the first 8 bytes
		const signature = await this._sign(payload);
		const signaturePart = new Uint8Array(signature.slice(0, 8));

		// Assemble final 16 bytes for the UUID
		const uuidBytes = new Uint8Array(16);
		uuidBytes.set(payload, 0);
		uuidBytes.set(signaturePart, 8);

		return this._bytesToUUID(uuidBytes);
	}

	/**
	 * Validates a dynamic UUID string.
	 * It checks both the expiration and the cryptographic signature.
	 * @param {string} uuidString The UUID string to validate.
	 * @returns {Promise<boolean>} A promise that resolves to true if the UUID is valid, otherwise false.
	 */
	async validate(uuidString) {
		const uuidBytes = this._uuidToBytes(uuidString);
		if (!uuidBytes) return false;

		// Deconstruct the UUID
		const payload = uuidBytes.slice(0, 8);
		const signaturePart = uuidBytes.slice(8, 16);

		// 1. Validate signature first (computationally cheaper than date ops)
		const expectedSignature = await this._sign(payload);
		const expectedSignaturePart = new Uint8Array(expectedSignature.slice(0, 8));

		// Constant-time comparison is not strictly necessary here but good practice
		if (signaturePart.length !== expectedSignaturePart.length) return false;
		let diff = 0;
		for (let i = 0; i < signaturePart.length; i++) {
			diff |= signaturePart[i] ^ expectedSignaturePart[i];
		}
		if (diff !== 0) return false;

		// 2. If signature is valid, check expiration
		const view = new DataView(payload.buffer);
		const timestamp = view.getUint32(0, false);
		const nowInSeconds = Math.floor(Date.now() / 1000);

		if (nowInSeconds - timestamp > this.expirationInSeconds) {
			return false; // Expired
		}

		return true; // Valid and not expired
	}
}


import {
	connect
} from 'cloudflare:sockets';

export default {
	async fetch(req, env) {
		// --- START: 改动点 1 ---
		// 同时读取动态和静态UUID的配置，如果不存在则为空字符串
		const UUIDKEY = env.UUIDKEY || '';
		const UUID = env.UUID || '';
		const UUIDTIME = parseInt(env.UUIDTIME, 10) || 24 * 60 * 60;
		// --- END: 改动点 1 ---


		if (req.headers.get('Upgrade')?.toLowerCase() === 'websocket') {
			// 如果没有设置任何UUID，则拒绝连接
			if (!UUIDKEY && !UUID) {
				return new Response('缺少 UUIDKEY 或 UUID 配置', { status: 403 });
			}
			
			const [client, ws] = Object.values(new WebSocketPair());
			ws.accept();

			const u = new URL(req.url);

			// 修复处理URL编码的查询参数  
			if (u.pathname.includes('%3F')) {
				const decoded = decodeURIComponent(u.pathname);
				const queryIndex = decoded.indexOf('?');
				if (queryIndex !== -1) {
					u.search = decoded.substring(queryIndex);
					u.pathname = decoded.substring(0, queryIndex);
				}
			}
			
			// --- START: 路径快捷方式处理 ---

			let s5Param = u.searchParams.get('s5');
			let proxyParam = u.searchParams.get('proxyip');
			let pathBasedOrder = null; // 用于存储路径快捷方式强制设定的连接顺序
			const path = u.pathname.slice(1);

			// 规则3: /socks5:// -> 强制SOCKS5
			if (path.startsWith('socks5://')) {
				s5Param = path.substring('socks5://'.length);
				pathBasedOrder = ['s5'];
			}
			// 规则1: /proxyip= -> 强制 direct, proxy
			else if (path.startsWith('proxyip=')) {
				proxyParam = path.substring('proxyip='.length);
				pathBasedOrder = ['direct', 'proxy'];
			}
			// 规则2: /socks5= -> 强制 direct, s5
			else if (path.startsWith('socks5=')) {
				s5Param = path.substring('socks5='.length);
				pathBasedOrder = ['direct', 's5'];
			}

			// --- END: 路径快捷方式处理 ---


			// 解析SOCKS5和ProxyIP (使用可能被路径快捷方式覆盖后的参数)
			const socks5 = s5Param && s5Param.includes('@') ? (() => {
				const [cred, server] = s5Param.split('@');
				const [user, pass] = cred.split(':');
				const [host, port = 443] = server.split(':');
				return {
					user,
					pass,
					host,
					port: +port
				};
			})() : null;
			const PROXY_IP = proxyParam ? String(proxyParam) : '3.112.21.102';

			// auto模式参数顺序（按URL参数位置）
			const getOrder = () => {
				// 如果路径快捷方式已设定顺序，则优先使用
				if (pathBasedOrder) {
					return pathBasedOrder;
				}

				// 否则，按原逻辑处理查询字符串
				const mode = u.searchParams.get('mode') || 'auto';
				if (mode === 'proxy') return ['direct', 'proxy'];
				if (mode !== 'auto') return [mode];
				
				const order = [];
				const searchStr = u.search.slice(1);
				for (const pair of searchStr.split('&')) {
					const key = pair.split('=')[0];
					if (key === 'direct') order.push('direct');
					else if (key === 's5') order.push('s5');
					else if (key === 'proxyip') order.push('proxy');
				}
				
				// 智能默认：如果只提供了s5或proxyip，自动添加direct作为首选
				if (order.includes('s5') && !order.includes('direct')) {
					order.unshift('direct');
				}
				if (order.includes('proxy') && !order.includes('direct')) {
					order.unshift('direct');
				}
				
				// 没有参数时默认 direct, proxy
				return order.length ? order : ['direct', 'proxy'];
			};

			let remote = null,
				udpWriter = null,
				isDNS = false;

			// SOCKS5连接
			const socks5Connect = async (targetHost, targetPort) => {
				const sock = connect({
					hostname: socks5.host,
					port: socks5.port
				});
				await sock.opened;
				const w = sock.writable.getWriter();
				const r = sock.readable.getReader();
				await w.write(new Uint8Array([5, 2, 0, 2]));
				const auth = (await r.read()).value;
				if (auth[1] === 2 && socks5.user) {
					const user = new TextEncoder().encode(socks5.user);
					const pass = new TextEncoder().encode(socks5.pass);
					await w.write(new Uint8Array([1, user.length, ...user, pass.length, ...pass]));
					await r.read();
				}
				const domain = new TextEncoder().encode(targetHost);
				await w.write(new Uint8Array([5, 1, 0, 3, domain.length, ...domain, targetPort >> 8,
					targetPort & 0xff
				]));
				await r.read();
				w.releaseLock();
				r.releaseLock();
				return sock;
			};

			new ReadableStream({
				start(ctrl) {
					ws.addEventListener('message', e => ctrl.enqueue(e.data));
					ws.addEventListener('close', () => {
						remote?.close();
						ctrl.close();
					});
					ws.addEventListener('error', () => {
						remote?.close();
						ctrl.error();
					});

					const early = req.headers.get('sec-websocket-protocol');
					if (early) {
						try {
							ctrl.enqueue(Uint8Array.from(atob(early.replace(/-/g, '+').replace(/_/g, '/')),
								c => c.charCodeAt(0)).buffer);
						} catch {}
					}
				}
			}).pipeTo(new WritableStream({
				async write(data) {
					if (isDNS) return udpWriter?.write(data);
					if (remote) {
						const w = remote.writable.getWriter();
						await w.write(data);
						w.releaseLock();
						return;
					}

					if (data.byteLength < 24) return;

					// --- START: 改动点 2 - 统一的UUID验证逻辑 ---
					let isValid = false;

					if (UUIDKEY) {
						// 动态UUID模式
						const dynamicUUID = new DynamicUUID(UUIDKEY, UUIDTIME);
						const uuidBytes = new Uint8Array(data.slice(1, 17));
						const receivedUUIDString = dynamicUUID._bytesToUUID(uuidBytes);
						isValid = await dynamicUUID.validate(receivedUUIDString);
					} else if (UUID) {
						// 静态UUID模式
						const uuidBytes = new Uint8Array(data.slice(1, 17));
						const expectedUUID = UUID.replace(/-/g, '');
						
						// 确保提供的静态UUID是有效的
						if (expectedUUID.length === 32) {
							let match = true;
							for (let i = 0; i < 16; i++) {
								if (uuidBytes[i] !== parseInt(expectedUUID.substr(i * 2, 2), 16)) {
									match = false;
									break;
								}
							}
							isValid = match;
						}
					}
					// 如果两个环境变量都没设置，isValid 将保持 false

					if (!isValid) {
						return; // 验证失败，终止处理
					}
					// --- END: 改动点 2 ---

					const view = new DataView(data);
					const optLen = view.getUint8(17);
					const cmd = view.getUint8(18 + optLen);
					if (cmd !== 1 && cmd !== 2) return;

					let pos = 19 + optLen;
					const port = view.getUint16(pos);
					const type = view.getUint8(pos + 2);
					pos += 3;

					let addr = '';
					if (type === 1) {
						addr =
							`${view.getUint8(pos)}.${view.getUint8(pos + 1)}.${view.getUint8(pos + 2)}.${view.getUint8(pos + 3)}`;
						pos += 4;
					} else if (type === 2) {
						const len = view.getUint8(pos++);
						addr = new TextDecoder().decode(data.slice(pos, pos + len));
						pos += len;
					} else if (type === 3) {
						const ipv6 = [];
						for (let i = 0; i < 8; i++, pos += 2) ipv6.push(view.getUint16(pos)
							.toString(16));
						addr = ipv6.join(':');
					} else return;

					const header = new Uint8Array([data[0], 0]);
					const payload = data.slice(pos);

					// UDP DNS
					if (cmd === 2) {
						if (port !== 53) return;
						isDNS = true;
						let sent = false;
						const {
							readable,
							writable
						} = new TransformStream({
							transform(chunk, ctrl) {
								for (let i = 0; i < chunk.byteLength;) {
									const len = new DataView(chunk.slice(i, i + 2))
										.getUint16(0);
									ctrl.enqueue(chunk.slice(i + 2, i + 2 + len));
									i += 2 + len;
								}
							}
						});

						readable.pipeTo(new WritableStream({
							async write(query) {
								try {
									const resp = await fetch(
										'https://1.1.1.1/dns-query', {
											method: 'POST',
											headers: {
												'content-type': 'application/dns-message'
											},
											body: query
										});
									if (ws.readyState === 1) {
										const result = new Uint8Array(await resp
											.arrayBuffer());
										ws.send(new Uint8Array([...(sent ? [] :
												header), result
											.length >> 8, result
											.length & 0xff, ...result
										]));
										sent = true;
									}
								} catch {}
							}
						}));
						udpWriter = writable.getWriter();
						return udpWriter.write(payload);
					}

					// TCP连接
					let sock = null;
					for (const method of getOrder()) {
						try {
							if (method === 'direct') {
								sock = connect({
									hostname: addr,
									port
								});
								await sock.opened;
								break;
							} else if (method === 's5' && socks5) {
								sock = await socks5Connect(addr, port);
								break;
							} else if (method === 'proxy' && PROXY_IP) {
								const [ph, pp = port] = PROXY_IP.split(':');
								sock = connect({
									hostname: ph,
									port: +pp || port
								});
								await sock.opened;
								break;
							}
						} catch {}
					}

					if (!sock) return;

					remote = sock;
					const w = sock.writable.getWriter();
					await w.write(payload);
					w.releaseLock();

					let sent = false;
					sock.readable.pipeTo(new WritableStream({
						write(chunk) {
							if (ws.readyState === 1) {
								ws.send(sent ? chunk : new Uint8Array([...header, ...
									new Uint8Array(chunk)
								]));
								sent = true;
							}
						},
						close: () => ws.readyState === 1 && ws.close(),
						abort: () => ws.readyState === 1 && ws.close()
					})).catch(() => {});
				}
			})).catch(() => {});

			return new Response(null, {
				status: 101,
				webSocket: client
			});
		}

		return Response.redirect('https://t.me/jiliankeji', 302);
	}
};
