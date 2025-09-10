// =================================================================
// =================== 动态密钥核心生成模块 =====================
// =================================================================

/**
 * 动态、自验证密钥生成器 (精简版)
 * 仅包含生成逻辑，适用于签发端。
 */
class DynamicKeyGenerator {
  /**
   * @param {string} uuidKey 用于签名的秘密密钥 (必须)。
   * @param {number} [expirationInSeconds=86400] 密钥有效期，单位秒。 默认为24小时。
   */
  constructor(uuidKey, expirationInSeconds = 86400) {
      if (!uuidKey || typeof uuidKey !== 'string' || uuidKey.length < 16) {
          throw new Error('必须提供一个有效且长度足够的 uuidKey (密钥)。');
      }
      this.uuidKey = uuidKey;
      this.encoder = new TextEncoder();
  }

  async _getImportedKey() {
      if (!this._importedKey) {
          this._importedKey = await crypto.subtle.importKey('raw', this.encoder.encode(this.uuidKey), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
      }
      return this._importedKey;
  }

  async _sign(data) {
      const key = await this._getImportedKey();
      return crypto.subtle.sign('HMAC', key, data);
  }

  _bytesToUUID(bytes) {
      const hex = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
      return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20,32)}`;
  }

  /**
   * 生成一个新的动态密钥 (UUID格式)。
   * @returns {Promise<string>} 新生成的密钥字符串。
   */
  async generate() {
      const nowInSeconds = Math.floor(Date.now() / 1000);
      const randomBytes = crypto.getRandomValues(new Uint8Array(4));
      const payload = new Uint8Array(8);
      const view = new DataView(payload.buffer);
      view.setUint32(0, nowInSeconds, false);
      payload.set(randomBytes, 4);
      const signature = await this._sign(payload);
      const signaturePart = new Uint8Array(signature.slice(0, 8));
      const keyBytes = new Uint8Array(16);
      keyBytes.set(payload, 0);
      keyBytes.set(signaturePart, 8);
      return this._bytesToUUID(keyBytes);
  }
}


// =================================================================
// =================== Worker 主逻辑 ========================
// =================================================================

export default {
  async fetch(request, env) {
      
      // --- 1. 从环境变量读取配置 ---
      // TOKEN: 用于访问此服务的路径
      // UUIDKEY: 用于生成动态密钥的秘密密钥
      // UUIDTIME: (可选) 动态密钥的有效期（秒）
      const TOKEN = env.TOKEN || 'getuuid'; // 默认访问路径为 /getuuid
      const UUIDKEY = env.UUIDKEY;
      const UUIDTIME = env.UUIDTIME ? Number(env.UUIDTIME) : 24 * 60 * 60;

      const url = new URL(request.url);

      // --- 2. 验证访问路径 ---
      // 只有访问正确的路径 (例如: https://your-worker.workers.dev/getuuid) 才能获取密钥
      if (url.pathname !== `/${TOKEN}`) {
          return new Response('Not Found.', { status: 404 });
      }
      
      // --- 3. 检查核心配置是否存在 ---
      if (!UUIDKEY) {
          return new Response('服务端错误：管理员未在后台设置 UUIDKEY 变量。', { 
              status: 500, 
              headers: { 'Content-Type': 'text/plain; charset=utf-8' } 
          });
      }

      // --- 4. 生成并返回动态密钥 ---
      try {
          const keyGenerator = new DynamicKeyGenerator(UUIDKEY, UUIDTIME);
          const newDynamicKey = await keyGenerator.generate();
          
          // 将生成的密钥作为纯文本返回
          return new Response(newDynamicKey, {
              status: 200,
              headers: { 
                  'Content-Type': 'text/plain; charset=utf-8',
                  'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
                  'Pragma': 'no-cache',
                  'Expires': '0'
               },
          });

      } catch (error) {
          console.error("密钥生成失败:", error);
          return new Response("服务端错误：密钥生成失败。", { 
              status: 500,
              headers: { 'Content-Type': 'text/plain; charset=utf-8' }  
          });
      }
  }
};
