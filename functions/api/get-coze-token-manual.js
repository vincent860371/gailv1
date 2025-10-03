/**
 * Cloudflare Pages Function - 手动实现 JWT Token 生成
 * 路径: /api/get-coze-token-manual
 * 
 * 此版本手动构造 JWT，确保 session_name 字段被正确包含
 * 如果 @coze/api SDK 不支持 session_name，使用此版本
 */

/**
 * Base64URL 编码
 */
function base64UrlEncode(str) {
  return btoa(str)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * 将字符串转换为 ArrayBuffer
 */
function str2ab(str) {
  const buf = new ArrayBuffer(str.length);
  const bufView = new Uint8Array(buf);
  for (let i = 0; i < str.length; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}

/**
 * 导入 PEM 格式的私钥
 */
async function importPrivateKey(pem) {
  // ✅ 验证私钥格式，避免导入错误
  if (!pem.includes('-----BEGIN PRIVATE KEY-----') || !pem.includes('-----END PRIVATE KEY-----')) {
    throw new Error('Invalid private key format. Ensure it is a PKCS8 PEM.');
  }
  
  // 移除 PEM 头尾和换行符
  const pemHeader = '-----BEGIN PRIVATE KEY-----';
  const pemFooter = '-----END PRIVATE KEY-----';
  const pemContents = pem
    .replace(pemHeader, '')
    .replace(pemFooter, '')
    .replace(/\s/g, '');
  
  // Base64 解码
  const binaryDer = atob(pemContents);
  const binaryArray = new Uint8Array(binaryDer.length);
  for (let i = 0; i < binaryDer.length; i++) {
    binaryArray[i] = binaryDer.charCodeAt(i);
  }
  
  // 导入密钥（显式指定哈希算法，避免默认值问题）
  return await crypto.subtle.importKey(
    'pkcs8',
    binaryArray.buffer,
    {
      name: 'RSASSA-PKCS1-v1_5',
      hash: { name: 'SHA-256' },  // ✅ 显式指定哈希算法
    },
    false,
    ['sign']
  );
}

/**
 * 使用私钥签名数据
 */
async function signData(privateKey, data) {
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);
  
  const signature = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    privateKey,
    dataBuffer
  );
  
  // 将 ArrayBuffer 转换为 base64url
  const signatureArray = new Uint8Array(signature);
  let binary = '';
  for (let i = 0; i < signatureArray.length; i++) {
    binary += String.fromCharCode(signatureArray[i]);
  }
  return base64UrlEncode(binary);
}

/**
 * 生成 JWT
 */
async function createJWT(appId, keyId, audience, studentId, privateKeyPEM) {
  // 1. 构造 Header
  const header = {
    alg: 'RS256',
    typ: 'JWT',
    kid: keyId
  };
  
  // 2. 构造 Payload
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: appId,
    aud: audience,
    iat: now,
    exp: now + 3600,  // 1 小时后过期
    jti: `${studentId}-${now}-${crypto.randomUUID()}`,  // ✅ 完整UUID，确保大于32字节（官方建议）
    session_name: studentId  // 🔑 关键：会话隔离字段
  };
  
  // 3. Base64URL 编码
  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  
  // 4. 签名
  const privateKey = await importPrivateKey(privateKeyPEM);
  const signatureInput = `${encodedHeader}.${encodedPayload}`;
  const signature = await signData(privateKey, signatureInput);
  
  // 5. 组合 JWT
  return `${encodedHeader}.${encodedPayload}.${signature}`;
}

/**
 * 处理 GET 请求
 */
export async function onRequestGet(context) {
  const { request, env } = context;
  
  // 从 URL 获取 student_id 参数
  const url = new URL(request.url);
  const studentId = url.searchParams.get('student_id');
  
  if (!studentId) {
    return new Response(
      JSON.stringify({ error: 'student_id parameter is required' }), 
      {
        status: 400,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',  // TODO: 部署后改为具体域名
        }
      }
    );
  }

  try {
    // 从环境变量读取配置
    const appId = env.COZE_APP_ID;
    const keyId = env.COZE_KEY_ID;
    const privateKey = env.COZE_PRIVATE_KEY;
    const botId = env.COZE_BOT_ID;  // 可选，用于限制权限范围

    if (!appId || !keyId || !privateKey) {
      return new Response(
        JSON.stringify({ 
          error: 'Server configuration missing. Please configure COZE_APP_ID, COZE_KEY_ID, and COZE_PRIVATE_KEY.' 
        }), 
        {
          status: 500,
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
          }
        }
      );
    }

    // 1. 生成 JWT（包含 session_name）
    const signedJWT = await createJWT(
      appId,
      keyId,
      'api.coze.cn',  // 国内版；国际版使用 'api.coze.com'
      studentId,
      privateKey
    );

    console.log(`✅ Generated JWT for student: ${studentId}`);

    // 2. 使用 JWT 交换 access_token（符合官方文档规范）
    // 文档：https://www.coze.cn/docs/developer_guides/oauth_jwt#2-获取访问令牌
    // ✅ 普通 JWT OAuth：不传 scope 参数（使用 OAuth 应用配置的权限）
    // 官方文档：https://www.coze.cn/open/docs/developer_guides/oauth_jwt
    // 
    // ⚠️ 重要：必须在 Coze 平台的 OAuth 应用中配置并授权以下权限：
    //   - chat：与智能体对话
    //   - getMetadata：获取智能体元数据（含开场白）
    //   - listConversation：列出会话
    //   - createConversation：创建会话
    // 
    // ⚠️ 配置后必须点击"授权"按钮！
    const requestBody = {
      duration_seconds: 86399,  // 24小时有效期（最大值）
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer'
      // ✅ 不传 scope 参数，避免 400 错误
    };

    const tokenResponse = await fetch('https://api.coze.cn/api/permission/oauth2/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${signedJWT}`,  // ✅ JWT 必须放在 Authorization Header 中
      },
      body: JSON.stringify(requestBody),
    });

    if (!tokenResponse.ok) {
      const errorText = await tokenResponse.text();
      // ⚠️ 生产环境下不打印完整错误内容，避免泄露敏感信息
      console.error('❌ Failed to exchange token:', tokenResponse.status);
      throw new Error(`Token exchange failed: ${tokenResponse.status}`);
    }

    const tokenData = await tokenResponse.json();

    console.log(`✅ Access token obtained for student: ${studentId}`);

    // 3. 返回 token 给前端
    return new Response(
      JSON.stringify({
        access_token: tokenData.access_token,
        expires_in: tokenData.expires_in || 3600,
        session_name: studentId
      }),
      {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          // ⚠️ 生产环境建议限制为具体域名，避免被恶意网站滥用
          // 例如：'https://gailv2.pages.dev'
          'Access-Control-Allow-Origin': '*',  // TODO: 部署后改为具体域名
          'Cache-Control': 'no-store',
        }
      }
    );

  } catch (error) {
    console.error('❌ Error:', error);
    
    return new Response(
      JSON.stringify({ 
        error: `Failed to generate token: ${error.message}` 
      }), 
      {
        status: 500,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',  // TODO: 部署后改为具体域名
        }
      }
    );
  }
}

/**
 * 处理 OPTIONS 请求（CORS 预检）
 */
export async function onRequestOptions() {
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',  // TODO: 部署后改为具体域名
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    }
  });
}

