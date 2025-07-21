require('dotenv').config();
const express = require('express');
const fetch = require('node-fetch');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const app = express();
const port = 5173;

const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI;

// 建立 JWKS 客戶端來取得 Google 的公鑰
const jwksClientInstance = jwksClient({
    jwksUri: 'https://www.googleapis.com/oauth2/v3/certs',
    cache: true,
    cacheMaxAge: 600000, // 10 分鐘
    cacheMaxEntries: 5,
    rateLimit: true,
    jwksRequestsPerMinute: 5
});

// 取得簽名用的公鑰
function getSigningKey(kid) {
    return new Promise((resolve, reject) => {
        jwksClientInstance.getSigningKey(kid, (err, key) => {
            if (err) {
                reject(err);
            } else {
                resolve(key.getPublicKey());
            }
        });
    });
}

// 驗證和解析 ID Token
async function verifyIdToken(idToken) {
    try {
        // 1. 解碼 header 取得 kid (key ID)
        const header = jwt.decode(idToken, { complete: true }).header;
        console.log('JWT Header:', header);
        
        // 2. 用 kid 取得對應的公鑰
        const publicKey = await getSigningKey(header.kid);
        
        // 3. 驗證簽名並解析 payload
        const decoded = jwt.verify(idToken, publicKey, {
            algorithms: ['RS256'], // Google 使用 RS256 演算法
            audience: CLIENT_ID,   // 驗證 audience 是否正確
            issuer: ['https://accounts.google.com', 'accounts.google.com'] // 驗證發行者
        });
        
        console.log('ID Token 驗證成功:', decoded);
        return decoded;
        
    } catch (error) {
        console.error('ID Token 驗證失敗:', error.message);
        throw new Error(`ID Token 驗證失敗: ${error.message}`);
    }
}

// 簡單的 Base64 URL 解碼函數（用於展示）
function base64UrlDecode(str) {
    str += '='.repeat((4 - str.length % 4) % 4);
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    return Buffer.from(str, 'base64').toString('utf-8');
}

// 手動解析 JWT（僅用於展示，不驗證簽名）
function parseJWTManual(token) {
    const parts = token.split('.');
    if (parts.length !== 3) {
        throw new Error('Invalid JWT format');
    }
    
    const header = JSON.parse(base64UrlDecode(parts[0]));
    const payload = JSON.parse(base64UrlDecode(parts[1]));
    
    return { header, payload };
}

// Serve static HTML
app.get('/', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>OAuth 2.0 示範</title>
            <meta charset="utf-8">
            <style>
                body { font-family: Arial, sans-serif; margin: 50px; }
                .container { max-width: 600px; margin: 0 auto; }
                button { background: #4285f4; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; }
                button:hover { background: #357ae8; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>OAuth 2.0 第三方登入示範</h1>
                <p>這個範例展示如何使用 OAuth 2.0 進行第三方登入，以及如何使用不同的 token：</p>
                <ul>
                    <li><strong>ID Token</strong>: 用於身份驗證（識別使用者是誰）</li>
                    <li><strong>Access Token</strong>: 用於存取 API 資源（讀取 Google Drive 檔案）</li>
                </ul>
                <button onclick="window.location.href='/auth'">使用 Google 登入</button>
            </div>
        </body>
        </html>
    `);
});

// Step 1: 重導向到 Google 的 OAuth 2.0 伺服器
app.get('/auth', (req, res) => {
    const scope = encodeURIComponent('openid email profile https://www.googleapis.com/auth/drive.readonly');
    const redirect_uri = encodeURIComponent(REDIRECT_URI);
    const state = crypto.randomBytes(32).toString('hex'); // 防止 CSRF 攻擊
    
    const googleAuthURL = 'https://accounts.google.com/o/oauth2/v2/auth?' +
        `response_type=code` +
        `&client_id=${CLIENT_ID}` +
        `&redirect_uri=${redirect_uri}` +
        `&scope=${scope}` +
        `&access_type=offline` +
        `&prompt=consent` +
        `&state=${state}`;
    
    res.redirect(googleAuthURL);
});

// Step 2: Google 重導向回來，帶著授權碼
app.get('/oauth2callback', async (req, res) => {
    const code = req.query.code;
    const state = req.query.state;
    
    if (!code) {
        return res.send('<h1>錯誤：沒有收到授權碼</h1>');
    }
    
    console.log("CallBackData: ", req.query);
    
    try {
        // Step 3: 用授權碼換取 tokens
        const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: new URLSearchParams({
                code,
                client_id: CLIENT_ID,
                client_secret: CLIENT_SECRET,
                redirect_uri: REDIRECT_URI,
                grant_type: 'authorization_code'
            })
        });
        
        const tokenData = await tokenRes.json();
        console.log("TokenData: ", tokenData);
        
        if (!tokenData.access_token || !tokenData.id_token) {
            throw new Error('無法取得 tokens');
        }
        
        // Step 4: 驗證 ID Token 並取得使用者資訊
        let userInfo;
        let verificationStatus = '';
        
        try {
            // 使用正確的簽名驗證
            const verifiedPayload = await verifyIdToken(tokenData.id_token);
            userInfo = {
                sub: verifiedPayload.sub,
                name: verifiedPayload.name,
                email: verifiedPayload.email,
                picture: verifiedPayload.picture,
                iss: verifiedPayload.iss,
                aud: verifiedPayload.aud,
                exp: verifiedPayload.exp,
                iat: verifiedPayload.iat
            };
            verificationStatus = '✅ ID Token 簽名驗證成功';
            
        } catch (verifyError) {
            // 如果簽名驗證失敗，使用手動解析作為後備（僅用於展示）
            console.warn('簽名驗證失敗，使用手動解析:', verifyError.message);
            const manualParse = parseJWTManual(tokenData.id_token);
            userInfo = {
                sub: manualParse.payload.sub,
                name: manualParse.payload.name,
                email: manualParse.payload.email,
                picture: manualParse.payload.picture,
                iss: manualParse.payload.iss,
                aud: manualParse.payload.aud,
                exp: manualParse.payload.exp,
                iat: manualParse.payload.iat
            };
            verificationStatus = '⚠️ 簽名驗證失敗，使用未驗證的資料 (僅供示範)';
        }
        
        // Step 5: 使用 Access Token 存取 Google Drive API
        const driveRes = await fetch('https://www.googleapis.com/drive/v3/files?pageSize=10&fields=files(id,name,mimeType,createdTime)', {
            headers: {
                'Authorization': `Bearer ${tokenData.access_token}`
            }
        });
        
        const driveData = await driveRes.json();
        console.log("Drive Data: ", driveData);
        
        // 產生結果頁面
        let filesList = '';
        if (driveData.files && driveData.files.length > 0) {
            filesList = driveData.files.map((file, index) => 
                `<li><strong>${index + 1}.</strong> ${file.name} <small>(${file.mimeType})</small></li>`
            ).join('');
        } else {
            filesList = '<li>沒有找到檔案或無法存取</li>';
        }
        
        res.send(`
            <!DOCTYPE html>
            <html>
            <head>
                <title>OAuth 2.0 登入成功</title>
                <meta charset="utf-8">
                <style>
                    body { font-family: Arial, sans-serif; margin: 20px; }
                    .container { max-width: 800px; margin: 0 auto; }
                    .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
                    .success { background-color: #d4edda; border-color: #c3e6cb; }
                    .info { background-color: #e2f3ff; border-color: #bee5eb; }
                    .token-info { background-color: #fff3cd; border-color: #ffeaa7; }
                    ul { margin: 10px 0; }
                    li { margin: 5px 0; }
                    code { background-color: #f8f9fa; padding: 2px 4px; border-radius: 3px; }
                    .avatar { width: 50px; height: 50px; border-radius: 50%; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>🎉 OAuth 2.0 登入成功！</h1>
                    
                    <div class="section success">
                        <h2>🔐 ID Token 簽名驗證</h2>
                        <p><strong>狀態</strong>: ${verificationStatus}</p>
                        <p><strong>驗證過程</strong>:</p>
                        <ul>
                            <li>1. 從 JWT header 取得 kid (key ID)</li>
                            <li>2. 向 Google JWKS 端點取得對應的公鑰</li>
                            <li>3. 使用 RS256 演算法驗證簽名</li>
                            <li>4. 驗證 audience 和 issuer</li>
                        </ul>
                    </div>
                    
                    <div class="section success">
                        <h2>📋 身份驗證結果 (來自 ID Token)</h2>
                        <p><strong>用途</strong>：ID Token 用於身份驗證，告訴我們使用者是誰</p>
                        <ul>
                            <li><strong>使用者 ID</strong>: ${userInfo.sub}</li>
                            <li><strong>姓名</strong>: ${userInfo.name}</li>
                            <li><strong>Email</strong>: ${userInfo.email}</li>
                            <li><strong>頭像</strong>: <img src="${userInfo.picture}" alt="頭像" class="avatar"></li>
                            <li><strong>發行者</strong>: ${userInfo.iss}</li>
                            <li><strong>目標應用程式</strong>: ${userInfo.aud}</li>
                            <li><strong>Token 發行時間</strong>: ${new Date(userInfo.iat * 1000).toLocaleString()}</li>
                            <li><strong>Token 過期時間</strong>: ${new Date(userInfo.exp * 1000).toLocaleString()}</li>
                        </ul>
                    </div>
                    
                    <div class="section info">
                        <h2>📁 Google Drive 檔案列表 (來自 Access Token)</h2>
                        <p><strong>用途</strong>：Access Token 用於存取 API 資源，這裡用來讀取 Google Drive 檔案</p>
                        <ul>
                            ${filesList}
                        </ul>
                    </div>
                    
                    <div class="section token-info">
                        <h2>🔑 JWT 簽名驗證說明</h2>
                        <ul>
                            <li><strong>為什麼需要驗證簽名？</strong>: 確保 Token 未被篡改，真的來自 Google</li>
                            <li><strong>JWKS (JSON Web Key Set)</strong>: Google 公開的公鑰集合，用於驗證簽名</li>
                            <li><strong>RS256 演算法</strong>: 使用 RSA 公鑰/私鑰加密的簽名演算法</li>
                            <li><strong>kid (Key ID)</strong>: JWT header 中的欄位，指定使用哪個公鑰</li>
                            <li><strong>audience 驗證</strong>: 確認 Token 是發給我們的應用程式</li>
                            <li><strong>issuer 驗證</strong>: 確認 Token 真的來自 Google</li>
                        </ul>
                    </div>
                    
                    <div class="section token-info">
                        <h2>🔑 Token 類型說明</h2>
                        <ul>
                            <li><strong>ID Token</strong>: JWT 格式，包含使用者身份資訊，用於身份驗證，有簽名保護</li>
                            <li><strong>Access Token</strong>: 不透明字串，用於存取 Google API 資源</li>
                            <li><strong>Refresh Token</strong>: 用於取得新的 Access Token（當 Access Token 過期時）</li>
                        </ul>
                    </div>
                    
                    <div class="section">
                        <h2>🔧 技術細節</h2>
                        <ul>
                            <li>使用 <code>openid</code> scope 取得 ID Token</li>
                            <li>使用 <code>https://www.googleapis.com/auth/drive.readonly</code> scope 存取 Drive API</li>
                            <li>使用 <code>jsonwebtoken</code> 和 <code>jwks-rsa</code> 套件驗證 JWT 簽名</li>
                            <li>從 Google JWKS 端點取得公鑰進行簽名驗證</li>
                            <li>使用 Access Token 呼叫 Google Drive API</li>
                        </ul>
                    </div>
                    
                    <p><a href="/">回到首頁</a></p>
                </div>
            </body>
            </html>
        `);
        
    } catch (error) {
        console.error('Error:', error);
        res.send(`
            <h1>錯誤</h1>
            <p>處理 OAuth 流程時發生錯誤：${error.message}</p>
            <p><a href="/">回到首頁</a></p>
        `);
    }
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
    console.log('請確保你的 .env 檔案包含以下變數：');
    console.log('CLIENT_ID=your_google_client_id');
    console.log('CLIENT_SECRET=your_google_client_secret');  
    console.log('REDIRECT_URI=http://localhost:5173/oauth2callback');
    console.log('');
    console.log('需要安裝的套件：');
    console.log('npm install express node-fetch jsonwebtoken jwks-rsa dotenv');
});