require('dotenv').config();
const express = require('express');
const fetch = require('node-fetch');
const app = express();
const port = 5173;

const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI;

// Serve static HTML
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/index.html');
});

// Step 1: Redirect user to Google's OAuth 2.0 server
app.get('/auth', (req, res) => {
    const scope = encodeURIComponent('openid email profile');
    const redirect_uri = encodeURIComponent(REDIRECT_URI)
    const googleAuthURL =
        'https://accounts.google.com/o/oauth2/v2/auth?' +
            `response_type=code` +
            `&client_id=${CLIENT_ID}` +
            `&redirect_uri=${redirect_uri}` +
            `&scope=${scope}` +
            `&access_type=offline` +
            `&prompt=consent`;
    res.redirect(googleAuthURL);
});

// Step 2: Google redirects back with ?code=XYZ
app.get('/oauth2callback', async (req, res) => {
    const code = req.query.code;

    console.log("CallBackData: ", req.query)

    // Step 3: Exchange code for tokens
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
            code,
            client_id: CLIENT_ID,
            client_secret: CLIENT_SECRET,
            redirect_uri: REDIRECT_URI,
            grant_type: 'authorization_code'
        })
    });

    const tokenData = await tokenRes.json();
    console.log("TokenData: ", tokenData)

    const accessToken = tokenData.access_token;

    // Step 4: Use token to fetch user info
    const userInfoRes = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
        headers: {
            Authorization: `Bearer ${accessToken}`
        }
    });

    const userInfo = await userInfoRes.json();

    res.send(`
    <h1>登入成功</h1>
    <p>名稱: ${userInfo.name}</p>
    <p>Email: ${userInfo.email}</p>
    <img src="${userInfo.picture}" alt="avatar" />
  `);
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
