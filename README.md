# Google OAuth Demo

## 環境需求

* 已安裝 [Node.js](https://nodejs.org/)（建議使用 Node.js 16 或以上）

  > 可使用 `node -v` 與 `npm -v` 指令確認是否已安裝

---

## Google OAuth 準備步驟

1. 前往 [Google Cloud Console](https://console.developers.google.com/project)
2. 建立新專案（或選擇既有專案）
3. 左側選單中選擇「API 和服務」 >「憑證」
4. 點選「建立憑證」 >「OAuth 2.0 用戶端 ID」
5. **應用程式類型** 選擇「網頁應用程式」
6. 設定授權重新導向 URI：`http://localhost:5173/oauth2callback`
7. 建立後，請複製 `用戶端 ID` 和 `用戶端密鑰`，稍後會用到

---

## 專案設定

### 1. 建立 `.env` 檔案

在專案根目錄下建立 `.env`，內容如下：

```
CLIENT_ID=your CLIENT_ID
CLIENT_SECRET=your CLIENT_SECRET
REDIRECT_URI=http://localhost:5173/oauth2callback
```

請將 `your CLIENT_ID` 和 `your CLIENT_SECRET` 替換成你從 Google Cloud Console 取得的憑證資料。

---

### 2. 安裝套件

```bash
npm init -y
npm install express node-fetch@2 dotenv jsonwebtoken jwks-rsa
```

---

## 執行

```bash
node server.js
```