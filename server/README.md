# Server README — 本地開發說明（種子資料與簡易範例）

本檔案說明如何在本機執行種子資料（`seed.js`）與如何使用已建立的測試帳號來取得 JWT 以及呼叫受保護的 API。

注意：伺服器主程式位於 `server/server.js`，SQLite 檔案位於 `server/data/database.sqlite`。

## 在 Windows (PowerShell) 執行 seed

1. 進入 `server` 目錄：

```powershell
cd 'c:\Users\rita9\Documents\SGTP\server'
```

2. 安裝相依（若尚未安裝）：

```powershell
npm install
```

3. 執行種子腳本（會執行 migrations 並插入測試帳號與商品）：

```powershell
node seed.js
```

預期輸出會顯示 migrations 的 Applied/Skipped 訊息，並列出已建立的使用者與商品。`seed.js` 避免重複建立相同 email 與相同 seller+title 的商品，因此可放心重複執行以確保資料存在。\
\
注意：已新增 `category`、`image` 與 `images` 欄位的種子資料（若原先表中該欄位為 NULL，重新執行 `node seed.js` 會自動更新現有商品以填入預設 category 與 images）。

---

## 已建立的測試帳號（預設）

- Admin: `admin@example.com` / `adminpass`
- Sellers: `alice@sellers.com` / `sellerpass` , `bob@sellers.com` / `sellerpass`
- Buyers: `charlie@buyers.com` / `buyerpass` , `dana@buyers.com` / `buyerpass`

這些帳號會被插入 `users` 表（若已存在相同 email，seed 會跳過該筆）。

---

## 圖片上傳與賣家上架（新增）

- 上傳 endpoint：`POST /api/uploads`（multipart/form-data, 欄位 `file`），需帶 `Authorization: Bearer <token>`（任何已登入使用者可上傳）。上傳成功會回傳 JSON `{ url: "/uploads/<filename>" }`。
- 上傳檔案會存到 `server/public/uploads/`，伺服器會透過 `/uploads/<filename>` 提供靜態存取。
- 賣家上架路由：`POST /api/seller/products`（需 `seller` token），接受 `title, description, price, quantity, category, image, images`（`images` 為陣列）。

前端範例：在 `seller_add_product.html` 已新增檔案選取功能，選取檔案會上傳並把回傳的 URL 加到上架內容中（第一張當封面）。

---

## 取得 JWT（fetch 範例）

以下為前端如何用 `fetch` 取得 JWT（以 `charlie@buyers.com` 為例）：

```javascript
// 登入並取得 token
async function login() {
  const res = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'charlie@buyers.com', password: 'buyerpass' })
  });
  const data = await res.json();
  if (res.ok) {
    localStorage.setItem('token', data.token);
    return data.token;
  }
  throw new Error(data.error || '登入失敗');
}

// 範例：呼叫受保護的 /api/auth/me
async function whoami(){
  const token = localStorage.getItem('token');
  const res = await fetch('/api/auth/me', { headers: { Authorization: 'Bearer ' + token } });
  return res.json();
}

// 用法：
// await login();
// const me = await whoami();
// console.log(me);
```

---

## 範例：取得商品列表與下單（簡短示範）

## 圖片上傳（從前端上傳檔案）

新增了 `POST /api/uploads`（需帶 Bearer token），接受 `multipart/form-data` 的 `file` 欄位，會把檔案儲存在 `server/public/uploads/` 並回傳 JSON `{ url: '/uploads/<filename>' }` 。

範例（在前端用 `fetch` 上傳）：

```javascript
const form = new FormData();
form.append('file', fileInput.files[0]);
const res = await fetch('/api/uploads', { method: 'POST', headers: { Authorization: 'Bearer ' + token }, body: form });
const data = await res.json();
console.log('Uploaded URL:', data.url);
```

## 賣家上架商品

為了讓賣家可以直接上架商品（不需管理者權限），新增了 `POST /api/seller/products`（需登入的 seller），會把 `seller_id` 由 token 決定，並接受 `image` / `images` 與 `category` 字段。

前端的 `seller_add_product.html` 已支援上傳檔案並將回傳的 URL 用於 `images`。

```javascript
// 取得商品（公開）
async function getProducts(){
  const res = await fetch('/api/products');
  return res.json();
}

// 建立訂單（需登入，示範 buyer 下單）
async function createOrder(items){
  const token = localStorage.getItem('token');
  const res = await fetch('/api/orders', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token },
    body: JSON.stringify({ items })
  });
  return res.json();
}

// items 範例： [{ productId: 1, quantity: 1 }, { productId: 2, quantity: 2 }]
```

---

## 快速驗證步驟

1. 在 `server` 執行 `node seed.js`。
2. 用瀏覽器開啟任一已改寫的前端頁面（例如 `buyer_login.html`），或在 console 中執行 `login()` 範例取得 token。 
3. 確認 `/api/auth/me` 回傳使用者資料，並測試 `/api/products` 與 `/api/orders`（依角色）是否正常。

---

如果你想，我可以把這些 fetch 範例直接內嵌到某個前端頁面（例如 `test_signup.html` 或新增一個 `examples.html`），或新增 PowerShell 的 curl 例子。要不要我也把範例加入一個前端示範頁？
# SGTP Server (SQLite + Express)

快速啟動：

1. 開啟 PowerShell，到專案 `server` 資料夾

```powershell
cd 'c:\Users\rita9\Documents\SGTP\server'
npm install
npm start
```

2. 伺服器會在 http://localhost:3000 運行。
3. 內建 endpoints：
   - POST /api/admin/register  -> 註冊管理者
   - POST /api/auth/login      -> 登入，回傳 JWT

環境變數：
- JWT_SECRET: 用於簽發 JWT（預設為 'change_this_secret'，上線請設定安全的 secret）

備註：生產環境請使用 MySQL/Postgres，並將資料庫憑證放在環境變數中。你可以稍後要求我把其他頁面從 Firebase 手動替換為呼叫此 API。
