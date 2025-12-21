/* chat.js */

const socket = io();

// DOM 元素
const messagesDiv = document.getElementById('messages');
const msgInput = document.getElementById('msgInput');
const sendBtn = document.getElementById('sendBtn');
const chatTitle = document.querySelector('.chat-title');

const contextBar = document.getElementById('contextBar');
const contextImg = document.getElementById('contextImg');
const contextTitle = document.getElementById('contextTitle');
const contextSubtitle = document.getElementById('contextSubtitle');

// URL 參數
const params = new URLSearchParams(window.location.search);
const targetId = params.get('targetId');
const productId = params.get('productId'); 
const orderId = params.get('orderId'); 

let myId = null; 
let myName = '';
const FALLBACK_IMG = 'https://via.placeholder.com/56?text=IMG'; 

function getAuthHeader() {
  const token = localStorage.getItem('token');
  return token ? { 'Authorization': 'Bearer ' + token } : {};
}

(async function init() {
  const token = localStorage.getItem('token');
  if (!token) { alert('請先登入'); window.location.href = 'index.html'; return; }

  try {
    // 1. 取得自己資料
    const res = await fetch('/api/auth/me', { headers: getAuthHeader() });
    if (!res.ok) throw new Error('Auth failed');
    const user = await res.json();
    myId = user.id;
    myName = user.name;

    // 2. 預設顯示對方名字 (如果沒有商品ID，就顯示這個)
    if (targetId) {
      try {
        const uRes = await fetch(`/api/users/${targetId}`);
        if (uRes.ok) {
          const targetUser = await uRes.json();
          chatTitle.textContent = targetUser.name || '聊天室';
        }
      } catch (e) { console.error(e); }
    }

    // 3. 設定商品模式 (✅ 修改重點：標題改成商品名稱，並顯示資訊列)
    if (productId) {
      try {
        const pRes = await fetch(`/api/products/${productId}`);
        if (pRes.ok) {
          const product = await pRes.json();
          
          let imgUrl = FALLBACK_IMG;
          if (product.image) imgUrl = product.image;
          else if (product.images && product.images.length) imgUrl = product.images[0];

          // === 設定資訊列 (保留) ===
          contextImg.src = imgUrl;
          contextTitle.textContent = product.title;
          contextSubtitle.textContent = `NT$ ${product.price}`;
          contextBar.style.cursor = 'pointer';
          contextBar.onclick = () => window.location.href = `product_detail.html?id=${productId}`;
          contextBar.style.display = 'flex';

          // === ✅ 修改重點：將 Header 標題改成商品名稱 ===
          chatTitle.textContent = product.title; 
        }
      } catch (e) { console.error('無法讀取商品資訊', e); }

    } else if (orderId) {
      // --- 訂單模式 (保留原樣) ---
      try {
        const oRes = await fetch('/api/orders/my', { headers: getAuthHeader() }); 
        if (oRes.ok) {
          const orders = await oRes.json();
          const order = orders.find(o => String(o.id) === String(orderId));
          if (order) {
            let items = order.items;
            if (typeof items === 'string') { try { items = JSON.parse(items); } catch(e){ items=[]; } }
            let firstItemName = '商品';
            let imgUrl = FALLBACK_IMG;
            if (Array.isArray(items) && items.length > 0) {
              firstItemName = items[0].title || items[0].name || '未命名商品';
              if (items[0].image) imgUrl = items[0].image;
            }
            contextImg.src = imgUrl;
            contextTitle.textContent = `訂單編號 #${order.id}`;
            const amount = order.total_amount !== undefined ? order.total_amount : order.totalAmount;
            contextSubtitle.textContent = `${firstItemName} 等 (總額 $${amount})`;            contextBar.style.display = 'flex';
            
            // 訂單模式下，標題也可以改成訂單號
            chatTitle.textContent = `訂單洽詢 #${order.id}`;
          }
        }
      } catch (e) { console.error(e); }
    }

    // 4. Socket 連線
    if (myId && targetId) {
      socket.emit('loadHistory', { 
          user1: myId, 
          user2: targetId, 
          productId: productId || 0,
          orderId: orderId || 0      // ✅ 新增這行
      });
    }

  } catch (err) {
    console.error(err);
  }
})();

// Socket 監聽
socket.on('receiveMessage', (msg) => {
  // ✅ 過濾：確保收到的訊息屬於目前的商品 (聊天室)
  if (String(msg.sender_id) === String(myId)) return;
  const currentPid = productId ? String(productId) : '0';
  const msgPid = msg.product_id ? String(msg.product_id) : '0';

  const isRelatedUser = (String(msg.sender_id) === String(targetId) && String(msg.receiver_id) === String(myId)) ||
                        (String(msg.sender_id) === String(myId) && String(msg.receiver_id) === String(targetId));
  
  // 只有當「人對」且「商品ID對」的時候才顯示
  if (isRelatedUser && currentPid === msgPid && currentOid === msgOid) {
      showMsg(msg);
  }
});

socket.on('history', (msgs) => {
  messagesDiv.innerHTML = '';
  msgs.forEach(showMsg);
});

// 發送訊息
function sendMessage() {
  const content = msgInput.value.trim();
  
  if (!myId || !targetId || !content) return;

  // 1. 準備訊息物件
  const msgData = {
    sender: myId, // Socket 傳送用
    receiver: targetId,
    content: content,
    product_id: productId || 0,
    order_id: orderId || 0
  };

  // 2. 發送給 Server
  socket.emit('sendMessage', msgData);

  // ✅ [修正 2] 立即顯示在畫面上 (不用等 Server 回傳)，解決手動更新問題
  // 為了 showMsg 能夠正常運作，我們需要模擬一個完整的 msg 物件
  showMsg({
      sender_id: myId, // showMsg 是用 sender_id 判斷左右
      content: content,
      product_id: productId || 0,
      order_id: orderId || 0
  });

  msgInput.value = '';
}

sendBtn.addEventListener('click', sendMessage);
msgInput.addEventListener('keypress', (e) => { if (e.key === 'Enter') sendMessage(); });

function showMsg(msg) {
  const div = document.createElement('div');
  const isMe = String(msg.sender_id) === String(myId);
  div.className = 'message ' + (isMe ? 'me' : 'other');
  div.textContent = msg.content;
  messagesDiv.appendChild(div);
  messagesDiv.scrollTop = messagesDiv.scrollHeight;
}