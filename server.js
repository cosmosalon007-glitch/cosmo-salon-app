require('dotenv').config();
const express = require('express');
const session = require('express-session');
const axios = require('axios');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const TOKEN_FILE = path.join(__dirname, '.access_token');
const SECRET = process.env.SESSION_SECRET || 'cosmo_secret_change_me';

// ── LOAD SAVED TOKEN ──
let savedAccessToken = process.env.SHOPIFY_ACCESS_TOKEN || '';
if (!savedAccessToken && fs.existsSync(TOKEN_FILE)) {
  savedAccessToken = fs.readFileSync(TOKEN_FILE, 'utf8').trim();
}

// ── MIDDLEWARE ──
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
  secret: SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));

// ════════════════════════════════════════
//  PASSWORD HASHING (built-in crypto — no extra package)
// ════════════════════════════════════════
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return salt + ':' + hash;
}
function verifyPassword(password, stored) {
  try {
    const [salt, hash] = stored.split(':');
    const check = crypto.scryptSync(password, salt, 64).toString('hex');
    return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(check, 'hex'));
  } catch (e) {
    return false;
  }
}

// ════════════════════════════════════════
//  LOGIN TOKEN (signed, stateless — used by the store gate)
// ════════════════════════════════════════
function makeToken(email) {
  const payload = Buffer.from(JSON.stringify({
    email: email,
    exp: Date.now() + 30 * 24 * 60 * 60 * 1000  // 30 days
  })).toString('base64url');
  const sig = crypto.createHmac('sha256', SECRET).update(payload).digest('base64url');
  return payload + '.' + sig;
}
function checkToken(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 2) return null;
    const expected = crypto.createHmac('sha256', SECRET).update(parts[0]).digest('base64url');
    if (parts[1] !== expected) return null;
    const data = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
    if (Date.now() > data.exp) return null;
    return data;
  } catch (e) {
    return null;
  }
}

// ════════════════════════════════════════
//  OAUTH INSTALLATION ROUTES
// ════════════════════════════════════════

// GET /install — Start OAuth
app.get('/install', (req, res) => {
  const shop = process.env.SHOPIFY_STORE_DOMAIN || req.query.shop;
  if (!shop) return res.send('Missing shop parameter');
  const apiKey = process.env.SHOPIFY_API_KEY;
  const scopes = 'read_customers,write_customers,read_orders,read_products';
  const redirectUri = `${process.env.APP_URL}/auth/callback`;
  const state = crypto.randomBytes(16).toString('hex');
  req.session.oauthState = state;
  const installUrl = `https://${shop}/admin/oauth/authorize?client_id=${apiKey}&scope=${scopes}&redirect_uri=${redirectUri}&state=${state}`;
  res.redirect(installUrl);
});

// GET /auth/callback — Complete OAuth, get access token
app.get('/auth/callback', async (req, res) => {
  const { code, state, shop } = req.query;
  try {
    const response = await axios.post(`https://${shop}/admin/oauth/access_token`, {
      client_id: process.env.SHOPIFY_API_KEY,
      client_secret: process.env.SHOPIFY_API_SECRET,
      code
    });
    const token = response.data.access_token;
    savedAccessToken = token;
    fs.writeFileSync(TOKEN_FILE, token);
    res.send(`
      <!DOCTYPE html>
      <html>
      <head><title>App Installed!</title>
      <style>body{font-family:sans-serif;background:#0f0f0f;color:#fff;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
      .box{background:#1a1a1a;border:1px solid #333;border-radius:12px;padding:36px;max-width:600px;text-align:center}
      h2{color:#22c55e;font-size:24px;margin-bottom:16px}
      .token{background:#111;border:1px solid #444;border-radius:8px;padding:16px;font-family:monospace;font-size:13px;word-break:break-all;margin:16px 0;color:#86efac;text-align:left}
      p{color:#aaa;font-size:14px;line-height:1.7}
      .label{font-size:11px;color:#666;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px}</style>
      </head>
      <body>
      <div class="box">
        <h2>✅ App Installed Successfully!</h2>
        <p>Copy this Access Token and save it in Railway as <b>SHOPIFY_ACCESS_TOKEN</b>:</p>
        <div class="label">ACCESS TOKEN — Copy karo</div>
        <div class="token">${token}</div>
        <p>Railway → Your Project → Variables → Add:<br>
        <b>SHOPIFY_ACCESS_TOKEN</b> = <i>above token</i></p>
        <p style="color:#22c55e">Token saved! Admin panel: <a href="/admin" style="color:#86efac">/admin</a></p>
      </div>
      </body>
      </html>
    `);
  } catch (err) {
    res.send('OAuth error: ' + err.message);
  }
});

// GET / — Landing + OAuth code capture (for Dev Dashboard install redirect)
app.get('/', async (req, res) => {
  const { code, shop } = req.query;
  if (code && shop) {
    try {
      const response = await axios.post(`https://${shop}/admin/oauth/access_token`, {
        client_id: process.env.SHOPIFY_API_KEY,
        client_secret: process.env.SHOPIFY_API_SECRET,
        code
      });
      const token = response.data.access_token;
      savedAccessToken = token;
      try { fs.writeFileSync(TOKEN_FILE, token); } catch (e) {}
      return res.send(`
        <!DOCTYPE html><html><head><title>App Installed!</title>
        <style>body{font-family:sans-serif;background:#0f0f0f;color:#fff;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
        .box{background:#1a1a1a;border:1px solid #333;border-radius:12px;padding:36px;max-width:620px;text-align:center}
        h2{color:#22c55e;font-size:24px;margin-bottom:16px}
        .token{background:#111;border:1px solid #444;border-radius:8px;padding:16px;font-family:monospace;font-size:13px;word-break:break-all;margin:16px 0;color:#86efac}
        p{color:#aaa;font-size:14px;line-height:1.7}</style></head>
        <body><div class="box">
        <h2>✅ App Installed Successfully!</h2>
        <p>Copy this Access Token and paste it in Railway as <b>SHOPIFY_ACCESS_TOKEN</b>:</p>
        <div class="token">${token}</div>
        <p>Railway → Variables → SHOPIFY_ACCESS_TOKEN = above token → Deploy</p>
        <p style="color:#22c55e">Admin panel: <a href="/admin" style="color:#86efac">/admin</a></p>
        </div></body></html>
      `);
    } catch (err) {
      const detail = err.response?.data ? JSON.stringify(err.response.data) : err.message;
      return res.send('OAuth token exchange error: ' + detail + ' — Please re-install from the Dev Dashboard (the code may have expired).');
    }
  }
  res.send(`<!DOCTYPE html><html><head><title>Cosmo App</title>
    <style>body{font-family:sans-serif;background:#1C0B1A;color:#fff;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
    .b{text-align:center}a{color:#C9A96E}</style></head>
    <body><div class="b"><h2>🌸 Cosmo App is running</h2>
    <p><a href="/admin">Admin Panel</a> · <a href="/login">Customer Login</a> · <a href="/register">Register</a></p>
    </div></body></html>`);
});

// ── SHOPIFY API HELPER ──
function getShopifyAPI() {
  return axios.create({
    baseURL: `https://${process.env.SHOPIFY_STORE_DOMAIN}/admin/api/2024-01`,
    headers: {
      'X-Shopify-Access-Token': savedAccessToken,
      'Content-Type': 'application/json'
    }
  });
}
const shopifyAPI = {
  get: (...a) => getShopifyAPI().get(...a),
  post: (...a) => getShopifyAPI().post(...a),
  put: (...a) => getShopifyAPI().put(...a),
  delete: (...a) => getShopifyAPI().delete(...a)
};

// ── EMAIL HELPER (non-blocking — call without await) ──
async function sendEmail(to, subject, html) {
  if (!process.env.GMAIL_USER || !process.env.GMAIL_PASS) {
    console.log('Email skipped (GMAIL_USER/GMAIL_PASS not set)');
    return;
  }
  try {
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_PASS }
    });
    await transporter.sendMail({
      from: `"Cosmo Salon" <${process.env.GMAIL_USER}>`,
      to, subject, html
    });
    console.log('Email sent to', to);
  } catch (e) {
    console.log('Email error:', e.message);
  }
}

// ── ADMIN AUTH MIDDLEWARE ──
function requireAdmin(req, res, next) {
  if (req.session.isAdmin) return next();
  res.redirect('/admin/login');
}

// ════════════════════════════════════════
//  STORE GATE — token verify (called by theme.liquid)
// ════════════════════════════════════════
app.get('/verify', (req, res) => {
  res.set('Access-Control-Allow-Origin', '*');
  const token = req.query.token;
  const data = token ? checkToken(token) : null;
  res.json({ ok: !!data });
});

// ════════════════════════════════════════
//  CUSTOMER LOGIN ROUTES  (email + password)
// ════════════════════════════════════════

// GET /login — Customer Login Form
app.get('/login', (req, res) => {
  res.send(loginPage());
});

// POST /login — Verify email + password + approved, then let into store
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.send(loginPage('Please enter your email and password.', email));

  try {
    const response = await shopifyAPI.get('/customers/search.json', {
      params: { query: `email:${email}`, limit: 1 }
    });
    const customers = response.data.customers || [];

    if (customers.length === 0) {
      return res.send(loginPage('No account found with this email. Please register first.', email));
    }

    const customer = customers[0];
    const tags = (customer.tags || '').split(',').map(t => t.trim());

    // Not approved yet?
    if (!tags.includes('approved')) {
      if (tags.includes('rejected')) {
        return res.send(loginPage('Your account request was declined. Please contact Cosmo Salon for details.', email));
      }
      if (tags.includes('pending_approval')) {
        return res.send(loginPage('⏳ Your account is pending admin approval. You will receive an email once approved.', email));
      }
      return res.send(loginPage('Your account is not approved yet. Please contact Cosmo Salon.', email));
    }

    // Verify password (hash stored in customer note)
    const note = customer.note || '';
    const pwdMatch = note.match(/PWD:\s*([^\s|]+)/);
    if (!pwdMatch || !verifyPassword(password, pwdMatch[1])) {
      return res.send(loginPage('Wrong password. Please try again.', email));
    }

    // Success! Make a login token and send them into the store
    const token = makeToken(email);
    const store = process.env.SHOPIFY_STORE_DOMAIN;
    return res.redirect(`https://${store}/?cosmo_token=${encodeURIComponent(token)}`);

  } catch (err) {
    console.log('Login error:', err.message);
    return res.send(loginPage('Something went wrong. Please try again.', email));
  }
});

// GET /register — Registration Form
app.get('/register', (req, res) => {
  res.send(registerPage());
});

// POST /register — Submit Registration
app.post('/register', async (req, res) => {
  const { first_name, phone, email, password, whatsapp, branch } = req.body;

  if (!first_name || !email || !password || !branch) {
    return res.send(registerPage('Please fill all required fields.'));
  }
  if (password.length < 5) {
    return res.send(registerPage('Password must be at least 5 characters.'));
  }

  try {
    const pwdHash = hashPassword(password);

    const response = await shopifyAPI.post('/customers.json', {
      customer: {
        first_name: first_name,
        last_name: '.',
        email: email,
        phone: phone || '',
        tags: 'pending_approval',
        note: `WhatsApp: ${whatsapp || 'Not provided'} | Branch: ${branch} | Status: pending_approval | PWD: ${pwdHash}`,
        send_email_welcome: false
      }
    });

    const customer = response.data.customer;

    // Notify admin (non-blocking — do NOT await, keeps page fast)
    sendEmail(
      process.env.ADMIN_EMAIL,
      `🆕 New Registration — ${first_name} (${branch})`,
      `
        <h2>New Customer Registration</h2>
        <p><b>Name:</b> ${first_name}</p>
        <p><b>Email:</b> ${email}</p>
        <p><b>Phone:</b> ${phone || 'N/A'}</p>
        <p><b>WhatsApp:</b> ${whatsapp || 'N/A'}</p>
        <p><b>Branch:</b> ${branch}</p>
        <p><b>Customer ID:</b> ${customer.id}</p>
        <br>
        <a href="${process.env.APP_URL}/admin" style="background:#1C0B1A;color:white;padding:10px 20px;text-decoration:none;border-radius:6px;">
          Open Admin Panel to Approve
        </a>
      `
    );

    return res.send(successPage(first_name));

  } catch (err) {
    const errors = err.response?.data?.errors;
    let msg = 'Something went wrong. Please try again.';
    if (errors?.email) msg = 'This email is already registered. Please sign in.';
    else if (errors?.phone) msg = 'Invalid phone number format.';
    return res.send(registerPage(msg));
  }
});

// ════════════════════════════════════════
//  ADMIN ROUTES
// ════════════════════════════════════════

// GET /admin/login
app.get('/admin/login', (req, res) => {
  if (req.session.isAdmin) return res.redirect('/admin');
  res.send(adminLoginPage());
});

// POST /admin/login
app.post('/admin/login', (req, res) => {
  const { password } = req.body;
  if (password === (process.env.ADMIN_PASSWORD || 'cosmo@admin123')) {
    req.session.isAdmin = true;
    res.redirect('/admin');
  } else {
    res.send(adminLoginPage('Wrong password. Try again.'));
  }
});

// GET /admin/logout
app.get('/admin/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/admin/login');
});

// GET /admin — Dashboard (pending customers)
app.get('/admin', requireAdmin, async (req, res) => {
  try {
    const response = await shopifyAPI.get('/customers/search.json', {
      params: { query: 'tag:pending_approval', limit: 100 }
    });
    const pending = response.data.customers || [];
    res.send(adminDashboard(pending));
  } catch (err) {
    res.send(adminDashboard([], 'Could not load customers: ' + err.message));
  }
});

// POST /admin/approve/:id — Approve a customer
app.post('/admin/approve/:id', requireAdmin, async (req, res) => {
  const id = req.params.id;
  try {
    const getRes = await shopifyAPI.get(`/customers/${id}.json`);
    const customer = getRes.data.customer;

    const currentTags = (customer.tags || '').split(',').map(t => t.trim()).filter(t => t && t !== 'pending_approval' && t !== 'rejected');
    currentTags.push('approved');

    await shopifyAPI.put(`/customers/${id}.json`, {
      customer: {
        id: id,
        tags: currentTags.join(', '),
        note: (customer.note || '').replace('Status: pending_approval', 'Status: approved')
      }
    });

    // Email customer (non-blocking)
    sendEmail(
      customer.email,
      '✅ Your Cosmo Salon account is approved!',
      `
        <h2>Welcome to Cosmo Salon Store!</h2>
        <p>Dear ${customer.first_name},</p>
        <p>Your account has been approved. You can now sign in with your email and password and place orders.</p>
        <br>
        <a href="${process.env.APP_URL}/login"
           style="background:#1C0B1A;color:white;padding:12px 24px;text-decoration:none;border-radius:6px;">
          Sign In Now
        </a>
        <br><br>
        <p>Thank you,<br>Cosmo Salon Team</p>
      `
    );

    res.json({ success: true });
  } catch (err) {
    res.json({ success: false, error: err.message });
  }
});

// POST /admin/reject/:id — Reject customer (keeps record, tags as rejected)
app.post('/admin/reject/:id', requireAdmin, async (req, res) => {
  const id = req.params.id;
  try {
    const getRes = await shopifyAPI.get(`/customers/${id}.json`);
    const customer = getRes.data.customer;

    const currentTags = (customer.tags || '').split(',').map(t => t.trim()).filter(t => t && t !== 'pending_approval' && t !== 'approved');
    currentTags.push('rejected');

    await shopifyAPI.put(`/customers/${id}.json`, {
      customer: {
        id: id,
        tags: currentTags.join(', '),
        note: (customer.note || '').replace(/Status: [^|]*/, 'Status: rejected ')
      }
    });

    sendEmail(
      customer.email,
      'Your Cosmo Salon account request',
      `
        <p>Dear ${customer.first_name},</p>
        <p>Unfortunately, your account request could not be approved at this time.</p>
        <p>Please contact us for more information.</p>
        <p>— Cosmo Salon Team</p>
      `
    );

    res.json({ success: true });
  } catch (err) {
    res.json({ success: false, error: err.message });
  }
});

// POST /admin/reset-password/:id — Admin sets a new password for a customer
app.post('/admin/reset-password/:id', requireAdmin, async (req, res) => {
  const id = req.params.id;
  const { password } = req.body;
  if (!password || password.length < 5) {
    return res.json({ success: false, error: 'Password must be at least 5 characters.' });
  }
  try {
    const getRes = await shopifyAPI.get(`/customers/${id}.json`);
    const customer = getRes.data.customer;
    const newHash = hashPassword(password);
    let note = customer.note || '';
    if (note.match(/PWD:\s*[^\s|]+/)) {
      note = note.replace(/PWD:\s*[^\s|]+/, 'PWD: ' + newHash);
    } else {
      note = note + ' | PWD: ' + newHash;
    }
    await shopifyAPI.put(`/customers/${id}.json`, {
      customer: { id: id, note: note }
    });
    res.json({ success: true });
  } catch (err) {
    res.json({ success: false, error: err.message });
  }
});

// GET /admin/approved — All approved customers
app.get('/admin/approved', requireAdmin, async (req, res) => {
  try {
    const response = await shopifyAPI.get('/customers/search.json', {
      params: { query: 'tag:approved', limit: 100 }
    });
    const approved = response.data.customers || [];
    res.send(approvedPage(approved));
  } catch (err) {
    res.send(approvedPage([], 'Error: ' + err.message));
  }
});

// GET /admin/rejected — All rejected customers
app.get('/admin/rejected', requireAdmin, async (req, res) => {
  try {
    const response = await shopifyAPI.get('/customers/search.json', {
      params: { query: 'tag:rejected', limit: 100 }
    });
    const rejected = response.data.customers || [];
    res.send(rejectedPage(rejected));
  } catch (err) {
    res.send(rejectedPage([], 'Error: ' + err.message));
  }
});

// ════════════════════════════════════════
//  HTML TEMPLATES
// ════════════════════════════════════════

function loginPage(error = '', email = '') {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign In — Cosmo Salon Store</title>
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;600&family=DM+Sans:wght@300;400;500&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--plum:#1C0B1A;--gold:#C9A96E;--cream:#FBF8F5;--border:#E8DDE6;--error:#B83A4A;--text:#1A1015;--muted:#5C4B56}
body{font-family:'DM Sans',sans-serif;background:var(--cream);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
.card{background:#fff;border-radius:16px;box-shadow:0 4px 40px rgba(28,11,26,.1);width:100%;max-width:420px;padding:40px 36px}
.logo{text-align:center;margin-bottom:28px}
.logo h1{font-family:'Playfair Display',serif;font-size:22px;color:var(--plum)}
.logo p{font-size:12px;letter-spacing:3px;text-transform:uppercase;color:var(--gold);margin-top:4px}
h2{font-family:'Playfair Display',serif;font-size:20px;font-weight:400;margin-bottom:20px;color:var(--text)}
.error-box{background:#fef2f2;border:1px solid #fca5a5;border-radius:8px;padding:12px 14px;margin-bottom:20px;font-size:13px;color:var(--error);line-height:1.6}
.pending-box{background:#fef9f0;border:1px solid #dfc98a;border-radius:8px;padding:12px 14px;margin-bottom:20px;font-size:13px;color:#7a6040;line-height:1.6}
.field{margin-bottom:16px}
.field label{display:block;font-size:12px;font-weight:500;color:var(--muted);margin-bottom:5px}
.field input{width:100%;height:44px;padding:0 13px;border:1.5px solid var(--border);border-radius:8px;font-family:'DM Sans',sans-serif;font-size:14px;color:var(--text);background:#fff;outline:none;transition:border-color .18s}
.field input:focus{border-color:var(--gold)}
.btn{width:100%;height:46px;background:var(--plum);color:#fff;border:none;border-radius:8px;font-family:'DM Sans',sans-serif;font-size:15px;font-weight:500;cursor:pointer;margin-top:4px;transition:opacity .18s}
.btn:hover{opacity:.85}
.links{text-align:center;margin-top:18px;font-size:13px;color:var(--muted)}
.links a{color:var(--plum);font-weight:500;text-decoration:none}
.divider{border:none;border-top:1px solid var(--border);margin:20px 0}
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <h1>Cosmo Salon Store</h1>
    <p>Partner Portal</p>
  </div>
  <h2>Sign In to Your Account</h2>
  ${error && error.includes('pending') ? `<div class="pending-box">${error}</div>` : error ? `<div class="error-box">⚠️ ${error}</div>` : ''}
  <form method="POST" action="/login">
    <div class="field">
      <label>Email Address *</label>
      <input type="email" name="email" placeholder="you@example.com" value="${email}" required autofocus>
    </div>
    <div class="field">
      <label>Password *</label>
      <div style="position:relative">
        <input type="password" name="password" id="loginPw" placeholder="Your password" required style="padding-right:46px">
        <button type="button" onclick="togglePw('loginPw',this)" aria-label="Show password" style="position:absolute;right:8px;top:0;height:44px;background:none;border:none;cursor:pointer;font-size:17px;color:#5C4B56">👁</button>
      </div>
    </div>
    <button type="submit" class="btn">Sign In →</button>
  </form>
  <hr class="divider">
  <div class="links">
    Don't have an account? <a href="/register">Register here</a>
  </div>
</div>
<script>
function togglePw(id,btn){var i=document.getElementById(id);if(i.type==='password'){i.type='text';btn.textContent='🙈';}else{i.type='password';btn.textContent='👁';}}
</script>
</body>
</html>`;
}

function registerPage(error = '') {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Register — Cosmo Salon Store</title>
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;600&family=DM+Sans:wght@300;400;500&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--plum:#1C0B1A;--gold:#C9A96E;--cream:#FBF8F5;--border:#E8DDE6;--error:#B83A4A;--text:#1A1015;--muted:#5C4B56}
body{font-family:'DM Sans',sans-serif;background:var(--cream);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
.card{background:#fff;border-radius:16px;box-shadow:0 4px 40px rgba(28,11,26,.1);width:100%;max-width:460px;padding:40px 36px}
.logo{text-align:center;margin-bottom:28px}
.logo h1{font-family:'Playfair Display',serif;font-size:22px;color:var(--plum)}
.logo p{font-size:12px;letter-spacing:3px;text-transform:uppercase;color:var(--gold);margin-top:4px}
h2{font-family:'Playfair Display',serif;font-size:20px;font-weight:400;margin-bottom:6px;color:var(--text)}
.subtitle{font-size:13px;color:var(--muted);margin-bottom:24px;line-height:1.6}
.notice{background:#fef9f0;border:1px solid #dfc98a;border-radius:8px;padding:11px 14px;margin-bottom:20px;font-size:12.5px;color:#7a6040;line-height:1.6}
.error-box{background:#fef2f2;border:1px solid #fca5a5;border-radius:8px;padding:11px 14px;margin-bottom:20px;font-size:13px;color:var(--error)}
.field{margin-bottom:14px}
.field label{display:block;font-size:12px;font-weight:500;color:var(--muted);margin-bottom:5px}
.field input,.field select{width:100%;height:44px;padding:0 13px;border:1.5px solid var(--border);border-radius:8px;font-family:'DM Sans',sans-serif;font-size:14px;color:var(--text);background:#fff;outline:none;transition:border-color .18s;appearance:none}
.field input:focus,.field select:focus{border-color:var(--gold)}
.field select{background-image:url("data:image/svg+xml,%3Csvg width='13' height='8' viewBox='0 0 13 8' fill='none' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M1 1L6.5 7L12 1' stroke='%23888' stroke-width='1.5' stroke-linecap='round'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 13px center;padding-right:36px;cursor:pointer}
.btn{width:100%;height:46px;background:var(--plum);color:#fff;border:none;border-radius:8px;font-family:'DM Sans',sans-serif;font-size:15px;font-weight:500;cursor:pointer;margin-top:8px;transition:opacity .18s}
.btn:hover{opacity:.85}
.signin-link{text-align:center;margin-top:18px;font-size:13px;color:var(--muted)}
.signin-link a{color:var(--plum);font-weight:500}
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <h1>Cosmo Salon Store</h1>
    <p>Partner Portal</p>
  </div>
  <h2>New Customer Registration</h2>
  <p class="subtitle">Create a new account. New accounts require admin approval before they can be used.</p>
  ${error ? `<div class="error-box">⚠️ ${error}</div>` : ''}
  <div class="notice">ℹ️ Your account will be reviewed by our admin team before access is granted.</div>
  <form method="POST" action="/register">
    <div class="field">
      <label>Full Name *</label>
      <input type="text" name="first_name" placeholder="Your full name" required>
    </div>
    <div class="field">
      <label>Phone Number</label>
      <input type="tel" name="phone" placeholder="+92 300 0000000">
    </div>
    <div class="field">
      <label>Email Address *</label>
      <input type="email" name="email" placeholder="you@example.com" required>
    </div>
    <div class="field">
      <label>Password *</label>
      <div style="position:relative">
        <input type="password" name="password" id="regPw" placeholder="Minimum 5 characters" required style="padding-right:46px">
        <button type="button" onclick="togglePw('regPw',this)" aria-label="Show password" style="position:absolute;right:8px;top:0;height:44px;background:none;border:none;cursor:pointer;font-size:17px;color:#5C4B56">👁</button>
      </div>
    </div>
    <div class="field">
      <label>WhatsApp Number</label>
      <input type="tel" name="whatsapp" placeholder="+92 300 0000000">
    </div>
    <div class="field">
      <label>Branch Name *</label>
      <select name="branch" required>
        <option value="">Select your branch</option>
        <option>MM Alam — Women</option>
        <option>MM Alam — Men</option>
        <option>DHA — Women</option>
        <option>DHA — Men</option>
        <option>PIA — Women</option>
        <option>PIA — Men</option>
        <option>Iqbal Town — Women</option>
      </select>
    </div>
    <button type="submit" class="btn">Create Account</button>
  </form>
  <p class="signin-link">Already have an account? <a href="/login">Sign in</a></p>
</div>
<script>
function togglePw(id,btn){var i=document.getElementById(id);if(i.type==='password'){i.type='text';btn.textContent='🙈';}else{i.type='password';btn.textContent='👁';}}
</script>
</body>
</html>`;
}

function successPage(name) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Registration Submitted — Cosmo Salon Store</title>
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400&family=DM+Sans:wght@400;500&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'DM Sans',sans-serif;background:#FBF8F5;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
.card{background:#fff;border-radius:16px;box-shadow:0 4px 40px rgba(28,11,26,.1);max-width:420px;width:100%;padding:48px 36px;text-align:center}
.icon{width:64px;height:64px;background:#f0faf4;border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 20px;font-size:28px}
h2{font-family:'Playfair Display',serif;font-size:22px;font-weight:400;margin-bottom:10px;color:#1A1015}
p{font-size:13.5px;color:#5C4B56;line-height:1.75;margin-bottom:8px}
.btn{display:inline-block;margin-top:16px;background:#1C0B1A;color:#fff;padding:11px 26px;border-radius:8px;text-decoration:none;font-size:14px}
</style>
</head>
<body>
<div class="card">
  <div class="icon">✅</div>
  <h2>Registration Submitted!</h2>
  <p>Thank you, <b>${name}</b>!</p>
  <p>Your account request has been received. Our admin team will review and approve your account. You'll receive an email once access is granted.</p>
  <a href="/login" class="btn">Go to Sign In</a>
</div>
</body>
</html>`;
}

function adminLoginPage(error = '') {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin Login — Cosmo Salon</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:sans-serif;background:#1C0B1A;min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:#fff;border-radius:12px;padding:36px 32px;width:340px}
h2{font-size:20px;margin-bottom:20px;color:#1C0B1A}
.err{background:#fef2f2;border:1px solid #fca5a5;border-radius:6px;padding:10px;margin-bottom:16px;font-size:13px;color:#b83a4a}
input{width:100%;height:42px;border:1.5px solid #E8DDE6;border-radius:7px;padding:0 12px;font-size:14px;margin-bottom:14px;outline:none}
input:focus{border-color:#C9A96E}
button{width:100%;height:44px;background:#1C0B1A;color:#fff;border:none;border-radius:7px;font-size:15px;cursor:pointer}
</style>
</head>
<body>
<div class="card">
  <h2>🔐 Admin Login</h2>
  ${error ? `<div class="err">${error}</div>` : ''}
  <form method="POST" action="/admin/login">
    <input type="password" name="password" placeholder="Admin Password" required autofocus>
    <button type="submit">Sign In</button>
  </form>
</div>
</body>
</html>`;
}

function adminDashboard(customers, error = '') {
  const rows = customers.map(c => {
    const note = c.note || '';
    const branch = note.match(/Branch: ([^|]+)/)?.[1]?.trim() || 'N/A';
    const whatsapp = note.match(/WhatsApp: ([^|]+)/)?.[1]?.trim() || 'N/A';
    return `<tr>
      <td>${c.first_name} ${c.last_name !== '.' ? c.last_name : ''}</td>
      <td>${c.email}</td>
      <td>${c.phone || 'N/A'}</td>
      <td>${whatsapp}</td>
      <td><b>${branch}</b></td>
      <td>${new Date(c.created_at).toLocaleDateString('en-PK')}</td>
      <td>
        <button onclick="approve(${c.id}, this)" style="background:#16a34a;color:#fff;border:none;padding:6px 14px;border-radius:6px;cursor:pointer;margin-right:6px">✓ Approve</button>
        <button onclick="reject(${c.id}, this)" style="background:#dc2626;color:#fff;border:none;padding:6px 14px;border-radius:6px;cursor:pointer">✗ Reject</button>
      </td>
    </tr>`;
  }).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin — Cosmo Salon</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:sans-serif;background:#f5f5f5;min-height:100vh}
.header{background:#1C0B1A;color:#fff;padding:16px 28px;display:flex;justify-content:space-between;align-items:center}
.header h1{font-size:18px;letter-spacing:.5px}
.header a{color:#C9A96E;text-decoration:none;font-size:13px}
.nav{background:#2E1229;padding:10px 28px;display:flex;gap:16px}
.nav a{color:rgba(255,255,255,.7);text-decoration:none;font-size:13px;padding:6px 12px;border-radius:6px}
.nav a.active,.nav a:hover{background:rgba(255,255,255,.1);color:#fff}
.body{padding:24px 28px}
h2{font-size:18px;margin-bottom:16px;color:#1C0B1A}
.badge{display:inline-block;background:#dc2626;color:#fff;border-radius:99px;font-size:11px;padding:2px 8px;margin-left:8px}
table{width:100%;background:#fff;border-radius:10px;border-collapse:collapse;box-shadow:0 1px 8px rgba(0,0,0,.06)}
th{background:#1C0B1A;color:#fff;padding:11px 14px;text-align:left;font-size:12px;font-weight:500}
td{padding:11px 14px;border-bottom:1px solid #f0f0f0;font-size:13px;color:#333;vertical-align:middle}
tr:last-child td{border-bottom:none}
tr:hover td{background:#fafafa}
.empty{text-align:center;padding:40px;color:#888;font-size:14px}
</style>
</head>
<body>
<div class="header">
  <h1>🌸 Cosmo Salon — Admin Panel</h1>
  <a href="/admin/logout">Sign out</a>
</div>
<div class="nav">
  <a href="/admin" class="active">⏳ Pending <span class="badge">${customers.length}</span></a>
  <a href="/admin/approved">✅ Approved</a>
  <a href="/admin/rejected">✗ Rejected</a>
  <a href="/admin/po">📦 Branch Orders &amp; PO</a>
</div>
<div class="body">
  <h2>Pending Approvals</h2>
  ${error ? `<p style="color:red;margin-bottom:16px">${error}</p>` : ''}
  ${customers.length === 0 ? '<p class="empty">🎉 No pending registrations right now.</p>' : `
  <table>
    <thead><tr>
      <th>Name</th><th>Email</th><th>Phone</th><th>WhatsApp</th><th>Branch</th><th>Date</th><th>Action</th>
    </tr></thead>
    <tbody>${rows}</tbody>
  </table>`}
</div>
<script>
async function approve(id, btn) {
  if (!confirm('Approve this customer?')) return;
  btn.disabled = true; btn.textContent = '...';
  const r = await fetch('/admin/approve/' + id, {method:'POST'});
  const d = await r.json();
  if (d.success) { btn.closest('tr').remove(); alert('✅ Customer approved! Email sent.'); }
  else { alert('Error: ' + d.error); btn.disabled = false; btn.textContent = '✓ Approve'; }
}
async function reject(id, btn) {
  if (!confirm('Reject this customer? (They will move to the Rejected list.)')) return;
  btn.disabled = true; btn.textContent = '...';
  const r = await fetch('/admin/reject/' + id, {method:'POST'});
  const d = await r.json();
  if (d.success) { btn.closest('tr').remove(); alert('Customer moved to Rejected list.'); }
  else { alert('Error: ' + d.error); btn.disabled = false; btn.textContent = '✗ Reject'; }
}
</script>
</body>
</html>`;
}

function approvedPage(customers, error = '') {
  const rows = customers.map(c => {
    const note = c.note || '';
    const branch = note.match(/Branch: ([^|]+)/)?.[1]?.trim() || 'N/A';
    return `<tr>
      <td>${c.first_name}</td>
      <td>${c.email}</td>
      <td>${c.phone || 'N/A'}</td>
      <td><b>${branch}</b></td>
      <td>${new Date(c.created_at).toLocaleDateString('en-PK')}</td>
      <td><button onclick="resetPwd(${c.id}, this)" style="background:#C9A96E;color:#1C0B1A;border:none;padding:6px 14px;border-radius:6px;cursor:pointer;font-weight:600">🔑 Reset Password</button></td>
    </tr>`;
  }).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Approved — Cosmo Salon</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:sans-serif;background:#f5f5f5}
.header{background:#1C0B1A;color:#fff;padding:16px 28px;display:flex;justify-content:space-between;align-items:center}
.header h1{font-size:18px}
.header a{color:#C9A96E;text-decoration:none;font-size:13px}
.nav{background:#2E1229;padding:10px 28px;display:flex;gap:16px}
.nav a{color:rgba(255,255,255,.7);text-decoration:none;font-size:13px;padding:6px 12px;border-radius:6px}
.nav a.active,.nav a:hover{background:rgba(255,255,255,.1);color:#fff}
.body{padding:24px 28px}
h2{font-size:18px;margin-bottom:16px;color:#1C0B1A}
table{width:100%;background:#fff;border-radius:10px;border-collapse:collapse;box-shadow:0 1px 8px rgba(0,0,0,.06)}
th{background:#16a34a;color:#fff;padding:11px 14px;text-align:left;font-size:12px}
td{padding:11px 14px;border-bottom:1px solid #f0f0f0;font-size:13px;color:#333}
tr:last-child td{border-bottom:none}
.empty{text-align:center;padding:40px;color:#888;font-size:14px}
</style>
</head>
<body>
<div class="header">
  <h1>🌸 Cosmo Salon — Admin Panel</h1>
  <a href="/admin/logout">Sign out</a>
</div>
<div class="nav">
  <a href="/admin">⏳ Pending</a>
  <a href="/admin/approved" class="active">✅ Approved (${customers.length})</a>
  <a href="/admin/rejected">✗ Rejected</a>
  <a href="/admin/po">📦 Branch Orders &amp; PO</a>
</div>
<div class="body">
  <h2>Approved Customers</h2>
  ${error ? `<p style="color:red;margin-bottom:16px">${error}</p>` : ''}
  ${customers.length === 0 ? '<p class="empty">No approved customers yet.</p>' : `
  <table>
    <thead><tr><th>Name</th><th>Email</th><th>Phone</th><th>Branch</th><th>Registered</th><th>Action</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>`}
</div>
<script>
async function resetPwd(id, btn) {
  var np = prompt('Enter NEW password for this customer (min 5 characters):');
  if (np === null) return;
  if (np.length < 5) { alert('Password must be at least 5 characters.'); return; }
  btn.disabled = true; var old = btn.textContent; btn.textContent = '...';
  const r = await fetch('/admin/reset-password/' + id, {
    method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({password: np})
  });
  const d = await r.json();
  if (d.success) { alert('✅ Password updated!\\nNew password: ' + np + '\\nTell this to the customer.'); }
  else { alert('Error: ' + (d.error||'failed')); }
  btn.disabled = false; btn.textContent = old;
}
</script>
</body>
</html>`;
}

function rejectedPage(customers, error = '') {
  const rows = customers.map(c => {
    const note = c.note || '';
    const branch = note.match(/Branch: ([^|]+)/)?.[1]?.trim() || 'N/A';
    const whatsapp = note.match(/WhatsApp: ([^|]+)/)?.[1]?.trim() || 'N/A';
    return `<tr>
      <td>${c.first_name}</td>
      <td>${c.email}</td>
      <td>${c.phone || 'N/A'}</td>
      <td>${whatsapp}</td>
      <td><b>${branch}</b></td>
      <td>${new Date(c.created_at).toLocaleDateString('en-PK')}</td>
      <td>
        <button onclick="reapprove(${c.id}, this)" style="background:#16a34a;color:#fff;border:none;padding:6px 14px;border-radius:6px;cursor:pointer">✓ Approve</button>
      </td>
    </tr>`;
  }).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Rejected — Cosmo Salon</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:sans-serif;background:#f5f5f5}
.header{background:#1C0B1A;color:#fff;padding:16px 28px;display:flex;justify-content:space-between;align-items:center}
.header h1{font-size:18px}
.header a{color:#C9A96E;text-decoration:none;font-size:13px}
.nav{background:#2E1229;padding:10px 28px;display:flex;gap:16px}
.nav a{color:rgba(255,255,255,.7);text-decoration:none;font-size:13px;padding:6px 12px;border-radius:6px}
.nav a.active,.nav a:hover{background:rgba(255,255,255,.1);color:#fff}
.body{padding:24px 28px}
h2{font-size:18px;margin-bottom:16px;color:#1C0B1A}
table{width:100%;background:#fff;border-radius:10px;border-collapse:collapse;box-shadow:0 1px 8px rgba(0,0,0,.06)}
th{background:#dc2626;color:#fff;padding:11px 14px;text-align:left;font-size:12px}
td{padding:11px 14px;border-bottom:1px solid #f0f0f0;font-size:13px;color:#333;vertical-align:middle}
tr:last-child td{border-bottom:none}
.empty{text-align:center;padding:40px;color:#888;font-size:14px}
</style>
</head>
<body>
<div class="header">
  <h1>🌸 Cosmo Salon — Admin Panel</h1>
  <a href="/admin/logout">Sign out</a>
</div>
<div class="nav">
  <a href="/admin">⏳ Pending</a>
  <a href="/admin/approved">✅ Approved</a>
  <a href="/admin/rejected" class="active">✗ Rejected (${customers.length})</a>
  <a href="/admin/po">📦 Branch Orders &amp; PO</a>
</div>
<div class="body">
  <h2>Rejected Requests</h2>
  ${error ? `<p style="color:red;margin-bottom:16px">${error}</p>` : ''}
  ${customers.length === 0 ? '<p class="empty">No rejected requests.</p>' : `
  <table>
    <thead><tr><th>Name</th><th>Email</th><th>Phone</th><th>WhatsApp</th><th>Branch</th><th>Date</th><th>Action</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>`}
</div>
<script>
async function reapprove(id, btn) {
  if (!confirm('Approve this rejected customer?')) return;
  btn.disabled = true; btn.textContent = '...';
  const r = await fetch('/admin/approve/' + id, {method:'POST'});
  const d = await r.json();
  if (d.success) { btn.closest('tr').remove(); alert('✅ Customer approved! Email sent.'); }
  else { alert('Error: ' + d.error); btn.disabled = false; btn.textContent = '✓ Approve'; }
}
</script>
</body>
</html>`;
}

// ════════════════════════════════════════
//  BRANCH ORDERS & PURCHASE ORDERS (PO)
// ════════════════════════════════════════
const BRANCHES = ['MM Alam — Women','MM Alam — Men','DHA — Women','DHA — Men','PIA — Women','PIA — Men','Iqbal Town — Women'];

function parseNoteBranch(note){ const m=(note||'').match(/Branch:\s*([^|]+)/); return m ? m[1].trim() : ''; }
function pkDate(dt){ return new Date(dt.getTime()+5*3600000).toISOString().slice(0,10); }
function fmtDateTime(iso){
  try{
    const d=new Date(iso);
    return {
      date:d.toLocaleDateString('en-GB',{day:'2-digit',month:'short',year:'numeric',timeZone:'Asia/Karachi'}),
      time:d.toLocaleTimeString('en-US',{hour:'2-digit',minute:'2-digit',timeZone:'Asia/Karachi'})
    };
  }catch(e){ return {date:String(iso).slice(0,10),time:''}; }
}
function money(n){ return (Math.round(Number(n)||0)).toLocaleString('en-PK'); }
function esc(s){ return String(s==null?'':s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }

async function customerBranchMap(){
  const map={};
  for(const q of ['tag:approved','tag:pending_approval','tag:rejected']){
    try{
      const r=await shopifyAPI.get('/customers/search.json',{params:{query:q,limit:250}});
      (r.data.customers||[]).forEach(c=>{
        map[c.id]={branch:parseNoteBranch(c.note),name:`${c.first_name||''} ${(c.last_name&&c.last_name!=='.')?c.last_name:''}`.trim(),phone:c.phone||'',email:c.email||''};
      });
    }catch(e){}
  }
  return map;
}

async function getBranchOrders(branch, from, to){
  const map=await customerBranchMap();
  const minISO=`${from}T00:00:00+05:00`, maxISO=`${to}T23:59:59+05:00`;
  const r=await shopifyAPI.get('/orders.json',{params:{status:'any',created_at_min:minISO,created_at_max:maxISO,limit:250}});
  return (r.data.orders||[]).map(o=>{
    const cb=(o.customer&&map[o.customer.id])?map[o.customer.id]:null;
    return Object.assign({},o,{_branch:cb?cb.branch:'',_cust:cb});
  }).filter(o=>o._branch===branch);
}

function presets(branch){
  const now=new Date(), today=pkDate(now);
  const minus=(d)=>pkDate(new Date(now.getTime()-d*86400000));
  return [
    {label:'Today',from:today,to:today},
    {label:'Yesterday',from:minus(1),to:minus(1)},
    {label:'This week',from:minus(6),to:today},
    {label:'This month',from:minus(29),to:today},
    {label:'All time',from:'2020-01-01',to:today}
  ].map(p=>Object.assign(p,{url:`/admin/po?branch=${encodeURIComponent(branch)}&from=${p.from}&to=${p.to}`}));
}

// GET /admin/po — Branch Orders & PO portal
app.get('/admin/po', requireAdmin, async (req,res)=>{
  const branch=req.query.branch||BRANCHES[0];
  const today=pkDate(new Date());
  const from=req.query.from||today, to=req.query.to||today;
  try{
    const orders=await getBranchOrders(branch,from,to);
    res.send(poPortalPage(branch,from,to,orders));
  }catch(err){
    const msg=(err.response&&err.response.data&&err.response.data.errors)?JSON.stringify(err.response.data.errors):err.message;
    res.send(poPortalPage(branch,from,to,[],msg));
  }
});

// GET /admin/po/doc — Printable Purchase Order
app.get('/admin/po/doc', requireAdmin, async (req,res)=>{
  const branch=req.query.branch||BRANCHES[0];
  const today=pkDate(new Date());
  const from=req.query.from||today, to=req.query.to||today;
  try{
    const orders=await getBranchOrders(branch,from,to);
    res.send(poDocPage(branch,from,to,orders,req.query.auto));
  }catch(err){ res.send('Error: '+esc(err.message)); }
});

function poPortalPage(branch, from, to, orders, error=''){
  const ps=presets(branch);
  const rows=orders.map(o=>{
    const t=fmtDateTime(o.created_at);
    const items=o.line_items||[];
    const qty=items.reduce((s,li)=>s+(li.quantity||0),0);
    const first=items.length?esc(items[0].title):'—';
    const more=items.length>1?` <small>+ ${items.length-1} more</small>`:'';
    const amt=items.reduce((s,li)=>s+(Number(li.price)||0)*(li.quantity||0),0);
    return `<tr><td class="ono">${esc(o.name)}</td><td>${t.date}</td><td><span class="time">${t.time}</span></td><td class="items">${first}${more}</td><td class="qty">${qty}</td><td class="amt">${money(amt)}</td></tr>`;
  }).join('');
  const totalItems=orders.reduce((s,o)=>s+(o.line_items||[]).reduce((a,li)=>a+(li.quantity||0),0),0);
  const grand=orders.reduce((s,o)=>s+(o.line_items||[]).reduce((a,li)=>a+(Number(li.price)||0)*(li.quantity||0),0),0);
  const opts=BRANCHES.map(b=>`<option ${b===branch?'selected':''}>${b}</option>`).join('');
  const chips=ps.map(p=>`<a href="${p.url}" class="chip ${(p.from===from&&p.to===to)?'on':''}">${p.label}</a>`).join('');
  const docBase=`/admin/po/doc?branch=${encodeURIComponent(branch)}&from=${from}&to=${to}`;
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Branch Orders &amp; PO</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:sans-serif;background:#f5f5f5;min-height:100vh}
.header{background:#1C0B1A;color:#fff;padding:16px 28px;display:flex;justify-content:space-between;align-items:center}
.header h1{font-size:18px}.header a{color:#C9A96E;text-decoration:none;font-size:13px}
.nav{background:#2E1229;padding:10px 28px;display:flex;gap:14px;flex-wrap:wrap}
.nav a{color:rgba(255,255,255,.7);text-decoration:none;font-size:13px;padding:6px 12px;border-radius:6px}
.nav a.active,.nav a:hover{background:rgba(255,255,255,.1);color:#fff}
.body{padding:24px 28px}
h2{font-size:20px;margin-bottom:4px;color:#1C0B1A}
.lead{font-size:13px;color:#8a7279;margin-bottom:18px}
.filters{background:#fff;border:1px solid #eee;border-radius:12px;padding:16px 18px;margin-bottom:18px}
.frow{display:flex;gap:14px;align-items:flex-end;flex-wrap:wrap}
.fg{display:flex;flex-direction:column;gap:5px}
.fg label{font-size:11px;color:#8a7279;font-weight:700}
.fg select,.fg input{height:40px;border:1.5px solid #E8DDE6;border-radius:8px;padding:0 11px;font-size:14px;min-width:170px;font-family:inherit}
.apply{height:40px;padding:0 20px;background:#1C0B1A;color:#fff;border:none;border-radius:8px;font-size:14px;cursor:pointer;font-weight:600}
.presets{display:flex;gap:7px;margin:14px 0 2px;flex-wrap:wrap}
.chip{padding:7px 13px;border-radius:999px;border:1px solid #E8DDE6;font-size:12.5px;color:#8a7279;text-decoration:none}
.chip.on{background:#1C0B1A;color:#fff;border-color:#1C0B1A;font-weight:700}
.btns{display:flex;gap:10px;margin-top:14px}
.pr{height:42px;padding:0 18px;background:#fff;color:#1C0B1A;border:1.5px solid #1C0B1A;border-radius:8px;font-size:14px;font-weight:700;text-decoration:none;display:inline-flex;align-items:center;gap:8px}
.dl{height:42px;padding:0 18px;background:#1C0B1A;color:#fff;border-radius:8px;font-size:14px;font-weight:700;text-decoration:none;display:inline-flex;align-items:center;gap:8px}
table{width:100%;background:#fff;border-radius:12px 12px 0 0;border-collapse:collapse;overflow:hidden;box-shadow:0 1px 8px rgba(0,0,0,.06)}
th{background:#1C0B1A;color:#fff;padding:11px 14px;text-align:left;font-size:11.5px}
th.c,td.c{text-align:center}th.r,td.r{text-align:right}
td{padding:12px 14px;border-bottom:1px solid #f0f0f0;font-size:13px;vertical-align:top}
tr:last-child td{border-bottom:none}
.ono{font-weight:700;color:#7a1f3d}
.time{background:#FBF4F6;color:#7a1f3d;border-radius:6px;padding:3px 8px;font-size:11.5px;font-weight:700}
.items small{color:#999}
.qty{text-align:center;font-weight:700}.amt{text-align:right;font-weight:700}
.foot{display:flex;gap:28px;padding:14px 18px;background:#FBF4F6;font-size:13px;border-radius:0 0 12px 12px}
.foot .g{margin-left:auto;font-weight:700;color:#7a1f3d;font-size:15px}
.empty{background:#fff;border-radius:12px;padding:40px;text-align:center;color:#999;box-shadow:0 1px 8px rgba(0,0,0,.06)}
.err{background:#fef2f2;border:1px solid #fca5a5;color:#b83a4a;padding:12px;border-radius:8px;margin-bottom:14px;font-size:13px}
</style></head><body>
<div class="header"><h1>🌸 Cosmo Salon — Admin Panel</h1><a href="/admin/logout">Sign out</a></div>
<div class="nav"><a href="/admin">⏳ Pending</a><a href="/admin/approved">✅ Approved</a><a href="/admin/rejected">✗ Rejected</a><a href="/admin/po" class="active">📦 Branch Orders &amp; PO</a></div>
<div class="body">
<h2>Branch Orders &amp; PO</h2>
<p class="lead">Select a branch and date range to view orders and generate a Purchase Order.</p>
${error?`<div class="err">⚠️ ${esc(error)}</div>`:''}
<div class="filters">
  <form method="GET" action="/admin/po"><div class="frow">
    <div class="fg"><label>BRANCH</label><select name="branch">${opts}</select></div>
    <div class="fg"><label>FROM</label><input type="date" name="from" value="${from}"></div>
    <div class="fg"><label>TO</label><input type="date" name="to" value="${to}"></div>
    <button class="apply" type="submit">Apply</button>
  </div></form>
  <div class="presets">${chips}</div>
  <div class="btns"><a class="pr" href="${docBase}&auto=print" target="_blank">🖨 Print PO</a><a class="dl" href="${docBase}" target="_blank">📥 Download PO (PDF)</a></div>
</div>
${orders.length===0?`<div class="empty">No orders for <b>${esc(branch)}</b> in the selected dates.</div>`:`
<table><thead><tr><th>ORDER</th><th>DATE</th><th>TIME</th><th>PRODUCTS</th><th class="c">QTY</th><th class="r">AMOUNT (PKR)</th></tr></thead><tbody>${rows}</tbody></table>
<div class="foot"><span>Total orders: <b>${orders.length}</b></span><span>Total items: <b>${totalItems}</b></span><span class="g">Grand Total: Rs ${money(grand)}</span></div>`}
</div></body></html>`;
}

function poDocPage(branch, from, to, orders, auto){
  const pm={};
  orders.forEach(o=>{ (o.line_items||[]).forEach(li=>{
    const k=li.title||'Item';
    if(!pm[k]) pm[k]={title:k,qty:0,amount:0,price:Number(li.price)||0,refs:new Set()};
    pm[k].qty+=li.quantity||0; pm[k].amount+=(Number(li.price)||0)*(li.quantity||0); pm[k].refs.add(o.name);
  });});
  const items=Object.values(pm);
  const subtotal=items.reduce((s,i)=>s+i.amount,0);
  const totalUnits=items.reduce((s,i)=>s+i.qty,0);
  const cust=(orders[0]&&orders[0]._cust)||{name:'',phone:'',email:''};
  const sa=(orders[0]&&orders[0].shipping_address)||{};
  const address=[sa.address1,sa.city].filter(Boolean).join(', ')||'—';
  const phone=cust.phone||sa.phone||'—';
  const email=cust.email||(orders[0]&&orders[0].email)||'—';
  const orderer=cust.name||(sa.name)||'—';
  const poNo='CC-'+from.replace(/-/g,'')+(orders[0]?('-'+orders[0].order_number):'');
  const rangeLabel = from===to ? from : (from+' → '+to);
  const times=orders.map(o=>fmtDateTime(o.created_at).time).join(', ');
  const rows=items.map((it,i)=>`<tr><td>${i+1}</td><td>${esc(it.title)} <span class="sub">· ${Array.from(it.refs).join(', ')}</span></td><td class="c">${it.qty}</td><td class="r">${money(it.price)}</td><td class="r">${money(it.amount)}</td></tr>`).join('');
  const autoPrint = auto==='print' ? `<script>window.addEventListener('load',function(){setTimeout(function(){window.print();},350);});</script>` : '';
  const backUrl=`/admin/po?branch=${encodeURIComponent(branch)}&from=${from}&to=${to}`;
  const body = orders.length===0 ? `<div style="padding:60px;text-align:center;color:#999">No orders for ${esc(branch)} in ${rangeLabel}.</div>` : `
  <div class="hd">
    <div class="em"><div class="c">&#10047;</div><div><h1>Cosmo Salon Store</h1><p>PURCHASE ORDER</p><div class="co">Head Office · Lahore, Pakistan</div></div></div>
    <div class="po-meta"><div class="t">PO #${esc(poNo)}</div><div class="r"><b>Date:</b> ${pkDate(new Date())}<br><b>Period:</b> ${rangeLabel}<br><b>Status:</b> Pending dispatch</div></div>
  </div>
  <div class="two">
    <div class="box"><div class="lbl">ORDERED BY (BRANCH)</div><div class="v">
      <b>${esc(orderer)}</b><br>
      <div class="rw"><span class="k">Branch:</span><span>${esc(branch)}</span></div>
      <div class="rw"><span class="k">Phone:</span><span>${esc(phone)}</span></div>
      <div class="rw"><span class="k">Email:</span><span>${esc(email)}</span></div>
      <div class="rw"><span class="k">Address:</span><span>${esc(address)}</span></div>
    </div></div>
    <div class="box r"><div class="lbl">ORDER SUMMARY</div><div class="v">
      <div class="rw"><span class="k">Orders:</span><span><b>${orders.length}</b> (${orders.map(o=>esc(o.name)).join(', ')})</span></div>
      <div class="rw"><span class="k">Times:</span><span>${times}</span></div>
      <div class="rw"><span class="k">Items:</span><span>${totalUnits} units · ${items.length} products</span></div>
      <div class="rw"><span class="k">Amount:</span><span><b>Rs ${money(subtotal)}</b></span></div>
    </div></div>
  </div>
  <table>
    <thead><tr><th>#</th><th>PRODUCT</th><th class="c">QTY</th><th class="r">RATE</th><th class="r">AMOUNT (PKR)</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>
  <div class="tot">
    <div class="rw2"><span>Subtotal</span><span>Rs ${money(subtotal)}</span></div>
    <div class="rw2"><span>GST (0%)</span><span>Rs 0</span></div>
    <div class="rw2 grand"><span>Grand Total</span><span>Rs ${money(subtotal)}</span></div>
  </div>
  <div class="signs">
    <div class="sg"><div class="l"><b>Authorized by</b>Cosmo Salon — Head Office</div></div>
    <div class="sg"><div class="l"><b>Received by</b>${esc(branch)} (Branch)</div></div>
  </div>
  <div class="ftn">Generated by Cosmo Salon Portal · ${pkDate(new Date())} · ${orders.length} orders · ${totalUnits} items</div>`;
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>PO ${esc(poNo)}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:sans-serif;background:#EDE7E2;color:#241A1E}
.toolbar{position:sticky;top:0;background:#1C0B1A;color:#fff;padding:12px 20px;display:flex;gap:12px;align-items:center;justify-content:space-between;z-index:10}
.toolbar .tt{font-size:14px}
.toolbar button{background:#C9A96E;color:#241A1E;border:none;border-radius:7px;padding:10px 18px;font-size:13px;font-weight:700;cursor:pointer}
.toolbar a{color:#fff;border:1px solid rgba(255,255,255,.4);border-radius:7px;padding:9px 16px;font-size:13px;text-decoration:none}
.wrap{display:flex;justify-content:center;padding:28px}
.page{width:800px;max-width:100%;background:#fff;box-shadow:0 20px 60px -30px rgba(0,0,0,.4);padding:42px 46px}
.hd{display:flex;justify-content:space-between;align-items:flex-start;border-bottom:3px solid #1C0B1A;padding-bottom:20px}
.em{display:flex;align-items:center;gap:13px}
.em .c{width:52px;height:52px;border-radius:50%;background:#1C0B1A;color:#C9A96E;font-size:24px;display:flex;align-items:center;justify-content:center}
.em h1{font-size:23px;font-weight:700}
.em p{font-size:11px;letter-spacing:2px;color:#7a1f3d;margin-top:3px;font-weight:700}
.em .co{font-size:11px;color:#8a7179;margin-top:4px}
.po-meta{text-align:right}.po-meta .t{font-size:22px;color:#7a1f3d;font-weight:700}
.po-meta .r{font-size:12px;color:#8a7179;margin-top:7px;line-height:1.7}.po-meta b{color:#241A1E}
.two{display:flex;gap:24px;margin:22px 0 18px}
.box{flex:1;background:#FBF4F6;border-radius:9px;padding:15px 17px}.box.r{background:#fff;border:1px solid #E7DDD6}
.box .lbl{font-size:10px;letter-spacing:.6px;color:#7a1f3d;font-weight:700;margin-bottom:8px}
.box .v{font-size:12.8px;line-height:1.85}.box .v b{font-size:14.5px}
.box .v .rw{display:flex;gap:6px}.box .v .k{color:#8a7179;min-width:62px}
table{width:100%;border-collapse:collapse;margin-top:4px}
th{background:#1C0B1A;color:#fff;font-size:11px;padding:11px 13px;text-align:left}
th.c,td.c{text-align:center}th.r,td.r{text-align:right}
td{padding:11px 13px;border-bottom:1px solid #EFE7E1;font-size:12.8px}
tbody tr:nth-child(even){background:#FBF4F6}
.sub{color:#999;font-size:11px}
.tot{margin-top:16px;margin-left:auto;width:270px}
.tot .rw2{display:flex;justify-content:space-between;padding:6px 0;font-size:13px}
.tot .grand{border-top:2px solid #1C0B1A;margin-top:6px;padding-top:10px;font-size:17px;font-weight:700;color:#7a1f3d}
.signs{display:flex;justify-content:space-between;margin-top:46px;gap:40px}
.sg{flex:1;text-align:center}
.sg .l{border-top:1px solid #B9A9AE;padding-top:7px;font-size:11.5px;color:#8a7179}
.sg .l b{display:block;color:#241A1E;font-size:12.5px;margin-bottom:1px}
.ftn{margin-top:26px;border-top:1px solid #E7DDD6;padding-top:13px;font-size:11px;color:#8a7179}
@media print{.toolbar{display:none}body{background:#fff}.wrap{padding:0}.page{box-shadow:none;width:auto;padding:10px 6px}}
</style></head><body>
<div class="toolbar"><span class="tt">PO ${esc(poNo)} · ${esc(branch)}</span><div><a href="${backUrl}">← Back</a> &nbsp;<button onclick="window.print()">🖨 Print / Save as PDF</button></div></div>
<div class="wrap"><div class="page">${body}</div></div>
${autoPrint}
</body></html>`;
}

// ── START SERVER ──
app.listen(PORT, () => {
  console.log(`✅ Cosmo Salon App running on port ${PORT}`);
  console.log(`📋 Register page: http://localhost:${PORT}/register`);
  console.log(`🔐 Admin panel:   http://localhost:${PORT}/admin`);
});
