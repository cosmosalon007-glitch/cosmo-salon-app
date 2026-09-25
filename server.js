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
  const scopes = 'read_customers,write_customers';
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
      <input type="password" name="password" placeholder="Your password" required>
    </div>
    <button type="submit" class="btn">Sign In →</button>
  </form>
  <hr class="divider">
  <div class="links">
    Don't have an account? <a href="/register">Register here</a>
  </div>
</div>
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
      <input type="password" name="password" placeholder="Minimum 5 characters" required>
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
</div>
<div class="body">
  <h2>Approved Customers</h2>
  ${error ? `<p style="color:red;margin-bottom:16px">${error}</p>` : ''}
  ${customers.length === 0 ? '<p class="empty">No approved customers yet.</p>' : `
  <table>
    <thead><tr><th>Name</th><th>Email</th><th>Phone</th><th>Branch</th><th>Registered</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>`}
</div>
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

// ── START SERVER ──
app.listen(PORT, () => {
  console.log(`✅ Cosmo Salon App running on port ${PORT}`);
  console.log(`📋 Register page: http://localhost:${PORT}/register`);
  console.log(`🔐 Admin panel:   http://localhost:${PORT}/admin`);
});
