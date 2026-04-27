require('fs').existsSync('.env') && require('fs').readFileSync('.env','utf8').split('\n').forEach(l => { const [k,...v]=l.split('='); if(k&&v.length) process.env[k.trim()]=v.join('=').trim(); });

const express = require('express');
const fs      = require('fs');
const path    = require('path');
const jwt     = require('jsonwebtoken');
const crypto  = require('crypto');
const cookieParser = require('cookie-parser');

const app  = express();
const PORT = process.env.PORT || 3001;

const DATA_FILE    = path.join(__dirname, 'data.json');
const USERS_FILE   = path.join(__dirname, 'users.json');
const INVITES_FILE = path.join(__dirname, 'invites.json');
const JWT_SECRET   = process.env.JWT_SECRET || 'dev-secret-change-in-prod';

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.get('/', (req, res) => res.redirect('/calendar.html'));

// ── File helpers ──────────────────────────────────────────────────────────────
function readJSON(file, def = {}) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch { return def; }
}
function writeJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2), 'utf8');
}

// ── Session helpers ───────────────────────────────────────────────────────────
function getSession(req) {
  try { return jwt.verify(req.cookies.session || '', JWT_SECRET); }
  catch { return null; }
}
function requireAuth(req, res, next) {
  if (!getSession(req)) return res.status(401).json({ error: 'Unauthorized' });
  next();
}
function requireSuperAdmin(req, res, next) {
  const s = getSession(req);
  if (!s || s.role !== 'superadmin') return res.status(403).json({ error: 'Forbidden' });
  next();
}

// ── WhatsApp OTP ──────────────────────────────────────────────────────────────
async function sendOTP(phone, otp) {
  const sid   = process.env.TWILIO_ACCOUNT_SID;
  const token = process.env.TWILIO_AUTH_TOKEN;
  const from  = process.env.TWILIO_WHATSAPP_FROM || 'whatsapp:+14155238886';
  if (!sid || !token) { console.log(`[DEV] OTP for ${phone}: ${otp}`); return; }
  const twilio = require('twilio')(sid, token);
  await twilio.messages.create({
    body: `Your Engagement Calendar code: *${otp}*\nExpires in 5 minutes.`,
    from,
    to: `whatsapp:${phone}`,
  });
}

// ── Auth ──────────────────────────────────────────────────────────────────────
app.get('/api/auth-status', (req, res) => {
  const s = getSession(req);
  if (!s) return res.json({ authenticated: false });
  res.json({ authenticated: true, username: s.username, role: s.role });
});

// Step 1: lookup username → send OTP to registered phone
app.post('/api/login', async (req, res) => {
  const { username } = req.body || {};
  const users = readJSON(USERS_FILE);
  const user  = users[username];
  if (!user) return res.status(401).json({ error: 'Username not found' });

  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  try {
    await sendOTP(user.phone, otp);
  } catch (e) {
    console.error('WhatsApp error:', e.message);
    return res.status(500).json({ error: 'Failed to send verification code' });
  }
  const pending = jwt.sign({ otp, username, role: user.role }, JWT_SECRET, { expiresIn: '5m' });
  res.cookie('otp_pending', pending, { httpOnly: true, maxAge: 5 * 60 * 1000, sameSite: 'strict' });
  res.json({ ok: true });
});

// Step 2: verify OTP → create session
app.post('/api/verify-otp', (req, res) => {
  const { otp } = req.body || {};
  try {
    const p = jwt.verify(req.cookies.otp_pending || '', JWT_SECRET);
    if (p.otp !== String(otp)) return res.status(401).json({ error: 'Incorrect code' });
    res.clearCookie('otp_pending');
    const session = jwt.sign({ username: p.username, role: p.role }, JWT_SECRET, { expiresIn: '8h' });
    res.cookie('session', session, { httpOnly: true, maxAge: 8 * 60 * 60 * 1000, sameSite: 'strict' });
    res.json({ ok: true, role: p.role });
  } catch {
    res.status(401).json({ error: 'Code expired or invalid' });
  }
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('session');
  res.clearCookie('otp_pending');
  res.json({ ok: true });
});

// ── User management (superadmin only) ────────────────────────────────────────
app.get('/api/users', requireSuperAdmin, (req, res) => {
  res.json(readJSON(USERS_FILE));
});

app.delete('/api/users/:username', requireSuperAdmin, (req, res) => {
  const me    = getSession(req);
  const { username } = req.params;
  if (username === me.username) return res.status(400).json({ error: 'Cannot delete yourself' });
  const users = readJSON(USERS_FILE);
  if (!users[username]) return res.status(404).json({ error: 'User not found' });
  delete users[username];
  writeJSON(USERS_FILE, users);
  res.json({ ok: true });
});

// ── Invite links ──────────────────────────────────────────────────────────────
app.post('/api/invite/generate', requireSuperAdmin, (req, res) => {
  const me      = getSession(req);
  const token   = crypto.randomBytes(24).toString('hex');
  const invites = readJSON(INVITES_FILE);
  invites[token] = {
    createdBy: me.username,
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 48 * 60 * 60 * 1000).toISOString(),
    used: false,
  };
  writeJSON(INVITES_FILE, invites);
  const proto = req.get('x-forwarded-proto') || 'http';
  const host  = req.get('host') || `localhost:${PORT}`;
  res.json({ ok: true, url: `${proto}://${host}/invite.html?token=${token}` });
});

app.get('/api/invite/:token', (req, res) => {
  const invites = readJSON(INVITES_FILE);
  const invite  = invites[req.params.token];
  if (!invite)       return res.status(404).json({ error: 'Invalid invite link' });
  if (invite.used)   return res.status(410).json({ error: 'This invite has already been used' });
  if (new Date() > new Date(invite.expiresAt)) return res.status(410).json({ error: 'Invite has expired' });
  res.json({ ok: true, createdBy: invite.createdBy });
});

// Claim: enter username + phone → send OTP
app.post('/api/invite/:token/claim', async (req, res) => {
  const invites = readJSON(INVITES_FILE);
  const invite  = invites[req.params.token];
  if (!invite || invite.used || new Date() > new Date(invite.expiresAt))
    return res.status(410).json({ error: 'Invalid or expired invite' });

  const { username, phone } = req.body || {};
  if (!username || !phone) return res.status(400).json({ error: 'Username and phone number required' });

  const users = readJSON(USERS_FILE);
  if (users[username]) return res.status(409).json({ error: 'Username already taken' });

  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  try {
    await sendOTP(phone, otp);
  } catch (e) {
    return res.status(500).json({ error: 'Failed to send verification code' });
  }
  const pending = jwt.sign(
    { otp, username, phone, inviteToken: req.params.token, role: 'admin' },
    JWT_SECRET, { expiresIn: '5m' }
  );
  res.cookie('otp_pending', pending, { httpOnly: true, maxAge: 5 * 60 * 1000, sameSite: 'strict' });
  res.json({ ok: true });
});

// Verify invite OTP → create user + session
app.post('/api/invite/:token/verify', (req, res) => {
  const { otp } = req.body || {};
  try {
    const p = jwt.verify(req.cookies.otp_pending || '', JWT_SECRET);
    if (p.otp !== String(otp) || p.inviteToken !== req.params.token)
      return res.status(401).json({ error: 'Incorrect code' });

    const invites = readJSON(INVITES_FILE);
    if (!invites[p.inviteToken] || invites[p.inviteToken].used)
      return res.status(410).json({ error: 'Invite no longer valid' });

    invites[p.inviteToken].used   = true;
    invites[p.inviteToken].usedBy = p.username;
    invites[p.inviteToken].usedAt = new Date().toISOString();
    writeJSON(INVITES_FILE, invites);

    const users = readJSON(USERS_FILE);
    users[p.username] = {
      phone:     p.phone,
      role:      'admin',
      createdAt: new Date().toISOString(),
      invitedBy: invites[p.inviteToken].createdBy,
    };
    writeJSON(USERS_FILE, users);

    res.clearCookie('otp_pending');
    const session = jwt.sign({ username: p.username, role: 'admin' }, JWT_SECRET, { expiresIn: '8h' });
    res.cookie('session', session, { httpOnly: true, maxAge: 8 * 60 * 60 * 1000, sameSite: 'strict' });
    res.json({ ok: true });
  } catch {
    res.status(401).json({ error: 'Code expired or invalid' });
  }
});

// ── Calendar ──────────────────────────────────────────────────────────────────
app.get('/api/calendar', (req, res) => {
  try { res.json(JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'))); }
  catch { res.status(500).json({ error: 'Failed to read data' }); }
});

app.post('/api/calendar', requireAuth, (req, res) => {
  try { writeJSON(DATA_FILE, req.body); res.json({ ok: true }); }
  catch { res.status(500).json({ error: 'Failed to save data' }); }
});

app.listen(PORT, () => console.log(`Engagement Calendar → http://localhost:${PORT}`));
