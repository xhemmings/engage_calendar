const express = require('express');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = process.env.PORT || 3001;
const DATA_FILE = path.join(__dirname, 'data.json');

const ADMIN_USER   = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASS   = process.env.ADMIN_PASSWORD || 'calendar2026';
const JWT_SECRET   = process.env.JWT_SECRET     || 'dev-secret-change-in-prod';
const WHATSAPP_TO  = process.env.WHATSAPP_TO    || 'whatsapp:+18762903666';

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => res.redirect('/calendar.html'));

// ── Auth helpers ──────────────────────────────────────────────────────────────

function requireAuth(req, res, next) {
  try {
    jwt.verify(req.cookies.session || '', JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Unauthorized' });
  }
}

async function sendWhatsApp(otp) {
  const sid   = process.env.TWILIO_ACCOUNT_SID;
  const token = process.env.TWILIO_AUTH_TOKEN;
  const from  = process.env.TWILIO_WHATSAPP_FROM || 'whatsapp:+14155238886';

  if (!sid || !token) {
    // Dev mode: print to console instead of sending
    console.log(`[DEV] OTP for ${WHATSAPP_TO}: ${otp}`);
    return;
  }

  const twilio = require('twilio')(sid, token);
  await twilio.messages.create({
    body: `Your Engagement Calendar verification code is: ${otp}`,
    from,
    to: WHATSAPP_TO,
  });
}

// ── Auth routes ───────────────────────────────────────────────────────────────

app.get('/api/auth-status', (req, res) => {
  try {
    jwt.verify(req.cookies.session || '', JWT_SECRET);
    res.json({ authenticated: true });
  } catch {
    res.json({ authenticated: false });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (username !== ADMIN_USER || password !== ADMIN_PASS) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const otp = Math.floor(100000 + Math.random() * 900000).toString();

  try {
    await sendWhatsApp(otp);
  } catch (e) {
    console.error('WhatsApp error:', e.message);
    return res.status(500).json({ error: 'Failed to send verification code' });
  }

  const pending = jwt.sign({ otp }, JWT_SECRET, { expiresIn: '5m' });
  res.cookie('otp_pending', pending, { httpOnly: true, maxAge: 5 * 60 * 1000, sameSite: 'strict' });
  res.json({ ok: true });
});

app.post('/api/verify-otp', (req, res) => {
  const { otp } = req.body;
  try {
    const payload = jwt.verify(req.cookies.otp_pending || '', JWT_SECRET);
    if (payload.otp !== String(otp)) {
      return res.status(401).json({ error: 'Incorrect code' });
    }
    res.clearCookie('otp_pending');
    const session = jwt.sign({ admin: true }, JWT_SECRET, { expiresIn: '8h' });
    res.cookie('session', session, { httpOnly: true, maxAge: 8 * 60 * 60 * 1000, sameSite: 'strict' });
    res.json({ ok: true });
  } catch {
    res.status(401).json({ error: 'Code expired or invalid' });
  }
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('session');
  res.clearCookie('otp_pending');
  res.json({ ok: true });
});

// ── Calendar routes ───────────────────────────────────────────────────────────

app.get('/api/calendar', (req, res) => {
  try {
    res.json(JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')));
  } catch {
    res.status(500).json({ error: 'Failed to read data' });
  }
});

app.post('/api/calendar', requireAuth, (req, res) => {
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify(req.body, null, 2), 'utf8');
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: 'Failed to save data' });
  }
});

app.listen(PORT, () => console.log(`Engagement Calendar → http://localhost:${PORT}`));
