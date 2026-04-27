require('fs').existsSync('.env') && require('fs').readFileSync('.env','utf8').split('\n').forEach(l => { const [k,...v]=l.split('='); if(k&&v.length) process.env[k.trim()]=v.join('=').trim(); });

const express    = require('express');
const path       = require('path');
const jwt        = require('jsonwebtoken');
const crypto     = require('crypto');
const cookieParser = require('cookie-parser');
const { Pool }   = require('pg');

const app  = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-prod';

// ── Database ──────────────────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      username   TEXT PRIMARY KEY,
      phone      TEXT NOT NULL,
      role       TEXT NOT NULL DEFAULT 'admin',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      invited_by TEXT
    );
    CREATE TABLE IF NOT EXISTS invites (
      token      TEXT PRIMARY KEY,
      created_by TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      expires_at TIMESTAMPTZ NOT NULL,
      used       BOOLEAN DEFAULT FALSE,
      used_by    TEXT,
      used_at    TIMESTAMPTZ
    );
    INSERT INTO users (username, phone, role)
    VALUES ('xavierh', '+18762903666', 'superadmin')
    ON CONFLICT DO NOTHING;
  `);
  console.log('Database ready');
}

// ── Helpers ───────────────────────────────────────────────────────────────────
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

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.get('/', (req, res) => res.redirect('/calendar.html'));

// ── Auth ──────────────────────────────────────────────────────────────────────
app.get('/api/auth-status', (req, res) => {
  const s = getSession(req);
  if (!s) return res.json({ authenticated: false });
  res.json({ authenticated: true, username: s.username, role: s.role });
});

app.post('/api/login', async (req, res) => {
  const { username } = req.body || {};
  const { rows } = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
  const user = rows[0];
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

// ── Users ─────────────────────────────────────────────────────────────────────
app.get('/api/users', requireSuperAdmin, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM users ORDER BY created_at');
  const users = {};
  rows.forEach(r => {
    users[r.username] = { phone: r.phone, role: r.role, createdAt: r.created_at, invitedBy: r.invited_by };
  });
  res.json(users);
});

app.delete('/api/users/:username', requireSuperAdmin, async (req, res) => {
  const me = getSession(req);
  const { username } = req.params;
  if (username === me.username) return res.status(400).json({ error: 'Cannot delete yourself' });
  const { rowCount } = await pool.query('DELETE FROM users WHERE username = $1 AND role != $2', [username, 'superadmin']);
  if (!rowCount) return res.status(404).json({ error: 'User not found or cannot be deleted' });
  res.json({ ok: true });
});

// ── Invites ───────────────────────────────────────────────────────────────────
app.post('/api/invite/generate', requireSuperAdmin, async (req, res) => {
  const me    = getSession(req);
  const token = crypto.randomBytes(24).toString('hex');
  const expires = new Date(Date.now() + 48 * 60 * 60 * 1000);
  await pool.query(
    'INSERT INTO invites (token, created_by, expires_at) VALUES ($1, $2, $3)',
    [token, me.username, expires]
  );
  const proto = req.get('x-forwarded-proto') || 'http';
  const host  = req.get('host') || `localhost:${PORT}`;
  res.json({ ok: true, url: `${proto}://${host}/invite.html?token=${token}` });
});

app.get('/api/invite/:token', async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM invites WHERE token = $1', [req.params.token]);
  const invite = rows[0];
  if (!invite)     return res.status(404).json({ error: 'Invalid invite link' });
  if (invite.used) return res.status(410).json({ error: 'This invite has already been used' });
  if (new Date() > new Date(invite.expires_at)) return res.status(410).json({ error: 'Invite has expired' });
  res.json({ ok: true, createdBy: invite.created_by });
});

app.post('/api/invite/:token/claim', async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM invites WHERE token = $1', [req.params.token]);
  const invite = rows[0];
  if (!invite || invite.used || new Date() > new Date(invite.expires_at))
    return res.status(410).json({ error: 'Invalid or expired invite' });

  const { username, phone } = req.body || {};
  if (!username || !phone) return res.status(400).json({ error: 'Username and phone required' });

  const existing = await pool.query('SELECT 1 FROM users WHERE username = $1', [username]);
  if (existing.rowCount) return res.status(409).json({ error: 'Username already taken' });

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

app.post('/api/invite/:token/verify', async (req, res) => {
  const { otp } = req.body || {};
  try {
    const p = jwt.verify(req.cookies.otp_pending || '', JWT_SECRET);
    if (p.otp !== String(otp) || p.inviteToken !== req.params.token)
      return res.status(401).json({ error: 'Incorrect code' });

    const { rows } = await pool.query('SELECT * FROM invites WHERE token = $1 AND used = false', [p.inviteToken]);
    if (!rows[0]) return res.status(410).json({ error: 'Invite no longer valid' });

    await pool.query(
      'UPDATE invites SET used = true, used_by = $1, used_at = NOW() WHERE token = $2',
      [p.username, p.inviteToken]
    );
    await pool.query(
      'INSERT INTO users (username, phone, role, invited_by) VALUES ($1, $2, $3, $4)',
      [p.username, p.phone, 'admin', rows[0].created_by]
    );

    res.clearCookie('otp_pending');
    const session = jwt.sign({ username: p.username, role: 'admin' }, JWT_SECRET, { expiresIn: '8h' });
    res.cookie('session', session, { httpOnly: true, maxAge: 8 * 60 * 60 * 1000, sameSite: 'strict' });
    res.json({ ok: true });
  } catch {
    res.status(401).json({ error: 'Code expired or invalid' });
  }
});

// ── Calendar ──────────────────────────────────────────────────────────────────
app.get('/api/calendar', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT data FROM calendar LIMIT 1');
    res.json(rows[0]?.data || {});
  } catch {
    // Table may not exist yet — serve from file as fallback
    try { res.json(JSON.parse(require('fs').readFileSync(path.join(__dirname,'data.json'),'utf8'))); }
    catch { res.status(500).json({ error: 'Failed to read calendar data' }); }
  }
});

app.post('/api/calendar', requireAuth, async (req, res) => {
  try {
    await pool.query(`
      INSERT INTO calendar (id, data) VALUES (1, $1)
      ON CONFLICT (id) DO UPDATE SET data = $1
    `, [req.body]);
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: 'Failed to save calendar data' });
  }
});

// ── Start ─────────────────────────────────────────────────────────────────────
async function start() {
  await initDB();

  // Create calendar table and seed from data.json if empty
  await pool.query(`
    CREATE TABLE IF NOT EXISTS calendar (
      id   INTEGER PRIMARY KEY,
      data JSONB NOT NULL
    )
  `);
  const { rowCount } = await pool.query('SELECT 1 FROM calendar WHERE id = 1');
  if (!rowCount) {
    let seed = {};
    try { seed = JSON.parse(require('fs').readFileSync(path.join(__dirname, 'data.json'), 'utf8')); } catch {}
    await pool.query('INSERT INTO calendar (id, data) VALUES (1, $1)', [seed]);
    console.log('Calendar seeded from data.json');
  }

  app.listen(PORT, () => console.log(`Engagement Calendar → http://localhost:${PORT}`));
}

start().catch(err => { console.error('Startup failed:', err.message); process.exit(1); });
