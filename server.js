require('fs').existsSync('.env') && require('fs').readFileSync('.env','utf8').split('\n').forEach(l => { const [k,...v]=l.split('='); if(k&&v.length) process.env[k.trim()]=v.join('=').trim(); });

const express      = require('express');
const path         = require('path');
const jwt          = require('jsonwebtoken');
const crypto       = require('crypto');
const cookieParser = require('cookie-parser');
const { Pool }     = require('pg');

const app  = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-prod';

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

// ── DB init ───────────────────────────────────────────────────────────────────
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      username   TEXT PRIMARY KEY,
      phone      TEXT NOT NULL,
      role       TEXT NOT NULL DEFAULT 'viewer',
      first_name TEXT,
      last_name  TEXT,
      email      TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      invited_by TEXT
    );
    ALTER TABLE users ADD COLUMN IF NOT EXISTS first_name TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS last_name  TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS email      TEXT;

    CREATE TABLE IF NOT EXISTS invites (
      token       TEXT PRIMARY KEY,
      created_by  TEXT NOT NULL,
      invite_role TEXT NOT NULL DEFAULT 'viewer',
      created_at  TIMESTAMPTZ DEFAULT NOW(),
      expires_at  TIMESTAMPTZ NOT NULL,
      used        BOOLEAN DEFAULT FALSE,
      used_by     TEXT,
      used_at     TIMESTAMPTZ
    );
    ALTER TABLE invites ADD COLUMN IF NOT EXISTS invite_role TEXT DEFAULT 'viewer';

    CREATE TABLE IF NOT EXISTS event_reactions (
      event_key  TEXT NOT NULL,
      username   TEXT NOT NULL,
      reaction   TEXT NOT NULL CHECK (reaction IN ('like','dislike')),
      created_at TIMESTAMPTZ DEFAULT NOW(),
      PRIMARY KEY (event_key, username)
    );

    CREATE TABLE IF NOT EXISTS event_comments (
      id         SERIAL PRIMARY KEY,
      event_key  TEXT NOT NULL,
      username   TEXT NOT NULL,
      body       TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS bookmarks (
      event_key  TEXT NOT NULL,
      username   TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      PRIMARY KEY (event_key, username)
    );

    CREATE TABLE IF NOT EXISTS calendar (
      id   INTEGER PRIMARY KEY,
      data JSONB NOT NULL
    );

    ALTER TABLE users ADD COLUMN IF NOT EXISTS birthday      DATE;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT;

    CREATE TABLE IF NOT EXISTS personal_events (
      id         SERIAL PRIMARY KEY,
      username   TEXT NOT NULL,
      date       TEXT NOT NULL,
      name       TEXT NOT NULL,
      note       TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
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
function requireAdmin(req, res, next) {
  const s = getSession(req);
  if (!s || !['admin','superadmin'].includes(s.role)) return res.status(403).json({ error: 'Forbidden' });
  next();
}
function requireSuperAdmin(req, res, next) {
  const s = getSession(req);
  if (!s || s.role !== 'superadmin') return res.status(403).json({ error: 'Forbidden' });
  next();
}

// ── Password helpers ──────────────────────────────────────────────────────────
function hashPassword(pwd) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(pwd, salt, 10000, 64, 'sha512').toString('hex');
  return `${salt}:${hash}`;
}
function verifyPassword(pwd, stored) {
  const [salt, hash] = (stored||'').split(':');
  if (!salt||!hash) return false;
  return crypto.pbkdf2Sync(pwd, salt, 10000, 64, 'sha512').toString('hex') === hash;
}
function generatePassword() {
  const chars = 'ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#';
  const bytes = crypto.randomBytes(12);
  return Array.from(bytes).map(b => chars[b % chars.length]).join('');
}

async function sendWhatsAppOTP(phone, otp) {
  const sid   = process.env.TWILIO_ACCOUNT_SID;
  const token = process.env.TWILIO_AUTH_TOKEN;
  const from  = process.env.TWILIO_WHATSAPP_FROM || 'whatsapp:+14155238886';
  if (!sid || !token) { console.log(`[DEV] WhatsApp OTP for ${phone}: ${otp}`); return; }
  const twilio = require('twilio')(sid, token);
  await twilio.messages.create({
    body: `Your Engagement Calendar code: *${otp}*\nExpires in 5 minutes.`,
    from,
    to: `whatsapp:${phone}`,
  });
}

async function sendEmailOTP(email, otp) {
  if (!process.env.EMAIL_USER) { console.log(`[DEV] Email OTP for ${email}: ${otp}`); return; }
  const nodemailer  = require('nodemailer');
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
  });
  await transporter.sendMail({
    from: `"Engagement Calendar" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: 'Your verification code',
    html: `<div style="font-family:'Segoe UI',Arial,sans-serif;max-width:420px;margin:0 auto;padding:32px 24px;background:#fff;border-radius:12px">
      <div style="font-size:1.2rem;font-weight:700;color:#1a1f36;margin-bottom:8px">Engagement Calendar</div>
      <p style="color:#555;margin-bottom:24px">Your verification code is:</p>
      <div style="font-size:36px;font-weight:800;letter-spacing:10px;color:#1a1f36;padding:20px 24px;background:#eef0f3;border-radius:10px;text-align:center">${otp}</div>
      <p style="color:#aaa;font-size:13px;margin-top:20px">Expires in 5 minutes. Do not share this code.</p>
    </div>`,
  });
}

// Route OTP by role: superadmin → WhatsApp, everyone else → email
async function sendOTP(user, otp) {
  if (user.role === 'superadmin') {
    await sendWhatsAppOTP(user.phone, otp);
  } else {
    if (!user.email) throw new Error('No email address on file for this user');
    await sendEmailOTP(user.email, otp);
  }
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
  if (!rows[0]) return res.status(401).json({ error: 'Username not found' });
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  try { await sendOTP(rows[0], otp); }
  catch (e) { console.error('OTP send error:', e.message); return res.status(500).json({ error: 'Failed to send verification code' }); }
  const pending = jwt.sign({ otp, username, role: rows[0].role }, JWT_SECRET, { expiresIn: '5m' });
  res.cookie('otp_pending', pending, { httpOnly: true, maxAge: 300000, sameSite: 'strict' });
  res.json({ ok: true, channel: rows[0].role === 'superadmin' ? 'whatsapp' : 'email', hasPassword: !!rows[0].password_hash });
});

app.post('/api/verify-otp', (req, res) => {
  const { otp } = req.body || {};
  try {
    const p = jwt.verify(req.cookies.otp_pending || '', JWT_SECRET);
    if (p.otp !== String(otp)) return res.status(401).json({ error: 'Incorrect code' });
    res.clearCookie('otp_pending');
    const session = jwt.sign({ username: p.username, role: p.role }, JWT_SECRET, { expiresIn: '8h' });
    res.cookie('session', session, { httpOnly: true, maxAge: 28800000, sameSite: 'strict' });
    res.json({ ok: true, role: p.role });
  } catch { res.status(401).json({ error: 'Code expired or invalid' }); }
});

// Password-based login (skips OTP)
app.post('/api/login/password', async (req, res) => {
  const { username, password } = req.body || {};
  const { rows } = await pool.query('SELECT * FROM users WHERE username=$1', [username]);
  const user = rows[0];
  if (!user || !user.password_hash) return res.status(401).json({ error: 'No password set for this account' });
  if (!verifyPassword(password, user.password_hash)) return res.status(401).json({ error: 'Incorrect password' });
  const session = jwt.sign({ username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '8h' });
  res.cookie('session', session, { httpOnly: true, maxAge: 28800000, sameSite: 'strict' });
  res.json({ ok: true, role: user.role });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('session'); res.clearCookie('otp_pending'); res.json({ ok: true });
});

// ── Users ─────────────────────────────────────────────────────────────────────
app.get('/api/users', requireAdmin, async (req, res) => {
  const me = getSession(req);
  // Superadmin sees all; regular admin sees only viewers
  const { rows } = me.role === 'superadmin'
    ? await pool.query('SELECT * FROM users ORDER BY created_at')
    : await pool.query("SELECT * FROM users WHERE role='viewer' ORDER BY created_at");
  const users = {};
  rows.forEach(r => { users[r.username] = { phone: r.phone, role: r.role, firstName: r.first_name, lastName: r.last_name, email: r.email, createdAt: r.created_at, invitedBy: r.invited_by, hasPassword: !!r.password_hash }; });
  res.json(users);
});

app.put('/api/users/:username', requireAdmin, async (req, res) => {
  const me = getSession(req);
  const { username } = req.params;
  const { rows } = await pool.query('SELECT role FROM users WHERE username=$1', [username]);
  if (!rows[0]) return res.status(404).json({ error: 'User not found' });
  // Admins can only edit viewers; superadmin can edit admin/viewer
  if (me.role === 'admin' && rows[0].role !== 'viewer') return res.status(403).json({ error: 'Forbidden' });
  if (rows[0].role === 'superadmin') return res.status(403).json({ error: 'Cannot edit superadmin' });
  const { firstName, lastName, email, phone, role } = req.body || {};
  // Only superadmin can change roles (viewer↔admin only)
  const newRole = me.role === 'superadmin' && ['viewer','admin'].includes(role) ? role : rows[0].role;
  await pool.query('UPDATE users SET first_name=$1, last_name=$2, email=$3, phone=$4, role=$5 WHERE username=$6',
    [firstName||null, lastName||null, email||null, phone||null, newRole, username]);
  res.json({ ok: true });
});

app.delete('/api/users/:username', requireAdmin, async (req, res) => {
  const me = getSession(req);
  const { username } = req.params;
  if (username === me.username) return res.status(400).json({ error: 'Cannot delete yourself' });
  const { rows } = await pool.query('SELECT role FROM users WHERE username=$1', [username]);
  if (!rows[0]) return res.status(404).json({ error: 'User not found' });
  if (rows[0].role === 'superadmin') return res.status(403).json({ error: 'Cannot delete superadmin' });
  if (me.role === 'admin' && rows[0].role !== 'viewer') return res.status(403).json({ error: 'Forbidden' });
  await pool.query('DELETE FROM users WHERE username=$1', [username]);
  res.json({ ok: true });
});

app.post('/api/users/:username/reset-password', requireAdmin, async (req, res) => {
  const me = getSession(req);
  const { username } = req.params;
  const { rows } = await pool.query('SELECT * FROM users WHERE username=$1', [username]);
  const user = rows[0];
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (user.role === 'superadmin') return res.status(403).json({ error: 'Cannot reset superadmin password' });
  if (me.role === 'admin' && user.role !== 'viewer') return res.status(403).json({ error: 'Forbidden' });
  if (!user.email) return res.status(400).json({ error: 'User has no email address on file' });
  const pwd  = generatePassword();
  const hash = hashPassword(pwd);
  await pool.query('UPDATE users SET password_hash=$1 WHERE username=$2', [hash, username]);
  try {
    await sendEmailOTP(user.email, `New login password`);
    // Send actual password email
    const nodemailer  = require('nodemailer');
    const transporter = nodemailer.createTransport({ service:'gmail', auth:{ user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS } });
    await transporter.sendMail({
      from: `"Engagement Calendar" <${process.env.EMAIL_USER}>`,
      to: user.email,
      subject: 'Your Engagement Calendar password',
      html: `<div style="font-family:'Segoe UI',Arial,sans-serif;max-width:420px;margin:0 auto;padding:32px 24px;background:#fff;border-radius:12px">
        <div style="font-size:1.1rem;font-weight:700;color:#1a1f36;margin-bottom:8px">Engagement Calendar</div>
        <p style="color:#555;margin-bottom:20px">Hi ${user.first_name||username}, your password has been set by an administrator.</p>
        <div style="font-size:1.4rem;font-weight:800;letter-spacing:4px;color:#1a1f36;padding:16px 20px;background:#eef0f3;border-radius:8px;text-align:center">${pwd}</div>
        <p style="color:#aaa;font-size:13px;margin-top:16px">Use this password to log in at your next session.</p>
      </div>`,
    });
  } catch(e) { console.error('Password email error:', e.message); return res.status(500).json({ error: 'Failed to send password email' }); }
  res.json({ ok: true });
});

// ── Invites ───────────────────────────────────────────────────────────────────
app.post('/api/invite/generate', requireAdmin, async (req, res) => {
  const me   = getSession(req);
  // Admins can only invite viewers; superadmin can invite admin or viewer
  const requestedRole = req.body?.role;
  const role = me.role === 'superadmin' && requestedRole === 'admin' ? 'admin' : 'viewer';
  const token = crypto.randomBytes(24).toString('hex');
  const expires = new Date(Date.now() + 48 * 60 * 60 * 1000);
  await pool.query('INSERT INTO invites (token, created_by, invite_role, expires_at) VALUES ($1,$2,$3,$4)', [token, me.username, role, expires]);
  const proto = req.get('x-forwarded-proto') || 'http';
  const host  = req.get('host') || `localhost:${PORT}`;
  res.json({ ok: true, url: `${proto}://${host}/invite.html?token=${token}`, role });
});

app.get('/api/invite/:token', async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM invites WHERE token=$1', [req.params.token]);
  const inv = rows[0];
  if (!inv)     return res.status(404).json({ error: 'Invalid invite link' });
  if (inv.used) return res.status(410).json({ error: 'This invite has already been used' });
  if (new Date() > new Date(inv.expires_at)) return res.status(410).json({ error: 'Invite has expired' });
  res.json({ ok: true, createdBy: inv.created_by, role: inv.invite_role });
});

app.post('/api/invite/:token/claim', async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM invites WHERE token=$1', [req.params.token]);
  const inv = rows[0];
  if (!inv || inv.used || new Date() > new Date(inv.expires_at))
    return res.status(410).json({ error: 'Invalid or expired invite' });
  const { username, phone, firstName, lastName, email, birthday } = req.body || {};
  if (!username || !phone || !firstName || !lastName || !email)
    return res.status(400).json({ error: 'All fields are required' });
  const taken = await pool.query('SELECT 1 FROM users WHERE username=$1', [username]);
  if (taken.rowCount) return res.status(409).json({ error: 'Username already taken' });
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  try { await sendEmailOTP(email, otp); }
  catch (e) { console.error('Invite OTP error:', e.message); return res.status(500).json({ error: 'Failed to send verification code' }); }
  const pending = jwt.sign({ otp, username, phone, firstName, lastName, email, birthday: birthday||null, inviteToken: req.params.token, role: inv.invite_role }, JWT_SECRET, { expiresIn: '5m' });
  res.cookie('otp_pending', pending, { httpOnly: true, maxAge: 300000, sameSite: 'strict' });
  res.json({ ok: true });
});

app.post('/api/invite/:token/verify', async (req, res) => {
  const { otp } = req.body || {};
  try {
    const p = jwt.verify(req.cookies.otp_pending || '', JWT_SECRET);
    if (p.otp !== String(otp) || p.inviteToken !== req.params.token)
      return res.status(401).json({ error: 'Incorrect code' });
    const { rows } = await pool.query('SELECT * FROM invites WHERE token=$1 AND used=false', [p.inviteToken]);
    if (!rows[0]) return res.status(410).json({ error: 'Invite no longer valid' });
    await pool.query('UPDATE invites SET used=true, used_by=$1, used_at=NOW() WHERE token=$2', [p.username, p.inviteToken]);
    await pool.query('INSERT INTO users (username, phone, role, first_name, last_name, email, birthday, invited_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
      [p.username, p.phone, p.role, p.firstName, p.lastName, p.email, p.birthday||null, rows[0].created_by]);
    res.clearCookie('otp_pending');
    const session = jwt.sign({ username: p.username, role: p.role }, JWT_SECRET, { expiresIn: '8h' });
    res.cookie('session', session, { httpOnly: true, maxAge: 28800000, sameSite: 'strict' });
    res.json({ ok: true, role: p.role });
  } catch { res.status(401).json({ error: 'Code expired or invalid' }); }
});

// ── Event Feedback ────────────────────────────────────────────────────────────
app.get('/api/events/:key/feedback', async (req, res) => {
  const s   = getSession(req);
  const key = decodeURIComponent(req.params.key);
  const [reactionRows, commentRows, userReactionRow, bookmarkRow] = await Promise.all([
    pool.query("SELECT reaction, COUNT(*) FROM event_reactions WHERE event_key=$1 GROUP BY reaction", [key]),
    pool.query(`SELECT ec.id, ec.username, ec.body, ec.created_at, u.first_name, u.last_name
                FROM event_comments ec LEFT JOIN users u ON ec.username=u.username
                WHERE ec.event_key=$1 ORDER BY ec.created_at ASC`, [key]),
    s ? pool.query('SELECT reaction FROM event_reactions WHERE event_key=$1 AND username=$2', [key, s.username]) : Promise.resolve({ rows: [] }),
    s ? pool.query('SELECT 1 FROM bookmarks WHERE event_key=$1 AND username=$2', [key, s.username]) : Promise.resolve({ rows: [] }),
  ]);
  const reactions = { like: 0, dislike: 0 };
  reactionRows.rows.forEach(r => { reactions[r.reaction] = parseInt(r.count); });
  res.json({
    reactions,
    userReaction: userReactionRow.rows[0]?.reaction || null,
    bookmarked: bookmarkRow.rows.length > 0,
    comments: commentRows.rows,
  });
});

app.post('/api/events/:key/react', requireAuth, async (req, res) => {
  const s        = getSession(req);
  const key      = decodeURIComponent(req.params.key);
  const { reaction } = req.body || {};
  if (!['like','dislike'].includes(reaction)) return res.status(400).json({ error: 'Invalid reaction' });
  const existing = await pool.query('SELECT reaction FROM event_reactions WHERE event_key=$1 AND username=$2', [key, s.username]);
  if (existing.rows[0]?.reaction === reaction) {
    await pool.query('DELETE FROM event_reactions WHERE event_key=$1 AND username=$2', [key, s.username]);
  } else {
    await pool.query('INSERT INTO event_reactions (event_key,username,reaction) VALUES ($1,$2,$3) ON CONFLICT (event_key,username) DO UPDATE SET reaction=$3', [key, s.username, reaction]);
  }
  const counts = await pool.query("SELECT reaction, COUNT(*) FROM event_reactions WHERE event_key=$1 GROUP BY reaction", [key]);
  const result = { like: 0, dislike: 0 };
  counts.rows.forEach(r => { result[r.reaction] = parseInt(r.count); });
  res.json({ ok: true, reactions: result });
});

app.post('/api/events/:key/comments', requireAuth, async (req, res) => {
  const s   = getSession(req);
  const key = decodeURIComponent(req.params.key);
  const { body } = req.body || {};
  if (!body?.trim()) return res.status(400).json({ error: 'Comment cannot be empty' });
  const { rows } = await pool.query('INSERT INTO event_comments (event_key,username,body) VALUES ($1,$2,$3) RETURNING *', [key, s.username, body.trim()]);
  const user = await pool.query('SELECT first_name, last_name FROM users WHERE username=$1', [s.username]);
  res.json({ ok: true, comment: { ...rows[0], ...user.rows[0] } });
});

app.delete('/api/events/:key/comments/:id', requireAuth, async (req, res) => {
  const s = getSession(req);
  const { rows } = await pool.query('SELECT * FROM event_comments WHERE id=$1', [req.params.id]);
  if (!rows[0]) return res.status(404).json({ error: 'Not found' });
  if (rows[0].username !== s.username && !['admin','superadmin'].includes(s.role))
    return res.status(403).json({ error: 'Forbidden' });
  await pool.query('DELETE FROM event_comments WHERE id=$1', [req.params.id]);
  res.json({ ok: true });
});

// ── Bookmarks ─────────────────────────────────────────────────────────────────
app.get('/api/me/bookmarks', requireAuth, async (req, res) => {
  const s = getSession(req);
  const { rows } = await pool.query('SELECT event_key, created_at FROM bookmarks WHERE username=$1 ORDER BY created_at DESC', [s.username]);
  res.json(rows);
});

app.post('/api/me/bookmarks/:key', requireAuth, async (req, res) => {
  const s = getSession(req);
  await pool.query('INSERT INTO bookmarks (event_key,username) VALUES ($1,$2) ON CONFLICT DO NOTHING', [decodeURIComponent(req.params.key), s.username]);
  res.json({ ok: true });
});

app.delete('/api/me/bookmarks/:key', requireAuth, async (req, res) => {
  const s = getSession(req);
  await pool.query('DELETE FROM bookmarks WHERE event_key=$1 AND username=$2', [decodeURIComponent(req.params.key), s.username]);
  res.json({ ok: true });
});

// ── Personal events ───────────────────────────────────────────────────────────
app.get('/api/personal-events', requireAuth, async (req, res) => {
  const s = getSession(req);
  const { rows } = await pool.query('SELECT * FROM personal_events WHERE username=$1 ORDER BY date', [s.username]);
  res.json(rows);
});
app.post('/api/personal-events', requireAuth, async (req, res) => {
  const s = getSession(req);
  const { date, name, note } = req.body || {};
  if (!date || !name) return res.status(400).json({ error: 'date and name required' });
  const { rows } = await pool.query('INSERT INTO personal_events (username,date,name,note) VALUES ($1,$2,$3,$4) RETURNING *', [s.username, date, name, note||null]);
  res.json({ ok: true, event: rows[0] });
});
app.delete('/api/personal-events/:id', requireAuth, async (req, res) => {
  const s = getSession(req);
  await pool.query('DELETE FROM personal_events WHERE id=$1 AND username=$2', [req.params.id, s.username]);
  res.json({ ok: true });
});

// ── Invite stats ──────────────────────────────────────────────────────────────
app.get('/api/invites/stats', requireAdmin, async (req, res) => {
  const me = getSession(req);
  const { rows } = me.role === 'superadmin'
    ? await pool.query('SELECT * FROM invites ORDER BY created_at DESC LIMIT 30')
    : await pool.query('SELECT * FROM invites WHERE created_by=$1 ORDER BY created_at DESC LIMIT 30', [me.username]);
  res.json(rows);
});

// ── Reminders ─────────────────────────────────────────────────────────────────
app.post('/api/reminders', requireAdmin, async (req, res) => {
  const me = getSession(req);
  const { toUsername, message, date } = req.body || {};
  if (!toUsername || !message) return res.status(400).json({ error: 'Recipient and message required' });
  const { rows } = await pool.query('SELECT * FROM users WHERE username=$1', [toUsername]);
  const user = rows[0];
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (!user.email) return res.status(400).json({ error: 'User has no email on file' });
  const from = [user.first_name, user.last_name].filter(Boolean).join(' ') || toUsername;
  try {
    if (!process.env.EMAIL_USER) { console.log(`[DEV] Reminder to ${user.email}: ${message}`); }
    else {
      const nodemailer  = require('nodemailer');
      const transporter = nodemailer.createTransport({ service:'gmail', auth:{ user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS } });
      await transporter.sendMail({
        from: `"Engagement Calendar" <${process.env.EMAIL_USER}>`,
        to: user.email,
        subject: date ? `Reminder for ${date}` : 'Reminder from Engagement Calendar',
        html: `<div style="font-family:'Segoe UI',Arial,sans-serif;max-width:480px;margin:0 auto;padding:28px;background:#fff;border-radius:12px">
          <div style="font-size:1.1rem;font-weight:700;color:#1a1f36;margin-bottom:6px">📅 Engagement Calendar</div>
          <div style="font-size:.85rem;color:#888;margin-bottom:18px">Reminder from ${me.username}</div>
          ${date ? `<div style="background:#eef0f3;border-radius:8px;padding:10px 14px;font-weight:600;color:#1a1f36;margin-bottom:14px">📅 ${date}</div>` : ''}
          <p style="color:#333;font-size:.95rem;line-height:1.6">${message}</p>
        </div>`,
      });
    }
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: 'Failed to send reminder: ' + e.message }); }
});

// ── Activity log ─────────────────────────────────────────────────────────────
app.get('/api/activity', requireAdmin, async (req, res) => {
  const [comments, reactions] = await Promise.all([
    pool.query(`SELECT ec.id, ec.event_key, ec.username, ec.body, ec.created_at,
                       u.first_name, u.last_name
                FROM event_comments ec
                LEFT JOIN users u ON ec.username=u.username
                ORDER BY ec.created_at DESC LIMIT 30`),
    pool.query(`SELECT er.event_key, er.username, er.reaction, er.created_at,
                       u.first_name, u.last_name
                FROM event_reactions er
                LEFT JOIN users u ON er.username=u.username
                ORDER BY er.created_at DESC LIMIT 30`),
  ]);
  // Merge and sort by date
  const feed = [
    ...comments.rows.map(r => ({ ...r, type: 'comment' })),
    ...reactions.rows.map(r => ({ ...r, type: 'reaction' })),
  ].sort((a,b) => new Date(b.created_at) - new Date(a.created_at)).slice(0, 40);
  res.json(feed);
});

// ── Birthdays ─────────────────────────────────────────────────────────────────
app.get('/api/birthdays', async (req, res) => {
  const { rows } = await pool.query(
    'SELECT first_name, last_name, username, birthday FROM users WHERE birthday IS NOT NULL'
  );
  const year = new Date().getFullYear();
  const events = rows.map(r => {
    const bd = new Date(r.birthday);
    const month = String(bd.getUTCMonth() + 1).padStart(2, '0');
    const day   = String(bd.getUTCDate()).padStart(2, '0');
    const firstName = r.first_name || r.username;
    const lastName  = r.last_name  || '';
    return {
      date: `${year}-${month}-${day}`,
      name: `🎂 ${firstName}${lastName ? ' ' + lastName : ''}'s Birthday`,
    };
  });
  res.json(events);
});

// ── Calendar ──────────────────────────────────────────────────────────────────
app.get('/api/calendar', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT data FROM calendar WHERE id=1');
    res.json(rows[0]?.data || {});
  } catch {
    try { res.json(JSON.parse(require('fs').readFileSync(path.join(__dirname,'data.json'),'utf8'))); }
    catch { res.status(500).json({ error: 'Failed to read data' }); }
  }
});

app.post('/api/calendar', requireAdmin, async (req, res) => {
  try {
    await pool.query('INSERT INTO calendar (id,data) VALUES (1,$1) ON CONFLICT (id) DO UPDATE SET data=$1', [req.body]);
    res.json({ ok: true });
  } catch { res.status(500).json({ error: 'Failed to save data' }); }
});

// ── Start ─────────────────────────────────────────────────────────────────────
async function start() {
  await initDB();
  const { rowCount } = await pool.query('SELECT 1 FROM calendar WHERE id=1');
  if (!rowCount) {
    let seed = {};
    try { seed = JSON.parse(require('fs').readFileSync(path.join(__dirname,'data.json'),'utf8')); } catch {}
    await pool.query('INSERT INTO calendar (id,data) VALUES (1,$1)', [seed]);
    console.log('Calendar seeded');
  }
  app.listen(PORT, () => console.log(`Engagement Calendar → http://localhost:${PORT}`));
}
start().catch(err => { console.error('Startup failed:', err.message); process.exit(1); });
