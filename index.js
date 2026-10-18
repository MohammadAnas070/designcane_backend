/**
 * DesignCane - Node backend (single file)
 *   POST /api/contact  -> validates the form and appends the inquiry to inquiry.txt
 *   GET  /inquiries    -> EJS page listing all saved inquiries (password protected)
 *   GET  /api/health   -> simple status check
 *
 * Start:  npm install && npm start        (default http://localhost:3000)
 */
'use strict';

try { require('dotenv').config(); } catch { /* env vars may come from the host (Render) */ }

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const ejs = require('ejs');

/* ------------------------------ config ------------------------------ */
const INQUIRY_FILE = process.env.INQUIRY_FILE || path.join(__dirname, 'inquiry.txt');
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const adminPassword = () => process.env.ADMIN_PASSWORD || '';

/* ------------------------ validation / sanitising ------------------------ */
const oneLine = (s, max) =>
  String(s ?? '').replace(/[\r\n\u2028\u2029]+/g, ' ').replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, max);
const multiLine = (s, max) =>
  String(s ?? '').replace(/\r\n?/g, '\n').replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '').trim().slice(0, max);

const EMAIL_RE = /^[^\s@<>()",;:]+@[^\s@<>()",;:]+\.[A-Za-z]{2,}$/;
const PHONE_RE = /^[+\d\s().-]{7,20}$/;

function validate(body) {
  const d = {
    kind: oneLine(body?.kind, 60) || 'General question',
    name: oneLine(body?.name, 100),
    phone: oneLine(body?.phone, 20),
    email: oneLine(body?.email, 254).toLowerCase(),
    subject: oneLine(body?.subject, 150),
    message: multiLine(body?.message, 5000),
  };
  if (!d.name) return { ok: false, message: 'Please enter your name.' };
  if (!EMAIL_RE.test(d.email)) return { ok: false, message: 'Please enter a valid email address.' };
  if (d.phone && !PHONE_RE.test(d.phone)) return { ok: false, message: 'Please enter a valid phone number.' };
  if (d.subject.length < 3) return { ok: false, message: 'Please enter a subject (at least 3 characters).' };
  if (d.message.length < 8) return { ok: false, message: 'Please write a message (at least 8 characters).' };
  if ((d.message.match(/https?:\/\//gi) || []).length > 3) return { ok: false, message: 'Your message contains too many links.' };
  return { ok: true, data: d };
}

/* ------------------------------ storage ------------------------------ */
// inquiry.txt holds one JSON object per line (newest at the bottom).
// Writes are queued so two simultaneous submissions can never interleave.
let writeQueue = Promise.resolve();
function saveInquiry(record) {
  const line = JSON.stringify(record) + '\n';
  const job = writeQueue.then(() => fs.promises.appendFile(INQUIRY_FILE, line, 'utf8'));
  writeQueue = job.catch(() => {}); // keep the queue alive after a failure
  return job; // the caller still sees the failure
}

async function readInquiries() {
  let raw;
  try { raw = await fs.promises.readFile(INQUIRY_FILE, 'utf8'); }
  catch (e) { if (e.code === 'ENOENT') return []; throw e; }
  const items = [];
  for (const line of raw.split('\n')) {
    if (!line.trim()) continue;
    try { items.push(JSON.parse(line)); } catch { /* skip a damaged line */ }
  }
  return items.reverse(); // newest first
}

/* --------------------------------- app --------------------------------- */
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1); // correct client IP behind Render's proxy

// Allow any frontend origin to call the API
app.use('/api', cors({ origin: '*', methods: ['GET', 'POST'] }));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5, // 5 submissions per IP per 15 minutes
  standardHeaders: true,
  legacyHeaders: false,
  handler: (_req, res) =>
    res.status(429).json({ ok: false, message: 'Too many messages from your connection. Please wait a few minutes and try again.' }),
});

app.get('/api/health', (_req, res) => res.json({ ok: true, viewerProtected: Boolean(adminPassword()) }));

app.post('/api/contact', limiter, express.json({ limit: '20kb' }), async (req, res) => {
  try {
    const v = validate(req.body);
    if (!v.ok) return res.status(422).json({ ok: false, message: v.message });

    const record = {
      id: crypto.randomUUID(),
      createdAt: new Date().toISOString(),
      ip: req.ip || 'unknown',
      ...v.data,
    };

    // Success only after the inquiry has been written to the file.
    await saveInquiry(record);
    console.log('[contact] saved', record.id);
    return res.status(200).json({ ok: true });
  } catch (err) {
    console.error('[contact] save failed:', err?.code, err?.message);
    return res.status(500).json({ ok: false, message: 'We could not save your message right now. Please try again shortly or message us on WhatsApp.' });
  }
});

// Bad JSON / oversized body
app.use('/api', (err, _req, res, _next) => {
  if (err?.type === 'entity.too.large') return res.status(413).json({ ok: false, message: 'Your message is too long.' });
  if (err instanceof SyntaxError) return res.status(400).json({ ok: false, message: 'Invalid request.' });
  console.error('[api] error:', err);
  return res.status(500).json({ ok: false, message: 'Something went wrong. Please try again.' });
});

/* ------------------------- inquiries page (EJS) ------------------------- */
// Inquiries contain personal details, so the page asks for a password (HTTP Basic Auth).
function requireAdmin(req, res, next) {
  const expected = adminPassword();
  if (!expected) {
    return res.status(503).type('text').send('Set the ADMIN_PASSWORD environment variable to enable this page.');
  }
  const header = req.headers.authorization || '';
  const [scheme, encoded] = header.split(' ');
  if (scheme === 'Basic' && encoded) {
    const decoded = Buffer.from(encoded, 'base64').toString('utf8');
    const i = decoded.indexOf(':');
    const user = decoded.slice(0, i);
    const pass = decoded.slice(i + 1);
    const hash = (s) => crypto.createHash('sha256').update(s).digest();
    const ok = crypto.timingSafeEqual(hash(user), hash(ADMIN_USER)) & crypto.timingSafeEqual(hash(pass), hash(expected));
    if (ok) return next();
  }
  res.set('WWW-Authenticate', 'Basic realm="DesignCane inquiries", charset="UTF-8"');
  return res.status(401).type('text').send('Authentication required.');
}

// Uses views/inquiries.ejs when it exists; otherwise the built-in copy below, so the page works
// even if the views folder was not deployed.
const VIEW_FILE = path.join(__dirname, 'views', 'inquiries.ejs');
async function loadTemplate() {
  try { return await fs.promises.readFile(VIEW_FILE, 'utf8'); }
  catch (e) { if (e.code === 'ENOENT') return DEFAULT_TEMPLATE; throw e; }
}

app.get('/inquiries', requireAdmin, async (_req, res) => {
  try {
    const [inquiries, template] = await Promise.all([readInquiries(), loadTemplate()]);
    const html = ejs.render(template, { inquiries, total: inquiries.length });
    res.set('Cache-Control', 'no-store');
    res.type('html').send(html);
  } catch (err) {
    console.error('[inquiries] failed:', err?.code, err?.message);
    res.status(500).type('text').send('Could not load the inquiries page. Check the server logs.');
  }
});

const DEFAULT_TEMPLATE = String.raw`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex, nofollow">
  <title>Inquiries | Crafted By Cane</title>
  <style>
    :root { --bg:#f3ede2; --card:#fffdf8; --line:#e4dccb; --ink:#292823; --muted:#7a7568; --forest:#2f4a3a; --accent:#b96f50; }
    @media (prefers-color-scheme: dark) {
      :root { --bg:#1d1f1b; --card:#262924; --line:#3a3e36; --ink:#ece7da; --muted:#a39d8d; --forest:#6f9a80; --accent:#e09274; }
    }
    * { box-sizing: border-box; }
    body { margin:0; padding:24px 16px 48px; background:var(--bg); color:var(--ink); font:15px/1.6 Arial, sans-serif; }
    .wrap { max-width:860px; margin:0 auto; }
    header { display:flex; flex-wrap:wrap; justify-content:space-between; align-items:baseline; gap:8px; margin-bottom:20px; }
    h1 { margin:0; font:600 28px Georgia, serif; color:var(--forest); }
    .count { color:var(--muted); font-size:14px; }
    .card { background:var(--card); border:1px solid var(--line); border-radius:6px; padding:18px 20px; margin-bottom:14px; }
    .top { display:flex; flex-wrap:wrap; justify-content:space-between; gap:8px; align-items:center; }
    .kind { display:inline-block; padding:2px 12px; border-radius:999px; background:var(--line); color:var(--accent); font-weight:600; font-size:12px; }
    time { color:var(--muted); font-size:13px; }
    h2 { margin:10px 0 8px; font:600 19px Georgia, serif; }
    dl { display:grid; grid-template-columns:90px 1fr; gap:4px 12px; margin:0 0 12px; }
    dt { color:var(--muted); font-size:11px; font-weight:600; letter-spacing:.12em; text-transform:uppercase; padding-top:3px; }
    dd { margin:0; overflow-wrap:anywhere; }
    a { color:var(--accent); }
    .msg { margin:0; padding:12px 14px; border-left:3px solid var(--accent); background:var(--bg); white-space:pre-wrap; overflow-wrap:anywhere; }
    .id { margin-top:10px; color:var(--muted); font-size:12px; }
    .empty { text-align:center; color:var(--muted); padding:48px 16px; }
  </style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>Inquiries</h1>
    <span class="count"><%= total %> total &middot; newest first</span>
  </header>

  <% if (!inquiries.length) { %>
    <div class="card empty">No inquiries yet.</div>
  <% } %>

  <% inquiries.forEach(function (q) {
       var when = new Date(q.createdAt);
       var shown = isNaN(when) ? q.createdAt : when.toLocaleString('en-IN', { timeZone: 'Asia/Kolkata', dateStyle: 'medium', timeStyle: 'medium' }) + ' IST';
  %>
    <article class="card">
      <div class="top">
        <span class="kind"><%= q.kind %></span>
        <time datetime="<%= q.createdAt %>"><%= shown %></time>
      </div>
      <h2><%= q.subject %></h2>
      <dl>
        <dt>Name</dt><dd><%= q.name %></dd>
        <dt>Email</dt><dd><a href="mailto:<%= q.email %>"><%= q.email %></a></dd>
        <% if (q.phone) { %><dt>Phone</dt><dd><a href="tel:<%= String(q.phone).replace(/[^+\d]/g, '') %>"><%= q.phone %></a></dd><% } %>
      </dl>
      <p class="msg"><%= q.message %></p>
      <div class="id">ID <%= q.id %> &middot; IP <%= q.ip %></div>
    </article>
  <% }) %>
</div>
</body>
</html>
`;

/* --------------------------------- boot --------------------------------- */
if (require.main === module) {
  const port = Number(process.env.PORT || 3000);
  app.listen(port, () => {
    console.log(`[server] listening on port ${port} (CORS: *)`);
    console.log(`[server] inquiries file: ${INQUIRY_FILE}`);
    if (!adminPassword()) console.warn('[server] ADMIN_PASSWORD is not set. /inquiries is disabled.');
  });
}

module.exports = { app };