/**
 * DesignCane - Node backend (single file)
 *   POST /api/contact  -> validates the form, builds an HTML email, sends it via Gmail SMTP
 *   GET  /api/health   -> simple status check
 *
 * Start:  npm install && npm start        (default http://localhost:3000)
 * Test SMTP login only:  npm run check-smtp
 */
'use strict';

try { require('dotenv').config(); } catch { /* env vars may come from the host (Render) */ }

const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');

/* ------------------------------ config ------------------------------ */
const cfg = () => ({
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: Number(process.env.SMTP_PORT || 587),
  user: process.env.SMTP_USER || 'designcane857@gmail.com',
  pass: (process.env.SMTP_APP_PASSWORD || '').replace(/\s+/g, ''), // Google shows it with spaces
  to: process.env.CONTACT_EMAIL || 'designcane857@gmail.com',
});

let transporter = null;
function getTransporter() {
  const c = cfg();
  if (!c.user || !c.pass) return null;
  if (!transporter) {
    transporter = nodemailer.createTransport({
      host: c.host,
      port: c.port,
      secure: false,     // port 587 = STARTTLS
      requireTLS: true,  // refuse to send if STARTTLS cannot be negotiated
      auth: { user: c.user, pass: c.pass },
      connectionTimeout: 10000,
      greetingTimeout: 10000,
      socketTimeout: 20000,
    });
  }
  return transporter;
}

async function verifySmtp() {
  const t = getTransporter();
  if (!t) { console.warn('[smtp] SMTP_APP_PASSWORD is not set. /api/contact will return 503.'); return false; }
  try { await t.verify(); console.log('[smtp] Connection and login verified.'); return true; }
  catch (e) {
    console.error('[smtp] Verify failed:', e.code || '', e.message);
    if (e.code === 'EAUTH') console.error('[smtp] Use a Gmail App Password (2-Step Verification on), not the normal password.');
    return false;
  }
}

/* ------------------------ validation / sanitising ------------------------ */
const oneLine = (s, max) =>
  String(s ?? '').replace(/[\r\n\u2028\u2029]+/g, ' ').replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, max);
const multiLine = (s, max) =>
  String(s ?? '').replace(/\r\n?/g, '\n').replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '').trim().slice(0, max);
const esc = (s) =>
  String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');

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

/* ----------------------------- email template ----------------------------- */
function renderHtml(d, meta) {
  const row = (k, v) =>
    `<tr><td style="padding:10px 0;width:120px;vertical-align:top;font:600 11px/1.4 Arial,sans-serif;letter-spacing:.12em;text-transform:uppercase;color:#7a7568">${k}</td><td style="padding:10px 0;font:15px/1.5 Arial,sans-serif;color:#292823">${v}</td></tr>`;
  return `<!doctype html><html><body style="margin:0;padding:24px;background:#f3ede2">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0"><tr><td align="center">
<table role="presentation" width="600" cellspacing="0" cellpadding="0" style="max-width:600px;width:100%;background:#fffdf8;border:1px solid #e4dccb;border-radius:4px">
<tr><td style="background:#2f4a3a;padding:24px 32px;border-radius:4px 4px 0 0">
  <div style="font:600 11px Arial,sans-serif;letter-spacing:.2em;text-transform:uppercase;color:#d9c9a8">Crafted By Cane</div>
  <div style="font:600 24px Georgia,serif;color:#fffdf8;margin-top:6px">New website inquiry</div>
</td></tr>
<tr><td style="padding:24px 32px 8px">
  <div style="display:inline-block;padding:4px 12px;background:#f3e3da;color:#8a4a30;border-radius:999px;font:600 12px Arial,sans-serif">${esc(d.kind)}</div>
  <h2 style="margin:14px 0 6px;font:600 20px Georgia,serif;color:#292823">${esc(d.subject)}</h2>
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="border-top:1px solid #e4dccb;margin-top:12px">
    ${row('Name', esc(d.name))}
    ${row('Email', `<a href="mailto:${esc(d.email)}" style="color:#b96f50">${esc(d.email)}</a>`)}
    ${d.phone ? row('Phone', `<a href="tel:${esc(d.phone.replace(/[^+\d]/g, ''))}" style="color:#b96f50">${esc(d.phone)}</a>`) : ''}
    ${row('Subject', esc(d.subject))}
  </table>
</td></tr>
<tr><td style="padding:8px 32px 24px">
  <div style="font:600 11px Arial,sans-serif;letter-spacing:.12em;text-transform:uppercase;color:#7a7568;margin-bottom:8px">Message</div>
  <div style="padding:16px 18px;background:#f8f3e9;border-left:3px solid #b96f50;font:15px/1.65 Arial,sans-serif;color:#292823;white-space:pre-wrap">${esc(d.message)}</div>
  <p style="margin:20px 0 0;font:13px Arial,sans-serif;color:#7a7568">Just hit <strong>Reply</strong> to answer ${esc(d.name)} directly.</p>
</td></tr>
<tr><td style="padding:14px 32px;border-top:1px solid #e4dccb;font:12px Arial,sans-serif;color:#9a9486">Received ${esc(meta.when)} &middot; IP ${esc(meta.ip)}</td></tr>
</table></td></tr></table></body></html>`;
}

function renderText(d) {
  const lines = [`New website inquiry - ${d.kind}`, '', `Name: ${d.name}`, `Email: ${d.email}`];
  if (d.phone) lines.push(`Phone: ${d.phone}`);
  lines.push(`Subject: ${d.subject}`, '', d.message);
  return lines.join('\n');
}

/* --------------------------------- app --------------------------------- */
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1); // correct client IP behind Render's proxy

// Allow any frontend origin to call this API
app.use('/api', cors({ origin: '*', methods: ['GET', 'POST'] }));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5, // 5 submissions per IP per 15 minutes
  standardHeaders: true,
  legacyHeaders: false,
  handler: (_req, res) =>
    res.status(429).json({ ok: false, message: 'Too many messages from your connection. Please wait a few minutes and try again.' }),
});

app.get('/api/health', (_req, res) => res.json({ ok: true, smtpConfigured: Boolean(cfg().pass) }));

app.post('/api/contact', limiter, express.json({ limit: '20kb' }), async (req, res) => {
  try {
    const v = validate(req.body);
    if (!v.ok) return res.status(422).json({ ok: false, message: v.message });
    const d = v.data;

    const t = getTransporter();
    if (!t) {
      console.error('[contact] SMTP_APP_PASSWORD missing.');
      return res.status(503).json({ ok: false, message: 'Our contact form is temporarily unavailable. Please message us on WhatsApp.' });
    }

    const c = cfg();
    const when = new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata', dateStyle: 'medium', timeStyle: 'short' }) + ' IST';

    const info = await t.sendMail({
      from: { name: 'Crafted By Cane Website', address: c.user }, // must be our own Gmail account
      to: c.to,
      replyTo: { name: d.name, address: d.email },                // visitor goes in replyTo, never in "from"
      subject: `[${d.kind}] ${d.subject}`.slice(0, 200),
      text: renderText(d),
      html: renderHtml(d, { ip: req.ip || 'unknown', when }),
    });

    // Success only if the SMTP server accepted the recipient
    const accepted = (info.accepted || []).map((a) => String(typeof a === 'string' ? a : a.address).toLowerCase());
    if (!accepted.includes(c.to.toLowerCase())) {
      console.error('[contact] Recipient not accepted', { accepted: info.accepted, rejected: info.rejected, response: info.response });
      return res.status(502).json({ ok: false, message: 'We could not deliver your message. Please try again or message us on WhatsApp.' });
    }

    console.log('[contact] sent', info.messageId);
    return res.status(200).json({ ok: true });
  } catch (err) {
    if (err?.code === 'EAUTH') console.error('[contact] SMTP auth failed. Check SMTP_USER / SMTP_APP_PASSWORD.');
    else console.error('[contact] send failed:', err?.code, err?.message);
    return res.status(502).json({ ok: false, message: 'We could not send your message right now. Please try again shortly or message us on WhatsApp.' });
  }
});

// Bad JSON / oversized body
app.use('/api', (err, _req, res, _next) => {
  if (err?.type === 'entity.too.large') return res.status(413).json({ ok: false, message: 'Your message is too long.' });
  if (err instanceof SyntaxError) return res.status(400).json({ ok: false, message: 'Invalid request.' });
  console.error('[api] error:', err);
  return res.status(500).json({ ok: false, message: 'Something went wrong. Please try again.' });
});

/* --------------------------------- boot --------------------------------- */
if (process.argv.includes('--check-smtp')) {
  verifySmtp().then((ok) => process.exit(ok ? 0 : 1));
} else if (require.main === module) {
  const port = Number(process.env.PORT || 3000);
  app.listen(port, () => {
    console.log(`[server] http://localhost:${port}  (CORS: *)`);
    verifySmtp();
  });
}

module.exports = { app };