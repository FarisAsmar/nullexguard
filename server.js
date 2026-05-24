require('dotenv').config();
const express = require('express');
const cors    = require('axios');
const axios   = require('axios');
const path    = require('path');

const app = express();
const _cors = require('cors');
app.use(_cors());
app.use(express.json());

// Serve the frontend
app.use(express.static(path.join(__dirname, 'public')));

const DEHASHED_EMAIL  = process.env.DEHASHED_EMAIL;
const DEHASHED_APIKEY = process.env.DEHASHED_APIKEY;

if (!DEHASHED_EMAIL || !DEHASHED_APIKEY) {
  console.error('\n[ERROR] Missing DEHASHED_EMAIL or DEHASHED_APIKEY in .env file');
  console.error('[ERROR] Copy .env.example to .env and fill in your credentials\n');
  process.exit(1);
}

// ── Mask password: only reveal first + last char ──────────────────────────
function maskPassword(pw) {
  if (!pw || typeof pw !== 'string' || pw.length < 2) return null;
  return { first: pw[0], last: pw[pw.length - 1], length: pw.length };
}

// ── Group Dehashed entries by breach source ───────────────────────────────
function groupByBreach(entries) {
  const map = {};
  for (const e of entries) {
    const source = e.obtained_from || 'Unknown Source';
    if (!map[source]) {
      map[source] = {
        name:       source,
        types:      new Set(),
        password:   null,
        hashedPw:   null,
        sampleUser: null,
        count:      0,
      };
    }
    const b = map[source];
    b.count++;
    if (e.email)           b.types.add('email');
    if (e.username)        { b.types.add('username'); if (!b.sampleUser) b.sampleUser = e.username; }
    if (e.name)            b.types.add('name');
    if (e.phone)           b.types.add('phone');
    if (e.address)         b.types.add('address');
    if (e.ip_address)      b.types.add('ip_address');
    if (e.password)        { b.types.add('password');   if (!b.password) b.password = maskPassword(e.password); }
    if (e.hashed_password) { b.types.add('hashed_pw');  if (!b.hashedPw) b.hashedPw = e.hashed_password.substring(0, 24) + '...'; }
  }
  return Object.values(map).map(b => ({ ...b, types: Array.from(b.types) }));
}

// ── Extract identity signals across all entries ───────────────────────────
function extractIdentity(entries) {
  const usernames = [...new Set(entries.map(e => e.username).filter(Boolean))];
  const names     = [...new Set(entries.map(e => e.name).filter(Boolean))];
  const phones    = [...new Set(entries.map(e => e.phone).filter(Boolean))];
  const ips       = [...new Set(entries.map(e => e.ip_address).filter(Boolean))];
  const addresses = [...new Set(entries.map(e => e.address).filter(Boolean))];
  const hashes    = [...new Set(entries.map(e => e.hashed_password).filter(Boolean))];
  return { usernames, names, phones, ips, addresses, hashes };
}

// ── GET /api/lookup?email=xxx ─────────────────────────────────────────────
app.get('/api/lookup', async (req, res) => {
  const email = (req.query.email || '').trim().toLowerCase();
  if (!email || !email.includes('@')) {
    return res.status(400).json({ error: 'Invalid email address.' });
  }

  try {
    const response = await axios.get('https://api.dehashed.com/search', {
      params:  { query: `email:"${email}"`, size: 100 },
      auth:    { username: DEHASHED_EMAIL, password: DEHASHED_APIKEY },
      headers: { Accept: 'application/json' },
      timeout: 15000,
    });

    const data    = response.data;
    const entries = data.entries || [];

    if (!data || data.success === false) {
      return res.status(401).json({ error: 'Dehashed authentication failed. Check your credentials.' });
    }

    const breaches  = groupByBreach(entries);
    const identity  = extractIdentity(entries);
    const hasLeakedPw = breaches.some(b => b.password !== null);

    return res.json({
      email,
      total:        data.total || 0,
      entryCount:   entries.length,
      breachCount:  breaches.length,
      hasLeakedPw,
      identity,
      breaches,
    });

  } catch (err) {
    if (err.response) {
      const s = err.response.status;
      if (s === 401) return res.status(401).json({ error: 'Invalid Dehashed API credentials.' });
      if (s === 429) return res.status(429).json({ error: 'Rate limited by Dehashed. Please wait a moment.' });
      if (s === 402) return res.status(402).json({ error: 'Dehashed API credits exhausted. Check your plan.' });
    }
    console.error('Lookup error:', err.message);
    return res.status(500).json({ error: 'Lookup failed: ' + err.message });
  }
});

// ── Health check ──────────────────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', account: DEHASHED_EMAIL });
});

// ── Catch-all: serve frontend ─────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`\n NullexGuard backend running → http://localhost:${PORT}`);
  console.log(` Dehashed account: ${DEHASHED_EMAIL}\n`);
});
