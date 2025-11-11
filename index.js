const express = require('express');
const path = require('path');
const crypto = require('crypto');
const mysql = require('mysql2/promise'); // ✅ ganti dari fs ke database

const app = express();
const port = process.env.PORT || 3000;

// Secret untuk HMAC
const HMAC_SECRET = process.env.HMAC_SECRET || 'change_this_signing_secret_in_prod';

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ✅ Buat koneksi ke database MySQL
const dbConfig = {
  host: 'localhost',
  user: 'root',
  password: '', // isi sesuai database kamu
  database: 'api_key_db' // nama database kamu
};

let db;
(async () => {
  db = await mysql.createConnection(dbConfig);
  console.log('✅ Connected to MySQL');
})();

// Helper hash API key
function hmacHash(key) {
  return crypto.createHmac('sha256', HMAC_SECRET).update(key).digest('hex');
}

// Helper generate API key
function generateApiKey() {
  const raw = crypto.randomBytes(32);
  const base64url = raw.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const kid = crypto.randomBytes(6).toString('hex');
  return { kid, key: `sk-${kid}-${base64url}` };
}

// Route utama
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ✅ POST /generate — generate API key dan simpan ke DB
app.post('/generate', async (req, res) => {
  const { name, email, notes } = req.body || {};
  try {
    const { kid, key } = generateApiKey();
    const hash = hmacHash(key);

    await db.execute(
      'INSERT INTO api_keys (kid, name, email, hash, revoked) VALUES (?, ?, ?, ?, ?)',
      [kid, name || null, email || null, hash, 0]
    );

    res.json({ success: true, apiKey: key, kid });
  } catch (err) {
    console.error('Error generating key:', err);
    res.status(500).json({ success: false, message: 'Database error' });
  }
});

// ✅ POST /validate — validasi API key dari database
app.post('/validate', async (req, res) => {
  const { apiKey } = req.body || {};
  if (!apiKey) return res.status(400).json({ success: false, message: 'apiKey required' });

  try {
    const hash = hmacHash(apiKey);
    const [rows] = await db.execute('SELECT * FROM api_keys WHERE hash = ? AND revoked = 0', [hash]);

    if (rows.length > 0) {
      res.json({
        success: true,
        valid: true,
        kid: rows[0].kid,
        name: rows[0].name,
        email: rows[0].email
      });
    } else {
      res.json({ success: true, valid: false });
    }
  } catch (err) {
    console.error('Error validating key:', err);
    res.status(500).json({ success: false, message: 'Database error' });
  }
});

// ✅ GET /keys — lihat semua key di database
app.get('/keys', async (req, res) => {
  const [rows] = await db.execute('SELECT kid, name, email, created_at, revoked FROM api_keys');
  res.json({ success: true, keys: rows });
});

// ✅ POST /revoke — menonaktifkan key tertentu
app.post('/revoke', async (req, res) => {
  const { kid } = req.body;
  if (!kid) return res.status(400).json({ success: false, message: 'kid required' });

  await db.execute('UPDATE api_keys SET revoked = 1 WHERE kid = ?', [kid]);
  res.json({ success: true, message: 'Key revoked', kid });
});

app.listen(port, () => {
  console.log(`🚀 Server running at http://localhost:${port}`);
});
