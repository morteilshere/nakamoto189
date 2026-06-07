const express = require('express');
const sqlite3 = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const path = require('path');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Database
const db = new sqlite3('nakamoto189.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    email TEXT DEFAULT '',
    bank_name TEXT DEFAULT '',
    bank_account TEXT DEFAULT '',
    balance REAL DEFAULT 0,
    role TEXT DEFAULT 'member',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS login_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    login_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )
`);

// Register
app.post('/api/register', (req, res) => {
  try {
    const { username, password, email, bank_name, bank_account } = req.body;
    if (!username || username.trim().length < 3) return res.json({ success: false, message: 'Username minimal 3 karakter' });
    if (!password || password.length < 6) return res.json({ success: false, message: 'Password minimal 6 karakter' });
    const ada = db.prepare('SELECT id FROM users WHERE username = ?').get(username.trim());
    if (ada) return res.json({ success: false, message: 'Username sudah dipakai' });
    const hash = bcrypt.hashSync(password, 10);
    db.prepare('INSERT INTO users (username, password, email, bank_name, bank_account) VALUES (?,?,?,?,?)').run(username.trim(), hash, email||'', bank_name||'', bank_account||'');
    res.json({ success: true, message: 'Registrasi berhasil! Silakan login.' });
  } catch(e) {
    res.json({ success: false, message: 'Server error' });
  }
});

// Login
app.post('/api/login', (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.json({ success: false, message: 'Isi username dan password' });
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username.trim());
    if (!user) return res.json({ success: false, message: 'Username tidak ditemukan' });
    if (!bcrypt.compareSync(password, user.password)) return res.json({ success: false, message: 'Password salah' });
    db.prepare('INSERT INTO login_logs (user_id) VALUES (?)').run(user.id);
    res.json({ success: true, message: 'Selamat datang, '+user.username+'!', user: { id: user.id, username: user.username, email: user.email, balance: user.balance, role: user.role } });
  } catch(e) {
    res.json({ success: false, message: 'Server error' });
  }
});

// Profile
app.get('/api/profile/:username', (req, res) => {
  const user = db.prepare('SELECT username, email, bank_name, bank_account, balance, role, created_at FROM users WHERE username = ?').get(req.params.username);
  if (!user) return res.json({ success: false });
  res.json({ success: true, user });
});

// Status
app.get('/api/status', (req, res) => {
  res.json({ status: 'online', server: 'NAKAMOTO189', time: new Date().toISOString() });
});

// Default
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => console.log('NAKAMOTO189 jalan di port '+PORT));
