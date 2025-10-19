// server.js
require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '15m';

if (!JWT_SECRET) {
  console.error("Error: JWT_SECRET not set. Copy .env.example -> .env and provide JWT_SECRET");
  process.exit(1);
}

/**
 * MOCK "database"
 * - password disimpan plain untuk simplicity (boleh ganti ke hashed di project nyata)
 */
const users = [
  { email: "masgus2gd@example.com", password: "12345", name: "User One" },
  { email: "user2@example.com", password: "pass456", name: "User Two" }
];

const items = [
  { id: 1, name: "Keyboard", price: 250000 },
  { id: 2, name: "Mouse", price: 150000 },
  { id: 3, name: "Monitor", price: 1200000 }
];

/* -----------------------
   Middleware: authenticateToken
   - expects header Authorization: Bearer <token>
   - responds 401 on missing/invalid/expired token
   ----------------------- */
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

  if (!token) {
    return res.status(401).json({ error: "Authorization token is required" });
  }

  jwt.verify(token, JWT_SECRET, (err, payload) => {
    if (err) {
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json({ error: "Token expired" });
      }
      return res.status(401).json({ error: "Invalid token" });
    }
    // payload includes sub and email (see login)
    req.user = payload;
    next();
  });
}

/* -----------------------
   Routes
   ----------------------- */

// Public endpoint: GET /items
app.get('/items', (req, res) => {
  return res.json({ items });
});

// Login: POST /auth/login
// Body: { email, password }
app.post('/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: "email and password required" });
  }

  const user = users.find(u => u.email === email && u.password === password);
  if (!user) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  // Payload must include sub/email/exp (exp will be set by sign via expiresIn)
  const payload = { sub: user.email, email: user.email, name: user.name };
  const access_token = jwt.sign(payload, JWT_SECRET, { algorithm: 'HS256', expiresIn: JWT_EXPIRES_IN });

  return res.json({ access_token });
});

// Protected endpoint: PUT /profile
// Header: Authorization: Bearer <token>
// Body: { name }  -> only updates the authenticated user's profile
app.put('/profile', authenticateToken, (req, res) => {
  const { name } = req.body || {};
  const email = req.user && req.user.sub;

  const user = users.find(u => u.email === email);
  if (!user) return res.status(404).json({ error: "User not found" });

  // simple validation
  if (name && typeof name !== 'string') {
    return res.status(400).json({ error: "name must be a string" });
  }

  user.name = name || user.name;

  // never return password in response
  const safeUser = { email: user.email, name: user.name };

  return res.json({ message: "Profile updated", user: safeUser });
});

// default route
app.get('/', (req, res) => res.json({ message: "JWT Marketplace API is running" }));

// fallback error handler
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: "Internal Server Error" });
});

/* -----------------------
   Start server
   ----------------------- */
app.listen(PORT, () => {
  console.log(`✅ Server running at http://localhost:${PORT}`);
});
