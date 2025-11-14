import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import ratelimit from 'express-rate-limit';
import helmet from 'helmet';
import OpenAI from 'openai';
import pkg from 'pg';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import serverless from 'serverless-http';

dotenv.config();

// Enforce required environment variables
const requiredEnvVars = ['DATABASE_URL', 'JWT_SECRET', 'API_KEY'];
for (const varName of requiredEnvVars) {
  if (!process.env[varName]) {
    throw new Error(`${varName} environment variable is required`);
  }
}

const { Pool } = pkg;

// PostgreSQL Database Setup (using Neon)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://neondb_owner:npg_y6wszWCpv4uE@ep-still-fire-ad8ldwtl-pooler.c-2.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require',
  ssl: { rejectUnauthorized: false },
});

// Create tables if not exist
async function initializeDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS explanations (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        code TEXT NOT NULL,
        language TEXT,
        explanation TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    console.log('✅ Connected to PostgreSQL database (Neon)');
  } catch (err) {
    console.error('❌ Database initialization failed:', err.stack);
  }
}
initializeDB();

// Express App Setup
const app = express();
export const handler = serverless(app);
app.use(express.json({ limit: '10mb' }));
app.use(helmet());
app.use(
  cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:5173',
    credentials: true,
    methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  })
);

// Rate Limiter
const limiter = ratelimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP, please try again after 15 minutes',
});
app.use(limiter);

// OpenAI Client Setup
const client = new OpenAI({
  baseURL: 'https://openrouter.ai/api/v1',
  apiKey: process.env.API_KEY || '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',
});

// Middleware: Verify JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(
    token,
    process.env.JWT_SECRET || 'replace_with_a_long_random_secret',
    (err, user) => {
      if (err) return res.sendStatus(403);
      req.user = user;
      next();
    }
  );
}

// Routes: Auth

// Register user
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res
      .status(400)
      .json({ error: 'Username and password are required' });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query(`INSERT INTO users (username, password) VALUES ($1, $2)`, [
      username,
      hashedPassword,
    ]);
    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    console.error('Register error:', err.stack);
    if (err.message.includes('duplicate key'))
      return res.status(400).json({ error: 'Username already exists' });
    res.status(500).json({ error: 'Database error' });
  }
});

// Login user
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'Username and password required' });

  try {
    const result = await pool.query(`SELECT * FROM users WHERE username = $1`, [
      username,
    ]);
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign(
      { id: user.id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({ message: 'Login successful', token });
  } catch (err) {
    console.error('Login error:', err.stack);
    res.status(500).json({ error: 'Database error' });
  }
});

// AI Explain Code Route
app.post('/api/explain-code', authenticateToken, async (req, res) => {
  try {
    const { code, language } = req.body;
    if (!code) return res.status(400).json({ error: 'Code is required' });

    const message = [
      {
        role: 'user',
        content: `Please explain the following ${
          language || ' '
        } code in simple Bangla line by line:\n\n${code}`,
      },
    ];

    const response = await client.chat.completions.create({
      model: 'ibm-granite/granite-4.0-h-micro',
      messages: message,
    });

    const explanation = response?.choices?.[0]?.message?.content;

    if (!explanation)
      return res
        .status(500)
        .json({ error: 'Failed to get explanation from AI model' });

    // Save explanation in DB
    await pool.query(
      `INSERT INTO explanations (user_id, code, language, explanation) VALUES ($1, $2, $3, $4)`,
      [req.user.id, code, language, explanation]
    );

    res.json({ explanation, language });
  } catch (error) {
    console.error('Explain code error:', error.stack);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Get User's Explanations
app.get('/api/my-explanations', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM explanations WHERE user_id = $1 ORDER BY created_at DESC`,
      [req.user.id]
    );
    res.json({ explanations: result.rows });
  } catch (err) {
    console.error('My explanations error:', err.stack);
    res.status(500).json({ error: 'Database error' });
  }
});

// Delete Explanation
app.delete('/api/explanations/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      `DELETE FROM explanations WHERE id = $1 AND user_id = $2 RETURNING *`,
      [id, req.user.id]
    );
    if (result.rowCount === 0)
      return res
        .status(404)
        .json({ error: 'Explanation not found or not owned by you' });
    res.json({ message: 'Explanation deleted successfully' });
  } catch (err) {
    console.error('Delete explanation error:', err.stack);
    res.status(500).json({ error: 'Database error' });
  }
});

// Global error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// For local development only
if (process.env.NODE_ENV === 'development') {
  const port = process.env.PORT || 5000;
  app.listen(port, () => {
    console.log(`🚀 Server running on http://localhost:${port}`);
  });
}
