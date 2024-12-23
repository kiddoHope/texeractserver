const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const mysql = require('mysql2/promise');
const cors = require("cors");
require('dotenv').config();
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const NodeCache = require('node-cache');

const app = express();
const port = 5003;
const cache = new NodeCache({ stdTTL: 60 });

app.use(compression());
app.use(bodyParser.json());

const allowedOrigins = [
  'https://texeract.network', 
  'http://localhost:3000', 
  'http://localhost:3001', 
  'https://texeract-network-beta.vercel.app',
  'https://tg-texeract-beta.vercel.app',
  'https://texeractbot.xyz'
];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    } else {
      return callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-access-token', 'X-Requested-With', 'Accept'],
  credentials: true,
}));

app.options('*', (req, res) => {
  res.header('Access-Control-Allow-Origin', req.headers.origin);
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-access-token, X-Requested-With, Accept');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.sendStatus(204);
});

app.use((req, res, next) => {
  res.header('Vary', 'Origin');
  next();
});

const jwtSecret = process.env.MAIN_JWT_SECRET;
const jwtAPISecret = process.env.API_JWT_SECRET;

// 46.202.129.137

const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
  port: 3306,
  waitForConnections: true,
  connectTimeout: 20000,
  connectionLimit: 10,
  queueLimit: 0,
});

process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
});

async function testConnection() {
  try {
    const connection = await db.getConnection();
    console.log('Database connection successful!');
    connection.release();
  } catch (error) {
    console.error('Database connection failed:', error);
  }
}

testConnection();

app.post('/xera/v1/api/token/faucet-transaction', async (req, res) => {
  const { request } = req.body;

  if (!request || !request.api || !request.limit || !request.page) {
    return res.status(400).json({ success: false, message: "Invalid or missing parameters" });
  }

  const { api, limit, page } = request;

  const limitNumber = parseInt(limit, 10);
  const pageNumber = parseInt(page, 10);

  if (isNaN(limitNumber) || isNaN(pageNumber) || limitNumber <= 0 || pageNumber <= 0) {
    return res.status(400).json({ success: false, message: "Invalid pagination parameters" });
  }

  try {
    const [assetTokens] = await db.query(
      'SELECT transaction_block, transaction_hash, transaction_amount, receiver_address, transaction_fee_token, transaction_fee_token_id FROM xera_network_transactions'
    );

    if (!assetTokens || assetTokens.length === 0) {
      return res.status(404).json({ success: false, message: "No tokens found" });
    }

    const sortedTokens = assetTokens.sort((a, b) => b.id - a.id);
    const startIndex = (pageNumber - 1) * limitNumber;
    const paginatedData = sortedTokens.slice(startIndex, startIndex + limitNumber);

    return res.status(200).json({ success: true, data: paginatedData });
  } catch (error) {
    console.error('Database query error:', error);
    return res.status(500).json({ success: false, message: "Server error", error: error.message });
  }
});

// Global error handling middleware
app.use((err, req, res, next) => {
  console.error("Global error:", err.message);
  res.status(500).json({ success: false, message: "An internal error occurred" });
});

// Start the server
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});