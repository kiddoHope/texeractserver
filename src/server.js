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

const getDevFromCache = async (api) => {
  let dev = cache.get(api);

  if (!dev) {
    const [dbDev] = await db.query('SELECT * FROM xera_developer WHERE BINARY xera_api = ?', [api]);
    if (dbDev.length > 0) {
      dev = dbDev[0];
      cache.set(api, dev);
    } else {
      throw new Error("Invalid API key");
    }
  }
  if (dev.xera_moderation !== 'creator') {
    throw new Error("Insufficient permissions");
  }
  return dev;
};

app.post('/xera/v1/api/token/asset-tokens', async (req, res) => {
  const { apikey } = req.body;

  if (!apikey) {
    return res.status(400).json({ success: false, message: "API key is required" });
  }

  try {
    await getDevFromCache(apikey);

    const [assetTokens] = await db.query('SELECT * FROM xera_asset_token');

    if (assetTokens.length > 0) {
      const cleanedData = assetTokens.map(({ id, ...clean }) => clean);
      return res.status(200).json({ success: true, data: cleanedData });
    } else {
      return res.status(404).json({ success: false, message: "No tokens found" });
    }
  } catch (error) {
    console.error('Error:', error.message);
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