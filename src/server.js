const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const mysql = require('mysql2/promise');
const cors = require("cors");
require('dotenv').config();
const CryptoJS = require("crypto-js");
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const NodeCache = require('node-cache');

const app = express();
const port = 5000;
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

// pm2 start src/server.js src/airdrop-server.js src/user-server.js src/faucet-server.js src/genesis-server.js src/watcher-server.js
// node start src/server.js src/airdrop-server.js src/user-server.js src/faucet-server.js src/genesis-server.js src/watcher-server.js

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

// Fetch developer data from cache or database
const getDevFromCache = async (api) => {
    let message = "";
    try {
        let dev = cache.get(api);
        if (!dev) {
            const [rows] = await db.query("SELECT * FROM xera_developer WHERE BINARY xera_api = ?", [api]);

            if (rows.length === 0) {
                return message = "Invalid API key" 
            }

            dev = rows[0];
            cache.set(api, dev);
        }

        if (dev.xera_moderation !== "creator") {
            return message = "Access denied"
        }

        return dev;
    } catch (error) {
        return message = "Internal server error" 
    }
};

app.post('/xera/v1/api/token/asset-tokens', async (req, res) => {
  const { apikey } = req.body;
  
  const isValid = await getDevFromCache(apikey);
  
  if (!isValid)  {
    return res.status(400).json({ success: false, message: isValid });
  }
  try {
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

// Route to get transaction history of nodes
app.post('/xera/v1/api/node/transaction-history', async (req, res) => {
  const { apikey } = req.body;
  
  const isValid = await getDevFromCache(apikey);
  
  if (!isValid)  {
    return res.status(400).json({ success: false, message: isValid });
  }
      
  try {
      // Fetch the most recent transaction date
      const [lastDateResult] = await db.query(
          `SELECT MAX(node_txdate) AS lastDate
           FROM xera_user_node`
      );

      const lastDate = lastDateResult[0]?.lastDate;

      if (!lastDate) {
          return res.json({ success: false, message: "No transactions available" });
      }

      // Query for transactions from the last transaction date
      const [transactionNode] = await db.query(
          `SELECT node_id, node_name, node_owner, node_points, node_txhash, node_txdate
           FROM xera_user_node
           WHERE node_txdate = ?`,
          [lastDate]
      );

      if (transactionNode.length > 0) {
          return res.status(200).json({
              success: true,
              message: "User transactions successfully retrieved",
              transaction: transactionNode,
          });
      } else {
          return res.status(404).json({ success: false, message: "No transactions found for the last date" });
      }
  } catch (error) {
      return res.status(500).json({ success: false, message: "Request error", error: error.message });
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