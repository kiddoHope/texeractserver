const express = require("express");
const bodyParser = require("body-parser");
const db = require('./connection');
const cors = require("cors");
require('dotenv').config();
const compression = require('compression');
const NodeCache = require('node-cache');

const app = express();
const port = 5003;
const cache = new NodeCache({ stdTTL: 60 });

app.use(compression());
app.use(bodyParser.json());

const allowedOrigins = [
    "https://texeract.network",
    "http://localhost:3000",
    "http://localhost:3001",
    "https://texeract-network-beta.vercel.app",
    "https://tg-texeract-beta.vercel.app",
    "https://texeractbot.xyz",
];

app.use(
    cors({
      origin: (origin, callback) => {
          if (!origin || allowedOrigins.includes(origin)) {
              return callback(null, true);
          }
          return callback(new Error("Not allowed by CORS"));
      },
      methods: ["GET", "POST", "PUT", "DELETE", "PATCH"],
      allowedHeaders: ["Content-Type", "Authorization", "x-access-token", "X-Requested-With", "Accept"],
      credentials: true,
    })
);

app.options("*", (req, res) => {
    res.header("Access-Control-Allow-Origin", req.headers.origin || "*");
    res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH");
    res.header("Access-Control-Allow-Headers", "Content-Type, Authorization, x-access-token, X-Requested-With, Accept");
    res.header("Access-Control-Allow-Credentials", "true");
    res.sendStatus(204);
});

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

app.post('/xera/v1/api/token/faucet-transaction', async (req, res) => {
  // Validate the API key and get the decoded key
  const { apikey } = req.body;
  
  const isValid = await getDevFromCache(apikey);
  
  if (!isValid)  {
    return res.status(400).json({ success: false, message: isValid });
  }
  const { limit, page } = req.body;
  const limitNumber = parseInt(limit, 10);
  const pageNumber = parseInt(page, 10);

  if (isNaN(limitNumber) || isNaN(pageNumber) || limitNumber <= 0 || pageNumber <= 0) {
    return res.status(400).json({ success: false, message: "Invalid pagination parameters" });
  }

  // Calculate the offset for pagination
  const offset = (pageNumber - 1) * limitNumber;

  try {
    // Query the database for transactions with the correct limit and offset
    const [assetTokens] = await db.query(
      `SELECT transaction_block, transaction_hash, transaction_amount, receiver_address, transaction_fee_token, transaction_fee_token_id 
      FROM xera_network_transactions 
      WHERE sender_address = 'TXERA Faucet'
      ORDER BY id DESC 
      LIMIT ? OFFSET ?`, 
      [limitNumber, offset]
    );

    if (!assetTokens || assetTokens.length === 0) {
      return res.status(404).json({ success: false, message: "No tokens found" });
    }

    // Calculate the total number of tokens for pagination info
    const [totalRows] = await db.query(
      `SELECT COUNT(*) AS total FROM xera_network_transactions WHERE sender_address = 'TXERA Faucet'`
    );

    const totalTokens = totalRows[0].total;
    const totalPages = Math.ceil(totalTokens / limitNumber);

    return res.status(200).json({
      success: true,
      data: assetTokens,
      pagination: {
        currentPage: pageNumber,
        totalPages,
        totalRecords: totalTokens,
        limit: limitNumber,
      }
    });
  } catch (error) {
    console.error('Database query error:', error);
    return res.status(500).json({ success: false, message: "Server error", error: error.message });
  }
});

app.post('/xera/v1/api/token/investments', async (req, res) => {
  // Validate the API key and get the decoded key
  const { apikey } = req.body;
  
  const isValid = await getDevFromCache(apikey);
  
  if (!isValid) {
    return res.status(400).json({ success: false, message: isValid });
  }
  
  const limitNumber = parseInt(apikey.limit, 10);
  const pageNumber = parseInt(apikey.page, 10);

  if (isNaN(limitNumber) || isNaN(pageNumber) || limitNumber <= 0 || pageNumber <= 0) {
    return res.status(400).json({ success: false, message: "Invalid pagination parameters" });
  }

  // Calculate the offset for pagination
  const offset = (pageNumber - 1) * limitNumber;

  try {
    // Query the database for transactions with the correct limit and offset
    const [fundings] = await db.query(
      `SELECT *
      FROM xera_user_investments 
      ORDER BY id DESC 
      LIMIT ? OFFSET ?`, 
      [limitNumber, offset]
    );

    
    if (!fundings || fundings.length === 0) {
      return res.status(404).json({ success: false, message: "No fundings found" });
    }

    const cleanFundings = fundings.map(({ id, ...clean }) => clean);
    // Calculate the total number of tokens for pagination info
    const [totalRows] = await db.query(
      `SELECT COUNT(*) AS total FROM xera_user_investments`
    );

    const totalTokens = totalRows[0].total;
    const totalPages = Math.ceil(totalTokens / limitNumber);

   

    return res.status(200).json({
      success: true,
      data: cleanFundings,
      pagination: {
        currentPage: pageNumber,
        totalPages,
        totalRecords: totalTokens,
        limit: limitNumber,
      }
    });
    
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