const express = require("express");
const bodyParser = require("body-parser");
const db = require('./connection');
const cors = require("cors");
require('dotenv').config();
const CryptoJS = require("crypto-js");
const compression = require('compression');
const NodeCache = require('node-cache');

const app = express();
const port = 5007;
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
// Fetch developer data from cache or database
const decodeKey = (encodedKey) => {
  if (!encodedKey) {
      console.error("No encoded API key provided.");
      return null;
  }

  const secret = {
      devKey: `xeraAPI-LokiNakamoto-0ea5b02a13i4bdhw94jwb`,
      webKey: `xeraAPI-webMainTexeract-egsdfw33resdfdsf`,
      apiKey: `XERA09aa939245f735992af1a9a6b6d6b91d234ee2`,
  };

  const fullSecret = secret.devKey + secret.webKey + secret.apiKey;
  if (!fullSecret) {
      console.error("Secret for decryption is missing or incomplete.");
      return null;
  }

  try {
      const bytes = CryptoJS.AES.decrypt(encodedKey, fullSecret);
      const originalKey = bytes.toString(CryptoJS.enc.Utf8);
      

      if (!originalKey) {
          console.error("Failed to decrypt API key: Decrypted key is empty.");
          return null;
      }

      return originalKey;
  } catch (error) {
      console.error("Decryption error:", error);
      return null;
  }
};

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

// Function to verify if the request is legitimate
const verifyRequestSource = (origin) => {
  const expectedOrigins = [
      "https://texeract.network",
      "http://localhost:3000",
      "http://localhost:3001",
      "https://texeract-network-beta.vercel.app",
      "https://tg-texeract-beta.vercel.app",
      "https://texeractbot.xyz",
  ];

  // Normalize `referer` to only include the origin if necessary
  if (origin.includes("://")) {
      const url = new URL(origin);
      origin = `${url.protocol}//${url.host}`;
  }

  // Check if the origin matches any allowed origins
  if (!expectedOrigins.includes(origin)) {
      console.error("Origin not allowed:", origin);
      return false;
  }

  return true;
};

const validateApiKey = async (apikey,origin) => {

  let message = "";
  if (!apikey) {
    return message = "No API key found";
  }

  const decodedKey = decodeKey(apikey);
  if (!decodedKey) {
      message = "Invalid encoded API key"
      return message
  }

  if (!verifyRequestSource(origin)) {
      message = "Unauthorized request"
      return message;
  }

  const dev = await getDevFromCache(decodedKey);
  if (!dev) {
      message = "Developer not found or unauthorized"
      return message;
  }

  return true;
};

app.post('/xera/v1/api/nft/collections', async (req, res) => {
  // Validate the API key and get the decoded key
  const { apikey } = req.body;
  const origin = req.headers.origin
  
  const isValid = await validateApiKey(apikey,origin);
  
  if (!isValid)  {
    return res.status(400).json({ success: false, message: isValid });
  }

  try {
    // Query the database for the required NFT collection details
    const [nfts] = await db.query(
      `SELECT nft_collection, COUNT(*) AS nft_count, SUM(nft_price) AS total_price, 
              SUBSTRING_INDEX(GROUP_CONCAT(DISTINCT nft_token), ',', 1) AS nft_token, 
              SUBSTRING_INDEX(GROUP_CONCAT(DISTINCT nft_token_id), ',', 1) AS nft_token_id
       FROM xera_asset_nfts 
       GROUP BY nft_collection`
    );

    if (!nfts || nfts.length === 0) {
      return res.status(404).json({ success: false, message: "No NFT collections found" });
    }

    return res.status(200).json({
      success: true,
      data: nfts
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