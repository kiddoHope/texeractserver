const express = require("express");
const bodyParser = require("body-parser");
const db = require('./connection');
const cors = require("cors");
require('dotenv').config();
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

app.post('/xera/v1/api/nft/collections', async (req, res) => {
    // Validate the API key and get the decoded key
    const { apikey } = req.body;
    
    const isValid = await getDevFromCache(apikey);
    
    if (!isValid) {
      return res.status(400).json({ success: false, message: isValid });
    }
  
    try {
      // Query the database for the required NFT collection details
      const [nfts] = await db.query(
        `SELECT nft_collections, COUNT(*) AS nft_count, SUM(nft_price) AS total_price, GROUP_CONCAT(nft_token) AS nft_tokens, GROUP_CONCAT(nft_token_id) AS nft_token_ids
        FROM xera_asset_nfts 
        GROUP BY nft_collections`
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