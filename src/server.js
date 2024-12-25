const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const compression = require('compression');
const NodeCache = require('node-cache');
const db = require('./connection');

const app = express();
const port = 5000;

app.use(compression());
app.use(bodyParser.json());

// Caching setup
const cache = new NodeCache({ stdTTL: 60, checkperiod: 120 });

// Middleware setup
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

app.post('/xera/v1/api/info/token/asset-tokens', async (req, res) => {
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
app.post('/xera/v1/api/info/node/transaction-history', async (req, res) => {
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

// Start the server
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});