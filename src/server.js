const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const compression = require('compression');
const CryptoJS = require("crypto-js");
const NodeCache = require('node-cache');
const db = require('./connection');
const { default: axios } = require("axios");

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

let conversionCache = {
  solToEthRate: null,
  lastUpdated: null
};

const fetchConversionRate = async () => {
  try {
    const response = await axios.get("https://api.coingecko.com/api/v3/simple/price?ids=solana&vs_currencies=eth");
    conversionCache.solToEthRate = response.data.solana.eth;
    conversionCache.lastUpdated = Date.now();
  } catch (error) {
    console.error('Error fetching conversion rate:', error.message);
    throw new Error("Error fetching conversion rate");
  }
};

const getConversionRate = async () => {
  const now = Date.now();
  const fiveMinutes = 5 * 60 * 1000;

  if (!conversionCache.solToEthRate || (now - conversionCache.lastUpdated) > fiveMinutes) {
    await fetchConversionRate();
  }

  return conversionCache.solToEthRate;
};
const cleanData = (data, fieldsToRemove = []) => {
  return data.map(item => {
      fieldsToRemove.forEach(field => delete item[field]);
      return item;
  });
};
app.post('/xera/v1/api/info/token/asset-tokens', async (req, res) => {
  const { apikey } = req.body;
  
  const isValid = await getDevFromCache(apikey);
  
  if (!isValid) {
    return res.status(400).json({ success: false, message: isValid });
  }
  
  try {
    const [assetTokens] = await db.query('SELECT * FROM xera_asset_token');
    const [sums] = await db.query(
      `SELECT tx_asset_id, tx_token, SUM(tx_amount) AS total_tx_amount
      FROM xera_user_investments
      WHERE tx_token IN ('SOL', 'ETH')
      GROUP BY tx_asset_id, tx_token`
    );

    const tokenPrices = {};

    if (sums.length > 0) {
      const solana = sums.filter((sum) => sum.tx_token === 'SOL');
      const solTotal = solana.reduce((acc, curr) => acc + curr.total_tx_amount, 0);
      const etherium = sums.filter((sum) => sum.tx_token === 'ETH');
      const ethTotal = etherium.reduce((acc, curr) => acc + curr.total_tx_amount, 0);

      try {
        const solToEthRate = await getConversionRate();

        // Calculate the percentage for each tx_asset_id
        sums.forEach(sum => {
          const { tx_asset_id, tx_token, total_tx_amount } = sum;
          let totalEth = 0;

          if (tx_token === 'SOL') {
            totalEth = total_tx_amount * solToEthRate;
          } else if (tx_token === 'ETH') {
            totalEth = total_tx_amount;
          }

          if (!tokenPrices[tx_asset_id]) {
            tokenPrices[tx_asset_id] = 0;
          }

          tokenPrices[tx_asset_id] += totalEth * 0.85;
        });

      } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
      }
    }

    if (assetTokens.length > 0) {
      // Map the tokenPrices to the assetTokens based on token_id
      const updatedAssetTokens = assetTokens.map(assetToken => {
        const tokenPrice = tokenPrices[assetToken.token_id] || assetToken.token_price;
        return {
          ...assetToken,
          token_price: tokenPrice
        };
      });
      const cleanedData = cleanData(updatedAssetTokens, ['id']);
      return res.status(200).json({ success: true, data: cleanedData });
    } else {
      return res.status(404).json({ success: false, message: "No tokens found" });
    }
  } catch (error) {
    console.error('Error:', error.message);
    return res.status(500).json({ success: false, message: "Server error", error: error.message });
  }
});

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

// app.post('/xera/v1/api/info/token/total-investments', async (req, res) => {
//   const { apikey } = req.body;
//   const origin = req.headers.origin
  
//   const isValid = await validateApiKey(apikey,origin);
  
//   if (!isValid)  {
//     return res.status(400).json({ success: false, message: isValid });
//   }

//   try {

//     // Calculate the sum of tx_amount and tx_dollar grouped by tx_token
//     const [sums] = await db.query(
//       `SELECT tx_token, SUM(tx_amount) AS total_tx_amount, SUM(tx_dollar) AS total_tx_dollar
//       FROM xera_user_investments
//       GROUP BY tx_token`
//     );

//     return res.status(200).json({
//       success: true,
//       tokens: sums,
//     });
    
//   } catch (error) {
//     console.error('Database query error:', error);
//     return res.status(500).json({ success: false, message: "Server error", error: error.message });
//   }
// });

// Start the server
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});