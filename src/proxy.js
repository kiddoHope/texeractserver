const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const compression = require('compression');
const CryptoJS = require("crypto-js");
const NodeCache = require('node-cache');
const db = require('./connection');
const { default: axios } = require("axios");

const app = express();
const port = 5008;
const jwtSecret = process.env.MAIN_JWT_SECRET;

// Validate required environment variables
if (!jwtSecret || !process.env.DB_HOST || !process.env.DB_USER || !process.env.DB_PASSWORD || !process.env.DB_DATABASE) {
    console.error("Missing required environment variables. Please check your .env file.");
    process.exit(1);
}

app.use(compression());
app.use(bodyParser.json());

// Caching setup
const cache = new NodeCache({ stdTTL: 60, checkperiod: 120 });

// Middleware setup
app.use(compression());
app.use(bodyParser.json());

const xeraBaseAPI = "https://texeract.network/xera/v1/api";

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

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) {
        return res.status(401).json({ success: false, message: "Authentication token is required" });
    }

    jwt.verify(token, jwtSecret, (err, decoded) => {
        if (err) {
            const errorMessage = err.name === "TokenExpiredError" ? "Token has expired" : "Invalid token";
            return res.status(403).json({ success: false, message: errorMessage });
        }
        req.user = decoded;
        next();
    });
};

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

const cleanData = (data, fieldsToRemove = []) => {
  return data.map(item => {
      fieldsToRemove.forEach(field => delete item[field]);
      return item;
  });
};

app.post('/xera/v1/api/public', async (req, res) => {
    const { apikey } = req.body;
    const origin = req.headers.origin
    
    const isValid = await validateApiKey(apikey,origin);

    if (!isValid)  {
        return res.status(400).json({ success: false, message: isValid });
    }
      
    const decodekey = decodeKey(apikey);
    
  try {

    const allWallet = await axios.post(`${xeraBaseAPI}/users/all-wallet`, {
        apikey: decodekey,
    })

    const assetToken  = await axios.post(`${xeraBaseAPI}/info/token/asset-tokens`, {
        apikey: decodekey,
    })

    const nftBanners  = await axios.post(`${xeraBaseAPI}/marketplace/banners`, {
        apikey: decodekey,
    })

    const nftFeatured  = await axios.post(`${xeraBaseAPI}/marketplace/featured`, {
        apikey: decodekey,
    })

    const collections  = await axios.post(`${xeraBaseAPI}/nft/collections`, {
      apikey: apikey,
    })

    const allData = {
        allWallet: allWallet.data || {},
        assetToken: assetToken.data || {},
        nftBanners: nftBanners.data || {},
        nftFeatured: nftFeatured.data || {},
        collections: collections.data || {},
    };

    const stringify = JSON.stringify(allData);
    const encryptedKey = CryptoJS.AES.encrypt(stringify, process.env.MAIN_JWT_SECRET).toString();
    
    return res.status(200).json({ success: true, data: encryptedKey });
  } catch (error) {
      return res.status(500).json({ success: false, message: "Request error", error: error.message });
  }
});

app.post('/xera/v1/api/public/airdrop', async (req, res) => {
  const { apikey } = req.body;
  const origin = req.headers.origin
  
  const isValid = await validateApiKey(apikey,origin);

  if (!isValid)  {
      return res.status(400).json({ success: false, message: isValid });
  }
    
  const decodekey = decodeKey(apikey);
  
try {
  const totalPointsP1  = await axios.post(`${xeraBaseAPI}/users/total-points/phase1`, {
    apikey: apikey,
  })

  const totalPointsP2  = await axios.post(`${xeraBaseAPI}/users/total-points/phase2`, {
    apikey: apikey,

  })
  
  const totalPointsP3  = await axios.post(`${xeraBaseAPI}/users/total-points/phase3`, {
    apikey: apikey,
  })

  const allData = {
      totalPointsP1: totalPointsP1.data || {},
      totalPointsP2: totalPointsP2.data || {},
      totalPointsP3: totalPointsP3.data || {},
  };

  const stringify = JSON.stringify(allData);
  const encryptedKey = CryptoJS.AES.encrypt(stringify, process.env.MAIN_JWT_SECRET).toString();
  
  return res.status(200).json({ success: true, data: encryptedKey });
} catch (error) {
    return res.status(500).json({ success: false, message: "Request error", error: error.message });
}
});

app.post('/xera/v1/api/public/user', authenticateToken, async (req, res) => {
  const { user } = req.body;

  if (!user) {
    return res.status(400).json({ success: false, message: "No user provided" });
  }
  
  const headers = { Authorization: `Bearer ${user.header}` };

try {

  const [security, lastTransactions, transactions, followers, balance, onstake, nodes, nfts, allTask, rankP1, rankP2] = await Promise.all([
    axios.post(`${xeraBaseAPI}/user/security`, {user: user.address}, { headers }),
    axios.post(`${xeraBaseAPI}/user/last-transaction`, {user: user.address}, { headers }),
    axios.post(`${xeraBaseAPI}/user/transactions`, {user: user.address}, { headers }),
    axios.post(`${xeraBaseAPI}/user/following`, {user: user.username}, { headers }),
    axios.post(`${xeraBaseAPI}/user/mainnet/balance`, {user: user.address}, { headers }),
    axios.post(`${xeraBaseAPI}/user/onstake/nft`, {user: user.address}, { headers }),
    axios.post(`${xeraBaseAPI}/user/nodes`, {user: user.address}, { headers }),
    axios.post(`${xeraBaseAPI}/user/nfts`, {user: user.address}, { headers }),
    axios.post(`${xeraBaseAPI}/user/tasks/all-task`, {user: user.username}, { headers }),
    axios.post(`${xeraBaseAPI}/user/rank-phase1`, {user: user.username}, { headers }),
    axios.post(`${xeraBaseAPI}/user/rank-phase2`, {user: user.username}, { headers }),
]);
  
  const allData = {
      security: security.data || {},
      lastTransactions: lastTransactions.data || {},
      transactions: transactions.data || {},
      followers: followers.data || {},
      balance: balance.data || {},
      onstake: onstake.data || {},
      nodes: nodes.data || {},
      nfts: nfts.data || {},
      allTask: allTask.data || {},
      rankP1: rankP1.data || {},
      rankP2: rankP2.data || {}
  };
  
  const stringify = JSON.stringify(allData);
  const encryptedKey = CryptoJS.AES.encrypt(stringify, process.env.MAIN_JWT_SECRET).toString();

  return res.status(200).json({ success: true, data: encryptedKey });
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