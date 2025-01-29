const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const db = require('./connection');
const cors = require("cors");
const compression = require("compression");
const NodeCache = require("node-cache");
const bcrypt = require("bcrypt");
const e = require("express");
const path = require('path');
const multer = require('multer');
const { default: axios } = require("axios");
require("dotenv").config();

const app = express();
const port = 5001;
const jwtSecret = process.env.MAIN_JWT_SECRET;

// Validate required environment variables
if (!jwtSecret || !process.env.DB_HOST || !process.env.DB_USER || !process.env.DB_PASSWORD || !process.env.DB_DATABASE) {
    console.error("Missing required environment variables. Please check your .env file.");
    process.exit(1);
}

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

// Authentication middleware
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
// Cache helper function
const getUserFromCache = async (username) => {
    try {
        let user = cache.get(username);
        if (!user) {
            const [dbUser] = await db.query("SELECT * FROM xera_user_accounts WHERE BINARY username = ?", [username]);
            if (dbUser.length > 0) {
                user = dbUser[0];
                cache.set(username, user);
            }
        }
        return user;
    } catch (error) {
        console.error("Error fetching user:", error.message);
        return null;
    }
};

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

// app.post("/xera/v1/api/generate/access-token", async (req,res) => {
//     const {apikey} = req.body;
    
//     if (!apikey) {
//         return res.json({ success: false, message: "API key is required" });
//     }

//     try {
//         const [apikeyCheck] = await db.query("SELECT * FROM xera_developer WHERE BINARY xera_api = ?", [apikey]);
//         if (apikeyCheck.length > 0) {
//             const xera_wallet = apikeyCheck[0].xera_wallet
//             const authToken = jwt.sign({ xera_wallet }, jwtAPISecret, { expiresIn: "1d" });
//             return res.json({ success: true, accessToken: authToken})
//         } else {
//             return res.json({ success: false, message: "Invalid api key"})
//         }
//     } catch (error) {
//         return res.json({ success: false, message: "request error"})
//     }
// })

// Helper function to generate JWT token
const generateAuthToken = async (username, publicKey) => {
    const user = await getUserFromCache(username);
    const xeraJWT = {
        loginState: "basic",
        isloggedIn: "true",
        myXeraUsername: username,
        myXeraAddress: publicKey,
        myXeraDisplay: user.display
    };
    
    return jwt.sign({ xeraJWT }, jwtSecret, { expiresIn: "1d" });
};

// Helper function to handle user login and token generation
const handleUserLogin = async (user, password, res) => {
    const dataPass = user.password;
    
    // Check and normalize password hash if needed
    if (dataPass.slice(0, 4) === "$2y$") {
        const normalizedHash = dataPass.replace("$2y$", "$2a$");
        if (await bcrypt.compare(password, normalizedHash)) {
            const authToken = await generateAuthToken(user.username, user.xera_wallet);
            return res.json({ success: true, message: `${user.username} Successfully Login`, authToken });
        } else {
            return res.json({ success: false, message: 'Wrong password' });
        }
    } else {
        if (await bcrypt.compare(password, dataPass)) {
            const authToken = await generateAuthToken(user.username, user.xera_wallet);
            return res.json({ success: true, message: `${user.username} Successfully Login Basic Account`, authToken });
        } else {
            return res.json({ success: false, message: 'Wrong password' });
        }
    }
};

// Route to check username availability
app.post("/xera/v1/api/user/check-username", async (req, res) => {
    const { username } = req.body;

    if (!username) {
        return res.json({ success: false, message: "Please complete all the fields" });
    }

    try {
        const user = await getUserFromCache(username);
        if (user) {
            return res.json({ success: false, message: 'Username already exists' });
        } else {
            return res.json({ success: true, message: 'Username is available' });
        }
    } catch (error) {
        return res.json({ success: false, message: 'Request error' });
    }
});

// Route for basic login using username and password
app.post('/xera/v1/api/user/login-basic', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.json({ success: false, message: "Request Error. Input Field missing" });
    }

    try {
        const userData = await getUserFromCache(username);
        
        if (userData) {
            await handleUserLogin(userData, password, res);
        } else {
            return res.json({ success: false, message: "No user found" });
        }
    } catch (error) {
        return res.json({ success: false, message: "Request error" });
    }
});

// Route for login using private key
app.post('/xera/v1/api/user/login-prKey', async (req, res) => {
    const { privateKey } = req.body;
    if (!privateKey) {
        return res.json({ success: false, message: "Request Error. No private key received" });
    }

    try {
        const [user] = await db.query("SELECT * FROM xera_user_wallet WHERE BINARY private_key = ?", [privateKey]);

        if (user.length > 0) {
            const userData = user[0];
            const [getUsername] = await db.query("SELECT * FROM xera_user_accounts WHERE BINARY xera_wallet = ?", [userData.public_key]);
            
            if (getUsername.length > 0) {
                const username = getUsername[0].username;
                const authToken = await generateAuthToken(username, userData.public_key);
                return res.json({ success: true, message: `${username} Successfully Login Full Access`, authToken });
            } else {
                return res.json({ success: false, message: "No user found for that key phrase" });
            }
        } else {
            return res.json({ success: false, message: "Invalid key phrase" });
        }
    } catch (error) {
        return res.json({ success: false, message: "Request error", error });
    }
});

// Route for login using seed phrase
app.post('/xera/v1/api/user/login-phrase', async (req, res) => {
    const { seedPhrase } = req.body;

    if (!seedPhrase) {
        return res.json({ success: false, message: "Request Error. No seed phrase received" });
    }

    const seed = JSON.parse(seedPhrase);

    try {
        const sqlPhrase = "SELECT * FROM xera_user_wallet WHERE BINARY word1 = ? AND word2 = ? AND word3 = ? AND word4 = ? AND word5 = ? AND word6 = ? AND word7 = ? AND word8 = ? AND word9 = ? AND word10 = ? AND word11 = ? AND word12 = ?";
        const [user] = await db.query(sqlPhrase, [
            seed.seedWord1, seed.seedWord2, seed.seedWord3, seed.seedWord4, seed.seedWord5, seed.seedWord6,
            seed.seedWord7, seed.seedWord8, seed.seedWord9, seed.seedWord10, seed.seedWord11, seed.seedWord12
        ]);

        if (user.length > 0) {
            const userData = user[0];
            const [getUsername] = await db.query("SELECT * FROM xera_user_accounts WHERE BINARY xera_wallet = ?", [userData.public_key]);

            if (getUsername.length > 0) {
                const username = getUsername[0].username;
                const authToken = await generateAuthToken(username, userData.public_key);
                return res.json({ success: true, message: `${username} Successfully Login Full Access`, authToken });
            } else {
                return res.json({ success: false, message: "No user found for that key phrase" });
            }
        } else {
            return res.json({ success: false, message: "No user found for that key phrase" });
        }
    } catch (error) {
        return res.json({ success: false, message: "Request error" });
    }
});

app.post('/xera/v1/api/user/tasks/all-task', authenticateToken, async (req, res) => {
    const { user } = req.body;

    if (!user) {
        return res.json({ success: false, message: "invalid request" });
    }

    try {
        // Fetch user transactions and wallet information
        const [transactions] = await db.query('SELECT * FROM xera_user_tasks WHERE BINARY username = ?', [user]);
        const [connectedWallet] = await db.query('SELECT * FROM xera_user_accounts WHERE BINARY username = ?', [user]);

        if (transactions && transactions.length > 0) {
            const alltask = {};

            // Task types and their corresponding names in the database
            const taskTypes = [
                "Telegram Task", "Twitter Task", "Wallet Connect Task", 
                "Subscribe - @MikeTamago", "Subscribe - @ALROCK", 
                "Follow - @BRGYTamago", "Follow - @ALrOck14",
                "Subscribe - @CrypDropPh", "Subscribe - @kimporsha11", 
                "Facebook Task", "Telegram 2 Task", "TikTok Task", 
                "Bluesky Task", "YouTube Task", "TXERA Claim Task", "Soldi Task",
                "StealthAI Task", "Validium Task" ,"IQwiki Task", "Cryptify Task"
            ];

            // Iterate through each task type and filter the transactions
            taskTypes.forEach(task => {
                const filteredTasks = transactions.filter(data => data.xera_task === task);
                if (filteredTasks.length > 0) {
                    // Use the task name as the key in the alltask object, assigning the status of the last task completed
                    alltask[task.replace(/[^a-zA-Z0-9]/g, '').toLowerCase()] = filteredTasks.reduce((latest, current) => {
                        return new Date(current.xera_completed_date) > new Date(latest.xera_completed_date) ? current : latest;
                    }).xera_status;
                }
            });

            // Check if the user has connected wallets
            if (connectedWallet && connectedWallet.length > 0) {
                const ethWallet = connectedWallet[0].eth_wallet;
                const solWallet = connectedWallet[0].sol_wallet;

                if (ethWallet) alltask.ethWallet = "true";
                if (solWallet) alltask.solWallet = "true";
            }

            // If TXERA claim task exists, include its completion date
            const filterTXERA = transactions.filter(data => data.xera_task === "TXERA Claim Task");
            if (filterTXERA.length > 0) {
                alltask.claimData = filterTXERA[0].xera_completed_date;
            }

            return res.json({ success: true, data: alltask });
        } else {
            return res.json({ success: false, message: "no transaction found" });
        }
    } catch (error) {
        return res.json({ success: false, message: "request error", error: error });
    }
});

async function getUserRank(user, startDate, endDate) {
    const [userRanking] = await db.query(`
        SELECT MAX(username) AS username, MAX(xera_wallet) AS xera_wallet, 
               SUM(CAST(xera_points AS DECIMAL(10))) AS total_points,
               SUM(CASE WHEN xera_task = 'Referral Task' THEN 1 ELSE 0 END) AS referral_task_count
        FROM xera_user_tasks
        WHERE DATE(xera_completed_date) BETWEEN ? AND ?
        GROUP BY BINARY username
        ORDER BY total_points DESC
    `, [startDate, endDate]);
    
    const userRank = userRanking.findIndex(rankUser => rankUser.username === user) + 1;
    const userTotalPoints = userRanking.find(rankUser => rankUser.username === user)?.total_points;
    
    if (userRank > 0 && userTotalPoints) {
        return { success: true, rank: userRank, totalPoints: userTotalPoints };
    } else {
        return { success: false, message: "User not found" };
    }
}

app.post('/xera/v1/api/user/rank-phase1', authenticateToken, async (req, res) => {
    const { user } = req.body;
    if (!user) return res.json({ success: false, message: "Invalid request" });

    try {
        const result = await getUserRank(user, '2024-09-28', '2024-12-18');
        return res.json(result);
    } catch (error) {
        return res.json({ success: false, message: "Request error", error: error.message });
    }
});

app.post('/xera/v1/api/user/rank-phase2', authenticateToken, async (req, res) => {
    const { user } = req.body;
    if (!user) return res.json({ success: false, message: "Invalid request" });

    try {
        const result = await getUserRank(user, '2024-12-19', '2025-02-25');
        return res.json(result);
    } catch (error) {
        return res.json({ success: false, message: "Request error", error: error.message });
    }
});

// app.post('/xera/v1/api/user/rank-phase3', authenticateToken, async (req, res) => {

//     const { user } = req.body;
//     if (!user) return res.json({ success: false, message: "Invalid request" });

//     try {
//         const result = await getUserRank(user, '2025-02-25', '2025-05-30');
//         return res.json(result);
//     } catch (error) {
//         return res.json({ success: false, message: "Request error", error: error.message });
//     }
// });

// Helper function for cleaning response data
const cleanData = (data, fieldsToRemove = []) => {
    return data.map(item => {
        fieldsToRemove.forEach(field => delete item[field]);
        return item;
    });
};

// Endpoint for fetching transactions
app.post('/xera/v1/api/user/transactions', authenticateToken, async (req, res) => {
    const { user, page = 1, limit = 50 } = req.body;
    if (!user) {
        return res.json({ success: false, message: "Invalid request" });
    }

    try {
        const offset = (page - 1) * limit;
        const [transactions] = await db.query(
            'SELECT * FROM xera_network_transactions WHERE receiver_address = ? OR sender_address = ? ORDER BY transaction_date DESC LIMIT ? OFFSET ?',
            [user, user, limit, offset]
        );

        if (transactions.length > 0) {
            const cleanedData = cleanData(transactions, ['id', 'transaction_origin', 'transaction_token_id', 'transaction_validator', 'transaction_date']);
            return res.json({ success: true, data: cleanedData });
        } else {
            return res.json({ success: false, message: "No transactions found" });
        }
    } catch (error) {
        return res.json({ success: false, message: "Request error", error });
    }
});

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

const fetchTotalBalanceTokens = async () => {
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

            return updatedAssetTokens;
        } else {
            return "No tokens found"
        }
        } catch (error) {
            return "Server error"
        }
}

// Endpoint for fetching user balances
app.post('/xera/v1/api/user/balance', authenticateToken, async (req, res) => {
    const { user } = req.body;
    if (!user) {
        return res.json({ success: false, message: "Invalid request" });
    }
    const assetTokens = await fetchTotalBalanceTokens();

    try {
        // Fetch user transactions and token list in parallel
        const [transactions] = await db.query('SELECT * FROM xera_network_transactions WHERE receiver_address = ? OR sender_address = ?', [user, user]);

        if (assetTokens.length > 0) {
            const balances = assetTokens.map(token => {
                const { token_id } = token;

                // Calculate total sent and received for each token
                const totalSend = transactions
                    .filter(tx => tx.transaction_token_id === token_id && tx.sender_address === user)
                    .reduce((total, tx) => total + parseFloat(tx.transaction_amount), 0);

                const totalReceive = transactions
                    .filter(tx => tx.transaction_token_id === token_id && tx.receiver_address === user)
                    .reduce((total, tx) => total + parseFloat(tx.transaction_amount), 0);

                const totalBalance = (totalReceive - totalSend).toFixed(2);
                const totalBalanceETH = (token.token_price/token.token_supply)*totalBalance;
                

                return { ...token, totalBalance, totalBalanceETH };
            });

            // Clean the data to exclude unnecessary fields
            const cleanedData = cleanData(balances, ['id', 'token_owner', 'token_symbol', 'token_decimal', 'token_supply', 'token_circulating', 'token_info', 'token_on_treasury', 'token_is_claimable', 'token_on_locked', 'token_created', 'token_price']);
            return res.json({ success: true, data: cleanedData });
        } else {
            return res.json({ success: false, message: "No tokens found" });
        }
    } catch (error) {
        return res.json({ success: false, message: "Request error", error });
    }
});

app.post('/xera/v1/api/user/mainnet/balance', authenticateToken, async (req, res) => {
    const { user } = req.body;
    if (!user) {
        return res.json({ success: false, message: "Invalid request" });
    }
    const assetTokens = await fetchTotalBalanceTokens();

    try {
        // Fetch user transactions and token list in parallel
        const [transactions] = await db.query('SELECT * FROM xera_mainnet_transactions WHERE receiver_address = ? OR sender_address = ?', [user, user]);

        if (assetTokens.length > 0) {
            const balances = assetTokens.map(token => {
                const { token_id } = token;

                // Calculate total sent and received for each token
                const totalSend = transactions
                    .filter(tx => tx.transaction_token_id === token_id && tx.sender_address === user)
                    .reduce((total, tx) => total + parseFloat(tx.transaction_amount), 0);

                const totalReceive = transactions
                    .filter(tx => tx.transaction_token_id === token_id && tx.receiver_address === user)
                    .reduce((total, tx) => total + parseFloat(tx.transaction_amount), 0);

                const totalBalance = (totalReceive - totalSend).toFixed(2);
                const totalBalanceETH = (token.token_price/token.token_supply)*totalBalance;
                

                return { ...token, totalBalance, totalBalanceETH };
            });

            // Clean the data to exclude unnecessary fields
            const cleanedData = cleanData(balances, ['id', 'token_owner', 'token_holder', 'token_max_supply', 'token_on_contract', 'token_on_contract_id', 'token_on_owner','token_decimal', 'token_supply', 'token_circulating', 'token_info', 'token_on_treasury', 'token_is_claimable', 'token_on_locked', 'token_created', 'token_price']);
            return res.json({ success: true, data: cleanedData });
        } else {
            return res.json({ success: false, message: "No tokens found" });
        }
    } catch (error) {
        return res.json({ success: false, message: "Request error", error });
    }
});

// Endpoint for fetching user's following list
app.post('/xera/v1/api/user/following', authenticateToken, async (req, res) => {
    const { user } = req.body;
    if (!user) {
        return res.json({ success: false, message: "Invalid request" });
    }

    try {
        const [userFollower] = await db.query(`
            SELECT *
            FROM xera_user_tasks
            WHERE xera_task = 'Referral Task' AND username = ?
        `,[user]);

        if (userFollower.length > 0) {
            // const cleanedData = cleanData(userFollower, ['id']);
            return res.json({ success: true, data: userFollower.length });
        } else {
            return res.json({ success: false, message: "No followers found" });
        }
    } catch (error) {
        return res.json({ success: false, message: "Request error", error });
    }
});

app.post('/xera/v1/api/user/faucet-claim', authenticateToken, async (req, res) => {
    const { data } = req.body;
    const decodedFormRequestTXERADetails = Buffer.from(data, 'base64').toString('utf-8');

    const formRequestTXERADetails = JSON.parse(decodedFormRequestTXERADetails);
    
    const apikey = formRequestTXERADetails.apiKey;
    const origin = req.headers.origin
    
    const isValid = await validateApiKey(apikey,origin);
    
    if (!isValid)  {
        return res.status(400).json({ success: false, message: isValid });
    }

    const { username, txHash, sender, receiver, command, amount, token, tokenId } = formRequestTXERADetails;
    // Validate request body
    if (![username, txHash, sender, receiver, command, amount, token, tokenId].every(Boolean)) {
        return res.status(400).json({ success: false, message: 'Incomplete transaction data.' });
    }
    
    const txLocalDate = new Date().toISOString().slice(0, 19).replace('T', ' ');

    try {
        // Check for recent transactions
        const [[lastTransaction]] = await db.query(
            'SELECT transaction_date, transaction_hash FROM xera_network_transactions WHERE receiver_address = ? AND sender_address = ? ORDER BY transaction_date DESC LIMIT 1',
            [receiver,sender]
        );

        let transactionOrigin = 'Genesis Transaction';
        if (lastTransaction) {
            const lastTxDate = new Date(lastTransaction.transaction_date).getTime();
            const timeDiff = Date.now() - lastTxDate;

            if (timeDiff < 21600000) { // 6 hours in milliseconds
                const timeRemainingMs = 21600000 - timeDiff;
                const hours = Math.floor(timeRemainingMs / 3600000);
                const minutes = Math.floor((timeRemainingMs % 3600000) / 60000);
                const seconds = Math.floor((timeRemainingMs % 60000) / 1000);
                return res.status(429).json({
                    success: false,
                    message: `Claim again after ${hours}h ${minutes}m ${seconds}s`,
                });
            }

            transactionOrigin = lastTransaction.transaction_hash;
        }

        // Retrieve the latest block details
        const [[blockData]] = await db.query(
            'SELECT current_block, block_validator FROM xera_network_blocks ORDER BY id DESC LIMIT 1'
        );

        if (!blockData) {
            return res.status(500).json({ success: false, message: 'Block data not found. Transaction aborted.' });
        }

        const { current_block: txBlock, block_validator: validator } = blockData;

        // Increment block transaction count
        const [incrementBlockResult] = await db.query(
            'UPDATE xera_network_blocks SET block_transactions = block_transactions + 1 WHERE current_block = ?',
            [txBlock]
        );

        if (incrementBlockResult.affectedRows === 0) {
            return res.status(500).json({ success: false, message: 'Error incrementing block count' });
        }

        // Add new transaction
        const [addTransactionResult] = await db.query(
            `INSERT INTO xera_network_transactions 
            (transaction_block, transaction_origin, transaction_hash, sender_address, receiver_address, transaction_command, transaction_amount, transaction_token, transaction_token_id, transaction_validator, transaction_date, transaction_fee_amount, transaction_fee_token, transaction_fee_token_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [txBlock, transactionOrigin, txHash, sender, receiver, command, amount, token, tokenId, validator, txLocalDate, 0.00, '', '']
        );

        if (addTransactionResult.affectedRows === 0) {
            return res.status(500).json({ success: false, message: 'Error adding transaction' });
        }

        // Update token circulation
        const [[currentToken]] = await db.query(
            'SELECT token_circulating FROM xera_asset_token WHERE token_symbol = ?',
            [token]
        );

        if (!currentToken) {
            return res.status(404).json({ success: false, message: 'Token not found or mismatched token symbol.' });
        }

        const newCirculating = parseInt(currentToken.token_circulating, 10) + parseInt(amount, 10);

        const [updateTokenResult] = await db.query(
            'UPDATE xera_asset_token SET token_circulating = ? WHERE token_id = ?',
            [newCirculating, tokenId]
        );

        if (updateTokenResult.affectedRows === 0) {
            return res.status(500).json({ success: false, message: 'Error updating token circulation' });
        }

        // Record task completion
        const [recordTaskResult] = await db.query(
            `INSERT INTO xera_user_tasks 
            (username, xera_wallet, xera_task, xera_status, xera_points, xera_telegram_id, xera_twitter_username)
            VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [username, receiver, 'TXERA Claim Task', 'ok', '1250', '', '']
        );

        if (recordTaskResult.affectedRows === 0) {
            return res.status(500).json({ success: false, message: 'Error inserting record' });
        }

        // All operations succeeded
        return res.status(200).json({ success: true, message: '1 TXERA Claimed Successfully.' });
    } catch (error) {
        console.error('Transaction Error:', error.message);
        return res.status(500).json({ success: false, message: 'Internal Server Error' });
    }
});

// Coin Claim Endpoint
app.post('/xera/v1/api/user/coin/claim', authenticateToken, async (req, res) => {
    const { data } = req.body;
    const decodedFormRequestTXERADetails = Buffer.from(data, 'base64').toString('utf-8');

    const formRequestTXERADetails = JSON.parse(decodedFormRequestTXERADetails);
    
    const apikey = formRequestTXERADetails.apiKey;
    const origin = req.headers.origin
    
    const isValid = await validateApiKey(apikey,origin);
    
    if (!isValid)  {
        return res.status(400).json({ success: false, message: isValid });
    }

    const { username, txHash, sender, receiver, command, amount, token, tokenId } = formRequestTXERADetails;

    // Validate request body
    if (![username, txHash, sender, receiver, command, amount, token, tokenId].every(Boolean)) {
        return res.status(400).json({ success: false, message: 'Incomplete transaction data.' });
    }

    const txLocalDate = new Date().toISOString().slice(0, 19).replace('T', ' ');

    try {
        // Check for recent transactions
        const [[lastTransaction]] = await db.query(
            'SELECT transaction_date, transaction_hash FROM xera_network_transactions WHERE receiver_address = ? ORDER BY transaction_date DESC LIMIT 1',
            [receiver]
        );

        let transactionOrigin = 'Genesis Transaction';
        if (lastTransaction) {
            transactionOrigin = lastTransaction.transaction_hash;

            // Ensure the sender hasn't already claimed coins
            const [tokenClaimedCheck] = await db.query(
                'SELECT * FROM xera_network_transactions WHERE sender_address = ? AND receiver_address = ?',
                [sender, receiver]
            );

            if (tokenClaimedCheck.length > 0) {
                return res.status(429).json({ success: false, message: 'Xera Coin already claimed.' });
            }
        }

        // Retrieve the latest block details
        const [[blockData]] = await db.query(
            'SELECT current_block, block_validator FROM xera_network_blocks ORDER BY id DESC LIMIT 1'
        );

        if (!blockData) {
            return res.status(500).json({ success: false, message: 'Block data not found. Transaction aborted.' });
        }

        const { current_block: txBlock, block_validator: validator } = blockData;

        // Increment block transaction count
        const [incrementBlockResult] = await db.query(
            'UPDATE xera_network_blocks SET block_transactions = block_transactions + 1 WHERE current_block = ?',
            [txBlock]
        );

        if (incrementBlockResult.affectedRows === 0) {
            return res.status(500).json({ success: false, message: 'Error incrementing block count.' });
        }

        // Add new transaction
        const [addTransactionResult] = await db.query(
            `INSERT INTO xera_network_transactions 
            (transaction_block, transaction_origin, transaction_hash, sender_address, receiver_address, transaction_command, transaction_amount, transaction_token, transaction_token_id, transaction_validator, transaction_date, transaction_fee_amount, transaction_fee_token, transaction_fee_token_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [txBlock, transactionOrigin, txHash, sender, receiver, command, amount, token, tokenId, validator, txLocalDate, 0.00, '', '']
        );

        if (addTransactionResult.affectedRows === 0) {
            return res.status(500).json({ success: false, message: 'Error adding transaction.' });
        }

        // Update token circulation
        const [[currentToken]] = await db.query(
            'SELECT token_circulating FROM xera_asset_token WHERE token_symbol = ?',
            [token]
        );

        if (!currentToken) {
            return res.status(404).json({ success: false, message: 'Token not found or mismatched token symbol.' });
        }

        const newCirculating = parseFloat(currentToken.token_circulating) + parseFloat(amount);

        const [updateTokenResult] = await db.query(
            'UPDATE xera_asset_token SET token_circulating = ? WHERE token_id = ?',
            [newCirculating.toFixed(8), tokenId]
        );

        if (updateTokenResult.affectedRows === 0) {
            return res.status(500).json({ success: false, message: 'Error updating token circulation.' });
        }

        // All operations succeeded
        return res.status(200).json({ success: true, message: 'Coin Claimed Successfully.' });
    } catch (error) {
        console.error('Transaction Error:', error.message);
        return res.status(500).json({ success: false, message: 'Internal Server Error.' });
    }
});

// Nodes Retrieval Endpoint
app.post('/xera/v1/api/user/nodes', authenticateToken, async (req, res) => {
    const { user } = req.body;

    if (!user) {
        return res.json({ success: false, message: 'No address provided' });
    }

    try {
        // Step 1: Retrieve user node details
        const [getUserNode] = await db.query('SELECT * FROM xera_asset_nodes WHERE node_owner = ?', [user]);

        if (getUserNode.length > 0) {
            const cleanNodeData = getUserNode.map(({ id, ...node }) => node);
            return res.json({ success: true, message: `Successfully retrieved node. Wallet: ${user}`, node: cleanNodeData });
        } else {
            return res.json({ success: false, message: 'No node found for the provided address' });
        }
    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
});

// Security Information Endpoint
app.post('/xera/v1/api/user/security', authenticateToken, async (req, res) => {
    const { user } = req.body;

    if (!user) {
        return res.json({ success: false, message: 'No address provided' });
    }

    try {
        // Retrieve user security data from the database
        const [getUserSecurity] = await db.query('SELECT * FROM xera_user_security WHERE xera_wallet = ?', [user]);
        
        if (getUserSecurity.length > 0) {
            // Clean response by removing sensitive data like id, ip_address, etc.
            const cleanSecurityData = getUserSecurity.map(({ id, ip_address, date_verified, ...clean }) => clean);
            return res.json({ success: true, message: `Successfully retrieved security. Wallet: ${user}`, security: cleanSecurityData });
        } else {
            return res.json({ success: false, message: "No security data found" });
        }
    } catch (error) {
        return res.json({ success: false, message: 'Error retrieving security data', error: error.message });
    }
});

// Telegram Task Endpoint
app.post('/xera/v1/api/user/task/telegram', authenticateToken, async (req, res) => {
    const { data } = req.body;
    const decodedFormRequestTXERADetails = Buffer.from(data, 'base64').toString('utf-8');

    const formRequestTXERADetails = JSON.parse(decodedFormRequestTXERADetails);

    const telegramID = formRequestTXERADetails.telegramID;
    const username = formRequestTXERADetails.username;
    const wallet = formRequestTXERADetails.wallet;
    const xeraStatus = 'ok';
    const xeraTask = 'Telegram Task';
    const xeraPoints = '10000';

    if (!telegramID || !username || !wallet || !formRequestTXERADetails) {
        return res.json({ success: false, message: 'Incomplete data' });
    }

    try {
        // Check if the task combination already exists
        const [duplicateCheck] = await db.query(`
            SELECT * 
            FROM xera_user_tasks 
            WHERE username = ? 
              AND xera_wallet = ? 
              AND xera_task = ?
        `, [username, wallet, xeraTask]);

        if (duplicateCheck.length > 0) {
            return res.json({ success: false, message: 'You have already completed this task' });
        }

        // Check if the Telegram ID already exists
        const [telegramCheck] = await db.query(`
            SELECT * 
            FROM xera_user_tasks 
            WHERE xera_telegram_id = ?
        `, [telegramID]);

        if (telegramCheck.length > 0) {
            return res.json({ success: false, message: 'Telegram ID already exists' });
        }

        // Insert the task into the database
        if (telegramID) {
            await db.query(`
                INSERT INTO xera_user_tasks (username, xera_wallet, xera_telegram_id, xera_twitter_username, xera_task, xera_status, xera_points) 
                VALUES (?, ?, ?, ?, ?, ?, ?)
            `, [username, wallet, telegramID, '', xeraTask, xeraStatus, xeraPoints]);
        }

        res.json({ success: true, message: 'Telegram user successfully verified' });
    } catch (error) {
        res.json({ success: false, message: 'Request error', error: error.message });
    }
});

// Twitter Task Endpoint
app.post('/xera/v1/api/user/task/twitter', authenticateToken, async (req, res) => {
    const { data } = req.body;
    const decodedFormRequestTXERADetails = Buffer.from(data, 'base64').toString('utf-8');

    const formRequestTXERADetails = JSON.parse(decodedFormRequestTXERADetails);

    if (!formRequestTXERADetails || !formRequestTXERADetails.username || !formRequestTXERADetails.wallet) {
        return res.json({ success: false, message: 'Incomplete data' });
    }

    const twitterUsername = formRequestTXERADetails.twitterUsername;
    const username = formRequestTXERADetails.username;
    const wallet = formRequestTXERADetails.wallet;
    const xeraStatus = 'pending';
    const xeraTask = 'Twitter Task';

    try {
        // Check if the task combination already exists
        const [duplicateCheck] = await db.query(`
            SELECT * 
            FROM xera_user_tasks 
            WHERE username = ? 
              AND xera_wallet = ? 
              AND xera_task = ?
        `, [username, wallet, xeraTask]);

        if (duplicateCheck.length > 0) {
            return res.json({ success: false, message: 'You have already completed this task' });
        }

        // Check if the Twitter username already exists
        const [twitterCheck] = await db.query(`
            SELECT * 
            FROM xera_user_tasks 
            WHERE xera_twitter_username = ?
        `, [twitterUsername]);

        if (twitterCheck.length > 0) {
            return res.json({ success: false, message: 'Twitter username already exists' });
        }

        // Insert the task into the database
        if (twitterUsername) {
            await db.query(`
                INSERT INTO xera_user_tasks (username, xera_wallet, xera_telegram_id, xera_twitter_username, xera_task, xera_status, xera_points) 
                VALUES (?, ?, ?, ?, ?, ?, ?)
            `, [username, wallet, '', twitterUsername, xeraTask, xeraStatus, '']);
        }

        res.json({ success: true, message: 'Twitter user successfully verified' });
    } catch (error) {
        res.json({ success: false, message: 'Request error', error: error.message });
    }
});

app.post('/xera/v1/api/user/task/social', authenticateToken, async (req, res) => {
    const { data } = req.body;
    
    const decodedFormRequestTXERADetails = Buffer.from(data, 'base64').toString('utf-8');

    const formRequestTXERADetails = JSON.parse(decodedFormRequestTXERADetails);
    
    if (!formRequestTXERADetails || !formRequestTXERADetails.username || !formRequestTXERADetails.wallet) {
        return res.status(400).json({ success: false, message: 'Incomplete data' });
    }

    const taskTitle = formRequestTXERADetails.taskTitle;
    const username = formRequestTXERADetails.username;
    const wallet = formRequestTXERADetails.wallet;
    const xeraStatus = 'ok';
    const xeraPoints = '1250';

    try {
        // Check if the task already exists
        const [checkResult] = await db.query(`
            SELECT COUNT(*) 
            FROM xera_user_tasks 
            WHERE xera_task = ? AND username = ? AND xera_wallet = ?
        `, [taskTitle, username, wallet]);
        
        if (checkResult[0].count > 0) {
            return res.json({ success: false, message: 'You already did this task' });
        }

        // Insert the new task
        await db.query(`
            INSERT INTO xera_user_tasks (xera_task, username, xera_wallet, xera_status, xera_points, xera_telegram_id, xera_twitter_username) 
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `, [taskTitle, username, wallet, xeraStatus, xeraPoints, '', '']);

        res.json({ success: true, message: 'Task successfully added' });
    } catch (error) {
        res.json({ success: false, message: 'Request error', error: error.message });
    }
});

app.post('/xera/v1/api/user/task/connect-wallet', authenticateToken, async (req, res) => {
    const { data } = req.body;
    const decodedFormRequestTXERADetails = Buffer.from(data, 'base64').toString('utf-8');

    const formRequestTXERADetails = JSON.parse(decodedFormRequestTXERADetails);

    if (!formRequestTXERADetails || !formRequestTXERADetails.ethWallet || !formRequestTXERADetails.solWallet || !formRequestTXERADetails.xeraWallet || !formRequestTXERADetails.xeraUsername) {
        return res.status(400).json({ success: false, message: 'Incomplete data' });
    }

    const ethWallet = formRequestTXERADetails.ethWallet;
    const solWallet = formRequestTXERADetails.solWallet;
    const xeraWallet = formRequestTXERADetails.xeraWallet; 
    const xeraUsername = formRequestTXERADetails.xeraUsername;
    const xeraStatus = 'ok';
    const xeraTask = 'Wallet Connect Task';
    const xeraPoints = '10000';

    try {
        // Check if both eth_wallet and sol_wallet already exist in another account
        const [existingWallet] = await db.query(`
            SELECT * FROM xera_user_accounts WHERE eth_wallet = ? AND sol_wallet = ? AND xera_wallet != ?
        `, [ethWallet, solWallet, xeraWallet]);

        if (existingWallet.length > 0) {
            return res.json({ success: false, message: 'Wallet already binded on other XERA Wallet' });
        } else {
            // Proceed with the wallet update
            await db.query(`
                UPDATE xera_user_accounts SET eth_wallet = ?, sol_wallet = ? WHERE xera_wallet = ?
            `, [ethWallet, solWallet, xeraWallet]);

            // Check if the task is already assigned
            const [existingTask] = await db.query(`
                SELECT COUNT(*) AS count FROM xera_user_tasks WHERE username = ? AND xera_wallet = ? AND xera_task = 'Wallet Connect Task'
            `, [xeraUsername, xeraWallet]);

            if (existingTask[0].count == 0) {
                // Insert task if not already assigned
                await db.query(`
                    INSERT INTO xera_user_tasks (username, xera_wallet, xera_task, xera_status, xera_points, xera_telegram_id, xera_twitter_username) 
                    VALUES (?, ?, ?, ?, ?, '', '')
                `, [xeraUsername, xeraWallet, xeraTask, xeraStatus, xeraPoints, '', '']);
            }

            return res.json({ success: true, message: 'Wallet successfully updated and task recorded' });
        }
    } catch (error) {
        return res.json({ success: false, message: 'Request error', error: error.message });
    }
});

app.post('/xera/v1/api/user/register', async (req, res) => {
    const { data } = req.body;
    const decodedFormRequestTXERADetails = Buffer.from(data, 'base64').toString('utf-8');

    const formRequestTXERADetails = JSON.parse(decodedFormRequestTXERADetails);

    const {
        username, password, userIP, referral, privateAddress, publicAddress,
        seedKey1, seedKey2, seedKey3, seedKey4, seedKey5, seedKey6, seedKey7, seedKey8, seedKey9, seedKey10, seedKey11, seedKey12
    } = formRequestTXERADetails;

    if (!username || !password || !userIP || !privateAddress || !publicAddress) {
        return res.json({ success: false, message: 'Incomplete data' });
    }

    try {
        // Check if the IP address exists 3 times
        const [ipResult] = await db.query(`
            SELECT COUNT(*) AS ip_count FROM xera_user_accounts WHERE xera_account_ip = ?
        `, [userIP]);

        if (ipResult[0].ip_count >= 3) {
            return res.json({ success: false, message: 'IP address already used 3 times' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        // Register user in xera_user_accounts table
        const [result] = await db.query(`
            INSERT INTO xera_user_accounts (username, password, xera_wallet, display, eth_wallet, bsc_wallet, pol_wallet, avax_wallet, arb_wallet, op_wallet, zks_wallet, sol_wallet, near_wallet, xera_referral, xera_account_ip, failed_attempts)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [username, hashedPassword, publicAddress, '' , '', '', '', '', '', '', '', '', '', referral, userIP, 0]);

        if (result.affectedRows > 0) {
            // Insert wallet details into xera_user_wallet table
            const [result2] = await db.query(`
                INSERT INTO xera_user_wallet (private_key, public_key, word1, word2, word3, word4, word5, word6, word7, word8, word9, word10, word11, word12) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `, [privateAddress, publicAddress, seedKey1, seedKey2, seedKey3, seedKey4, seedKey5, seedKey6, seedKey7, seedKey8, seedKey9, seedKey10, seedKey11, seedKey12]);

            if (result2.affectedRows > 0) {
                if (referral) {
                    const [findUser] = await db.query(`
                        SELECT * FROM xera_user_accounts WHERE username = ?
                    `, [referral]);

                    if (findUser.length > 0) {
                        const [refres] = await db.query(`
                            INSERT INTO xera_user_tasks (username, xera_wallet, xera_telegram_id, xera_twitter_username, xera_task, xera_status, xera_points) 
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                        `, [findUser[0].username, findUser[0].xera_wallet, '', '', 'Referral Task', 'ok', '2500']);
                        if (refres.affectedRows > 0) {
                            return res.json({ success: true, message: 'User successfully registered' });
                        }
                    }
                }
                return res.json({ success: true, message: 'User successfully registered' });
            } else {
                return res.json({ success: false, message: 'Registration failed' });
            }
        } else {
            return res.json({ success: false, message: 'Registration failed' });
        }
    } catch (error) {
        return res.json({ success: false, message: 'Request error', error: error.message });
    }
});

app.post('/xera/v1/api/user/update-display', authenticateToken, async (req, res) => {
    const { data } = req.body;
    const decodedFormRequestTXERADetails = Buffer.from(data, 'base64').toString('utf-8');

    const formRequestTXERADetails = JSON.parse(decodedFormRequestTXERADetails);

    if (!formRequestTXERADetails || !formRequestTXERADetails.xeraWallet || !formRequestTXERADetails.username) {
        return res.status(400).json({ success: false, message: 'Incomplete data' });
    }

    try {
        const [userAcc] = await db.query(`
            SELECT * FROM xera_user_accounts WHERE username = ? AND xera_wallet = ?
        `, [formRequestTXERADetails.username, formRequestTXERADetails.xeraWallet]);
        if (userAcc.length > 0) {
            const [updateDisplay] = await db.query(`UPDATE xera_user_accounts SET display = ? WHERE xera_wallet = ?`, [formRequestTXERADetails.displayID, formRequestTXERADetails.xeraWallet]);
            if (updateDisplay.affectedRows > 0) {
                return res.json({ success: true, message: 'Display updated successfully' });
            } else {
                return res.json({ success: false, message: 'Display update failed' });
            }
        } else {
            return res.json({ success: false, message: 'User not found' });
        }
        
    } catch (error) {
        return res.json({ success: false, message: 'Request error', error: error.message });
    }
});

app.post('/xera/v1/api/user/mainnet/booster/sol', authenticateToken, async (req, res) => {
    const { data } = req.body;
    const decodedFormRequestTXERADetails = Buffer.from(data, 'base64').toString('utf-8');

    const formRequestTXERADetails = JSON.parse(decodedFormRequestTXERADetails);

    if (!formRequestTXERADetails) {
        return res.status(400).json({ success: false, message: 'Incomplete data' });
    }

    const apikey = formRequestTXERADetails.apikey;
    const origin = req.headers.origin
    
    const isValid = await validateApiKey(apikey,origin);
    
    if (!isValid)  {
        return res.status(400).json({ success: false, message: isValid });
    }

    try {
        const [inserFund] = await db.query(`
            INSERT INTO xera_user_investments (tx_hash, tx_amount, tx_token, tx_dollar, tx_investor_address, tx_investor_name, tx_external_hash, tx_external_date, tx_bought_asset, tx_funding_asset, tx_asset_id, xera_address) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [formRequestTXERADetails.tx_hash, formRequestTXERADetails.tx_amount, formRequestTXERADetails.tx_token, '', formRequestTXERADetails.tx_investor_address, formRequestTXERADetails.tx_investor_name, formRequestTXERADetails.tx_external_hash, formRequestTXERADetails.tx_external_date, '', formRequestTXERADetails.tx_funding_asset,  formRequestTXERADetails.tx_asset_id, formRequestTXERADetails.xera_address]);
        
        if (inserFund.affectedRows === 0) {
            return res.json({ success: false, message: 'Funding addition failed' });
        }

        const [recordTaskResult] = await db.query(
            `INSERT INTO xera_user_tasks 
            (username, xera_wallet, xera_task, xera_status, xera_points, xera_telegram_id, xera_twitter_username)
            VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [formRequestTXERADetails.tx_investor_name, formRequestTXERADetails.xera_address, 'Booster Task', 'ok', formRequestTXERADetails.xera_points, '', '']
        );

        if (recordTaskResult.affectedRows === 0) {
            return res.status(500).json({ success: false, message: 'Error inserting record' });
        }

        let transactionOrigin = 'Genesis Transaction';
        
        const [[lastTransaction]] = await db.query(
            'SELECT transaction_date, transaction_hash FROM xera_mainnet_transactions WHERE transaction_command = ? AND sender_address = ? ORDER BY transaction_date DESC LIMIT 1',
            [formRequestTXERADetails.transaction_command,formRequestTXERADetails.sender_address]
        );
        if (lastTransaction) {
            transactionOrigin = lastTransaction.transaction_hash;
        }
        const [addTokenTransaction] = await db.query(
            `INSERT INTO xera_mainnet_transactions 
            (transaction_block, transaction_origin, transaction_hash, sender_address, receiver_address, transaction_command, transaction_amount, transaction_token, transaction_token_id, transaction_fee_amount, transaction_fee_token, transaction_fee_token_id, transaction_validator, transaction_info)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            ["Genesis", transactionOrigin, formRequestTXERADetails.transaction_hash, formRequestTXERADetails.sender_address, formRequestTXERADetails.receiver_address, formRequestTXERADetails.transaction_command, formRequestTXERADetails.transaction_amount, formRequestTXERADetails.transaction_token, formRequestTXERADetails.transaction_token_id, '', '', '', formRequestTXERADetails.transaction_validator, formRequestTXERADetails.transaction_info ]
        );

        if (addTokenTransaction.affectedRows === 0) {
            return res.json({ success: false, message: 'Add Transaction failed' });
        }

        const [addBlock] = await db.query(
            `UPDATE xera_mainnet_blocks SET block_transactions = block_transactions + 1 WHERE block_validator = ?`,[formRequestTXERADetails.transaction_validator]
        );

        if (addBlock.affectedRows === 0) {
            return res.json({ success: false, message: 'Add Block failed' });
        }
        
        return res.json({ success: true, message: `Successfully Apply Booster` });
    } catch (error) {
        return res.json({ success: false, message: 'Request error', error: error.message });
    }
});

app.post('/xera/v1/api/user/send-token', authenticateToken, async (req, res) => {
    const { data } = req.body;
    const decodedFormRequestTXERADetails = Buffer.from(data, 'base64').toString('utf-8');

    const formRequestTXERADetails = JSON.parse(decodedFormRequestTXERADetails);
    
    const apikey = formRequestTXERADetails.apiKey;
    const origin = req.headers.origin
    
    const isValid = await validateApiKey(apikey,origin);
    
    if (!isValid)  {
        return res.status(400).json({ success: false, message: isValid });
    }

    const { username, txHash, sender, receiver, command, amount, token, tokenId } = formRequestTXERADetails;
    // Validate request body
    if (![username, txHash, sender, receiver, command, amount, token, tokenId].every(Boolean)) {
        return res.status(400).json({ success: false, message: 'Incomplete transaction data.' });
    }

    const txLocalDate = new Date().toISOString().slice(0, 19).replace('T', ' ');

    try {
        // Check for recent transactions
        const [[lastTransaction]] = await db.query(
            'SELECT transaction_date, transaction_hash FROM xera_network_transactions WHERE transaction_command = ? AND sender_address = ? ORDER BY transaction_date DESC LIMIT 1',
            [command,sender]
        );

        let transactionOrigin = 'Genesis Transaction';
        if (lastTransaction) {
            const lastTxDate = new Date(lastTransaction.transaction_date).getTime();
            const timeDiff = Date.now() - lastTxDate;

            if (timeDiff < 21600000) { // 12 hours in milliseconds
                const timeRemainingMs = 21600000 - timeDiff;
                const hours = Math.floor(timeRemainingMs / 3600000);
                const minutes = Math.floor((timeRemainingMs % 3600000) / 60000);
                const seconds = Math.floor((timeRemainingMs % 60000) / 1000);
                return res.status(429).json({
                    success: false,
                    message: `Send again after ${hours}h ${minutes}m ${seconds}s`,
                });
            }

            transactionOrigin = lastTransaction.transaction_hash;
        }

        // Retrieve the latest block details
        const [[blockData]] = await db.query(
            'SELECT current_block, block_validator FROM xera_network_blocks ORDER BY id DESC LIMIT 1'
        );

        if (!blockData) {
            return res.status(500).json({ success: false, message: 'Block data not found. Transaction aborted.' });
        }

        const { current_block: txBlock, block_validator: validator } = blockData;

        // Increment block transaction count
        const [incrementBlockResult] = await db.query(
            'UPDATE xera_network_blocks SET block_transactions = block_transactions + 1 WHERE current_block = ?',
            [txBlock]
        );

        if (incrementBlockResult.affectedRows === 0) {
            return res.status(500).json({ success: false, message: 'Error incrementing block count' });
        }

        // Add new transaction
        const [addTransactionResult] = await db.query(
            `INSERT INTO xera_network_transactions 
            (transaction_block, transaction_origin, transaction_hash, sender_address, receiver_address, transaction_command, transaction_amount, transaction_token, transaction_token_id, transaction_validator, transaction_date, transaction_fee_amount, transaction_fee_token, transaction_fee_token_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [txBlock, transactionOrigin, txHash, sender, receiver, command, amount, token, tokenId, validator, txLocalDate, 0.00, '', '']
        );

        if (addTransactionResult.affectedRows === 0) {
            return res.status(500).json({ success: false, message: 'Error adding transaction' });
        }

        // Update token circulation
        // const [[currentToken]] = await db.query(
        //     'SELECT token_circulating FROM xera_asset_token WHERE token_symbol = ?',
        //     [token]
        // );

        // if (!currentToken) {
        //     return res.status(404).json({ success: false, message: 'Token not found or mismatched token symbol.' });
        // }

        // const newCirculating = parseInt(currentToken.token_circulating, 10) + parseInt(amount, 10);

        // const [updateTokenResult] = await db.query(
        //     'UPDATE xera_asset_token SET token_circulating = ? WHERE token_id = ?',
        //     [newCirculating, tokenId]
        // );

        // if (updateTokenResult.affectedRows === 0) {
        //     return res.status(500).json({ success: false, message: 'Error updating token circulation' });
        // }

        // Record task completion
        const [recordTaskResult] = await db.query(
            `INSERT INTO xera_user_tasks 
            (username, xera_wallet, xera_task, xera_status, xera_points, xera_telegram_id, xera_twitter_username)
            VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [username, receiver, 'Send TXERA Task', 'ok', '1250', '', '']
        );

        if (recordTaskResult.affectedRows === 0) {
            return res.status(500).json({ success: false, message: 'Error inserting record' });
        }

        // All operations succeeded
        return res.status(200).json({ success: true, message: `${amount} ${token} Sent Successfully.` });
    } catch (error) {
        console.error('Transaction Error:', error.message);
        return res.status(500).json({ success: false, message: 'Internal Server Error' });
    }
});

app.post('/xera/v1/api/user/mainnet/mint/token', authenticateToken, async (req, res) => {
    const { data } = req.body;
    const decodedFormRequestTXERADetails = Buffer.from(data, 'base64').toString('utf-8');

    const formRequestTXERADetails = JSON.parse(decodedFormRequestTXERADetails);
    
    const apikey = formRequestTXERADetails.apiKey;
    const origin = req.headers.origin
    
    const isValid = await validateApiKey(apikey,origin);
    
    if (!isValid)  {
        return res.status(400).json({ success: false, message: isValid });
    }

    const { token_id, token_type, token_creator, token_name, token_symbol, token_decimal, token_logo, token_max_supply,token_is_claimable, token_info, transaction_hash, sender_address, transaction_command, transaction_fee_amount, transaction_fee_token, transaction_fee_token_id, transaction_validator,transaction_info } = formRequestTXERADetails;
    // Validate request body
    if (![token_id, token_type, token_creator, token_name, token_symbol, token_decimal, token_logo, token_max_supply, token_is_claimable, token_info].every(Boolean)) {
        return res.status(400).json({ success: false, message: 'Incomplete transaction data.' });
    }

    const [[lastTransaction]] = await db.query(
        'SELECT transaction_date, transaction_hash FROM xera_mainnet_transactions WHERE transaction_command = ? AND sender_address = ? ORDER BY transaction_date DESC LIMIT 1',
        [transaction_command, sender_address]
    );

    let transactionOrigin = 'Genesis Transaction';

    if (lastTransaction) {
        transactionOrigin = lastTransaction.transaction_hash;
    }
    try {
        // Check for recent transactions
        const [assetTokens] = await db.query(
            'SELECT token_name, token_symbol FROM xera_asset_token WHERE token_symbol = ? AND token_name = ?',
            [token_symbol,token_name]
        );

        if (assetTokens.length > 0) {
            return res.status(429).json({ success: false, message: 'Token already minted.' });
        }

        const [addToken] = await db.query(
            `INSERT INTO xera_asset_token 
            (token_id, token_type, token_creator, token_owner, token_name, token_symbol, token_decimal, token_logo, token_max_supply, token_supply, token_on_owner, token_on_contract, token_on_contract_id, token_is_claimable, token_on_locked, token_circulating, token_holders, token_info)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [token_id, token_type, token_creator, token_creator, token_name, token_symbol, token_decimal, token_logo, token_max_supply, 0, token_max_supply, '', '', token_is_claimable, '', 0, '', token_info]
        );

        if (addToken.affectedRows === 0) {
            return res.json({ success: false, message: 'Add Token failed' });
        }
        const [addTokenTransaction] = await db.query(
            `INSERT INTO xera_mainnet_transactions 
            (transaction_block, transaction_origin, transaction_hash, sender_address, receiver_address, transaction_command, transaction_amount, transaction_token, transaction_token_id, transaction_fee_amount, transaction_fee_token, transaction_fee_token_id, transaction_validator, transaction_info)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            ["Genesis", transactionOrigin, transaction_hash, sender_address, token_creator, transaction_command, token_max_supply, token_symbol, token_id, transaction_fee_amount, transaction_fee_token, transaction_fee_token_id, transaction_validator,transaction_info ]
        );

        if (addTokenTransaction.affectedRows === 0) {
            return res.json({ success: false, message: 'Add Transaction failed' });
        }

        const [addBlock] = await db.query(
            `UPDATE xera_mainnet_blocks SET block_transactions = block_transactions + 1 WHERE block_validator = ?`,[transaction_validator]
        );

        if (addBlock.affectedRows === 0) {
            return res.json({ success: false, message: 'Add Block failed' });
        }
        
        return res.json({ success: true, message: `Successfully minted ${token_name}` });
    } catch (error) {
        console.error('Transaction Error:', error.message);
        return res.status(500).json({ success: false, message: 'Internal Server Error' });
    }
});

app.post('/xera/v1/api/user/mainnet/mintnft/sol', authenticateToken, async (req, res) => {
    const { data } = req.body;
    const decodedFormRequestTXERADetails = Buffer.from(data, 'base64').toString('utf-8');
    
    const formRequestTXERADetails = JSON.parse(decodedFormRequestTXERADetails);

    if (!formRequestTXERADetails) {
        return res.status(400).json({ success: false, message: 'Incomplete data' });
    }

    const apikey = formRequestTXERADetails.apikey;
    const origin = req.headers.origin
    
    const isValid = await validateApiKey(apikey,origin);
    
    if (!isValid)  {
        return res.status(400).json({ success: false, message: isValid });
    }
    

    const { nft_id, nft_collection, nft_version, nft_icon, nft_name, nft_content, nft_creator, nft_type, nft_status, nft_rarity, nft_info, tx_hash, tx_amount, tx_token, tx_investor_address, tx_investor_name, tx_external_hash, tx_external_date, tx_funding_asset, tx_asset_id, xera_address, transaction_hash, sender_address, receiver_address, transaction_command, transaction_amount, transaction_token, transaction_token_id, transaction_validator, transaction_info } = formRequestTXERADetails;
    // Validate request body

    const [[lastTransaction]] = await db.query(
        'SELECT transaction_date, transaction_hash FROM xera_mainnet_transactions WHERE transaction_command = ? AND sender_address = ? ORDER BY transaction_date DESC LIMIT 1',
        [transaction_command, sender_address]
    );

    let transactionOrigin = 'Genesis Transaction';

    if (lastTransaction) {
        transactionOrigin = lastTransaction.transaction_hash;
    }

    try {
        const [addNft] = await db.query(
            `INSERT INTO xera_asset_nfts 
            (nft_id, nft_collection, nft_version, nft_icon, nft_name, nft_content, nft_creator, nft_owner, nft_type, nft_status, nft_rarity, nft_parts, nft_stakeable, nft_redeemable, nft_price, nft_token, nft_token_id, nft_info)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [nft_id, nft_collection, nft_version, nft_icon, nft_name, nft_content, nft_creator, nft_creator, nft_type, nft_status, nft_rarity, "[]", 'true', 'true', 0, '', '', nft_info]
        );

        if (addNft.affectedRows === 0) {
            return res.json({ success: false, message: 'Add NFT failed' });
        }

        const [inserFund] = await db.query(`
            INSERT INTO xera_user_investments (tx_hash, tx_amount, tx_token, tx_dollar, tx_investor_address, tx_investor_name, tx_external_hash, tx_external_date, tx_bought_asset, tx_funding_asset, tx_asset_id, xera_address) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [tx_hash, tx_amount, tx_token, '', tx_investor_address, tx_investor_name, tx_external_hash, tx_external_date, '', tx_funding_asset,  tx_asset_id, xera_address]);
        
        if (inserFund.affectedRows === 0) {
            return res.json({ success: false, message: 'Funding addition failed' });
        }

        const [addTokenTransaction] = await db.query(
            `INSERT INTO xera_mainnet_transactions 
            (transaction_block, transaction_origin, transaction_hash, sender_address, receiver_address, transaction_command, transaction_amount, transaction_token, transaction_token_id, transaction_fee_amount, transaction_fee_token, transaction_fee_token_id, transaction_validator, transaction_info)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            ["Genesis", transactionOrigin, transaction_hash, sender_address, receiver_address, transaction_command, transaction_amount, transaction_token, transaction_token_id, '', '', '', transaction_validator,transaction_info ]
        );

        if (addTokenTransaction.affectedRows === 0) {
            return res.json({ success: false, message: 'Add Transaction failed' });
        }

        const [addBlock] = await db.query(
            `UPDATE xera_mainnet_blocks SET block_transactions = block_transactions + 1 WHERE block_validator = ?`,[transaction_validator]
        );

        if (addBlock.affectedRows === 0) {
            return res.json({ success: false, message: 'Add Block failed' });
        }
        
        return res.json({ success: true, message: `Successfully minted NFT ${nft_name}` });
    } catch (error) {
        console.error('Transaction Error:', error.message);
        return res.status(500).json({ success: false, message: 'Internal Server Error', error: error.message });
    }
});

app.post('/xera/v1/api/user/mainnet/mintlab/nft', authenticateToken, async (req, res) => {
    const { data } = req.body;
    const decodedFormRequestTXERADetails = Buffer.from(data, 'base64').toString('utf-8');

    const formRequestTXERADetails = JSON.parse(decodedFormRequestTXERADetails);
    
    const apikey = formRequestTXERADetails.apiKey;
    const origin = req.headers.origin
    
    const isValid = await validateApiKey(apikey,origin);
    
    if (!isValid)  {
        return res.status(400).json({ success: false, message: isValid });
    }

    const { transaction_origin, transaction_hash, sender_address, receiver_address, transaction_command, transaction_amount, transaction_token, transaction_token_id, transaction_validator, transaction_info } = formRequestTXERADetails;
    // Validate request body
    if (![ transaction_hash, sender_address, receiver_address, transaction_command, transaction_amount, transaction_token, transaction_token_id, transaction_validator, transaction_info].every(Boolean)) {
        return res.status(400).json({ success: false, message: 'Incomplete transaction data.' });
    }

    try {
        const [addTokenTransaction] = await db.query(
            `INSERT INTO xera_mainnet_transactions 
            (transaction_block, transaction_origin, transaction_hash, sender_address, receiver_address, transaction_command, transaction_amount, transaction_token, transaction_token_id, transaction_fee_amount, transaction_fee_token, transaction_fee_token_id, transaction_validator, transaction_info)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            ["Genesis", transaction_origin, transaction_hash, sender_address, receiver_address, transaction_command, transaction_amount, transaction_token, transaction_token_id, '', '', '', transaction_validator,transaction_info ]
        );

        if (addTokenTransaction.affectedRows === 0) {
            return res.json({ success: false, message: 'Add Transaction failed' });
        }

        const [addBlock] = await db.query(
            `UPDATE xera_mainnet_blocks SET block_transactions = block_transactions + 1 WHERE block_validator = ?`,[transaction_validator]
        );

        if (addBlock.affectedRows === 0) {
            return res.json({ success: false, message: 'Add Block failed' });
        }
        
        return res.json({ success: true, message: `Successfully minted NFT` });
    } catch (error) {
        console.error('Transaction Error:', error.message);
        return res.status(500).json({ success: false, message: 'Internal Server Error', error: error.message });
    }
});

app.post('/xera/v1/api/user/mainnet/send/token', authenticateToken, async (req, res) => {
    const { data } = req.body;
    const decodedFormRequestTXERADetails = Buffer.from(data, 'base64').toString('utf-8');

    const formRequestTXERADetails = JSON.parse(decodedFormRequestTXERADetails);
    
    const apikey = formRequestTXERADetails.apiKey;
    const origin = req.headers.origin
    
    const isValid = await validateApiKey(apikey,origin);
    
    if (!isValid)  {
        return res.status(400).json({ success: false, message: isValid });
    }

    const { username, txHash, sender, receiver, command, amount, token, tokenId, transactioninfo } = formRequestTXERADetails;
    // Validate request body
    if (![username, txHash, sender, receiver, command, amount, token, tokenId,transactioninfo].every(Boolean)) {
        return res.status(400).json({ success: false, message: 'Incomplete transaction data.' });
    }

    try {
        // Check for recent transactions
        const [[lastTransaction]] = await db.query(
            'SELECT transaction_date, transaction_hash FROM xera_mainnet_transactions WHERE transaction_command = ? AND sender_address = ? ORDER BY transaction_date DESC LIMIT 1',
            [command,sender]
        );

        let transactionOrigin = 'Genesis Transaction';
        if (lastTransaction) {
            transactionOrigin = lastTransaction.transaction_hash;
        }

        // Retrieve the latest block details
        const [[blockData]] = await db.query(
            'SELECT current_block, block_validator FROM xera_mainnet_blocks ORDER BY id DESC LIMIT 1'
        );

        if (!blockData) {
            return res.status(500).json({ success: false, message: 'Block data not found. Transaction aborted.' });
        }

        const { current_block: txBlock, block_validator: validator } = blockData;

        // Increment block transaction count
        const [incrementBlockResult] = await db.query(
            'UPDATE xera_network_blocks SET block_transactions = block_transactions + 1 WHERE current_block = ?',
            [txBlock]
        );

        if (incrementBlockResult.affectedRows === 0) {
            return res.status(500).json({ success: false, message: 'Error incrementing block count' });
        }

        // Add new transaction
        const [addTransactionResult] = await db.query(
            `INSERT INTO xera_mainnet_transactions 
            (transaction_block, transaction_origin, transaction_hash, sender_address, receiver_address, transaction_command, transaction_amount, transaction_token, transaction_token_id, transaction_validator, transaction_fee_amount, transaction_fee_token, transaction_fee_token_id, transaction_info)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [txBlock, transactionOrigin, txHash, sender, receiver, command, amount, token, tokenId, validator, '', '', '',transactioninfo]
        );

        if (addTransactionResult.affectedRows === 0) {
            return res.status(500).json({ success: false, message: 'Error adding transaction' });
        }

        const [checkTokenOwner] = await db.query('SELECT token_symbol FROM xera_asset_token WHERE token_owner = ?', [sender]);

        if (receiver === 'XERA Centralized Treasury' && checkTokenOwner.length > 0) {
            const [updateTokenOwner] = await db.query('UPDATE xera_asset_token SET token_supply = token_supply + ? WHERE token_symbol = ?', [amount, token]);
            if (updateTokenOwner.affectedRows === 0) {
                return res.status(500).json({ success: false, message: 'Error updating token owner' });
            } else {
                return res.status(200).json({ success: true, message: `${amount} ${token} Sent Successfully.` });
            }
        } 
        // Update token circulation
        if (checkTokenOwner.length > 0) {
            const [[currentToken]] = await db.query(
                'SELECT token_circulating FROM xera_asset_token WHERE token_symbol = ?',
                [token]
            );
    
            if (!currentToken) {
                return res.status(404).json({ success: false, message: 'Token not found or mismatched token symbol.' });
            }
    
            const newCirculating = parseInt(currentToken.token_circulating, 10) + parseInt(amount, 10);
    
            const [updateTokenResult] = await db.query(
                'UPDATE xera_asset_token SET token_circulating = ? WHERE token_id = ?',
                [newCirculating, tokenId]
            );
    
            if (updateTokenResult.affectedRows === 0) {
                return res.status(500).json({ success: false, message: 'Error updating token circulation' });
            }
        }

        // All operations succeeded
        return res.status(200).json({ success: true, message: `${amount} ${token} Sent Successfully.` });
    } catch (error) {
        console.error('Transaction Error:', error.message);
        return res.status(500).json({ success: false, message: 'Internal Server Error' });
    }
});

// Endpoint for fetching user nft
app.post('/xera/v1/api/user/nfts', authenticateToken, async (req, res) => {
    const { user } = req.body;

    if (!user) {
        return res.json({ success: false, message: 'No address provided' });
    }

    try {
        // Step 1: Retrieve user node details
        const [getNFT] = await db.query('SELECT * FROM xera_asset_nfts WHERE nft_owner = ?', [user]);

        if (getNFT.length > 0) {
            const cleanNFT = getNFT.map(({ id, ...nft }) => nft);
            return res.json({ success: true, message: `Successfully retrieved NFT. Wallet: ${user}`, nft: cleanNFT });
        } else {
            return res.json({ success: false, message: 'No NFT found for the provided address' });
        }
    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
});

app.post('/xera/v1/api/user/nft-claim', authenticateToken, async (req, res) => {
    const { user } = req.body;
    
    if (!user || !user.nftName || !user.nftOwner) {
        return res.json({ success: false, message: "Invalid request" });
    }

    let transactionOrigin = 'Genesis Transaction';
    
    try {
        const [nftClaim] = await db.query(`
            SELECT nft_owner
            FROM xera_asset_nfts
            WHERE nft_name = ? AND nft_owner = ?
        `, [user.nftName, user.nftOwner]);

        const [checkTransaction] = await db.query(
            'SELECT transaction_hash FROM xera_network_transactions WHERE sender_address = ? AND receiver_address = ? ORDER BY transaction_date DESC LIMIT 1',
            [user.sender,user.receiver]
        );

        if (nftClaim.length > 0 || checkTransaction.length > 0) {
            return res.json({ success: false, message:"NFT Already claimed" });
        } else {
            const [insertNFT] = await db.query(` INSERT INTO xera_asset_nfts (nft_id, nft_name, nft_content, nft_creator, nft_owner, nft_state, nft_status, nft_rarity, nft_redeemable, nft_price, nft_token, nft_token_id, nft_transaction, nft_mining, nft_info) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [user.nftId, user.nftName, user.nftContent, user.nftCreator, user.nftOwner, user.nftState, user.nftStatus, user.nftRarity, user.nftRedeemable, 0.00, "", "", user.nftTransaction, user.nftMining, user.nftInfo]);
            
            if (insertNFT.affectedRows > 0) {
                
                // Check for recent transactions
                const [lastTransaction] = await db.query(
                    'SELECT transaction_hash FROM xera_network_transactions WHERE sender_address = ? AND receiver_address = ? ORDER BY transaction_date DESC LIMIT 1',
                    [user.sender,user.receiver]
                );

                // Retrieve the latest block details
                const [[blockData]] = await db.query(
                    'SELECT current_block, block_validator FROM xera_network_blocks ORDER BY id DESC LIMIT 1'
                );

                if (!blockData) {
                    return res.status(500).json({ success: false, message: 'Block data not found. Transaction aborted.' });
                }

                const { current_block: txBlock, block_validator: validator } = blockData;

                // Increment block transaction count
                const [incrementBlockResult] = await db.query(
                    'UPDATE xera_network_blocks SET block_transactions = block_transactions + 1 WHERE current_block = ?',
                    [txBlock]
                );

                if (incrementBlockResult.affectedRows === 0) {
                    return res.status(500).json({ success: false, message: 'Error incrementing block count' });
                }

                if (lastTransaction.length > 0) {
                    const lasttransaction = lastTransaction[0].transaction_hash;
                    const [insertTransaction] = await db.query(` INSERT INTO xera_network_transactions (transaction_block, transaction_origin, transaction_hash, sender_address, receiver_address, transaction_command, transaction_amount, transaction_token, transaction_token_id, transaction_fee_amount, transaction_fee_token, transaction_fee_token_id, transaction_validator) VALUES (?, ? ,? ,? ,? ,? ,? ,? ,? ,? ,? ,? ,?)`, ["Genesis", lasttransaction, user.txHash, user.sender, user.receiver, user.command, user.amount, user.token, user.tokenId, 0, "", "", validator,]);
                    if (insertTransaction.affectedRows > 0) {
                        return res.json({ success: true, message: "NFT claimed successfully" });
                    } else {
                        return res.json({ success: false, message: "NFT claim failed" });
                    }
                } else {
                    const [insertTransaction] = await db.query(` INSERT INTO xera_network_transactions (transaction_block, transaction_origin, transaction_hash, sender_address, receiver_address, transaction_command, transaction_amount, transaction_token, transaction_token_id, transaction_fee_amount, transaction_fee_token, transaction_fee_token_id, transaction_validator) VALUES (?, ? ,? ,? ,? ,? ,? ,? ,? ,? ,? ,? ,?)`, ["Genesis", transactionOrigin, user.txHash, user.sender, user.receiver, user.command, user.amount, user.token, user.tokenId, 0, "", "", validator,]);
                    if (insertTransaction.affectedRows > 0) {
                        return res.json({ success: true, message: "NFT claimed successfully" });
                    } else {
                        return res.json({ success: false, message: "NFT claim failed" });
                    }
                }
            } else {
                return res.json({ success: false, message: "NFT claim failed" });
            }
        }
    } catch (error) {
        return res.json({ success: false, message: "Request error", error });
    }
});
let fileName = ''
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
      cb(null, '/home/texeract/htdocs/texeract.network/nft/'); // Directory to save files
    },
    filename: (req, file, cb) => {
    console.log(fileName);
    
      cb(null, `${fileName}`); // Unique filename
    },
  });

const upload = multer({ storage });

// Create the uploads directory if it doesn't exist
const fs = require('fs');
if (!fs.existsSync('uploads')) {
fs.mkdirSync('uploads');
}

// Upload route
app.post('/xera/v1/api/user/mainnet/mintnft/upload-content', upload.single('file'), (req, res) => {
    fileName = req.body.fileName
if (!req.file) {
    return res.status(400).send('No file uploaded.');
}
res.send({ message: 'File uploaded successfully!', file: req.file });
});

// Serve uploaded files statically
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Global error handling middleware
app.use((err, req, res, next) => {
    console.error("Global error:", err.message);
    res.status(500).json({ success: false, message: "An internal error occurred" });
});

// Start the server
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});