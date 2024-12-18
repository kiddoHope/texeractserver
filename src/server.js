const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const mysql = require('mysql2/promise')
const cors = require("cors");
require('dotenv').config();
const rateLimit = require('express-rate-limit')
const app = express();
const port = 5000;
const compression = require('compression');
const NodeCache = require('node-cache');
const cache = new NodeCache({ stdTTL: 60 });

app.use(compression());
app.use(bodyParser.json());

const allowedOrigins = ['https://texeract.network', 'http://localhost:3000', 'http://localhost:3001', 'https://texeract-network-beta.vercel.app','https://tg-texeract-beta.vercel.app','https://texeractbot.xyz'];

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin, like mobile apps or curl requests
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    } else {
      return callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-access-token', 'X-Requested-With', 'Accept'],
  credentials: true, // Allow credentials (cookies, etc.) in CORS requests
}));

app.options('*', (req, res) => {
  res.header('Access-Control-Allow-Origin', req.headers.origin);
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE', 'PATCH');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-access-token, X-Requested-With, Accept');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.sendStatus(204);
});

app.use((req, res, next) => {
  res.header('Vary', 'Origin');
  next();
});

const jwtSecret = process.env.MAIN_JWT_SECRET
const jwtAPISecret = process.env.API_JWT_SECRET

// 46.202.129.137
// 2a02:4780:28:feaa::1

// database
const db = mysql.createPool({
    // host: '2a02:4780:28:feaa::1',  // use this in production
    host: process.env.DB_HOST ,
    user: process.env.DB_USER ,
    password: process.env.DB_PASSWORD ,
    database: process.env.DB_DATABASE ,
    port: 3306,
    waitForConnections: true,
    connectTimeout: 20000,      
    connectionLimit: 10,  
    queueLimit: 0          
});

process.on('uncaughtException', function (err) {
    console.log(err);
});

async function testConnection() {
    try {
        const connection = await db.getConnection();
        console.log('Database connection successful!');
        connection.release(); // Release the connection back to the pool
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
        }
    }
    return dev;
};

app.get('/xera', (req, res) => {
    res.status(200).send('Xera API is running');
});


// app.post('/xera/v1/api/users/users-list', async (req,res) => {
//     const { apikey } = req.body
//     try {
//         const checkModeration = await getDevFromCache(apikey)
        
//         if (checkModeration) {
//             if (checkModeration.xera_moderation === "creator") {
//                 const [users] = await db.query(`
//                     SELECT 
//                     xera_user_display.xera_wallet,
//                     xera_user_accounts.username
//                     FROM xera_user_display
//                     INNER JOIN xera_user_accounts 
//                     ON xera_user_display.xera_wallet = xera_user_accounts.xera_wallet COLLATE utf8mb4_unicode_ci
//                 `); 
                
//                 return res.status(200).json({ success: true, data: users})
//             } else {
//                 return res.status(401).json({ success:false, message : "unknown request"})
//             }
//         } else {
//             return res.status(401).json({ success:false, message : "invalid request"})
//         }
//     } catch (error) {
//         return res.status(500).json({ success: false, message: "request error", error: error})
//     }
// })

// app.post('/xera/v1/api/users/user-task/referrals', async (req, res) => {
//     const { request } = req.body;
    
//     if (!request) {
//         res.status(400).json({ success: false, message: "no request found"})
//     }
//     const apikey = request.api
//     const limit = request.limit
//     const page = request.page
//     try {
//         const [checkModeration] = await db.query('SELECT * FROM xera_developer WHERE BINARY xera_api = ?', [apikey]);
//         if (checkModeration.length > 0) {
//             if (checkModeration[0].xera_moderation === "creator") {
//                 const [userstask] = await db.query(`
//                     SELECT 
//                         xera_user_accounts.username,
//                         xera_user_accounts.xera_wallet, 
//                         xera_user_display.xera_nft_meta,
//                         xera_user_tasks.xera_task,
//                         xera_user_tasks.xera_points
//                     FROM xera_user_accounts
//                     INNER JOIN xera_user_tasks 
//                     ON BINARY xera_user_accounts.username = BINARY xera_user_tasks.username COLLATE utf8mb4_unicode_ci
//                     INNER JOIN xera_user_display 
//                     ON xera_user_accounts.xera_wallet = xera_user_display.xera_wallet COLLATE utf8mb4_unicode_ci
//                 `);
                
//                 if (userstask.length > 0) {
//                     const referralFilter = userstask.filter(user => user.xera_task === "Referral Task");
//                     const combinedArray = Object.values(
//                         referralFilter.reduce((acc, item) => {
//                             const { username, xera_wallet, xera_nft_meta } = item;
//                             if (!acc[username]) {
//                                 acc[username] = {
//                                     username,
//                                     xera_wallet, 
//                                     xera_nft_meta, 
//                                     count: 0,
//                                 };
//                             }
//                             acc[username].count += 1;
//                             return acc;
//                         }, {})
//                     );
//                     const sortedData = combinedArray.sort((a, b) => b.count - a.count);
                    
//                     // Pagination logic
//                     const startIndex = (page - 1) * limit;
//                     const endIndex = page * limit;
//                     const paginatedData = sortedData.slice(startIndex, endIndex);
                    
//                     return res.status(200).json({ success: true, data: paginatedData });
//                 } else {
//                     return res.status(404).json({ success: false, message: "No tasks found" });
//                 }
//             } else {
//                 return res.status(401).json({ success: false, message: "Unknown request" });
//             }
//         } else {
//             return res.status(401).json({ success: false, message: "Invalid request" });
//         }
//     } catch (error) {
//         return res.status(500).json({ success: false, message: "Request error", error: error });
//     }
// });

app.post('/xera/v1/api/users/total-points', async (req, res) => {
    const { apikey } = req.body;
    
    if (!apikey) {
        return res.status(400).json({ success: false, message: "No request found" });
    }

    try {
        const checkModeration = await getDevFromCache(apikey)
        
        if (checkModeration) {
            if (checkModeration.xera_moderation === "creator") {
                const [userstask] = await db.query(`SELECT SUM(xera_points) AS total_points FROM xera_user_tasks`);
                
                if (userstask.length > 0) {
                    const totalPoints = userstask[0].total_points
                    
                    return res.status(200).json({ success: true, totalPoints });
                } else {
                    return res.status(404).json({ success: false, message: "No tasks found" });
                }
            } else {
                return res.status(401).json({ success: false, message: "Unknown request" });
            }
        } else {
            return res.status(401).json({ success: false, message: "Invalid request" });
        }
    } catch (error) {
        return res.status(500).json({ success: false, message: "Request error", error: error });
    }
});

app.post('/xera/v1/api/users/all-wallet',async (req,res) => {
    const {apikey} = req.body; 
    
    if (!apikey) {
        return res.status(400).json({ success: false, message: "No request found" });
    }

    try {
        const checkModeration = await getDevFromCache(apikey)
        
        if (checkModeration) {
            if (checkModeration.xera_moderation === "creator") {
                const [countWallet] = await db.query('SELECT COUNT(*) AS user_count FROM xera_user_accounts')
                
                if (countWallet.length > 0) {
                    const walletCount = countWallet[0].user_count
                    res.status(200).json({ success:true, message: "Successfully count all wallet", walletCount: walletCount})
                }
            } else {
                return res.status(401).json({ success: false, message: "unknown request" });
            } 
        } else {
            return res.status(401).json({ success: false, message: "invalid request" });
        }
    } catch (error) {
        return res.status(500).json({ success: false, message: "request error", error: error });
    }
})

// app.post('/xera/v1/api/users/all-participant',async (req, res) => {
//     const { apikey } = req.body;

//     if (!apikey) {
//         return res.status(400).json({ success: false, message: "No request found" });
//     }

//     try {
//         const checkModeration = await getDevFromCache(apikey)
        
//         if (checkModeration) {
//             if (checkModeration.xera_moderation === "creator") {
//                 const [userParticipants] = await db.query(`
//                     SELECT DISTINCT xera_user_accounts.username
//                     FROM 
//                         xera_user_accounts 
//                     INNER JOIN 
//                         xera_user_tasks ON BINARY xera_user_accounts.username = BINARY xera_user_tasks.username 
//                 `);

//                 if (userParticipants.length > 0) {
//                     const uniqueParticipantCount = userParticipants.length;
//                     return res.status(200).json({ success: true, message: "Successfully retrieved data count", participantCount: uniqueParticipantCount });
//                 } else {
//                     return res.status(404).json({ success: false, message: "no tasks found" });
//                 }
//             } else {
//                 return res.status(401).json({ success: false, message: "unknown request" });
//             }
//         } else {
//             return res.status(401).json({ success: false, message: "invalid request" });
//         }
//     } catch (error) {
//         return res.status(500).json({ success: false, message: "request error", error: error });
//     }
// });

app.post('/xera/v1/api/token/asset-tokens', async(req,res) => {
    const { apikey } = req.body

    if (!apikey) {
        return res.status(400).json({ success: false, message: "No request found" });
    }
    try {
        const checkModeration = await getDevFromCache(apikey)
        
        if (checkModeration) {
            
            if (checkModeration.xera_moderation === "creator") {
                const [assetTokens] = await db.query(`SELECT * FROM xera_asset_token`);
                
                if (assetTokens.length > 0) {
                    const cleanedData = assetTokens.map(({id, ...clean}) => clean)
                    
                    return res.status(200).json({ success: true, data: cleanedData})
                } else {
                    return res.status(404).json({ success:false, message : "no tokens found"})
                }
            } else {
                return res.status(401).json({ success:false, message : "unknown request"})
            }
        } else {
            return res.status(401).json({ success:false, message : "invalid request"})
        }
    } catch (error) {
        return res.status(500).json({ success: false, message: "request error", error: error})
    }
})

app.post('/xera/v1/api/token/faucet-transaction', async (req, res) => {
    const { request } = req.body;
    
    if (!request) {
        res.status(400).json({ success: false, message: "no request found"})
    }
    const apikey = request.api
    const limit = request.limit
    const page = request.page
    try {
        const [checkModeration] = await db.query('SELECT * FROM xera_developer WHERE BINARY xera_api = ?', [apikey]);
        if (checkModeration.length > 0) {
            if (checkModeration[0].xera_moderation === "creator") {
                const [assetTokens] = await db.query('SELECT * FROM xera_network_transactions');

                if (assetTokens.length > 0) {
                    const sorted = assetTokens.sort((a, b) => b.id - a.id);
                    const cleanedData = sorted.map(({ id, transaction_origin, sender_address, tansaction_command, transaction_token, transaction_token_id, transaction_validator, transaction_date, ...clean }) => clean);

                    // Pagination logic
                    const startIndex = (page - 1) * limit;
                    const endIndex = page * limit;
                    const paginatedData = cleanedData.slice(startIndex, endIndex);

                    return res.status(200).json({ success: true, data: paginatedData });
                } else {
                    return res.status(404).json({ success: false, message: "No tokens found" });
                }
            } else {
                return res.status(401).json({ success: false, message: "Unknown request" });
            }
        } else {
            return res.status(401).json({ success: false, message: "Invalid request" });
        }
    } catch (error) {
        return res.status(500).json({ success: false, message: "Request error", error: error });
    }
});

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});