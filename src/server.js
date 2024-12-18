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


const limiter = rateLimit({
    windowMs: 5 * 60 * 1000, 
    max: 10,
    handler: (req, res) => {
      res.status(429).json({
        success: false,
        message: "Rate limit exceeded. Please try again in 5 minutes."
      });
    }
  });

const Loginlimiter = rateLimit({
    windowMs: 5 * 60 * 1000, 
    max: 5, 
    message: "Too many login attempts from this account, please try again later."
});

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1]; // Extract token from "Bearer <token>"

    if (!token) {
        return res.status(401).json({ success: false, message: "Authentication token is required" });
    }

    jwt.verify(token, jwtSecret, (err, decoded) => {
        if (err) {
            if (err.name === "TokenExpiredError") {
                // Handle expired token case
                return res.status(401).json({ success: false, message: "Token has expired" });
            }
            if (err.name === "JsonWebTokenError") {
                // Handle invalid token case
                return res.status(403).json({ success: false, message: "Invalid token" });
            }
            // Handle other errors
            return res.status(403).json({ success: false, message: "Token verification failed" });
        }
        
        req.user = decoded; // Attach decoded user information to the request object
        next(); // Proceed to the next middleware or route handler
    });
};

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
// const apitokn = "xeraAPI-"+generateRandomString(10)+"-"+generateRandomString(20)
// console.log(apitokn);


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

app.post("/xera/v1/api/generate/access-token", async (req,res) => {
    const {apikey} = req.body;
    
    if (!apikey) {
        return res.status(400).json({ success: false, message: "API key is required" });
    }

    try {
        const [apikeyCheck] = await db.query("SELECT * FROM xera_developer WHERE BINARY xera_api = ?", [apikey]);
        if (apikeyCheck.length > 0) {
            const xera_wallet = apikeyCheck[0].xera_wallet
            const authToken = jwt.sign({ xera_wallet }, jwtAPISecret, { expiresIn: "1d" });
            return res.status(200).json({ success: true, accessToken: authToken})
        } else {
            return res.status(401).json({ success: false, message: "Invalid api key"})
        }
    } catch (error) {
        return res.status(500).json({ success: false, message: "request error"})
    }
})

// app.post("/xera/v1/api/user/check-username" ,async (req,res) => {
//     const {username} = req.body;
    
//     if (!username) {
//         return res.status(400).json({ success: false, message: "please complete all the fields"});
//     }

//     try {
//         const user = await getUserFromCache(username) 
        
//         if (user) {
//             return res.status(200).json({ success: false, message: 'Username already exists' });
//         } else {
//             return res.status(200).json({ success: true, message: 'Username is available' });
//         }
//     } catch (error) {
//         res.status(500).json({ success: false, message: 'request error' }); 
//     }
// })

// app.post('/xera/v1/api/user/login-basic',authenticateToken, async (req, res) => {
//     const { username, password } = req.body;

//     if (!username || !password) {
//         return res.status(403).json({ success: false, message: "Request Error. Input Field"})
//     }
    
//     try {

//         const userData = await getUserFromCache(username);
        
//         if (userData) {
//             const dataPass = userData.password
            
//             if (dataPass.slice(0,4) === "$2y$") {
//                 const normalizedHash = dataPass.replace("$2y$", "$2a$");
                
//                 if (await bcrypt.compare(password, normalizedHash)) {
//                     const xeraJWT = {
//                         loginState : "basic",
//                         isloggedIn : "true",
//                         myXeraUsername : userData.username,
//                         myXeraAddress : userData.xera_wallet
//                     }
//                     const authToken = jwt.sign({ xeraJWT }, jwtSecret, { expiresIn: "2d" });
//                     return res.status(200).json({ success: true, message: `${userData.username} Successfully Login`, authToken: authToken})
//                 } else {
//                     return res.status(401).json({ success: false, message: 'Wrong password' });
//                 }
//             } else {
//                 if (await bcrypt.compare(password, dataPass)) {
//                     const xeraJWT = {
//                         loginState : "basic",
//                         isloggedIn : "true",
//                         myXeraUsername : userData.username,
//                         myXeraAddress : userData.xera_wallet
//                     }
//                     const authToken = jwt.sign({ xeraJWT }, jwtSecret, { expiresIn: "2d" });
//                     return res.status(200).json({ success: true, message: `${userData.username} Successfully Login Basic Account`, authToken: authToken})
//                 } else {
//                     return res.status(401).json({ success: false, message: 'Wrong password' });
//                 }
//             }
            
//         } else {
//             return res.status(403).json({ success: false, message: "no user found"})
//         }
//     } catch (error) {
//         return res.status(500).json({ success: false, message: "request error"})
//     }
// })

// app.post('/xera/v1/api/user/login-prKey',authenticateToken, async (req, res) => {
//     const { privateKey } = req.body;
    
    
//     if (!privateKey) {
//         return res.status(403).json({ success: false, message: "Request Error. No private key received"})
//     }

//     try {
//         const [user] = await db.query("SELECT * FROM xera_user_wallet WHERE BINARY private_key = ?", [privateKey]);
        
//         if (user.length > 0) {
//             const userData = user[0]
//             const [getUsername] = await db.query("SELECT * FROM xera_user_accounts WHERE BINARY xera_wallet = ?", [userData.public_key]);
//             if (getUsername.length > 0) {
//                 const userarray = getUsername[0]
//                 const username = userarray.username
//                 const xeraJWT = {
//                     loginState : "basic",
//                     isloggedIn : "true",
//                     myXeraUsername : username,
//                     myXeraAddress : userData.public_key
//                 }
//                 const authToken = jwt.sign({ xeraJWT }, jwtSecret, { expiresIn: "2d" });
//                 return res.status(200).json({ success: true, message: `${username} Successfully Login Full Access`, authToken: authToken})
//             } else {
//                 return res.status(400).json({ success: false, message: "No user found in that key phrase"})
//             }
//         } else {
//             return res.status(403).json({ success: false, message: "invalid key phrase"})
//         }
//     } catch (error) {
//         return res.status(500).json({ success: false, message: "request error", error: error})
//     }
// })

// app.post('/xera/v1/api/user/login-phrase',authenticateToken, async (req, res) => {
//     const { seedPhrase } = req.body;

//     if (!seedPhrase) {
//         return res.status(403).json({ success: false, message: "Request Error. No private key received"})
//     }
    
//     const seed = JSON.parse(seedPhrase)

//     try {
//         const sqlPhrase = "SELECT * FROM xera_user_wallet WHERE BINARY word1 = ? AND word2 = ? AND word3 = ? AND word4 = ? AND word5 = ? AND word6 = ? AND word7 = ? AND word8 = ? AND word9 = ? AND word10 = ? AND word11 = ? AND word12 = ?"
//         const [user] = await db.query(sqlPhrase, [seed.seedWord1,seed.seedWord2,seed.seedWord3,seed.seedWord4,seed.seedWord5,seed.seedWord6,seed.seedWord7,seed.seedWord8,seed.seedWord9,seed.seedWord10,seed.seedWord11,seed.seedWord12]);

//         if (user.length > 0) {
//             const userData = user[0]
            
//             const [getUsername] = await db.query("SELECT * FROM xera_user_accounts WHERE BINARY xera_wallet = ?", [userData.public_key]);
            
//             if (getUsername.length > 0) {
//                 const userarray = getUsername[0]
                
//                 const username = userarray.username
//                 const xeraJWT = {
//                     loginState : "basic",
//                     isloggedIn : "true",
//                     myXeraUsername : username,
//                     myXeraAddress : userData.public_key
//                 }
//                 const authToken = jwt.sign({ xeraJWT }, jwtSecret, { expiresIn: "2d" });
//                 return res.status(200).json({ success: true, message: `${username} Successfully Login Full Access`, authToken: authToken})
//             } else {
//                 return res.status(400).json({ success: false, message: "No user found in that key phrase"})
//             }
//         } else {
//             return res.status(400).json({ success: false, message: "No user found in that key phrase"})
//         }
//     } catch (error) {
//         return res.status(500).json({ success: false, message: "request error"})
//     }
// })

app.post('/xera/v1/api/users/users-list', async (req,res) => {
    const { apikey } = req.body
    try {
        const checkModeration = await getDevFromCache(apikey)
        
        if (checkModeration) {
            if (checkModeration.xera_moderation === "creator") {
                const [users] = await db.query(`
                    SELECT 
                    xera_user_display.xera_wallet,
                    xera_user_accounts.username
                    FROM xera_user_display
                    INNER JOIN xera_user_accounts 
                    ON xera_user_display.xera_wallet = xera_user_accounts.xera_wallet COLLATE utf8mb4_unicode_ci
                `); 
                
                return res.status(200).json({ success: true, data: users})
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

app.post('/xera/v1/api/users/user-task/referrals', async (req, res) => {
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
                const [userstask] = await db.query(`
                    SELECT 
                        xera_user_accounts.username,
                        xera_user_accounts.xera_wallet, 
                        xera_user_display.xera_nft_meta,
                        xera_user_tasks.xera_task,
                        xera_user_tasks.xera_points
                    FROM xera_user_accounts
                    INNER JOIN xera_user_tasks 
                    ON BINARY xera_user_accounts.username = BINARY xera_user_tasks.username COLLATE utf8mb4_unicode_ci
                    INNER JOIN xera_user_display 
                    ON xera_user_accounts.xera_wallet = xera_user_display.xera_wallet COLLATE utf8mb4_unicode_ci
                `);
                
                if (userstask.length > 0) {
                    const referralFilter = userstask.filter(user => user.xera_task === "Referral Task");
                    const combinedArray = Object.values(
                        referralFilter.reduce((acc, item) => {
                            const { username, xera_wallet, xera_nft_meta } = item;
                            if (!acc[username]) {
                                acc[username] = {
                                    username,
                                    xera_wallet, 
                                    xera_nft_meta, 
                                    count: 0,
                                };
                            }
                            acc[username].count += 1;
                            return acc;
                        }, {})
                    );
                    const sortedData = combinedArray.sort((a, b) => b.count - a.count);
                    
                    // Pagination logic
                    const startIndex = (page - 1) * limit;
                    const endIndex = page * limit;
                    const paginatedData = sortedData.slice(startIndex, endIndex);
                    
                    return res.status(200).json({ success: true, data: paginatedData });
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

// app.post('/xera/v1/api/users/user-tasks/ranking', async (req, res) => {
//     const { request } = req.body;
    
//     if (!request) {
//         res.status(400).json({ success: false, message: "no request found"})
//     }
//     const apikey = request.api
//     const limit = request.limit
//     const page = request.page
//     try {
//         const checkModeration = await getDevFromCache(apikey)
//         if (checkModeration) {
//             if (checkModeration.xera_moderation === "creator") {
//                 const [userstask] = await db.query(`
//                     SELECT 
//                         xera_user_accounts.username, 
//                         xera_user_accounts.xera_wallet, 
//                         xera_user_display.xera_nft_meta, 
//                         xera_user_tasks.xera_task, 
//                         xera_user_tasks.xera_points 
//                     FROM xera_user_accounts 
//                     INNER JOIN xera_user_tasks 
//                     ON BINARY xera_user_accounts.username = BINARY xera_user_tasks.username 
//                     INNER JOIN xera_user_display 
//                     ON xera_user_accounts.xera_wallet = xera_user_display.xera_wallet
//                 `);

//                 if (userstask.length > 0) {
//                     const result = {};

//                     // Combine data for the same username
//                     userstask.forEach(({ username, xera_wallet, xera_task, xera_points }) => {
//                         if (!result[username]) {
//                             result[username] = { username, xera_wallet, referralTaskCount: 0, totalPoints: 0 };
//                         }
//                         result[username].totalPoints += Number(xera_points);
//                         if (xera_task === 'Referral Task') {
//                             result[username].referralTaskCount += 1;
//                         }
//                     });

//                     // Convert the result to an array and sort by totalPoints (descending)
//                     const sortedData = Object.values(result)
//                         .sort((a, b) => b.totalPoints - a.totalPoints)
//                         .map((item, index) => ({ ...item, rank: index + 1 }));

//                     const filtereddata = sortedData.filter(xerapoints => Number(xerapoints.totalPoints) > 0);

//                     // Pagination logic
//                     const startIndex = (page - 1) * limit;
//                     const endIndex = page * limit;
//                     const paginatedData = filtereddata.slice(startIndex, endIndex);
                    
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

app.post('/xera/v1/api/user/tasks/all-task', authenticateToken, async (req,res) => {
    const {user} = req.body;
    
    if (!user) {
        return res.status(403).json({ success: false, message: "invalid request"})
    }

    try {
        const [transactions] = await db.query('SELECT * FROM xera_user_tasks WHERE BINARY username = ?',[user]);
        const [connectedWallet] = await db.query('SELECT * FROM xera_user_accounts WHERE BINARY username = ?',[user]);
        
        if (transactions) {
            const filterTelegram = transactions.filter(data => data.xera_task === "Telegram Task");
            const filterTwitter = transactions.filter(data => data.xera_task === "Twitter Task");
            const filterWalletConnect = transactions.filter(data => data.xera_task === "Wallet Connect Task");
            
            const filterSubsTamago = transactions.filter(data => data.xera_task === "Subscribe - @MikeTamago");
            const filterAlrock = transactions.filter(data => data.xera_task === "Subscribe - @ALROCK");
            const followTamago = transactions.filter(data => data.xera_task === "Follow - @BRGYTamago");
            const followAlrock = transactions.filter(data => data.xera_task === "Follow - @ALrOck14");
            const filterSubsCryp = transactions.filter(data => data.xera_task === "Subscribe - @CrypDropPh")
            const filterSubsKim = transactions.filter(data => data.xera_task === "Subscribe - @kimporsha11")
            const filterFacebook = transactions.filter(data => data.xera_task === "Facebook Task")
            const filterTelegram2 = transactions.filter(data => data.xera_task === "Telegram 2 Task")
            const filterTiktok = transactions.filter(data => data.xera_task === "TikTok Task")
            const ffilterBluesky = transactions.filter(data => data.xera_task === "Bluesky Task")
            const filterTXERA = transactions.filter(data => data.xera_task === "TXERA Claim Task");

            let alltask = {};

            if (filterTXERA.length > 0) {
                const txeracount = filterTXERA.reduce((latest, current) => {
                    return new Date(current.xera_completed_date) > new Date(latest.xera_completed_date) ? current : latest;
                })
                alltask.claimtask = txeracount.xera_status;
            }
            
            if (filterFacebook.length > 0) {
                filterFacebook.forEach(item => {
                    alltask.facebooktask = item.xera_status;
                });
            }
            
            if (filterTelegram2.length > 0) {
                filterTelegram2.forEach(item => {
                    alltask.telegramtask2 = item.xera_status;
                });
            }
            
            if (filterTiktok.length > 0) {
                filterTiktok.forEach(item => {
                    alltask.tiktoktask = item.xera_status;
                });
            }

            if (ffilterBluesky.length > 0) {
                ffilterBluesky.forEach(item => {
                    alltask.blueskytask = item.xera_status;
                });
            }

            if (filterSubsCryp.length > 0) {
                filterSubsCryp.forEach(item => {
                    alltask.subsCrypdropPh = item.xera_status;
                });
            }
            
            if (filterSubsKim.length > 0) {
                filterSubsKim.forEach(item => {
                    alltask.subsKimporsha11 = item.xera_status;
                });
            }

            if (filterTelegram.length > 0) {
                filterTelegram.forEach(item => {
                    alltask.telegramtask = item.xera_status;
                });
            }

            if (filterSubsTamago.length > 0) {
                filterSubsTamago.forEach(item => {
                    alltask.subsTamago = item.xera_status;
                });
            }

            if (filterAlrock.length > 0) {
                filterAlrock.forEach(item => {
                    alltask.subsalrock = item.xera_status;
                });
            }

            if (followTamago.length > 0) {
                followTamago.forEach(item => {
                    alltask.followTamago = item.xera_status;
                });
            }

            if (followAlrock.length > 0) {
                followAlrock.forEach(item => {
                    alltask.followalrock = item.xera_status;
                });
            }

            if (filterTwitter.length > 0) {
                filterTwitter.forEach(item => {
                    alltask.twittertask = item.xera_status;
                });
            }

            if (filterWalletConnect.length > 0) {
                filterWalletConnect.forEach(item => {
                    alltask.walletConnect = item.xera_status;
                });
            }

            if (connectedWallet.length > 0) {
                const ethWallet = connectedWallet[0].eth_wallet
                if (ethWallet) {
                    alltask.ethWallet = "true";
                }
            }
            if (connectedWallet.length > 0) {
                const ethWallet = connectedWallet[0].sol_wallet
                if (ethWallet) {
                    alltask.solWallet = "true";
                }
            }

            

            return res.status(200).json({ success: true, data: alltask, claimData: filterTXERA.xera_completed_date})
        } else {
            return res.status(404).json({ success:false, message : "no transaction found"})
        }
    } catch (error) {
        return res.status(500).json({ success: false, message: "request error", error: error})
    }
})

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

app.post('/xera/v1/api/users/all-participant',async (req, res) => {
    const { apikey } = req.body;

    if (!apikey) {
        return res.status(400).json({ success: false, message: "No request found" });
    }

    try {
        const checkModeration = await getDevFromCache(apikey)
        
        if (checkModeration) {
            if (checkModeration.xera_moderation === "creator") {
                const [userParticipants] = await db.query(`
                    SELECT DISTINCT xera_user_accounts.username
                    FROM 
                        xera_user_accounts 
                    INNER JOIN 
                        xera_user_tasks ON BINARY xera_user_accounts.username = BINARY xera_user_tasks.username 
                `);

                if (userParticipants.length > 0) {
                    const uniqueParticipantCount = userParticipants.length;
                    return res.status(200).json({ success: true, message: "Successfully retrieved data count", participantCount: uniqueParticipantCount });
                } else {
                    return res.status(404).json({ success: false, message: "no tasks found" });
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
});

// app.post('/xera/v1/api/user/current-rank', authenticateToken, async (req, res) => {
//     const { user } = req.body;

//     if (!user) {
//         return res.status(403).json({ success: false, message: "Invalid request" });
//     }

//     try 
//         {const [userRankings] = await db.query(`
//             SELECT t.username, MAX(t.xera_wallet) AS xera_wallet, SUM(t.xera_points) AS total_points, 
//                 SUM(CASE WHEN t.xera_task = 'Referral Task' THEN 1 ELSE 0 END) AS referral_task_count
//             FROM xera_user_tasks t
//             WHERE DATE(t.xera_completed_date) BETWEEN '2024-09-28' AND '2024-12-20'
//             GROUP BY BINARY t.username
//             ORDER BY total_points DESC
//         `);
        
//         // Find the specific user's rank
//         const userRank = userRankings.findIndex(rankUser => rankUser.username === user) + 1;
//         const userTotalPoints = userRankings.find(rankUser => rankUser.username === user)?.total_points;
        
//         if (userRank > 0 && userTotalPoints) {
//             return res.status(200).json({ 
//                 success: true, 
//                 message: "Successfully retrieved user rank", 
//                 username: user, 
//                 rank: userRank,
//                 totalPoints: userTotalPoints 
//             });
//         } else {
//             return res.status(404).json({ success: false, message: "User not found" });
//         }
        
//     } catch (error) {
//         return res.status(500).json({ success: false, message: "Request error", error: error.message });
//     }
// });

// app.post('/xera/v1/api/user/transactions', authenticateToken,async (req, res) => {
//     const { user } = req.body;
    
//     if (!user) {
//         return res.status(403).json({ success: false, message: "Invalid request" });
//     }
//     const page = 1
//     const limit = 50
//     try {
//         const offset = (page - 1) * limit;
//         const [transactions] = await db.query(
//             'SELECT * FROM xera_network_transactions WHERE receiver_address = ? OR sender_address = ? ORDER BY transaction_date DESC LIMIT ? OFFSET ?', 
//             [user, user, limit, offset]
//         );

//         if (transactions.length > 0) {
//             const cleanedData = transactions.map(({ id, transaction_origin, transaction_token_id, transaction_validator, transaction_date, ...clean }) => clean);
//             return res.status(200).json({ success: true, data: cleanedData });
//         } else {
//             return res.status(404).json({ success: false, message: "No transactions found" });
//         }
        
//     } catch (error) {
//         return res.status(500).json({ success: false, message: "Request error", error: error });
//     }
// });

// app.post('/xera/v1/api/user/balance', authenticateToken,async (req,res) => {
//     const {user} = req.body;
//     if (!user) {
//         return res.status(403).json({ success: false, message: "invalid request"})
//     }

//     try {
//         const [transactions] = await db.query( 'SELECT * FROM xera_network_transactions WHERE receiver_address = ? OR sender_address = ?',[user,user]);
//         const [tokenList] = await db.query("SELECT * FROM xera_asset_token")
        
//         if (tokenList.length > 0) {
//             const balances = tokenList.map((token) => {
//                 const { token_id } = token;
                
//                 // Calculate total sent for the current token
//                 const totalSend = transactions
//                 .filter((tx) => 
//                     tx.transaction_token_id === token_id && 
//                     tx.sender_address === user
//                 )
//                 .reduce((total, tx) => total + parseFloat(tx.transaction_amount), 0);

//                 // Calculate total received for the current token
//                 const totalReceive = transactions
//                 .filter((tx) => 
//                     tx.transaction_token_id === token_id && 
//                     tx.receiver_address === user
//                 )
//                 .reduce((total, tx) => total + parseFloat(tx.transaction_amount), 0);
//                 // Calculate net balance
//                 const totalBalance = (totalReceive - totalSend).toFixed(2);
        
//                 return { ...token, totalBalance };
//             });

//             // npx update-browserslist-db@latest
            
//             const cleanedData = balances.map(({ id, token_id, token_owner, token_symbol, token_decimal, token_supply, token_circulating, token_info, ...clean}) => clean)
            
//             return res.status(200).json({ success: true, data: cleanedData})
//         } else {
//             return res.status(404).json({ success:false, message : "no balance found"})
//         }
        
//     } catch (error) {
//         return res.status(500).json({ success: false, message: "request error", error: error})
//     }
    
// })

// app.post('/xera/v1/api/user/following', authenticateToken, async (req,res) => {
//     const {user} = req.body;
//     if (!user) {
//         return res.status(403).json({ success: false, message: "invalid request"})
//     }

//     try {
//         const [userFollower] = await db.query(`
//             SELECT 
//             xera_user_following.xera_wallet,
//             xera_user_following.*, 
//             xera_user_display.*
//             FROM xera_user_following
//             INNER JOIN xera_user_display 
//             ON xera_user_following.xera_wallet = xera_user_display.xera_wallet COLLATE utf8mb4_unicode_ci
//         `);
//         if (userFollower.length > 0) {
//             const cleanedData = userFollower.map(({ id, ...clean}) => clean)
//             return res.status(200).json({ success: true, data: cleanedData})
//         } else {
//             return res.status(404).json({ success:false, message : "no followers found"})
//         }
//     } catch (error) {
//         return res.status(500).json({ success: false, message: "request error", error: error})
//     }
    
// })

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

// app.post('/xera/v1/api/token/faucet-claim', authenticateToken, async (req, res) => {
//     const { username, txHash, sender, receiver, command, amount, token, tokenId } = req.body;
    
  
//     if (!username || !txHash || !sender || !receiver || !command || !amount || !token || !tokenId) {
//       return res.status(400).json({ success: false, message: 'Incomplete transaction data.' });
//     }
  
//     const txLocalDate = new Date().toISOString().slice(0, 19).replace('T', ' ');
    
//     try {
  
//       // Step 1: Check for recent transactions
//       const [lastTransaction] = await db.query(
//         'SELECT transaction_date, transaction_hash FROM xera_network_transactions WHERE receiver_address = ? ORDER BY transaction_date DESC LIMIT 1',
//         [receiver]
//       );
  
//       let transactionOrigin = 'Genesis Transaction';
//       if (lastTransaction.length > 0) {
//         const lastTxDate = new Date(lastTransaction[0].transaction_date).getTime()
//         const dateNow = (new Date()).getTime()
        
//         const timeDiff = dateNow - lastTxDate;
        
  
//         // Block if the last transaction is within 12 hours
//         if (timeDiff < 43200000) { // 12 hours in milliseconds
//           const timeRemaining = new Date(timeDiff).toISOString().substr(11, 8);
          
//           return res.status(400).json({success: false, message: `Claim again after ${timeRemaining}`,});
//         } else {
//             transactionOrigin = lastTransaction[0].transaction_hash;
//             // Step 2: Retrieve block details
//             const [blockData] = await db.query(
//                 'SELECT current_block, block_validator FROM xera_network_blocks ORDER BY id DESC LIMIT 1'
//             );
            
//             if (blockData.length > 0) {
//                 const { current_block: txBlock, block_validator: validator } = blockData[0];
//                 const [incrementBlockCount] = await db.query('UPDATE xera_network_blocks SET block_transactions = block_transactions + 1 WHERE current_block = ?',[txBlock]);
//                 if (incrementBlockCount.affectedRows > 0) {
//                     // Step 3: Insert new transaction
//                     const [addTransaction] = await db.query(
//                         'INSERT INTO xera_network_transactions (transaction_block, transaction_origin, transaction_hash, sender_address, receiver_address, transaction_command, transaction_amount, transaction_token, transaction_token_id, transaction_validator, transaction_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
//                         [txBlock, transactionOrigin, txHash, sender, receiver, command, amount, token, tokenId, validator, txLocalDate]
//                     );
//                     if (addTransaction.affectedRows > 0) {
//                         // Step 4: Update token circulation
//                         const [currentToken] = await db.query(
//                             'SELECT token_circulating FROM xera_asset_token WHERE token_symbol = ?',
//                             [token]
//                         );
//                         if (currentToken.length > 0) {
//                             const newCirculating = parseInt(currentToken[0].token_circulating) + amount;
            
//                             const [updateTokenCirculating] = await db.query(
//                                 'UPDATE xera_asset_token SET token_circulating = ? WHERE token_id = ?',
//                                 [newCirculating, tokenId]
//                             );
//                             if (updateTokenCirculating.affectedRows > 0) {
//                                 // Step 5: Record task completion
//                                 const [recordTask] = await db.query(
//                                     'INSERT INTO xera_user_tasks (username, xera_wallet, xera_task, xera_status, xera_points) VALUES (?, ?, ?, ?, ?)',
//                                     [username, receiver, 'TXERA Claim Task', 'ok', '1250']
//                                 );
//                                 if (recordTask.affectedRows > 0) {
//                                     res.json({ success: true, message: '1 TXERA Claimed Successfully.' });
//                                 } else {
//                                     res.status(400).json({success:false, message: "Error inserting record"})
//                                 }
//                             } else {
//                                 res.status(400).json({success:false, message: "Error updating token circulation"})
//                             }
//                         } else {
//                             res.status(400).json({success:false, message: "Token not found or mismatched token symbol."})
//                         }
//                     } else {
//                         res.status(400).json({success:false, message: "Error adding transaction"})
//                     }
//                 } else {
//                 res.status(400).json({ success: false, message: "Error increment count"})
//                 }
//             } else {
//                 res.status(400).json({ success:false, message: 'Block data not found. Transaction aborted.'});
//             }
//         }
  
//       }
  
//     //   // Step 2: Retrieve block details
//     //   const [blockData] = await db.query(
//     //     'SELECT current_block, block_validator FROM xera_network_blocks ORDER BY id DESC LIMIT 1'
//     //   );
//     //   console.log(blockData);
      
//     //   if (blockData.length > 0) {

//     //   } else {
//     //     throw new Error('Block data not found. Transaction aborted.');
//     //   }
  
  
//     //   // Increment block transaction count
//     //   const [incrementBlockCount] = await db.query(
//     //     'UPDATE xera_network_blocks SET block_transactions = block_transactions + 1 WHERE current_block = ?',
//     //     [txBlock]
//     //   );

//     //   if (incrementBlockCount.affectedRows > 0) {
//     //     // Step 3: Insert new transaction
//     //     const [addTransaction] = await db.query(
//     //         'INSERT INTO xera_network_transactions (transaction_block, transaction_origin, transaction_hash, sender_address, receiver_address, transaction_command, transaction_amount, transaction_token, transaction_token_id, transaction_validator, transaction_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
//     //         [txBlock, transactionOrigin, txHash, sender, receiver, command, amount, token, tokenId, validator, txLocalDate]
//     //     );
//     //     if (addTransaction.affectedRows > 0) {
//     //         // Step 4: Update token circulation
//     //         const [currentToken] = await db.query(
//     //             'SELECT token_circulating FROM xera_asset_token WHERE token_symbol = ?',
//     //             [token]
//     //         );
//     //         if (currentToken.length > 0) {
//     //             const newCirculating = currentToken[0].token_circulating + amount;
  
//     //             const [updateTokenCirculating] = await db.query(
//     //                 'UPDATE xera_asset_token SET token_circulating = ? WHERE token_id = ?',
//     //                 [newCirculating, tokenId]
//     //             );
//     //             if (updateTokenCirculating.affectedRows > 0) {
//     //                 // Step 5: Record task completion
//     //                 const [recordTask] = await db.query(
//     //                     'INSERT INTO xera_user_tasks (username, xera_wallet, xera_task, xera_status, xera_points) VALUES (?, ?, ?, ?, ?)',
//     //                     [username, receiver, 'TXERA Claim Task', 'ok', '1250']
//     //                 );
//     //                 if (recordTask.affectedRows > 0) {
//     //                     res.json({ success: true, message: '1 TXERA Claimed Successfully.' });
//     //                 } else {
//     //                     res.status(400).json({success:false, message: "Error inserting record"})
//     //                 }
//     //             } else {
//     //                 res.status(400).json({success:false, message: "Error updating token circulation"})
//     //             }
//     //         } else {
//     //             res.status(400).json({success:false, message: "Token not found or mismatched token symbol."})
//     //         }
//     //     }
//     //   } else {
//     //     res.status(400).json({ success: false, message: "Error increment count"})
//     //   }
//     } catch (err) {
//       res.status(400).json({ success: false, message: err.message });
//     }
// });

// app.post('/xera/v1/api/users/airdrop/full-stats', async (req, res) => {
//     const { apikey } = req.body;
    
//     if (!apikey) {
//         return res.status(400).json({ success: false, message: "No request found" });
//     }

//     try {
//         const checkModeration = await getDevFromCache(apikey);
//         if (checkModeration) {
//             if (checkModeration.xera_moderation === "creator") {
//                 const results = [];

//                 for (let i = 0; i < 10; i++) {
//                     const date = moment().subtract(i, 'days').format('YYYY-MM-DD');
//                     const startDate = `${date} 00:00:00`;
//                     const endDate = `${date} 23:59:59`;

//                     // Get total points for the day
//                     const [pointsRows] = await db.query(
//                         `SELECT SUM(xera_points) AS totalPoints
//                          FROM xera_user_tasks
//                          WHERE xera_completed_date BETWEEN ? AND ?`,
//                         [startDate, endDate]
//                     );

//                     const totalPoints = pointsRows[0]?.totalPoints || 0;

//                     // Get daily participants
//                     const [usersRows] = await db.query(
//                         `SELECT COUNT(DISTINCT username) AS dailyParticipants
//                          FROM xera_user_tasks
//                          WHERE xera_completed_date BETWEEN ? AND ?`,
//                         [startDate, endDate]
//                     );

//                     const dailyParticipants = usersRows[0]?.dailyParticipants || 0;

//                     // Get new users from referral tasks
//                     const [referralRows] = await db.query(
//                         `SELECT COUNT(*) AS newUsers
//                          FROM xera_user_tasks
//                          WHERE xera_completed_date BETWEEN ? AND ?
//                            AND xera_task = 'Referral Task'`,
//                         [startDate, endDate]
//                     );

//                     const newUsers = referralRows[0]?.newUsers || 0;

//                     // Get TXERA claim tasks
//                     const [txeraClaimRows] = await db.query(
//                         `SELECT COUNT(*) AS txeraClaimTasks
//                          FROM xera_user_tasks
//                          WHERE xera_completed_date BETWEEN ? AND ?
//                            AND xera_task = 'TXERA Claim Task'`,
//                         [startDate, endDate]
//                     );

//                     const txeraClaimTasks = txeraClaimRows[0]?.txeraClaimTasks || 0;

//                     // Add the data for the current date to the results array
//                     results.push({
//                         date,
//                         totalPoints,
//                         dailyParticipants,
//                         newUsers,
//                         txeraClaimTasks,
//                     });
//                 }

//                 // Send the response after the loop finishes
//                 return res.status(200).json({
//                     success: true,
//                     message: "Successfully retrieved users data",
//                     usersData: results,
//                 });
//             } else {
//                 return res.status(401).json({ success: false, message: "Unknown request" });
//             }
//         } else {
//             return res.status(401).json({ success: false, message: "Invalid request" });
//         }
//     } catch (error) {
//         return res.status(500).json({ success: false, message: "Request error", error: error.message });
//     }
// });

// app.post('/xera/v1/api/users/airdrop/phase1', async (req,res) => {
//     const { request } = req.body;

//     if (!request) {
//         return res.status(400).json({ success: false, message: "No request found" });
//     }

//     const apikey = request.api;
//     const limit = parseInt(request.limit, 10) || 10; 
//     const page = parseInt(request.page, 10) || 1;

//     if (!apikey) {
//         return res.status(403).json({ success: false, message: "Invalid or missing API key" });
//     }

//     const offset = (page - 1) * limit; 

//     try {
//         const checkModeration = await getDevFromCache(apikey);
//         if (checkModeration) {
//             if (checkModeration.xera_moderation === "creator") {
//                 const [rows] = await db.query(`
//                     SELECT t.username, 
//                         MAX(t.xera_wallet) AS xera_wallet, 
//                         SUM(t.xera_points) AS total_points, 
//                         SUM(CASE WHEN t.xera_task = 'Referral Task' THEN 1 ELSE 0 END) AS referral_task_count
//                     FROM xera_user_tasks t
//                     WHERE DATE(t.xera_completed_date) BETWEEN '2024-09-28' AND '2024-12-20'
//                     GROUP BY t.username
//                     ORDER BY total_points DESC
//                     LIMIT ? OFFSET ?`, [limit, offset]);

//                 // Query to get total number of records
//                 const [totalRows] = await db.query(`
//                     SELECT COUNT(DISTINCT username) AS total
//                     FROM xera_user_tasks
//                     WHERE DATE(xera_completed_date) BETWEEN '2024-09-28' AND '2024-12-20'
//                 `);

//                 const total = totalRows[0]?.total || 0;
//                 const totalPages = Math.ceil(total / limit);

//                 res.status(200).json({
//                     success: true,
//                     data: rows,
//                     message: "data retrieved Successfully",
//                     pagination: {
//                         currentPage: page,
//                         totalPages,
//                         totalRecords: total,
//                         limit
//                     }
//                 });
//             } else {
//                 return res.status(401).json({ success: false, message: "Unknown request" });
//             }
//         } else {
//             return res.status(401).json({ success: false, message: "Invalid request" });
//         }
//     } catch (error) {
//         return res.status(500).json({ success: false, message: "Request error", error: error.message });
//     }

    
// })

// app.post('/xera/v1/api/users/airdrop/participants', async (req,res) => {
//     const { apikey } = req.body;
    
//     if (!apikey) {
//         return res.status(400).json({ success: false, message: "No request found" });
//     }

//     try {
//         const checkModeration = await getDevFromCache(apikey);
//         if (checkModeration) {
//             if (checkModeration.xera_moderation === "creator") {
//                 const [userTask] = await db.query('SELECT COUNT(DISTINCT BINARY username) AS user_participants FROM xera_user_tasks')
//                 if (userTask.length > 0) {
//                     const participantData = userTask[0]
//                     res.status(200).json({ success: true, message: "User tasks successfully retrieve", participantData})
//                 } else {
//                     return res.status(400).json({ success: false, message: "No data retrieve" });
//                 }
//             } else {
//                 return res.status(401).json({ success: false, message: "Unknown request" });
//             }
//         } else {
//             return res.status(401).json({ success: false, message: "Invalid request" });
//         }
//     } catch (error) {
//         return res.status(500).json({ success: false, message: "Request error", error: error.message });
//     }
// })

// app.post('/xera/v1/api/users/airdrop/recent-participant', async (req,res) => {
//     const { apikey } = req.body;
    
//     if (!apikey) {
//         return res.status(400).json({ success: false, message: "No request found" });
//     }

//     try {
//         const checkModeration = await getDevFromCache(apikey);
//         if (checkModeration) {
//             if (checkModeration.xera_moderation === "creator") {
//                 const [recentParticipants] = await db.query(`
//                     SELECT COUNT(DISTINCT BINARY username) AS recent_participants
//                     FROM xera_user_tasks
//                     WHERE xera_completed_date BETWEEN CONCAT(CURDATE(), ' 00:00:00') AND CONCAT(CURDATE(), ' 23:59:59')
//                       AND xera_task != 'TXERA Claim Task'
//                 `);
        
//                 if (recentParticipants.length > 0) {
//                     const participantsData = recentParticipants[0]
//                     res.status(200).json({ success: true, message: "User tasks successfully retrieve", participantsData})
//                 } else {
//                     return res.status(400).json({ success: false, message: "No data retrieve" });
//                 }
//             } else {
//                 return res.status(401).json({ success: false, message: "Unknown request" });
//             }
//         } else {
//             return res.status(401).json({ success: false, message: "Invalid request" });
//         }
//     } catch (error) {
//         return res.status(500).json({ success: false, message: "Request error", error: error.message });
//     }
// })

// app.post('/xera/v1/api/users/node/transaction-history', async (req,res) => {
//     const { apikey } = req.body;
    
//     if (!apikey) {
//         return res.status(400).json({ success: false, message: "No request found" });
//     }

//     try {
//         const checkModeration = await getDevFromCache(apikey);
//         if (checkModeration) {
//             if (checkModeration.xera_moderation === "creator") {
//                 const currentDate = new Date().toISOString().split('T')[0];
//                 const [transactionNode] = await db.query(`
//                     SELECT node_id, node_name, node_owner, node_points, node_txhash, node_txdate
//                     FROM xera_user_node
//                     WHERE node_txdate >= ?
//                 `,[currentDate]);
        
//                 if (transactionNode.length > 0) {
//                     res.status(200).json({ success: true, message: "User tasks successfully retrieve", transaction : transactionNode})
//                 } else {
//                     return res.status(400).json({ success: false, message: "No data retrieve" });
//                 }
//             } else {
//                 return res.status(401).json({ success: false, message: "Unknown request" });
//             }
//         } else {
//             return res.status(401).json({ success: false, message: "Invalid request" });
//         }
//     } catch (error) {
//         return res.status(500).json({ success: false, message: "Request error", error: error.message });
//     }
// })

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});