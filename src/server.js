const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const mysql = require('mysql2/promise')
const cors = require("cors");
const { body, validationResult } = require('express-validator');
require('dotenv').config();
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit')
const app = express();
const port = 5001;
const axios = require('axios')

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

const jwtDecode = (token) => {
  try {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
      return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));

    return JSON.parse(jsonPayload);
  } catch (error) {
    throw new Error('Invalid token specified');
  }
};

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, 
  max: 5, 
  message: "Too many requests from this IP, please try again later."
});

const Loginlimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 5, 
    message: "Too many login attempts from this account, please try again later."
});

const authenticateAPIToken = (req, res, next) => {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1]; // Extract token from "Bearer <token>"

    if (!token) {
        return res.status(401).json({ success: false, message: "Authentication token is required" });
    }

    jwt.verify(token, jwtAPISecret, (err, decoded) => {
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
    //host: '2a02:4780:28:feaa::1',  // use this in production
    host: process.env.DB_HOST,
    user: process.env.DB_USER,           
    password: process.env.DB_PASSWORD,            
    database: process.env.DB_DATABASE,    
    waitForConnections: true,
    connectTimeout: 20000, 
    port: 3306,               
    connectionLimit: 10,  
    queueLimit: 0          
  });

function generateRandomString(length) {
    return crypto.randomBytes(length).toString('hex').slice(0, length);
}

// const apitokn = "xeraAPI-"+generateRandomString(10)+"-"+generateRandomString(20)
// console.log(apitokn);


async function testConnection() {
    try {
        const connection = await db.getConnection();
        console.log('Database connection successful!');
        connection.release(); // Release the connection back to the pool
    } catch (error) {
        console.error('Database connection failed:', error.message);
    }
}

testConnection();

app.post("/xera/v1/api/generate/access-token", async (req,res) => {
    const {apikey} = req.body;
    
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

app.post("/xera/v1/api/user/check-username", async (req,res) => {
    const {username} = req.body;
    console.log(username);

    if (!username) {
        return res.status(400).json({ success: false, message: "please complete all the fields"});
    }

    try {
        const [checkuser] = await db.query(`SELECT * FROM xera_user_accounts WHERE BINARY username = ?`,[username])
        if (checkuser.length > 0) {
            return res.status(400).json({ success: false, message: 'Username already exists' });
        } else {
            return res.status(200).json({ success: true, message: 'Username is available' });
        }
    } catch (error) {
        res.status(500).json({ success: false, message: 'request error', error: error.message }); 
    }
})

app.post("/xera/v1/api/user/register",authenticateAPIToken, async (req,res) => {
    const { username } = req.body;
    
    if (!username) {
        return res.status(400).json({ success: false, message: "please complete all the fields"});
    }

    try {
    
        const customerID = 'skms_' + generateRandomString(10);
        const { email, mobileno, username, password, referral,region } = req.body;
    
        let ref
        
        const usernameCheckSql = "SELECT * FROM sk_customer_credentials WHERE BINARY user_username = ?";
        const [usernameCheckResults] = await db.query(usernameCheckSql, [username]);
        if (usernameCheckResults.length > 0) {
          return res.status(400).json({ success: false, message: 'Username already exists' });
        }
    
        const emailCheckSql = "SELECT * FROM sk_customer_credentials WHERE BINARY user_email = ?";
        const [emailCheckResults] = await db.query(emailCheckSql, [email]);
        if (emailCheckResults.length > 0) {
          return res.status(400).json({ success: false, message: 'Email already exists' });
        }
    
        if (mobileno !== "no phone added") {
          const mobileCheckSql = "SELECT * FROM sk_customer_credentials WHERE user_mobileno = ?";
          const [mobileCheckResults] = await db.query(mobileCheckSql, [mobileno]);
          if (mobileCheckResults.length > 0) {
            return res.status(400).json({ success: false, message: 'Mobile number already exists' });
          }
        }
    
        
        if (referral !== "") {
          const referralCheckSql = "SELECT * FROM sk_participant_info WHERE user_participant_referral = ?";
          const [referralCheckResults] = await db.query(referralCheckSql, [referral]);
          if (referralCheckResults.length === 0) {
            return res.status(400).json({ success: false, message: 'Referral Code Does not exist' });
          }
        }
    
        if (referral === '') {
          ref = 'def'
        } else (
          ref = referral
        )
    
        const hash_pass = await bcrypt.hash(password, 10);
        const generatedSession = generateRandomString(10);
        const userRole = 'customer';
        const loginSession = 'sknms' + generatedSession + 'log';
        const activity = 'active';
    
        const insertSql = "INSERT INTO sk_customer_credentials (user_customerID, user_mobileno, user_email, user_username, user_password, user_role, user_referral,user_region, user_activity, user_loginSession) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        const [insertResult] = await db.query(insertSql, [customerID, mobileno, email, username, hash_pass, userRole, ref, region, activity, loginSession]);
    
        if (insertResult.affectedRows > 0) {
    
          const insertInfo = "INSERT INTO sk_customer_info (user_customerID) VALUES (?)";
          const [insertInfoResult] = await db.query(insertInfo, [customerID]);
    
          if (insertInfoResult.affectedRows > 0) {
            const authToken = jwt.sign({ customerID }, jwtSecret, { expiresIn: "7d" });
            return res.status(200).json({ success: true, message: 'Customer successfully registered', loginSession, token: authToken });
          } else {
            return res.status(500).json({ success: false, message: 'Error registering user' });
          }
        } else {
          return res.status(500).json({ success: false, message: 'Error registering user' });
        }
      } catch (error) {
        res.status(500).json({ success: false, message: 'request error', error: error.message }); // Return specific error message
      }
})

app.post('/xera/v1/api/user/login-basic',authenticateAPIToken, async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(403).json({ success: false, message: "Request Error. Input Field"})
    }
    
    try {

        const [user] = await db.query("SELECT * FROM xera_user_accounts WHERE BINARY username = ?", [username]);
        
        if (user.length > 0) {
            const userData = user[0]
            const dataPass = userData.password
            
            if (dataPass.slice(0,4) === "$2y$") {
                const normalizedHash = dataPass.replace("$2y$", "$2a$");
                
                if (await bcrypt.compare(password, normalizedHash)) {
                    const xeraJWT = {
                        loginState : "basic",
                        isloggedIn : "true",
                        myXeraUsername : userData.username,
                        myXeraAddress : userData.xera_wallet
                    }
                    const authToken = jwt.sign({ xeraJWT }, jwtSecret, { expiresIn: "2d" });
                    return res.status(200).json({ success: true, message: `${user[0].username} Successfully Login`, authToken: authToken})
                } else {
                    return res.status(401).json({ success: false, message: 'Wrong password' });
                }
            } else {
                if (await bcrypt.compare(password, dataPass)) {
                    const xeraJWT = {
                        loginState : "basic",
                        isloggedIn : "true",
                        myXeraUsername : userData.username,
                        myXeraAddress : userData.xera_wallet
                    }
                    const authToken = jwt.sign({ xeraJWT }, jwtSecret, { expiresIn: "2d" });
                    return res.status(200).json({ success: true, message: `${user[0].username} Successfully Login Basic Account`, authToken: authToken})
                } else {
                    return res.status(401).json({ success: false, message: 'Wrong password' });
                }
            }
            
        } else {
            return res.status(403).json({ success: false, message: "no user found"})
        }
    } catch (error) {
        return res.status(500).json({ success: false, message: "request error"})
    }
})

app.post('/xera/v1/api/user/login-prKey',authenticateAPIToken, async (req, res) => {
    const { privateKey } = req.body;
    
    
    if (!privateKey) {
        return res.status(403).json({ success: false, message: "Request Error. No private key received"})
    }

    try {
        const [user] = await db.query("SELECT * FROM xera_user_wallet WHERE BINARY private_key = ?", [privateKey]);
        
        if (user.length > 0) {
            const userData = user[0]
            const [getUsername] = await db.query("SELECT * FROM xera_user_accounts WHERE BINARY xera_wallet = ?", [userData.public_key]);
            if (getUsername.length > 0) {
                const userarray = getUsername[0]
                const username = userarray.username
                const xeraJWT = {
                    loginState : "basic",
                    isloggedIn : "true",
                    myXeraUsername : username,
                    myXeraAddress : userData.public_key
                }
                const authToken = jwt.sign({ xeraJWT }, jwtSecret, { expiresIn: "2d" });
                return res.status(200).json({ success: true, message: `${username} Successfully Login Full Access`, authToken: authToken})
            } else {
                return res.status(400).json({ success: false, message: "No user found in that key phrase"})
            }
        } else {
            return res.status(403).json({ success: false, message: "invalid key phrase"})
        }
    } catch (error) {
        return res.status(500).json({ success: false, message: "request error", error: error})
    }
})

app.post('/xera/v1/api/user/login-phrase',authenticateAPIToken, async (req, res) => {
    const { seedPhrase } = req.body;

    if (!seedPhrase) {
        return res.status(403).json({ success: false, message: "Request Error. No private key received"})
    }
    
    const seed = JSON.parse(seedPhrase)

    try {
        const sqlPhrase = "SELECT * FROM xera_user_wallet WHERE BINARY word1 = ? AND word2 = ? AND word3 = ? AND word4 = ? AND word5 = ? AND word6 = ? AND word7 = ? AND word8 = ? AND word9 = ? AND word10 = ? AND word11 = ? AND word12 = ?"
        const [user] = await db.query(sqlPhrase, [seed.seedWord1,seed.seedWord2,seed.seedWord3,seed.seedWord4,seed.seedWord5,seed.seedWord6,seed.seedWord7,seed.seedWord8,seed.seedWord9,seed.seedWord10,seed.seedWord11,seed.seedWord12]);

        if (user.length > 0) {
            const userData = user[0]
            
            const [getUsername] = await db.query("SELECT * FROM xera_user_accounts WHERE BINARY xera_wallet = ?", [userData.public_key]);
            
            if (getUsername.length > 0) {
                const userarray = getUsername[0]
                
                const username = userarray.username
                const xeraJWT = {
                    loginState : "basic",
                    isloggedIn : "true",
                    myXeraUsername : username,
                    myXeraAddress : userData.public_key
                }
                const authToken = jwt.sign({ xeraJWT }, jwtSecret, { expiresIn: "2d" });
                return res.status(200).json({ success: true, message: `${username} Successfully Login Full Access`, authToken: authToken})
            } else {
                return res.status(400).json({ success: false, message: "No user found in that key phrase"})
            }
        } else {
            return res.status(400).json({ success: false, message: "No user found in that key phrase"})
        }
    } catch (error) {
        return res.status(500).json({ success: false, message: "request error"})
    }
})

app.post('/xera/v1/api/users/users-list', async (req,res) => {
    const { apikey } = req.body
    try {
        const [checkModeration] = await db.query('SELECT * FROM xera_developer WHERE BINARY xera_api = ?', [apikey])
        if (checkModeration.length > 0) {
            if (checkModeration[0].xera_moderation === "creator") {
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
    const { apikey, page = 1, limit = 50 } = req.body;
    const offset = (page - 1) * limit;

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
                    LIMIT ?, ?
                `, [offset, limit]);
                
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
                    return res.status(200).json({ success: true, data: sortedData });
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

app.post('/xera/v1/api/users/user-tasks/ranking', async (req, res) => {
    const { apikey, page = 1, limit = 100 } = req.body;
    const offset = (page - 1) * limit;

    try {
        const [checkModeration] = await db.query('SELECT * FROM xera_developer WHERE BINARY xera_api = ?', [apikey]);
        if (checkModeration.length > 0) {
            if (checkModeration[0].xera_moderation === "creator") {
                const [userstask] = await db.query(`SELECT xera_user_accounts.username, xera_user_accounts.xera_wallet, xera_user_display.xera_nft_meta, xera_user_tasks.xera_task, xera_user_tasks.xera_points FROM xera_user_accounts INNER JOIN xera_user_tasks ON BINARY xera_user_accounts.username = BINARY xera_user_tasks.username INNER JOIN xera_user_display ON xera_user_accounts.xera_wallet = xera_user_display.xera_wallet LIMIT ?, ?`, [offset, limit]);
                
                if (userstask.length > 0) {
                    const result = {};

                    // Combine data for the same username
                    userstask.forEach(({ username, xera_wallet, xera_task, xera_points }) => {
                        if (!result[username]) {
                            result[username] = { username, xera_wallet, referralTaskCount: 0, totalPoints: 0 };
                        }
                        result[username].totalPoints += Number(xera_points);
                        if (xera_task === 'Referral Task') {
                            result[username].referralTaskCount += 1;
                        }
                    });

                    // Convert the result to an array and sort by totalPoints (descending)
                    const sortedData = Object.values(result)
                        .sort((a, b) => b.totalPoints - a.totalPoints)
                        .map((item, index) => ({ ...item, rank: index + 1 }));

                    const filtereddata = sortedData.filter(xerapoints => Number(xerapoints.totalPoints) > 0);
                    
                    return res.status(200).json({ success: true, data: filtereddata });
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

app.post('/xera/v1/api/users/user-tasks/all-task',authenticateToken, async (req,res) => {
    const {user} = req.body;
    
    if (!user) {
        return res.status(403).json({ success: false, message: "invalid request"})
    }

    try {
        const [transactions] = await db.query('SELECT * FROM xera_user_tasks WHERE BINARY username = ?',[user]);
        
        const [connectedWallet] = await db.query('SELECT * FROM xera_user_accounts WHERE BINARY username = ?',[user]);
        
        if (transactions.length > 0) {
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
        console.log(error);
        
        return res.status(500).json({ success: false, message: "request error", error: error})
    }
})

app.post('/xera/v1/api/users/all-wallet', async (req,res) => {
    const {apikey} = req.body; 
    
    try {
        const [checkModeration] = await db.query('SELECT * FROM xera_developer WHERE BINARY xera_api = ?', [apikey]);
        if (checkModeration.length > 0) {
            if (checkModeration[0].xera_moderation === "creator") {
                const [countWallet] = await db.query('SELECT * FROM xera_user_accounts')
                if (countWallet.length > 0) {
                    res.status(200).json({ success:true, message: "Successfully count all wallet", walletCount: countWallet.length})
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

app.post('/xera/v1/api/users/all-participant', async (req, res) => {
    const { apikey } = req.body;
    
    try {
        const [checkModeration] = await db.query('SELECT * FROM xera_developer WHERE BINARY xera_api = ?', [apikey]);
        if (checkModeration.length > 0) {
            if (checkModeration[0].xera_moderation === "creator") {
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

app.post('/xera/v1/api/user/current-rank', authenticateToken, async (req, res) => {
    const { user } = req.body;
    
    if (!user) {
        return res.status(403).json({ success: false, message: "Invalid request" });
    }

    try {
        // Query to get the total points and rank the users
        const [userRankings] = await db.query(`
            SELECT username, SUM(xera_points) as totalPoints
            FROM xera_user_tasks
            GROUP BY username
            ORDER BY totalPoints DESC
        `);

        // Find the specific user's rank
        const userRank = userRankings.findIndex(rankUser => rankUser.username === user) + 1;
        const userTotalPoints = userRankings.find(rankUser => rankUser.username === user)?.totalPoints;

        if (userRank > 0 && userTotalPoints) {
            return res.status(200).json({ 
                success: true, 
                message: "Successfully retrieved user rank", 
                username: user, 
                rank: userRank,
                totalPoints: userTotalPoints 
            });
        } else {
            return res.status(404).json({ success: false, message: "User not found" });
        }
    } catch (error) {
        return res.status(500).json({ success: false, message: "Request error", error: error });
    }
});

app.post('/xera/v1/api/user/transactions', authenticateToken, async (req,res) => {
    const {user} = req.body;
    
    if (!user) {
        return res.status(403).json({ success: false, message: "invalid request"})
    }

    try {
        const [transactions] = await db.query( 'SELECT * FROM xera_network_transactions WHERE receiver_address = ? OR sender_address = ?',[user,user]);

        if (transactions.length > 0) {
            const cleanedData = transactions.map(({ id, transaction_origin, transaction_token_id, transaction_validator, transaction_date, ...clean}) => clean)
            return res.status(200).json({ success: true, data: cleanedData})
        } else {
            return res.status(404).json({ success:false, message : "no transaction found"})
        }
        
    } catch (error) {
        return res.status(500).json({ success: false, message: "request error", error: error})
    }
    
})

app.post('/xera/v1/api/user/balance', authenticateToken, async (req,res) => {
    const {user} = req.body;
    if (!user) {
        return res.status(403).json({ success: false, message: "invalid request"})
    }

    try {
        const [transactions] = await db.query( 'SELECT * FROM xera_network_transactions WHERE receiver_address = ? OR sender_address = ?',[user,user]);
        const [tokenList] = await db.query("SELECT * FROM xera_asset_token")
        
        if (tokenList.length > 0) {
            const balances = tokenList.map((token) => {
                const { token_id } = token;
                
                // Calculate total sent for the current token
                const totalSend = transactions
                .filter((tx) => 
                    tx.transaction_token_id === token_id && 
                    tx.sender_address === user
                )
                .reduce((total, tx) => total + parseFloat(tx.transaction_amount), 0);

                // Calculate total received for the current token
                const totalReceive = transactions
                .filter((tx) => 
                    tx.transaction_token_id === token_id && 
                    tx.receiver_address === user
                )
                .reduce((total, tx) => total + parseFloat(tx.transaction_amount), 0);
                // Calculate net balance
                const totalBalance = (totalReceive - totalSend).toFixed(2);
        
                return { ...token, totalBalance };
            });

            // npx update-browserslist-db@latest
            
            const cleanedData = balances.map(({ id, token_id, token_owner, token_symbol, token_decimal, token_supply, token_circulating, token_info, ...clean}) => clean)
            
            return res.status(200).json({ success: true, data: cleanedData})
        } else {
            return res.status(404).json({ success:false, message : "no balance found"})
        }
        
    } catch (error) {
        return res.status(500).json({ success: false, message: "request error", error: error})
    }
    
})

app.post('/xera/v1/api/user/following', authenticateToken, async (req,res) => {
    const {user} = req.body;
    if (!user) {
        return res.status(403).json({ success: false, message: "invalid request"})
    }

    try {
        const [userFollower] = await db.query(`
            SELECT 
            xera_user_following.xera_wallet,
            xera_user_following.*, 
            xera_user_display.*
            FROM xera_user_following
            INNER JOIN xera_user_display 
            ON xera_user_following.xera_wallet = xera_user_display.xera_wallet COLLATE utf8mb4_unicode_ci
        `);
        if (userFollower.length > 0) {
            const cleanedData = userFollower.map(({ id, ...clean}) => clean)
            return res.status(200).json({ success: true, data: cleanedData})
        } else {
            return res.status(404).json({ success:false, message : "no followers found"})
        }
    } catch (error) {
        return res.status(500).json({ success: false, message: "request error", error: error})
    }
    
})

app.post('/xera/v1/api/token/asset-tokens', async (req,res) => {
    const { apikey } = req.body
    try {
        const [checkModeration] = await db.query('SELECT * FROM xera_developer WHERE BINARY xera_api = ?', [apikey])
        if (checkModeration.length > 0) {
            if (checkModeration[0].xera_moderation === "creator") {
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
    const { apikey, page = 1, limit = 100 } = req.body;
    const offset = (page - 1) * limit;

    try {
        const [checkModeration] = await db.query('SELECT * FROM xera_developer WHERE BINARY xera_api = ?', [apikey]);
        if (checkModeration.length > 0) {
            if (checkModeration[0].xera_moderation === "creator") {
                const [assetTokens] = await db.query(`SELECT * FROM xera_network_transactions LIMIT ?, ?`, [offset, limit]);
                
                if (assetTokens.length > 0) {
                    const sorted = assetTokens.sort((a, b) => b.id - a.id);
                    
                    const cleanedData = sorted.map(({ id, transaction_origin, sender_address, transaction_command, transaction_token, transaction_token_id, transaction_validator, transaction_date, ...clean }) => clean);
                    return res.status(200).json({ success: true, data: cleanedData });
                } else {
                    return res.status(404).json({ success: false, message: "no tokens found" });
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


app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});