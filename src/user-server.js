const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const mysql = require('mysql2/promise')
const cors = require("cors");
const { body, validationResult } = require('express-validator');
require('dotenv').config();
const bcrypt = require('bcrypt');
const app = express();
const port = 5001;
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

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1]; // Extract token from "Bearer <token>"

    if (!token) {
        return res.json({ success: false, message: "Authentication token is required" });
    }

    jwt.verify(token, jwtSecret, (err, decoded) => {
        if (err) {
            if (err.name === "TokenExpiredError") {
                // Handle expired token case
                return res.json({ success: false, message: "Token has expired" });
            }
            if (err.name === "JsonWebTokenError") {
                // Handle invalid token case
                return res.json({ success: false, message: "Invalid token" });
            }
            // Handle other errors
            return res.json({ success: false, message: "Token verification failed" });
        }
        
        req.user = decoded; // Attach decoded user information to the request object
        next(); // Proceed to the next middleware or route handler
    });
};

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

const getUserFromCache = async (username) => {
    let user = cache.get(username);
    if (!user) {
        const [dbUser] = await db.query("SELECT * FROM xera_user_accounts WHERE BINARY username = ?", [username]);
        if (dbUser.length > 0) {
            user = dbUser[0];
            cache.set(username, user);
        }
    }
    return user;
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

app.post("/xera/v1/api/user/check-username" ,async (req,res) => {
    const {username} = req.body;
    
    if (!username) {
        return res.json({ success: false, message: "please complete all the fields"});
    }

    try {
        const user = await getUserFromCache(username) 
        
        if (user) {
            return res.json({ success: false, message: 'Username already exists' });
        } else {
            return res.json({ success: true, message: 'Username is available' });
        }
    } catch (error) {
        res.json({ success: false, message: 'request error' }); 
    }
})

app.post('/xera/v1/api/user/login-basic', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.json({ success: false, message: "Request Error. Input Field"})
    }
    
    try {

        const userData = await getUserFromCache(username);
        
        if (userData) {
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
                    return res.json({ success: true, message: `${userData.username} Successfully Login`, authToken: authToken})
                } else {
                    return res.json({ success: false, message: 'Wrong password' });
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
                    return res.json({ success: true, message: `${userData.username} Successfully Login Basic Account`, authToken: authToken})
                } else {
                    return res.json({ success: false, message: 'Wrong password' });
                }
            }
            
        } else {
            return res.json({ success: false, message: "no user found"})
        }
    } catch (error) {
        return res.json({ success: false, message: "request error"})
    }
})

app.post('/xera/v1/api/user/login-prKey', async (req, res) => {
    const { privateKey } = req.body;
    
    
    if (!privateKey) {
        return res.json({ success: false, message: "Request Error. No private key received"})
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
                return res.json({ success: true, message: `${username} Successfully Login Full Access`, authToken: authToken})
            } else {
                return res.json({ success: false, message: "No user found in that key phrase"})
            }
        } else {
            return res.json({ success: false, message: "invalid key phrase"})
        }
    } catch (error) {
        return res.json({ success: false, message: "request error", error: error})
    }
})

app.post('/xera/v1/api/user/login-phrase', async (req, res) => {
    const { seedPhrase } = req.body;

    if (!seedPhrase) {
        return res.json({ success: false, message: "Request Error. No private key received"})
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
                return res.json({ success: true, message: `${username} Successfully Login Full Access`, authToken: authToken})
            } else {
                return res.json({ success: false, message: "No user found in that key phrase"})
            }
        } else {
            return res.json({ success: false, message: "No user found in that key phrase"})
        }
    } catch (error) {
        return res.json({ success: false, message: "request error"})
    }
})

app.post('/xera/v1/api/user/tasks/all-task', authenticateToken, async (req,res) => {
    const {user} = req.body;
    
    if (!user) {
        return res.json({ success: false, message: "invalid request"})
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
            const filterBluesky = transactions.filter(data => data.xera_task === "Bluesky Task")
            const filterYoutube = transactions.filter(data => data.xera_task === "YouTube Task");
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

            if (filterBluesky.length > 0) {
                filterBluesky.forEach(item => {
                    alltask.blueskytask = item.xera_status;
                });
            }

            if (filterYoutube.length > 0) {
                filterYoutube.forEach(item => {
                    alltask.youtubetask = item.xera_status;
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

            return res.json({ success: true, data: alltask, claimData: filterTXERA.xera_completed_date})
        } else {
            return res.json({ success:false, message : "no transaction found"})
        }
    } catch (error) {
        return res.json({ success: false, message: "request error", error: error})
    }
})

app.post('/xera/v1/api/user/rank-phase1', authenticateToken, async (req, res) => {
    const { user } = req.body;
    
    if (!user) {
        return res.json({ success: false, message: "Invalid request" });
    }

    try {
        const [userRanking] = await db.query(`
            SELECT MAX(username) AS username, MAX(xera_wallet) AS xera_wallet, SUM(CAST(xera_points AS DECIMAL(10))) AS total_points, 
                SUM(CASE WHEN xera_task = 'Referral Task' THEN 1 ELSE 0 END) AS referral_task_count
            FROM xera_user_tasks
            WHERE DATE(xera_completed_date) BETWEEN '2024-09-28' AND '2024-12-18'
            GROUP BY BINARY username
            ORDER BY total_points DESC
        `);
        
         // Find the specific user's rank
         const userRank = userRanking.findIndex(rankUser => rankUser.username === user) + 1;
         const userTotalPoints = userRanking.find(rankUser => rankUser.username === user)?.total_points;
         
         if (userRank > 0 && userTotalPoints) {
             return res.json({ 
                 success: true, 
                 message: "Successfully retrieved user rank", 
                 username: user, 
                 rank: userRank,
                 totalPoints: userTotalPoints 
             });
         } else {
             return res.json({ success: false, message: "User not found" });
         }
        
    } catch (error) {
        return res.json({ success: false, message: "Request error", error: error.message });
    }
});

app.post('/xera/v1/api/user/rank-phase2', authenticateToken, async (req, res) => {
    const { user } = req.body;

    if (!user) {
        return res.json({ success: false, message: "Invalid request" });
    }

    try {
        const [userRanking] = await db.query(`
            SELECT MAX(username) AS username, MAX(xera_wallet) AS xera_wallet, SUM(CAST(xera_points AS DECIMAL(10))) AS total_points, 
                SUM(CASE WHEN xera_task = 'Referral Task' THEN 1 ELSE 0 END) AS referral_task_count
            FROM xera_user_tasks
            WHERE DATE(xera_completed_date) BETWEEN '2024-12-19' AND '2025-02-25'
            GROUP BY BINARY username
            ORDER BY total_points DESC
        `);

        // Find the specific user's rank
        const userRank = userRanking.findIndex(rankUser => rankUser.username === user) + 1;
        const userTotalPoints = userRanking.find(rankUser => rankUser.username === user)?.total_points;
        
        if (userRank > 0 && userTotalPoints) {
            return res.json({ 
                success: true, 
                message: "Successfully retrieved user rank", 
                username: user, 
                rank: userRank,
                totalPoints: userTotalPoints 
            });
        } else {
            return res.json({ success: false, message: "User not found" });
        }
        
    } catch (error) {
        return res.json({ success: false, message: "Request error", error: error.message });
    }
});

app.post('/xera/v1/api/user/rank-phase3', authenticateToken, async (req, res) => {
    const { user } = req.body;

    if (!user) {
        return res.json({ success: false, message: "Invalid request" });
    }

    try {
        const [userRanking] = await db.query(`
            SELECT MAX(username) AS username, MAX(xera_wallet) AS xera_wallet, SUM(CAST(xera_points AS DECIMAL(10))) AS total_points, 
                SUM(CASE WHEN xera_task = 'Referral Task' THEN 1 ELSE 0 END) AS referral_task_count
            FROM xera_user_tasks
            WHERE DATE(xera_completed_date) BETWEEN '2025-02-25' AND '2025-05-30'
            GROUP BY BINARY username
            ORDER BY total_points DESC
        `);

        // Find the specific user's rank
        const userRank = userRanking.findIndex(rankUser => rankUser.username === user) + 1;
        const userTotalPoints = userRanking.find(rankUser => rankUser.username === user)?.total_points;
        
        if (userRank > 0 && userTotalPoints) {
            return res.json({ 
                success: true, 
                message: "Successfully retrieved user rank", 
                username: user, 
                rank: userRank,
                totalPoints: userTotalPoints 
            });
        } else {
            return res.json({ success: false, message: "User not found" });
        }
        
    } catch (error) {
        return res.json({ success: false, message: "Request error", error: error.message });
    }
});

app.post('/xera/v1/api/user/transactions', authenticateToken,async (req, res) => {
    const { user } = req.body;
    
    if (!user) {
        return res.json({ success: false, message: "Invalid request" });
    }
    const page = 1
    const limit = 50
    try {
        const offset = (page - 1) * limit;
        const [transactions] = await db.query(
            'SELECT * FROM xera_network_transactions WHERE receiver_address = ? OR sender_address = ? ORDER BY transaction_date DESC LIMIT ? OFFSET ?', 
            [user, user, limit, offset]
        );

        if (transactions.length > 0) {
            const cleanedData = transactions.map(({ id, transaction_origin, transaction_token_id, transaction_validator, transaction_date, ...clean }) => clean);
            return res.json({ success: true, data: cleanedData });
        } else {
            return res.json({ success: false, message: "No transactions found" });
        }
        
    } catch (error) {
        return res.json({ success: false, message: "Request error", error: error });
    }
});

app.post('/xera/v1/api/user/balance', authenticateToken,async (req,res) => {
    const {user} = req.body;
    if (!user) {
        return res.json({ success: false, message: "invalid request"})
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
            
            return res.json({ success: true, data: cleanedData})
        } else {
            return res.json({ success:false, message : "no balance found"})
        }
        
    } catch (error) {
        return res.json({ success: false, message: "request error", error: error})
    }
    
})

app.post('/xera/v1/api/user/following', authenticateToken, async (req,res) => {
    const {user} = req.body;
    if (!user) {
        return res.json({ success: false, message: "invalid request"})
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
            return res.json({ success: true, data: cleanedData})
        } else {
            return res.json({ success:false, message : "no followers found"})
        }
    } catch (error) {
        return res.json({ success: false, message: "request error", error: error})
    }
    
})

app.post('/xera/v1/api/user/faucet-claim', authenticateToken, async (req, res) => {
    const { username, txHash, sender, receiver, command, amount, token, tokenId } = req.body;
    
    
    if (!username || !txHash || !sender || !receiver || !command || !amount || !token || !tokenId) {
      return res.json({ success: false, message: 'Incomplete transaction data.' });
    }
  
    const txLocalDate = new Date().toISOString().slice(0, 19).replace('T', ' ');
    
    try {
  
      // Step 1: Check for recent transactions
      const [lastTransaction] = await db.query(
        'SELECT transaction_date, transaction_hash FROM xera_network_transactions WHERE receiver_address = ? ORDER BY transaction_date DESC LIMIT 1',
        [receiver]
      );
  
      let transactionOrigin = 'Genesis Transaction';
      if (lastTransaction.length > 0) {
        const lastTxDate = new Date(lastTransaction[0].transaction_date).getTime();
        const dateNow = (new Date()).getTime();

        const timeDiff = dateNow - lastTxDate;

        // Block if the last transaction is within 12 hours
        if (timeDiff < 21600000) { // 6 hours in milliseconds
            const timeRemainingMs = 21600000 - timeDiff;
            const hours = Math.floor(timeRemainingMs / 3600000);
            const minutes = Math.floor((timeRemainingMs % 3600000) / 60000);
            const seconds = Math.floor((timeRemainingMs % 60000) / 1000);

            const timeRemaining = `${hours}h ${minutes}m ${seconds}s`;

            return res.json({ success: false, message: `Claim again after ${timeRemaining}` });
        } else {
            transactionOrigin = lastTransaction[0].transaction_hash;
            // Step 2: Retrieve block details
            const [blockData] = await db.query(
                'SELECT current_block, block_validator FROM xera_network_blocks ORDER BY id DESC LIMIT 1'
            );
            
            if (blockData.length > 0) {
                const { current_block: txBlock, block_validator: validator } = blockData[0];
                const [incrementBlockCount] = await db.query('UPDATE xera_network_blocks SET block_transactions = block_transactions + 1 WHERE current_block = ?',[txBlock]);
                
                if (incrementBlockCount.affectedRows > 0) {
                    // Step 3: Insert new transaction
                    const [addTransaction] = await db.query(
                        'INSERT INTO xera_network_transactions (transaction_block, transaction_origin, transaction_hash, sender_address, receiver_address, transaction_command, transaction_amount, transaction_token, transaction_token_id, transaction_validator, transaction_date, transaction_fee_amount,transaction_fee_token,transaction_fee_token_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                        [txBlock, transactionOrigin, txHash, sender, receiver, command, amount, token, tokenId, validator, txLocalDate, 0.00, '', '']
                    );
                    
                    if (addTransaction.affectedRows > 0) {
                        // Step 4: Update token circulation
                        const [currentToken] = await db.query(
                            'SELECT token_circulating FROM xera_asset_token WHERE token_symbol = ?',
                            [token]
                        );
                        
                        if (currentToken.length > 0) {
                            const newCirculating = parseInt(currentToken[0].token_circulating) + amount;
            
                            const [updateTokenCirculating] = await db.query(
                                'UPDATE xera_asset_token SET token_circulating = ? WHERE token_id = ?',
                                [newCirculating, tokenId]
                            );
                            
                            if (updateTokenCirculating.affectedRows > 0) {
                                // Step 5: Record task completion
                                const [recordTask] = await db.query(
                                    'INSERT INTO xera_user_tasks (username, xera_wallet, xera_task, xera_status, xera_points, xera_telegram_id, xera_twitter_username) VALUES (?, ?, ?, ?, ?, ?, ?)',
                                    [username, receiver, 'TXERA Claim Task', 'ok', '1250', '', '']
                                );
                                
                                if (recordTask.affectedRows > 0) {
                                    res.json({ success: true, message: '1 TXERA Claimed Successfully.' });
                                    
                                } else {
                                    res.json({success:false, message: "Error inserting record"})
                                }
                            } else {
                                res.json({success:false, message: "Error updating token circulation"})
                            }
                        } else {
                            res.json({success:false, message: "Token not found or mismatched token symbol."})
                        }
                    } else {
                        res.json({success:false, message: "Error adding transaction"})
                    }
                } else {
                res.json({ success: false, message: "Error increment count"})
                }
            } else {
                res.json({ success:false, message: 'Block data not found. Transaction aborted.'});
            }
        }
  
      }
    } catch (err) {
      res.json({ success: false, message: err.message });
    }
});

app.post('/xera/v1/api/user/coin/claim', authenticateToken, async (req, res) => {
    const { username, txHash, sender, receiver, command, amount, token, tokenId } = req.body;
    
    if (!username || !txHash || !sender || !receiver || !command || !amount || !token || !tokenId) {
      return res.json({ success: false, message: 'Incomplete transaction data.' });
    }
  
    const txLocalDate = new Date().toISOString().slice(0, 19).replace('T', ' ');
    
    try {
  
      // Step 1: Check for recent transactions
      const [lastTransaction] = await db.query(
        'SELECT transaction_date, transaction_hash FROM xera_network_transactions WHERE receiver_address = ? ORDER BY transaction_date DESC LIMIT 1',
        [receiver]
      );
  
      let transactionOrigin = 'Genesis Transaction';
      if (lastTransaction.length > 0) {
        const [tokenClaimedcheck] = await db.query(`SELECT * FROM xera_network_transactions WHERE sender_address = ? AND receiver_address = ?`,[sender,receiver]);
        // Block if the last transaction is within 12 hours
        if (tokenClaimedcheck.length > 0) { // 12 hours in milliseconds
          return res.json({success: false, message: `Xera Coin already claimed`,});
        } else {
            transactionOrigin = lastTransaction[0].transaction_hash;
            // Step 2: Retrieve block details
            const [blockData] = await db.query(
                'SELECT current_block, block_validator FROM xera_network_blocks ORDER BY id DESC LIMIT 1'
            );
            
            if (blockData.length > 0) {
                const { current_block: txBlock, block_validator: validator } = blockData[0];
                const [incrementBlockCount] = await db.query('UPDATE xera_network_blocks SET block_transactions = block_transactions + 1 WHERE current_block = ?',[txBlock]);
                
                if (incrementBlockCount.affectedRows > 0) {
                    // Step 3: Insert new transaction
                    const [addTransaction] = await db.query(
                        'INSERT INTO xera_network_transactions (transaction_block, transaction_origin, transaction_hash, sender_address, receiver_address, transaction_command, transaction_amount, transaction_token, transaction_token_id, transaction_validator, transaction_date, transaction_fee_amount,transaction_fee_token,transaction_fee_token_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                        [txBlock, transactionOrigin, txHash, sender, receiver, command, amount, token, tokenId, validator, txLocalDate, 0.00, '', '']
                    );
                    
                    if (addTransaction.affectedRows > 0) {
                        // Step 4: Update token circulation
                        const [currentToken] = await db.query(
                            'SELECT token_circulating FROM xera_asset_token WHERE token_symbol = ?',
                            [token]
                        );
                        
                        if (currentToken.length > 0) {
                            const tokenCirculating = parseFloat(currentToken[0].token_circulating).toFixed(8);
                            const amountNumber = parseFloat(amount);
                            const newCirculating = parseFloat(tokenCirculating) + amountNumber;
                            
                            const [updateTokenCirculating] = await db.query(
                                'UPDATE xera_asset_token SET token_circulating = ? WHERE token_id = ?',
                                [newCirculating, tokenId]
                            );
                            
                            if (updateTokenCirculating.affectedRows > 0) {
                                res.json({ success: true, message: 'Coin Claimed Successfully.' });
                            } else {
                                return res.json({success:false, message: "Error updating token circulation"})
                            }
                        } else {
                            return res.json({success:false, message: "Token not found or mismatched token symbol."})
                        }
                    } else {
                        return res.json({success:false, message: "Error adding transaction"})
                    }
                } else {
                    return res.json({ success: false, message: "Error increment count"})
                }
            } else {
                return res.json({ success:false, message: 'Block data not found. Transaction aborted.'});
            }
        }
  
      }
    } catch (err) {
        return res.json({ success: false, message: err.message });
    }
});

app.post('/xera/v1/api/user/nodes', authenticateToken, async (req,res) => {
    const { user } = req.body

    if (!user) {
      return res.json({ success: false, message: 'No address get' });
    }

    try {
        const [getUsernode] = await db.query('SELECT * FROM xera_asset_nodes WHERE node_owner = ?',[user])
        if (getUsernode.length > 0) {
            const clean = getUsernode.map(({id, ...clean}) => clean)
            res.json({success:true, message :`Successfully retrieved node. wallet: ${user}`, node: clean})
        } else {
            res.json({ success: false, message: "No node retrieved"})
        }
    } catch (error) {
        res.json({ success: false, message: err.message });
    }
})

app.post('/xera/v1/api/user/security', authenticateToken, async (req,res) => {
    const { user } = req.body

    if (!user) {
      return res.json({ success: false, message: 'No address get' });
    }

    try {
        const [getUserSecurity] = await db.query('SELECT * FROM xera_user_security WHERE xera_wallet = ?',[user])
        if (getUserSecurity.length > 0) {
            const clean = getUserSecurity.map(({id, ip_address, date_verified, ...clean}) => clean)
            return res.json({success:true, message :`Successfully retrieved security. wallet: ${user}`, security: clean})
        } else {
            return res.json({ success: false, message: "No security retrieved"})
        }
    } catch (error) {
        res.json({ success: false, message: err.message });
    }
})

app.post('/xera/v1/api/user/task/telegram', authenticateToken, async (req, res) => {
    const { user } = req.body;

    if (!telegramID || !username || !wallet || !user) {
        return res.json({ success: false, message: 'Incomplete data' });
    }

    const telegramID = user.telegramID;
    const username = user.username;
    const wallet = user.wallet;
    const xeraStatus = 'ok';
    const xeraTask = 'Telegram Task';
    const xeraPoints = '10000';

    try {

        // Check if the combination of username, wallet, and task already exists
        const [duplicateCheck] = await db.query(`
            SELECT * 
            FROM xera_user_tasks 
            WHERE username = ? 
              AND xera_wallet = ? 
              AND xera_task = ?
        `, [username, wallet, xeraTask]);

        if (duplicateCheck.length > 0) {
            return res.json({ success: false, message: 'You already finished this task' });
        }

        // Check if the telegram ID already exists
        const [telegramCheck] = await db.query(`
            SELECT * 
            FROM xera_user_tasks 
            WHERE xera_telegram_id = ?
        `, [telegramID]);

        if (telegramCheck.length > 0) {
            return res.json({ success: false, message: 'User ID already exists' });
        }

        // Insert into xera_user_tasks if telegramID has a value
        if (telegramID) {
            await db.query(`
                INSERT INTO xera_user_tasks (username, xera_wallet, xera_telegram_id, xera_twitter_username, xera_task, xera_status, xera_points) 
                VALUES (?, ?, ?, ?, ?, ?, ?)
            `, [username, wallet, telegramID, '', xeraTask, xeraStatus, xeraPoints]);
        }

        res.json({ success: true, message: 'Telegram User Successfully Verified' });
    } catch (error) {
        res.json({ success: false, message: 'Request error', error: error.message });
    }
});

app.post('/xera/v1/api/user/task/twitter', authenticateToken, async (req, res) => {
    const { user } = req.body;

    if (!user || !user.username || !user.wallet) {
        return res.json({ success: false, message: 'Incomplete data' });
    }

    const twitterUsername = user.twitterUsername;
    const username = user.username;
    const wallet = user.wallet;
    const xeraStatus = 'pending';
    const xeraTask = 'Twitter Task';

    try {

        // Check if the combination of username, wallet, and task already exists
        const [duplicateCheck] = await db.query(`
            SELECT * 
            FROM xera_user_tasks 
            WHERE username = ? 
              AND xera_wallet = ? 
              AND xera_task = ?
        `, [username, wallet, xeraTask]);

        if (duplicateCheck.length > 0) {
            return res.json({ success: false, message: 'You already did this task' });
        }

        // Check if the twitter username already exists
        const [twitterCheck] = await db.query(`
            SELECT * 
            FROM xera_user_tasks 
            WHERE xera_twitter_username = ?
        `, [twitterUsername]);

        if (twitterCheck.length > 0) {
            return res.json({ success: false, message: 'Twitter username already exists' });
        }

        // Insert into xera_user_tasks if twitterUsername has a value
        if (twitterUsername) {
            await db.query(`
                INSERT INTO xera_user_tasks (username, xera_wallet, xera_telegram_id, xera_twitter_username, xera_task, xera_status, xera_points) 
                VALUES (?, ?, ?, ?, ?, ?, ?)
            `, [username, wallet, '', twitterUsername, xeraTask, xeraStatus, '']);
        }

        res.json({ success: true, message: 'Twitter User Successfully Verified' });
    } catch (error) {
        res.json({ success: false, message: 'Request error', error: error.message });
    }
});

app.post('/xera/v1/api/user/task/social', authenticateToken, async (req, res) => {
    const { user } = req.body;
    
    if (!user || !user.username || !user.wallet) {
        return res.status(400).json({ success: false, message: 'Incomplete data' });
    }

    const taskTitle = user.taskTitle;
    const username = user.username;
    const wallet = user.wallet;
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
    const { user } = req.body;

    if (!user || !user.ethWallet || !user.solWallet || !user.xeraWallet || !user.xeraUsername) {
        return res.status(400).json({ success: false, message: 'Incomplete data' });
    }

    const ethWallet = user.ethWallet;
    const solWallet = user.solWallet;
    const xeraWallet = user.xeraWallet; 
    const xeraUsername = user.xeraUsername;
    const xeraStatus = 'ok';
    const xeraTask = 'Wallet Connect Task';
    const xeraPoints = '10000';
    try {

        // Check if both eth_wallet and sol_wallet already exist in another account
        const [existingWallet] = await db.query(`
            SELECT * FROM xera_user_accounts WHERE eth_wallet = ? AND sol_wallet = ? AND xera_wallet != ?
        `, [ethWallet, solWallet, xeraWallet]);

        if (existingWallet.length > 0) {
            // Both wallets are already bound to another XERA wallet
            return res.json({ success: false, message: 'Wallet already binded on other XERA Wallet' });
        } else {
            // Proceed with the update
            await db.query(`
                UPDATE xera_user_accounts SET eth_wallet = ?, sol_wallet = ? WHERE xera_wallet = ?
            `, [ethWallet, solWallet, xeraWallet]);

            if (ethWallet || solWallet) {
                // Check if an entry with the same username, xera_wallet, and xera_task "Wallet Connect Task" already exists
                const [existingTask] = await db.query(`
                    SELECT COUNT(*) AS count FROM xera_user_tasks WHERE username = ? AND xera_wallet = ? AND xera_task = 'Wallet Connect Task'
                `, [xeraUsername, xeraWallet]);

                // Proceed only if no matching entry was found
                if (existingTask[0].count == 0) {
                    await db.query(`
                        INSERT INTO xera_user_tasks (username, xera_wallet, xera_task, xera_status, xera_points, xera_telegram_id, xera_twitter_username) 
                        VALUES (?, ?, ?, ?, ?, '', '')
                    `, [xeraUsername, xeraWallet, xeraTask, xeraStatus, xeraPoints, '', '']);
                }
            }

            return res.json({ success: true, message: 'Wallet successfully updated and task recorded' });
        }
    } catch (error) {
        return res.json({ success: false, message: 'Request error', error: error.message });
    }
});

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});