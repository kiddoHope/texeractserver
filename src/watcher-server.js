const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const mysql = require('mysql2/promise')
const cors = require("cors");
require('dotenv').config();
const rateLimit = require('express-rate-limit')
const app = express();
const port = 5005;
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

const jwtSecret = process.env.MAIN_JWT_SECRET

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

const getDevFromCache = async (api) => {
    let dev = cache.get(api);

    if (!dev) {
        const [dbDev] = await db.query('SELECT * FROM xera_developer WHERE BINARY xera_api = ?', [api]);
        if (dbDev.length > 0) {
            dev = dbDev[0];
            cache.set(api, dev);
        } else {
            return res.status(401).json({ success: false, message: "Invalid request" });
        }
    }
    if (dev.xera_moderation !== 'creator') {
        return res.status(401).json({ success: false, message: "Invalid request" });
    }
};

app.post('/xera/v1/api/watcher/active-nodes', async (req,res) => {
    const { apikey } = req.body;
    
    if (!apikey) {
        return res.status(400).json({ success: false, message: "No request found" });
    }
    
    await getDevFromCache(apikey);

    try {
         // Query to fetch total nodes
         const [totalResult] = await db.query(`
            SELECT COUNT(*) AS total_nodes 
            FROM xera_asset_nodes 
            WHERE node_name = 'XERA WATCHER NODE'
        `);

        // Query to fetch activated nodes count
        const [activatedCountResult] = await db.query(`
            SELECT COUNT(*) AS activated_nodes 
            FROM xera_asset_nodes 
            WHERE node_name = 'XERA WATCHER NODE' 
            AND node_state = 'activated'
        `);

        // Query to fetch activated nodes details (node_id and node_owner)
        const [activatedDetailsResult] = await db.query(`
            SELECT node_id, node_owner 
            FROM xera_asset_nodes 
            WHERE node_name = 'XERA WATCHER NODE' 
            AND node_state = 'activated'
        `);

        // Prepare the response
        const responseData = {
            activated: activatedCountResult[0].activated_nodes,
            nodes: totalResult[0].total_nodes,
            activated_details: activatedDetailsResult
        };

        res.status(200).json({success: true, message: "Results retrieved", data:responseData })
    } catch (error) {
        return res.status(500).json({ success: false, message: "Request error", error: error.message });
    }
})

app.post('/xera/v1/api/watcher/watch-result', async (req,res) => {
    const { apikey } = req.body;
    
    if (!apikey) {
        return res.status(400).json({ success: false, message: "No request found" });
    }
    
    await getDevFromCache(apikey);

    try {
        const [watch] = await db.query(`
            SELECT 
                DATE(date_verified) AS date, 
                SUM(CASE WHEN xera_status = 'safe' THEN 1 ELSE 0 END) AS safe_count,
                SUM(CASE WHEN xera_status = 'danger' THEN 1 ELSE 0 END) AS danger_count,
                COUNT(DISTINCT username) AS total_checked
            FROM xera_user_security
            WHERE date_verified >= DATE_SUB(CURDATE(), INTERVAL 5 DAY)
            GROUP BY DATE(date_verified)
            ORDER BY DATE(date_verified) DESC
        `);
        if (watch.length > 0) {
            res.status(200).json({success: true, message: "Watch results retrieved", stats:watch})
        } else {
            res.status(400).json({success: false, message: "No watch data retrieved"})
        }
    } catch (error) {
        return res.status(500).json({ success: false, message: "Request error", error: error.message });
    }
})

app.post('/xera/v1/api/watcher/recovered-exp', async (req,res) => {
    const { apikey } = req.body;
    
    if (!apikey) {
        return res.status(400).json({ success: false, message: "No request found" });
    }
    
    await getDevFromCache(apikey);

    try {
        const [countData] = await db.query(`
            SELECT COUNT(*) AS referral_task_count
            FROM xera_user_tasks
            WHERE xera_task = 'Referral Task' AND xera_points = 0
        `);

        // Calculate recovered_xp
        const recoveredXp = countData[0].referral_task_count * 5000;
        if (countData.length > 0) {
            res.status(200).json({success: true, message: "Recovered Exp retrieved", recoveredExp:recoveredXp})
        } else {
            res.status(400).json({success: false, message: "No watch data retrieved"})
        }
    } catch (error) {
        return res.status(500).json({ success: false, message: "Request error", error: error.message });
    }
})

app.post('/xera/v1/api/watcher/activate-node', authenticateToken, async (req,res) => {
    const { user } = req.body;
    
    if (!user || !user.wallet || !user.username) {
        return res.status(400).json({
            success: false,
            message: "Invalid request: Missing user details (wallet or nodeName)."
        });
    }

    const formatDateTime = (date) => {
        const year = date.getFullYear();
        const month = String(date.getMonth() + 1).padStart(2, '0'); // Months are 0-indexed
        const day = String(date.getDate()).padStart(2, '0');
        const hours = String(date.getHours()).padStart(2, '0');
        const minutes = String(date.getMinutes()).padStart(2, '0');
        const seconds = String(date.getSeconds()).padStart(2, '0');
    
        return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
    };
    
    const addHoursToDate = (date, hoursToAdd) => {
        const updatedDate = new Date(date); // Create a new date object to avoid mutating the original
        updatedDate.setHours(updatedDate.getHours() + hoursToAdd); // Add hours
        return updatedDate;
    };
    
    const username = user.username
    const owner = user.wallet
    const nodename = user.nodeName
    const nodeid = user.nodeID
    const nodeHash = user.nodeTXHash
    const now = new Date(); // Current date and time
    const formattedDateTime = formatDateTime(now);
    const updatedDate = addHoursToDate(now, 12); // Add 12 hours
    const formattedUpdatedDateTime = formatDateTime(updatedDate);

    try {
        const [updateNode] = await db.query(`UPDATE xera_asset_nodes SET node_state = 'activate' WHERE node_owner = ? AND node_id = ?`,[owner,nodeid])
        if (updateNode.affectedRows > 0) {
            const [insertNode] = await db.query(`
                INSERT INTO xera_user_node (node_id, node_name, node_owner, node_points, node_reward, node_token, node_start, node_expire, node_txhash) VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [nodeid, nodename, owner, 20000, 0.00, '', formattedDateTime, formattedUpdatedDateTime, nodeHash] )
            if (insertNode.affectedRows > 0) {
                const [insertTask] = await db.query(`
                    INSERT INTO xera_user_tasks (username, xera_wallet, xera_telegram_id, xera_twitter_username, xera_task, xera_status, xera_points) VALUES ( ?, ?, ?, ?, ?, ?, ?)`,
                    [username, owner, '' , '', nodename, 'ok', 20000] )
                if (insertTask.length > 0) {
                    res.status(200).json({success: true, message: `Successfully activated 1 ${nodename}`, start: formattedDateTime, expire: formattedUpdatedDateTime  })
                } else {
                    res.status(400).json({success: true, message: `Error adding in users node` })
                }
            } else {
                res.status(400).json({success: true, message: `Error adding in users node` })
            }
        } else {
            res.status(400).json({ success: false, message: `Failed to activate ${nodename}`})
        }
    } catch (error) {
        return res.status(500).json({ success: false, message: "Request error", error: error.message });
    }
})

app.post('/xera/v1/api/watcher/operate', async (req,res) => {
    const { apikey } = req.body;
    
    if (!apikey) {
        return res.status(400).json({ success: false, message: "No request found" });
    }
    
    await getDevFromCache(apikey);

    try {
        const [rows] = await db.query(`
            SELECT username, xera_wallet, xera_account_ip, xera_referral
            FROM xera_user_accounts
            WHERE xera_account_ip IS NOT NULL AND xera_account_ip != '' 
              AND NOT EXISTS (
                  SELECT 1 FROM xera_user_security
                  WHERE xera_user_security.username = xera_user_accounts.username
                    AND xera_user_security.xera_wallet = xera_user_accounts.xera_wallet
              ) 
            LIMIT 1 FOR UPDATE
        `);
        if (rows.length > 0) {
            res.status(200).json({success: true, message: "User found", data:rows})
        } else {
            res.status(400).json({success: false, message: "No user found"})
        }
    } catch (error) {
        return res.status(500).json({ success: false, message: "Request error", error: error.message });
    }
})

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});