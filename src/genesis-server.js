const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const mysql = require('mysql2/promise')
const cors = require("cors");
require('dotenv').config();
const rateLimit = require('express-rate-limit')
const app = express();
const port = 5004;
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

const getDevFromCache = async (api) => {
    let dev = cache.get(api);

    if (!dev) {
        const [dbDev] = await db.query('SELECT * FROM xera_developer WHERE BINARY xera_api = ?', [api]);
        if (dbDev.length > 0) {
            dev = dbDev[0];
            cache.set(api, dev);
        } else {
            return res.json({ success: false, message: "Invalid request" });
        }
    }
    if (dev.xera_moderation !== 'creator') {
        return res.json({ success: false, message: "Invalid request" });
    }
};

app.post('/xera/v1/api/genesis/active-nodes', async (req,res) => {
    const { apikey } = req.body;
    
    if (!apikey) {
        return res.json({ success: false, message: "No request found" });
    }
    
    await getDevFromCache(apikey);

    try {
        const [totalResult] = await db.query(`
            SELECT COUNT(*) AS total_nodes 
            FROM xera_asset_nodes 
            WHERE node_name = 'XERA GENESIS NODE'
        `);

        const [activatedResult] = await db.query(`
            SELECT COUNT(*) AS activated_nodes 
            FROM xera_asset_nodes 
            WHERE node_name = 'XERA GENESIS NODE' 
            AND node_state = 'activated'
        `);
        
        const responseData = {
            activated: activatedResult[0].activated_nodes,
            nodes: totalResult[0].total_nodes
        };

        res.json({success: true, message: "Results retrieved", data:responseData })
    } catch (error) {
        return res.json({ success: false, message: "Request error", error: error.message });
    }
})

app.post('/xera/v1/api/genesis/claim-node', authenticateToken, async (req,res) => {
    const { user } = req.body;
    
    if (!user || !user.wallet || !user.nodeName) {
        return res.json({
            success: false,
            message: "Invalid request: Missing user details (wallet or nodeName)."
        });
    }
    
    const owner = user.wallet
    const nodename = user.nodeName
    
    try {
        const [selectNode] = await db.query(`SELECT node_id FROM xera_asset_nodes WHERE node_name = ? AND node_owner = 'none'`,[nodename])
        
        if (selectNode.length > 0) {
            const freeNode = selectNode[0].node_id
            
            const [updateNode] = await db.query(
                `UPDATE xera_asset_nodes 
                 SET node_owner = ?, node_status = 'owned', node_state = 'idle' 
                 WHERE node_id = ?`,
                [owner, freeNode]
            );
            
            if (updateNode.affectedRows > 0) {
                res.json({success: true, message: `Successfully Claim 1 ${nodename}` })
            } else {
                res.json({ success: false, message: `Failed to claim ${nodename}`})
            }
        } else {
            return res.json({ success: false, message: `No ${nodename} available`})
        }
    } catch (error) {
        return res.json({ success: false, message: "Request error", error: error.message });
    }
})

app.post('/xera/v1/api/genesis/activate-node', authenticateToken, async (req,res) => {
    const { user } = req.body;
    
    if (!user || !user.wallet || !user.username) {
        return res.json({
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
        const [selectNode] = await db.query(`SELECT * FROM xera_asset_nodes WHERE node_name = ? AND node_owner = ?`,[nodename, owner])
        if (selectNode.length > 0) {
            const [updateNode] = await db.query(`UPDATE xera_asset_nodes SET node_state = 'active' WHERE node_owner = ? AND node_id = ?`,[owner,nodeid])
            if (updateNode.affectedRows > 0) {
                const nodePoints = selectNode[0].node_points
                const [insertNode] = await db.query(`
                    INSERT INTO xera_user_node (node_id, node_name, node_owner, node_points, node_reward, node_token, node_start, node_expire, node_txhash) VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                    [nodeid, nodename, owner, nodePoints, 0.00, '', formattedDateTime, formattedUpdatedDateTime, nodeHash] )
                    
                if (insertNode.affectedRows > 0) {
                    const [insertTask] = await db.query(`
                        INSERT INTO xera_user_tasks (username, xera_wallet, xera_telegram_id, xera_twitter_username, xera_task, xera_status, xera_points) VALUES ( ?, ?, ?, ?, ?, ?, ?)`,
                        [username, owner, '' , '', nodename, 'ok', nodePoints] )
                    if (insertTask.affectedRows > 0) {
                        res.json({success: true, message: `Successfully activated 1 ${nodename}`, start: formattedDateTime, expire: formattedUpdatedDateTime  })
                    } else {
                        res.json({success: true, message: `Error adding in users node` })
                    }
                } else {
                    res.json({success: true, message: `Error adding in users node` })
                }
            } else {
                res.json({ success: false, message: `Failed to activate ${nodename}`})
            }
        } else {
            return res.json({ success: false, message: `No ${nodename} available`})
        }
    } catch (error) {
        return res.json({ success: false, message: "Request error", error: error.message });
    }
})

app.post('/xera/v1/api/genesis/operate', async (req,res) => {
    const { user } = req.body;
    
    if (!user || !user.apikey || !user.nodeID || !user.nodeTXHash) {
        return res.json({success: false, message: "Invalid request: Missing user details"});
    }

    const apikey = user.apikey
    await getDevFromCache(apikey);

    const nodeid = user.nodeID
    const txHash = user.nodeTXHash

    try {
        const [checkNode] = await db.query(`SELECT * FROM xera_network_transaction WHERE transaction_hash = ?`,[txHash])
        if (checkNode.length <= 1) {
            await db.query(`
                UPDATE xera_network_transactions
                SET transaction_validator = ?
                WHERE transaction_validator = 'XERA Validator'
                LIMIT 1
            `, [nodeid]);
        } else {
            return res.json({ success: false, message: "Invalid transaction" });
        }
    } catch (error) {
        return res.json({ success: false, message: "Request error", error: error.message });
    }
})

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});