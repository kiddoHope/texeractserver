const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const db = require('./connection');
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const compression = require("compression");
const NodeCache = require("node-cache");
require("dotenv").config();

const app = express();
const port = 5004;
const jwtSecret = process.env.MAIN_JWT_SECRET;

// Validate essential environment variables
if (!jwtSecret || !process.env.DB_HOST || !process.env.DB_USER || !process.env.DB_PASSWORD || !process.env.DB_DATABASE) {
    console.error("Missing required environment variables. Please check your .env file.");
    process.exit(1);
}

// Initialize caching
const cache = new NodeCache({ stdTTL: 60, checkperiod: 120 });

// Apply middleware
app.use(compression());
app.use(bodyParser.json());

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per window
    message: { success: false, message: "Too many requests, please try again later." },
});
app.use(limiter);

// CORS setup
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
            callback(new Error("Not allowed by CORS"));
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


// JWT Authentication Middleware
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
const getDevFromCache = async (api, res) => {
    try {
        let dev = cache.get(api);

        if (!dev) {
            const [rows] = await db.query("SELECT * FROM xera_developer WHERE BINARY xera_api = ?", [api]);

            if (rows.length === 0) {
                return res.status(400).json({ success: false, message: "Invalid API key" });
            }

            dev = rows[0];
            cache.set(api, dev);
        }

        if (dev.xera_moderation !== "creator") {
            return res.status(403).json({ success: false, message: "Access denied" });
        }

        return dev;
    } catch (error) {
        console.error("Error fetching developer data:", error.message);
        return res.status(500).json({ success: false, message: "Internal server error" });
    }
};

// app.post('/xera/v1/api/genesis/active-nodes', async (req,res) => {
//     const { apikey } = req.body;
    
//     if (!apikey) {
//         return res.json({ success: false, message: "No request found" });
//     }
    
//     await getDevFromCache(apikey);

//     try {
//         const [totalResult] = await db.query(`
//             SELECT COUNT(*) AS total_nodes 
//             FROM xera_asset_nodes 
//             WHERE node_name = 'XERA GENESIS NODE'
//         `);

//         const [activatedResult] = await db.query(`
//             SELECT COUNT(*) AS activated_nodes 
//             FROM xera_asset_nodes 
//             WHERE node_name = 'XERA GENESIS NODE' 
//             AND node_state = 'activated'
//         `);
        
//         const responseData = {
//             activated: activatedResult[0].activated_nodes,
//             nodes: totalResult[0].total_nodes
//         };

//         res.json({success: true, message: "Results retrieved", data:responseData })
//     } catch (error) {
//         return res.json({ success: false, message: "Request error", error: error.message });
//     }
// })
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
    const username =  user.username
    try {
        const userRank = await getUserRank(username, '2024-09-28', '2024-12-18');
        
        if (userRank?.rank <= 1000) {
            const [checkNode] = await db.query(`SELECT node_id FROM xera_asset_nodes WHERE node_name = ? AND node_owner = ?`,[nodename, owner])
            if (checkNode.length > 0) {
                return res.json({ success: false, message: `You have already claimed ${nodename}`});
            } else {
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
            }
        } else {
            return res.json({ success: false, message: "You are not eligible to claim a node" });
        }
    } catch (error) {
        return res.json({ success: false, message: "Request error", error: error.message });
    }
})

// app.post('/xera/v1/api/genesis/activate-node', authenticateToken, async (req,res) => {
//     const { user } = req.body;
    
//     if (!user || !user.wallet || !user.username) {
//         return res.json({
//             success: false,
//             message: "Invalid request: Missing user details (wallet or nodeName)."
//         });
//     }

//     const formatDateTime = (date) => {
//         const year = date.getFullYear();
//         const month = String(date.getMonth() + 1).padStart(2, '0'); // Months are 0-indexed
//         const day = String(date.getDate()).padStart(2, '0');
//         const hours = String(date.getHours()).padStart(2, '0');
//         const minutes = String(date.getMinutes()).padStart(2, '0');
//         const seconds = String(date.getSeconds()).padStart(2, '0');
    
//         return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
//     };
    
//     const addHoursToDate = (date, hoursToAdd) => {
//         const updatedDate = new Date(date); // Create a new date object to avoid mutating the original
//         updatedDate.setHours(updatedDate.getHours() + hoursToAdd); // Add hours
//         return updatedDate;
//     };
    
//     const username = user.username
//     const owner = user.wallet
//     const nodename = user.nodeName
//     const nodeid = user.nodeID
//     const nodeHash = user.nodeTXHash
//     const now = new Date(); // Current date and time
//     const formattedDateTime = formatDateTime(now);
//     const updatedDate = addHoursToDate(now, 12); // Add 12 hours
//     const formattedUpdatedDateTime = formatDateTime(updatedDate);

//     try {
//         const [selectNode] = await db.query(`SELECT * FROM xera_asset_nodes WHERE node_name = ? AND node_owner = ?`,[nodename, owner])
//         if (selectNode.length > 0) {
//             const [updateNode] = await db.query(`UPDATE xera_asset_nodes SET node_state = 'active' WHERE node_owner = ? AND node_id = ?`,[owner,nodeid])
//             if (updateNode.affectedRows > 0) {
//                 const nodePoints = selectNode[0].node_points
//                 const [insertNode] = await db.query(`
//                     INSERT INTO xera_user_node (node_id, node_name, node_owner, node_points, node_reward, node_token, node_start, node_expire, node_txhash) VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
//                     [nodeid, nodename, owner, nodePoints, 0.00, '', formattedDateTime, formattedUpdatedDateTime, nodeHash] )
                    
//                 if (insertNode.affectedRows > 0) {
//                     const [insertTask] = await db.query(`
//                         INSERT INTO xera_user_tasks (username, xera_wallet, xera_telegram_id, xera_twitter_username, xera_task, xera_status, xera_points) VALUES ( ?, ?, ?, ?, ?, ?, ?)`,
//                         [username, owner, '' , '', nodename, 'ok', nodePoints] )
//                     if (insertTask.affectedRows > 0) {
//                         res.json({success: true, message: `Successfully activated 1 ${nodename}`, start: formattedDateTime, expire: formattedUpdatedDateTime  })
//                     } else {
//                         res.json({success: true, message: `Error adding in users node` })
//                     }
//                 } else {
//                     res.json({success: true, message: `Error adding in users node` })
//                 }
//             } else {
//                 res.json({ success: false, message: `Failed to activate ${nodename}`})
//             }
//         } else {
//             return res.json({ success: false, message: `No ${nodename} available`})
//         }
//     } catch (error) {
//         return res.json({ success: false, message: "Request error", error: error.message });
//     }
// })

// app.post('/xera/v1/api/genesis/operate', async (req,res) => {
//     const { user } = req.body;
    
//     if (!user || !user.apikey || !user.nodeID || !user.nodeTXHash) {
//         return res.json({success: false, message: "Invalid request: Missing user details"});
//     }

//     const apikey = user.apikey
//     await getDevFromCache(apikey);

//     const nodeid = user.nodeID
//     const txHash = user.nodeTXHash

//     try {
//         const [checkNode] = await db.query(`SELECT * FROM xera_network_transaction WHERE transaction_hash = ?`,[txHash])
//         if (checkNode.length <= 1) {
//             await db.query(`
//                 UPDATE xera_network_transactions
//                 SET transaction_validator = ?
//                 WHERE transaction_validator = 'XERA Validator'
//                 LIMIT 1
//             `, [nodeid]);
//         } else {
//             return res.json({ success: false, message: "Invalid transaction" });
//         }
//     } catch (error) {
//         return res.json({ success: false, message: "Request error", error: error.message });
//     }
// })

// Global error handling middleware

app.use((err, req, res, next) => {
    console.error("Global error:", err.message);
    res.status(500).json({ success: false, message: "An internal error occurred" });
});

// Start the server
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});