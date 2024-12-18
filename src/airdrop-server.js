const express = require("express");
const bodyParser = require("body-parser");
const mysql = require('mysql2/promise')
const cors = require("cors");
require('dotenv').config();
const moment = require('moment');
const app = express();
const port = 5002;
const NodeCache = require('node-cache');
const cache = new NodeCache({ stdTTL: 60 });
const compression = require('compression');

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
        } else {
            return res.status(401).json({ success: false, message: "Invalid request" });
        }
    }
    if (dev.xera_moderation !== 'creator') {
        return res.status(401).json({ success: false, message: "Invalid request" });
    }
};


app.post('/xera/v1/api/users/airdrop/full-stats', async (req, res) => {
    const { apikey } = req.body;
    
    if (!apikey) {
        return res.status(400).json({ success: false, message: "No request found" });
    }

    
    await getDevFromCache(apikey);
    
    try {
        const results = [];

        for (let i = 0; i < 10; i++) {
            const date = moment().subtract(i, 'days').format('YYYY-MM-DD');
            const startDate = `${date} 00:00:00`;
            const endDate = `${date} 23:59:59`;

            // Get total points for the day
            const [pointsRows] = await db.query(
                `SELECT SUM(xera_points) AS totalPoints
                    FROM xera_user_tasks
                    WHERE xera_completed_date BETWEEN ? AND ?`,
                [startDate, endDate]
            );

            const totalPoints = pointsRows[0]?.totalPoints || 0;

            // Get daily participants
            const [usersRows] = await db.query(
                `SELECT COUNT(DISTINCT username) AS dailyParticipants
                    FROM xera_user_tasks
                    WHERE xera_completed_date BETWEEN ? AND ?`,
                [startDate, endDate]
            );

            const dailyParticipants = usersRows[0]?.dailyParticipants || 0;

            // Get new users from referral tasks
            const [referralRows] = await db.query(
                `SELECT COUNT(*) AS newUsers
                    FROM xera_user_tasks
                    WHERE xera_completed_date BETWEEN ? AND ?
                    AND xera_task = 'Referral Task'`,
                [startDate, endDate]
            );

            const newUsers = referralRows[0]?.newUsers || 0;

            // Get TXERA claim tasks
            const [txeraClaimRows] = await db.query(
                `SELECT COUNT(*) AS txeraClaimTasks
                    FROM xera_user_tasks
                    WHERE xera_completed_date BETWEEN ? AND ?
                    AND xera_task = 'TXERA Claim Task'`,
                [startDate, endDate]
            );

            const txeraClaimTasks = txeraClaimRows[0]?.txeraClaimTasks || 0;

            // Add the data for the current date to the results array
            results.push({
                date,
                totalPoints,
                dailyParticipants,
                newUsers,
                txeraClaimTasks,
            });
        }

        // Send the response after the loop finishes
        return res.status(200).json({
            success: true,
            message: "Successfully retrieved users data",
            usersData: results,
        });

    } catch (error) {
        return res.status(500).json({ success: false, message: "Request error", error: error.message });
    }
});

app.post('/xera/v1/api/users/airdrop/phase1', async (req,res) => {
    const { request } = req.body;

    if (!request) {
        return res.status(400).json({ success: false, message: "No request found" });
    }

    const apikey = request.api;
    const limit = parseInt(request.limit, 10) || 10; 
    const page = parseInt(request.page, 10) || 1;

    if (!apikey) {
        return res.status(403).json({ success: false, message: "Invalid or missing API key" });
    }
    await getDevFromCache(apikey);

    const offset = (page - 1) * limit; 

    try {
        
        const [rows] = await db.query(`
            SELECT t.username, 
                MAX(t.xera_wallet) AS xera_wallet, 
                SUM(t.xera_points) AS total_points, 
                SUM(CASE WHEN t.xera_task = 'Referral Task' THEN 1 ELSE 0 END) AS referral_task_count
            FROM xera_user_tasks t
            WHERE DATE(t.xera_completed_date) BETWEEN '2024-09-28' AND '2024-12-20'
            GROUP BY t.username
            ORDER BY total_points DESC
            LIMIT ? OFFSET ?`, [limit, offset]);

        // Query to get total number of records
        const [totalRows] = await db.query(`
            SELECT COUNT(DISTINCT username) AS total
            FROM xera_user_tasks
            WHERE DATE(xera_completed_date) BETWEEN '2024-09-28' AND '2024-12-20'
        `);

        const total = totalRows[0]?.total || 0;
        const totalPages = Math.ceil(total / limit);

        res.status(200).json({
            success: true,
            data: rows,
            message: "data retrieved Successfully",
            pagination: {
                currentPage: page,
                totalPages,
                totalRecords: total,
                limit
            }
        });
    } catch (error) {
        return res.status(500).json({ success: false, message: "Request error", error: error.message });
    }

    
})

app.post('/xera/v1/api/users/airdrop/participants', async (req,res) => {
    const { apikey } = req.body;
    
    if (!apikey) {
        return res.status(400).json({ success: false, message: "No request found" });
    }
    await getDevFromCache(apikey);

    try {
        const [userTask] = await db.query('SELECT COUNT(DISTINCT BINARY username) AS user_participants FROM xera_user_tasks')
        if (userTask.length > 0) {
            const participantData = userTask[0].user_participants
            
            res.status(200).json({ success: true, message: "User tasks successfully retrieve", participants :participantData})
        } else {
            return res.status(400).json({ success: false, message: "No data retrieve" });
        }
    } catch (error) {
        return res.status(500).json({ success: false, message: "Request error", error: error.message });
    }
})

app.post('/xera/v1/api/users/total-points', async (req, res) => {
    const { apikey } = req.body;
    
    if (!apikey) {
        return res.status(400).json({ success: false, message: "No request found" });
    }
    await getDevFromCache(apikey);
    try {
        const [userstask] = await db.query(`SELECT SUM(xera_points) AS total_points FROM xera_user_tasks`);
        
        if (userstask.length > 0) {
            const totalPoints = userstask[0].total_points
            
            return res.status(200).json({ success: true, totalPoints });
        } else {
            return res.status(404).json({ success: false, message: "No tasks found" });
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
    await getDevFromCache(apikey);
    try {
        const [countWallet] = await db.query('SELECT COUNT(*) AS user_count FROM xera_user_accounts')
        
        if (countWallet.length > 0) {
            const walletCount = countWallet[0].user_count
            res.status(200).json({ success:true, message: "Successfully count all wallet", walletCount: walletCount})
        }
            
    } catch (error) {
        return res.status(500).json({ success: false, message: "request error", error: error });
    }
})

app.post('/xera/v1/api/users/airdrop/recent-participant', async (req,res) => {
    const { apikey } = req.body;
    
    if (!apikey) {
        return res.status(400).json({ success: false, message: "No request found" });
    }
    await getDevFromCache(apikey);
    try {
        const [recentParticipants] = await db.query(`
            SELECT COUNT(DISTINCT BINARY username) AS recent_participants
            FROM xera_user_tasks
            WHERE xera_completed_date BETWEEN CONCAT(CURDATE(), ' 00:00:00') AND CONCAT(CURDATE(), ' 23:59:59')
                AND xera_task != 'TXERA Claim Task'
        `);

        if (recentParticipants.length > 0) {
            const participantsData = recentParticipants[0].recent_participants
            res.status(200).json({ success: true, message: "Participants successfully retrieve", recentparticipants: participantsData})
        } else {
            return res.status(400).json({ success: false, message: "No data retrieve" });
        }
    } catch (error) {
        return res.status(500).json({ success: false, message: "Request error", error: error.message });
    }
})

app.post('/xera/v1/api/users/node/transaction-history', async (req,res) => {
    const { apikey } = req.body;
    
    if (!apikey) {
        return res.status(400).json({ success: false, message: "No request found" });
    }
    await getDevFromCache(apikey);
    try {
       
        const currentDate = new Date().toISOString().split('T')[0];
        const [transactionNode] = await db.query(`
            SELECT node_id, node_name, node_owner, node_points, node_txhash, node_txdate
            FROM xera_user_node
            WHERE node_txdate >= ?
        `,[currentDate]);

        if (transactionNode.length > 0) {
            res.status(200).json({ success: true, message: "User tasks successfully retrieve", transaction : transactionNode})
        } else {
            return res.status(400).json({ success: false, message: "No data retrieve" });
        }
    } catch (error) {
        return res.status(500).json({ success: false, message: "Request error", error: error.message });
    }
})

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});