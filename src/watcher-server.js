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

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});