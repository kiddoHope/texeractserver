const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const mysql = require("mysql2/promise");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const compression = require("compression");
const NodeCache = require("node-cache");
require("dotenv").config();

const app = express();
const port = 5002;
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
// const limiter = rateLimit({
//     windowMs: 15 * 60 * 1000, // 15 minutes
//     max: 100, // Limit each IP to 100 requests per window
//     message: { success: false, message: "Too many requests, please try again later." },
// });
// app.use(limiter);

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

// Database connection pool
const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    port: 3306,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
});

// Test database connection
(async function testConnection() {
    try {
        const connection = await db.getConnection();
        console.log("Database connection successful!");
        connection.release();
    } catch (error) {
        console.error("Database connection failed:", error.message);
        process.exit(1);
    }
})();

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



// Function to handle API key check and cache fetching
const validateApiKey = async (req, res) => {
    const { apikey } = req.body;
    if (!apikey) {
        return res.json({ success: false, message: "No request found" });
    }
    await getDevFromCache(apikey);
};


// Airdrop Full Stats - Optimized for Efficiency
app.post('/xera/v1/api/users/airdrop/full-stats', async (req, res) => {
    await validateApiKey(req, res); // Centralized API Key validation

    try {
        const results = [];

        // Perform a single query to get all the necessary data for the last 10 days
        const dates = Array.from({ length: 10 }, (_, i) => moment().subtract(i, 'days').format('YYYY-MM-DD'));
        const startDateRange = dates.map(date => `${date} 00:00:00`);
        const endDateRange = dates.map(date => `${date} 23:59:59`);

        const [pointsRows, usersRows, referralRows, txeraClaimRows] = await Promise.all([
            db.query(`
                SELECT xera_completed_date, SUM(xera_points) AS totalPoints
                FROM xera_user_tasks
                WHERE xera_completed_date BETWEEN ? AND ?
                GROUP BY xera_completed_date
            `, [startDateRange[0], endDateRange[0]]),
            db.query(`
                SELECT xera_completed_date, COUNT(DISTINCT username) AS dailyParticipants
                FROM xera_user_tasks
                WHERE xera_completed_date BETWEEN ? AND ?
                GROUP BY xera_completed_date
            `, [startDateRange[0], endDateRange[0]]),
            db.query(`
                SELECT xera_completed_date, COUNT(*) AS newUsers
                FROM xera_user_tasks
                WHERE xera_task = 'Referral Task' AND xera_completed_date BETWEEN ? AND ?
                GROUP BY xera_completed_date
            `, [startDateRange[0], endDateRange[0]]),
            db.query(`
                SELECT xera_completed_date, COUNT(*) AS txeraClaimTasks
                FROM xera_user_tasks
                WHERE xera_task = 'TXERA Claim Task' AND xera_completed_date BETWEEN ? AND ?
                GROUP BY xera_completed_date
            `, [startDateRange[0], endDateRange[0]]),
        ]);

        for (let i = 0; i < dates.length; i++) {
            const date = dates[i];
            results.push({
                date,
                totalPoints: pointsRows[i]?.totalPoints || 0,
                dailyParticipants: usersRows[i]?.dailyParticipants || 0,
                newUsers: referralRows[i]?.newUsers || 0,
                txeraClaimTasks: txeraClaimRows[i]?.txeraClaimTasks || 0,
            });
        }

        return res.json({
            success: true,
            message: "Successfully retrieved users data",
            usersData: results,
        });

    } catch (error) {
        console.error("Error in full-stats:", error);
        return res.json({ success: false, message: "Request error", error: error.message });
    }
});

// Airdrop Phase1, Phase2, and Phase3 Optimized
const handleAirdropPhase = async (req, res, phaseStartDate, phaseEndDate) => {
    const { request } = req.body;
    const { api, limit = 10, page = 1 } = request;

    if (!api) {
        return res.json({ success: false, message: "Invalid or missing API key" });
    }

    await getDevFromCache(api, res);
    const offset = (page - 1) * limit;

    try {
        const [rows] = await db.query(`
            SELECT MAX(username) AS username, MAX(xera_wallet) AS xera_wallet, SUM(CAST(xera_points AS DECIMAL(10))) AS total_points, 
                SUM(CASE WHEN xera_task = 'Referral Task' THEN 1 ELSE 0 END) AS referral_task_count
            FROM xera_user_tasks
            WHERE DATE(xera_completed_date) BETWEEN ? AND ?
            GROUP BY BINARY username
            ORDER BY total_points DESC
            LIMIT ? OFFSET ?`, 
            [phaseStartDate, phaseEndDate, limit, offset]
        );

        const [totalRows] = await db.query(`
            SELECT COUNT(DISTINCT username) AS total
            FROM xera_user_tasks
            WHERE DATE(xera_completed_date) BETWEEN ? AND ?
        `, [phaseStartDate, phaseEndDate]);

        const total = totalRows[0]?.total || 0;
        const totalPages = Math.ceil(total / limit);

        res.json({
            success: true,
            data: rows,
            message: "Data retrieved successfully",
            pagination: {
                currentPage: page,
                totalPages,
                totalRecords: total,
                limit,
            },
        });
    } catch (error) {
        console.error("Error in phase handler:", error);
        return res.json({ success: false, message: "Request error", error: error.message });
    }
};
app.post('/xera/v1/api/users/airdrop/phase1', (req, res) => handleAirdropPhase(req, res, '2024-09-28', '2024-12-18'));
app.post('/xera/v1/api/users/airdrop/phase2', (req, res) => handleAirdropPhase(req, res, '2024-12-19', '2025-02-25'));
app.post('/xera/v1/api/users/airdrop/phase3', (req, res) => handleAirdropPhase(req, res, '2025-02-25', '2025-05-30'));

//  Airdrop Participants
app.post('/xera/v1/api/users/airdrop/participants', async (req, res) => {
    await validateApiKey(req, res); // Centralized API Key validation

    try {
        const [userTask] = await db.query('SELECT COUNT(DISTINCT BINARY username) AS user_participants FROM xera_user_tasks');
        
        if (userTask.length > 0) {
            const participantData = userTask[0].user_participants;
            res.json({ success: true, message: "User tasks successfully retrieved", participants: participantData });
        } else {
            return res.json({ success: false, message: "No data retrieved" });
        }
    } catch (error) {
        return res.json({ success: false, message: "Request error", error: error.message });
    }
});

// Function to handle total points for a given phase
const getTotalPoints = async (req, res, startDate, endDate) => {
    await validateApiKey(req, res); // Centralized API Key validation

    try {
        const [userstask] = await db.query(`
            SELECT SUM(xera_points) AS total_points 
            FROM xera_user_tasks 
            WHERE xera_completed_date BETWEEN ? AND ?`, 
            [startDate, endDate]
        );

        if (userstask.length > 0) {
            const totalPoints = userstask[0].total_points;
            return res.json({ success: true, totalPoints });
        } else {
            return res.json({ success: false, message: "No tasks found" });
        }
    } catch (error) {
        return res.json({ success: false, message: "Request error", error: error.message });
    }
};
// Routes for each phase using the optimized function
app.post('/xera/v1/api/users/total-points/phase1', (req, res) => {
    getTotalPoints(req, res, '2024-11-01 01:01:01', '2024-12-18 01:01:01');
});
app.post('/xera/v1/api/users/total-points/phase2', (req, res) => {
    getTotalPoints(req, res, '2024-12-19 01:01:01', '2025-02-25 01:01:01');
});
app.post('/xera/v1/api/users/total-points/phase3', (req, res) => {
    getTotalPoints(req, res, '2025-02-25 01:01:01', '2025-05-30 01:01:01');
});

// Route to get the total count of wallets
app.post('/xera/v1/api/users/all-wallet', async (req, res) => {
    await validateApiKey(req, res); // Centralized API Key validation
    try {
        const [countWallet] = await db.query('SELECT COUNT(*) AS user_count FROM xera_user_accounts');
        
        if (countWallet.length > 0) {
            const walletCount = countWallet[0].user_count;
            res.json({ success: true, message: "Successfully counted all wallets", walletCount });
        } else {
            res.json({ success: false, message: "No data found" });
        }
    } catch (error) {
        return res.json({ success: false, message: "Request error", error: error.message });
    }
});

// Route to get the count of recent participants
app.post('/xera/v1/api/users/airdrop/recent-participant', async (req, res) => {
    await validateApiKey(req, res); // Centralized API Key validation
    try {
        const [recentParticipants] = await db.query(`
            SELECT COUNT(DISTINCT BINARY username) AS recent_participants
            FROM xera_user_tasks
            WHERE xera_completed_date BETWEEN CONCAT(CURDATE(), ' 00:00:00') AND CONCAT(CURDATE(), ' 23:59:59')
                AND xera_task != 'TXERA Claim Task'
        `);

        if (recentParticipants.length > 0) {
            const participantsData = recentParticipants[0].recent_participants;
            res.json({ success: true, message: "Participants successfully retrieved", recentparticipants: participantsData });
        } else {
            res.json({ success: false, message: "No data found" });
        }
    } catch (error) {
        return res.json({ success: false, message: "Request error", error: error.message });
    }
});

// Route to get transaction history of nodes
app.post('/xera/v1/api/users/node/transaction-history', async (req, res) => {
    await validateApiKey(req, res); // Centralized API Key validation
    try {
        const currentDate = new Date().toISOString().split('T')[0]; // Get current date in YYYY-MM-DD format
        const [transactionNode] = await db.query(`
            SELECT node_id, node_name, node_owner, node_points, node_txhash, node_txdate
            FROM xera_user_node
            WHERE node_txdate >= ?
        `, [currentDate]);

        if (transactionNode.length > 0) {
            res.json({ success: true, message: "User transactions successfully retrieved", transaction: transactionNode });
        } else {
            res.json({ success: false, message: "No data found" });
        }
    } catch (error) {
        return res.json({ success: false, message: "Request error", error: error.message });
    }
});


// Global error handling middleware
app.use((err, req, res, next) => {
    console.error("Global error:", err.message);
    res.status(500).json({ success: false, message: "An internal error occurred" });
});

// Start the server
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});