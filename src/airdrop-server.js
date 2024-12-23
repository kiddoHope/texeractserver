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
// Helper functions to handle dates
const getDateNDaysAgo = (n) => {
    const date = new Date();
    date.setDate(date.getDate() - n);
    return date.toISOString().split('T')[0]; // Format as 'YYYY-MM-DD'
};

const getStartAndEndOfDay = (n) => {
    const date = new Date();
    date.setDate(date.getDate() - n);

    const startDate = new Date(date);
    startDate.setHours(0, 0, 0, 0);

    const endDate = new Date(date);
    endDate.setHours(23, 59, 59, 999);

    return {
        startDate: startDate.toISOString().replace('T', ' ').split('.')[0],
        endDate: endDate.toISOString().replace('T', ' ').split('.')[0],
    };
};

app.post('/xera/v1/api/users/airdrop/full-stats', async (req, res) => {
    await validateApiKey(req, res); // Centralized API Key validation

    try {
        const results = [];

        // Calculate the start and end dates for the 10-day range
        const allDates = Array.from({ length: 10 }, (_, i) => getDateNDaysAgo(i));
        const { startDate, endDate } = getStartAndEndOfDay(9); // Covers the 10-day range

        // Query data for the 10-day period in a single batch
        const [pointsData, usersData, referralData, txeraClaimData] = await Promise.all([
            db.query(`
                SELECT xera_completed_date, SUM(xera_points) AS totalPoints
                FROM xera_user_tasks
                WHERE xera_completed_date BETWEEN ? AND ?
                GROUP BY xera_completed_date
            `, [startDate, endDate]),
            db.query(`
                SELECT xera_completed_date, COUNT(DISTINCT username) AS dailyParticipants
                FROM xera_user_tasks
                WHERE xera_completed_date BETWEEN ? AND ?
                GROUP BY xera_completed_date
            `, [startDate, endDate]),
            db.query(`
                SELECT xera_completed_date, COUNT(*) AS newUsers
                FROM xera_user_tasks
                WHERE xera_task = 'Referral Task' AND xera_completed_date BETWEEN ? AND ?
                GROUP BY xera_completed_date
            `, [startDate, endDate]),
            db.query(`
                SELECT xera_completed_date, COUNT(*) AS txeraClaimTasks
                FROM xera_user_tasks
                WHERE xera_task = 'TXERA Claim Task' AND xera_completed_date BETWEEN ? AND ?
                GROUP BY xera_completed_date
            `, [startDate, endDate]),
        ]);

        // Preprocess data into lookup objects for efficient access
        const pointsMap = Object.fromEntries(pointsData.map(row => [row.xera_completed_date, row.totalPoints || 0]));
        const usersMap = Object.fromEntries(usersData.map(row => [row.xera_completed_date, row.dailyParticipants || 0]));
        const referralMap = Object.fromEntries(referralData.map(row => [row.xera_completed_date, row.newUsers || 0]));
        const txeraClaimMap = Object.fromEntries(txeraClaimData.map(row => [row.xera_completed_date, row.txeraClaimTasks || 0]));

        // Build results for the last 10 days
        for (const date of allDates) {
            results.push({
                date,
                totalPoints: pointsMap[date] || 0,
                dailyParticipants: usersMap[date] || 0,
                newUsers: referralMap[date] || 0,
                txeraClaimTasks: txeraClaimMap[date] || 0,
            });
        }

        return res.json({
            success: true,
            message: "Successfully retrieved users data",
            usersData: results,
        });
    } catch (error) {
        console.error("Error in full-stats:", error);
        return res.status(500).json({ success: false, message: "Request error", error: error.message });
    }
});

// Airdrop Phase1, Phase2, and Phase3 Optimized
const handleAirdropPhase = async (req, res, phaseStartDate, phaseEndDate) => {
    const { request } = req.body;
    const { api, limit = 10, page = 1 } = request;

    if (!api) {
        return res.status(400).json({ success: false, message: "Invalid or missing API key" });
    }

    // Validate API key and retrieve developer data from cache
    if (!(await getDevFromCache(api, res))) return;

    const offset = (page - 1) * limit;

    try {
        // Fetch paginated data with case-sensitive usernames
        const queryData = `
            SELECT username, xera_wallet, 
                   SUM(xera_points) AS total_points,
                   SUM(CASE WHEN xera_task = 'Referral Task' THEN 1 ELSE 0 END) AS referral_task_count
            FROM xera_user_tasks
            WHERE xera_completed_date BETWEEN ? AND ?
            GROUP BY BINARY username
            ORDER BY total_points DESC
            LIMIT ? OFFSET ?`;

        const queryCount = `
            SELECT COUNT(DISTINCT BINARY username) AS total
            FROM xera_user_tasks
            WHERE xera_completed_date BETWEEN ? AND ?`;

        const [dataRows] = await db.query(queryData, [phaseStartDate, phaseEndDate, limit, offset]);
        const [countRows] = await db.query(queryCount, [phaseStartDate, phaseEndDate]);

        const totalRecords = countRows[0]?.total || 0;
        const totalPages = Math.ceil(totalRecords / limit);

        res.json({
            success: true,
            data: dataRows,
            pagination: {
                currentPage: page,
                totalPages,
                totalRecords,
                limit,
            },
            message: "Data retrieved successfully",
        });
    } catch (error) {
        console.error("Error in handleAirdropPhase:", error);
        res.status(500).json({ success: false, message: "Server error", error: error.message });
    }
};

// Define the endpoints for each phase
const phases = [
    { route: '/xera/v1/api/users/airdrop/phase1', start: '2024-09-28', end: '2024-12-18' },
    { route: '/xera/v1/api/users/airdrop/phase2', start: '2024-12-19', end: '2025-02-25' },
    { route: '/xera/v1/api/users/airdrop/phase3', start: '2025-02-25', end: '2025-05-30' },
];

phases.forEach(({ route, start, end }) => {
    app.post(route, (req, res) => handleAirdropPhase(req, res, start, end));
});


// Airdrop Participants
app.post('/xera/v1/api/users/airdrop/participants', async (req, res) => {
    try {
        // Validate API Key
        const isValidApiKey = await validateApiKey(req, res);
        if (!isValidApiKey) return;

        // Fetch unique case-sensitive participant count
        const [userTask] = await db.query(`
            SELECT COUNT(DISTINCT BINARY username) AS user_participants 
            FROM xera_user_tasks
        `);

        // Return the data if retrieved successfully
        const participantData = userTask[0]?.user_participants || 0;
        res.json({
            success: true,
            message: "User participant count retrieved successfully",
            participants: participantData,
        });
    } catch (error) {
        console.error("Error retrieving airdrop participants:", error);
        res.status(500).json({
            success: false,
            message: "Server error",
            error: error.message,
        });
    }
});

// Function to handle total points for a given phase
const getTotalPoints = async (req, res, startDate, endDate) => {
    try {
        // Validate API Key and exit early if invalid
        const isValidApiKey = await validateApiKey(req, res);
        if (!isValidApiKey) return;

        // Fetch total points from the database
        const [userstask] = await db.query(
            `SELECT SUM(xera_points) AS total_points 
             FROM xera_user_tasks 
             WHERE xera_completed_date BETWEEN ? AND ?`, 
            [startDate, endDate]
        );

        // Extract and respond with the total points
        const totalPoints = userstask[0]?.total_points || 0; // Default to 0 if no rows found
        res.json({
            success: true,
            message: "Total points retrieved successfully",
            totalPoints,
        });
    } catch (error) {
        console.error("Error in getTotalPoints:", error);
        res.status(500).json({
            success: false,
            message: "Server error",
            error: error.message,
        });
    }
};

// Routes for each phase using the optimized function
const totalPointsRoutes = [
    { path: '/xera/v1/api/users/total-points/phase1', start: '2024-11-01 01:01:01', end: '2024-12-18 01:01:01' },
    { path: '/xera/v1/api/users/total-points/phase2', start: '2024-12-19 01:01:01', end: '2025-02-25 01:01:01' },
    { path: '/xera/v1/api/users/total-points/phase3', start: '2025-02-25 01:01:01', end: '2025-05-30 01:01:01' },
];
totalPointsRoutes.forEach(({ path, start, end }) => {
    app.post(path, (req, res) => getTotalPoints(req, res, start, end));
});

// Route to get the total count of wallets
app.post('/xera/v1/api/users/all-wallet', async (req, res) => {
    try {
        // Validate API Key and exit early if invalid
        const isValidApiKey = await validateApiKey(req, res);
        if (!isValidApiKey) return;

        // Fetch wallet count
        const [countWallet] = await db.query('SELECT COUNT(*) AS user_count FROM xera_user_accounts');

        // Respond with the count
        const walletCount = countWallet[0]?.user_count || 0;
        res.json({
            success: true,
            message: "Successfully counted all wallets",
            walletCount,
        });
    } catch (error) {
        console.error("Error in /all-wallet:", error);
        res.status(500).json({
            success: false,
            message: "Server error",
            error: error.message,
        });
    }
});

// Route to get the count of recent participants
app.post('/xera/v1/api/users/airdrop/recent-participant', async (req, res) => {
    try {
        // Validate API Key and exit early if invalid
        const isValidApiKey = await validateApiKey(req, res);
        if (!isValidApiKey) return;

        // Fetch recent participants count
        const [recentParticipants] = await db.query(`
            SELECT COUNT(DISTINCT BINARY username) AS recent_participants
            FROM xera_user_tasks
            WHERE xera_completed_date BETWEEN CONCAT(CURDATE(), ' 00:00:00') AND CONCAT(CURDATE(), ' 23:59:59')
                AND xera_task != 'TXERA Claim Task'
        `);

        // Respond with the count
        const participantsData = recentParticipants[0]?.recent_participants || 0;
        res.json({
            success: true,
            message: "Participants successfully retrieved",
            recentParticipants: participantsData,
        });
    } catch (error) {
        console.error("Error in /recent-participant:", error);
        res.status(500).json({
            success: false,
            message: "Server error",
            error: error.message,
        });
    }
});

// Route to get transaction history of nodes
app.post('/xera/v1/api/users/node/transaction-history', async (req, res) => {
    try {
        // Validate API Key and exit early if invalid
        const isValidApiKey = await validateApiKey(req, res);
        if (!isValidApiKey) return;

        // Fetch transaction history
        const currentDate = new Date().toISOString().split('T')[0]; // Get current date in YYYY-MM-DD format
        const [transactionNode] = await db.query(`
            SELECT node_id, node_name, node_owner, node_points, node_txhash, node_txdate
            FROM xera_user_node
            WHERE node_txdate >= ?
        `, [currentDate]);

        // Respond with the transaction history
        res.json({
            success: true,
            message: transactionNode.length > 0 ? "User transactions successfully retrieved" : "No transactions found",
            transactions: transactionNode,
        });
    } catch (error) {
        console.error("Error in /node/transaction-history:", error);
        res.status(500).json({
            success: false,
            message: "Server error",
            error: error.message,
        });
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