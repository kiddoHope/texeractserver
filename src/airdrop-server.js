const express = require("express");
const bodyParser = require("body-parser");
const CryptoJS = require("crypto-js");
const cors = require("cors");
const db = require('./connection');
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

const decodeKey = (encodedKey) => {
    if (!encodedKey) {
        console.error("No encoded API key provided.");
        return null;
    }

    const secret = {
        devKey: `xeraAPI-LokiNakamoto-0ea5b02a13i4bdhw94jwb`,
        webKey: `xeraAPI-webMainTexeract-egsdfw33resdfdsf`,
        apiKey: `XERA09aa939245f735992af1a9a6b6d6b91d234ee2`,
    };

    const fullSecret = secret.devKey + secret.webKey + secret.apiKey;
    if (!fullSecret) {
        console.error("Secret for decryption is missing or incomplete.");
        return null;
    }

    try {
        const bytes = CryptoJS.AES.decrypt(encodedKey, fullSecret);
        const originalKey = bytes.toString(CryptoJS.enc.Utf8);
        

        if (!originalKey) {
            console.error("Failed to decrypt API key: Decrypted key is empty.");
            return null;
        }

        return originalKey;
    } catch (error) {
        console.error("Decryption error:", error);
        return null;
    }
};

// Fetch developer data from cache or database
const getDevFromCache = async (api) => {
    let message = "";
    try {
        let dev = cache.get(api);
        if (!dev) {
            const [rows] = await db.query("SELECT * FROM xera_developer WHERE BINARY xera_api = ?", [api]);

            if (rows.length === 0) {
                return message = "Invalid API key" 
            }

            dev = rows[0];
            cache.set(api, dev);
        }

        if (dev.xera_moderation !== "creator") {
            return message = "Access denied"
        }

        return dev;
    } catch (error) {
        return message = "Internal server error" 
    }
};

// Function to verify if the request is legitimate
const verifyRequestSource = (origin) => {
    const expectedOrigins = [
        "https://texeract.network",
        "http://localhost:3000",
        "http://localhost:3001",
        "https://texeract-network-beta.vercel.app",
        "https://tg-texeract-beta.vercel.app",
        "https://texeractbot.xyz",
    ];

    // Normalize `referer` to only include the origin if necessary
    if (origin.includes("://")) {
        const url = new URL(origin);
        origin = `${url.protocol}//${url.host}`;
    }

    // Check if the origin matches any allowed origins
    if (!expectedOrigins.includes(origin)) {
        console.error("Origin not allowed:", origin);
        return false;
    }

    return true;
};

const validateApiKey = async (apikey,origin) => {

    let message = "";
    if (!apikey) {
      return message = "No API key found";
    }

    const decodedKey = decodeKey(apikey);
    if (!decodedKey) {
        message = "Invalid encoded API key"
        return message
    }

    if (!verifyRequestSource(origin)) {
        message = "Unauthorized request"
        return message;
    }

    const dev = await getDevFromCache(decodedKey);
    if (!dev) {
        message = "Developer not found or unauthorized"
        return message;
    }

    return true;
};

// Airdrop Full Stats - Optimized for Efficiency
// Helper functions to handle dates
const getDateNDaysAgo = (n) => {
    const date = new Date();
    date.setDate(date.getDate() - n);
    return date.toISOString().split('T')[0]; // Format as 'YYYY-MM-DD'
};

const getStartAndEndOfDay = (date) => {
    const startDate = `${date} 00:00:00`;
    const endDate = `${date} 23:59:59`;
    return { startDate, endDate };
};

app.post('/xera/v1/api/users/airdrop/full-stats', async (req, res) => {
    const { apikey } = req.body;
    const origin = req.headers.origin
    const isValid = await validateApiKey(apikey,origin);
  
    if (!isValid)  {
        return res.status(400).json({ success: false, message: isValid });
    }
    try {
        const results = [];

        for (let i = 0; i < 10; i++) {
            const date = getDateNDaysAgo(i);
            const { startDate, endDate } = getStartAndEndOfDay(date);

            // Query total xera_points
            const pointsData = await db.query(`
                SELECT SUM(xera_points) AS totalPoints
                FROM xera_user_tasks
                WHERE xera_completed_date BETWEEN ? AND ?
            `, [startDate, endDate]);
            const totalPoints = pointsData[0]?.[0]?.totalPoints || 0;
            

            // Query unique usernames (daily participants)
            const usersData = await db.query(`
                SELECT COUNT(DISTINCT username) AS dailyParticipants
                FROM xera_user_tasks
                WHERE xera_completed_date BETWEEN ? AND ?
            `, [startDate, endDate]);
            const dailyParticipants = usersData[0]?.[0]?.dailyParticipants || 0;

            // Query total "Referral Task"
            const referralData = await db.query(`
                SELECT COUNT(*) AS newUsers
                FROM xera_user_tasks
                WHERE xera_completed_date BETWEEN ? AND ? AND xera_task = 'Referral Task'
            `, [startDate, endDate]);
            const newUsers = referralData[0]?.[0]?.newUsers || 0;

            // Query total "TXERA Claim Task"
            const txeraClaimData = await db.query(`
                SELECT COUNT(*) AS txeraClaimTasks
                FROM xera_user_tasks
                WHERE xera_completed_date BETWEEN ? AND ? AND xera_task = 'TXERA Claim Task'
            `, [startDate, endDate]);
            const txeraClaimTasks = txeraClaimData[0]?.[0]?.txeraClaimTasks || 0;

            // Append results for the current day
            results.push({
                date,
                totalPoints,
                dailyParticipants,
                newUsers,
                txeraClaimTasks,
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
    const { apikey } = req.body;
    const origin = req.headers.origin
    // Validate the API key and get the decoded key
    const isValid = await validateApiKey(apikey,origin);
  
    if (!isValid)  {
        return res.status(400).json({ success: false, message: isValid });
    }

    // If validation passes, continue with the logic
    const limit = 10 
    const page = 1
    const offset = (page - 1) * limit;

    try {
        const [rows] = await db.query(
            `SELECT MAX(username) AS username, MAX(xera_wallet) AS xera_wallet, SUM(CAST(xera_points AS DECIMAL(10))) AS total_points, 
                SUM(CASE WHEN xera_task = 'Referral Task' THEN 1 ELSE 0 END) AS referral_task_count
            FROM xera_user_tasks
            WHERE DATE(xera_completed_date) BETWEEN ? AND ?
            GROUP BY BINARY username
            ORDER BY total_points DESC
            LIMIT ? OFFSET ?`, 
            [phaseStartDate, phaseEndDate, limit, offset]
        );

        const [totalRows] = await db.query(
            `SELECT COUNT(DISTINCT username) AS total
            FROM xera_user_tasks
            WHERE DATE(xera_completed_date) BETWEEN ? AND ?`
        , [phaseStartDate, phaseEndDate]);

        const total = totalRows[0]?.total || 0;
        const totalPages = Math.ceil(total / limit);

        return res.json({
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
    const { apikey } = req.body;
    const origin = req.headers.origin

    const isValid = await validateApiKey(apikey,origin);
    if (!isValid)  {
        return res.status(400).json({ success: false, message: isValid });
    }

    try {
        const [userTask] = await db.query('SELECT COUNT(DISTINCT BINARY username) AS user_participants FROM xera_user_tasks');
        
        if (userTask.length > 0) {
            const participantData = userTask[0].user_participants;
            return res.json({ success: true, message: "User tasks successfully retrieved", participants: participantData });
        } else {
            return res.json({ success: false, message: "No data retrieved" });
        }
    } catch (error) {
        return res.json({ success: false, message: "Request error", error: error.message });
    }
});

// Function to handle total points for a given phase
const getTotalPoints = async (req, res, startDate, endDate) => {
    const { apikey } = req.body;
    const origin = req.headers.origin
    const isValid = await validateApiKey(apikey,origin);
  
    if (!isValid)  {
        return res.status(400).json({ success: false, message: isValid });
    }

    try {
        const [userstask] = await db.query(
            `SELECT SUM(xera_points) AS total_points 
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
    const { apikey } = req.body;
    const origin = req.headers.origin
    
    const isValid = await validateApiKey(apikey,origin);
    
    if (!isValid)  {
      return res.status(400).json({ success: false, message: isValid });
    }

    try {
        const [countWallet] = await db.query('SELECT COUNT(*) AS user_count FROM xera_user_accounts');

        if (countWallet.length > 0) {
            const walletCount = countWallet[0].user_count;
            return res.json({ success: true, message: "Successfully counted all wallets", walletCount });
        } else {
            return res.json({ success: false, message: "No data found" });
        }
    } catch (error) {
        return res.json({ success: false, message: "Request error", error: error.message });
    }
});

// Route to get the count of recent participants
app.post('/xera/v1/api/users/airdrop/recent-participant', async (req, res) => {
    const { apikey } = req.body;
    const origin = req.headers.origin
    
    const isValid = await validateApiKey(apikey,origin);
    
    if (!isValid)  {
      return res.status(400).json({ success: false, message: isValid });
    }

    try {
        const [recentParticipants] = await db.query(
            `SELECT COUNT(DISTINCT BINARY username) AS recent_participants
            FROM xera_user_tasks
            WHERE xera_completed_date BETWEEN CONCAT(CURDATE(), ' 00:00:00') AND CONCAT(CURDATE(), ' 23:59:59')
                AND xera_task != 'TXERA Claim Task'`
        );

        if (recentParticipants.length > 0) {
            const participantsData = recentParticipants[0].recent_participants;
            return res.json({ success: true, message: "Participants successfully retrieved", recentparticipants: participantsData });
        } else {
            return res.json({ success: false, message: "No data found" });
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