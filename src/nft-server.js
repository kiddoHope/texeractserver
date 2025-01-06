const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const db = require('./connection');
const cors = require("cors");
const compression = require("compression");
const NodeCache = require("node-cache");
const bcrypt = require("bcrypt");
require("dotenv").config();

const app = express();
const port = 5006;
const jwtSecret = process.env.MAIN_JWT_SECRET;

// Validate required environment variables
if (!jwtSecret || !process.env.DB_HOST || !process.env.DB_USER || !process.env.DB_PASSWORD || !process.env.DB_DATABASE) {
    console.error("Missing required environment variables. Please check your .env file.");
    process.exit(1);
}

// Caching setup
const cache = new NodeCache({ stdTTL: 60, checkperiod: 120 });

// Middleware setup
app.use(compression());
app.use(bodyParser.json());

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
            return callback(new Error("Not allowed by CORS"));
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

// Authentication middleware
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

// Endpoint for fetching user balances
app.post('/xera/v1/api/user/nft', authenticateToken, async (req, res) => {
    const { user } = req.body;

    if (!user) {
        return res.json({ success: false, message: 'No address provided' });
    }

    try {
        // Step 1: Retrieve user node details
        const [getNFT] = await db.query('SELECT * FROM xera_asset_nfts WHERE nft_owner = ?', [user]);

        if (getNFT.length > 0) {
            const cleanNFT = getNFT.map(({ id, ...nft }) => nft);
            return res.json({ success: true, message: `Successfully retrieved NFT. Wallet: ${user}`, nft: cleanNFT });
        } else {
            return res.json({ success: false, message: 'No NFT found for the provided address' });
        }
    } catch (error) {
        return res.json({ success: false, message: error.message });
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