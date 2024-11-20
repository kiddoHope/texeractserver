const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const mysql = require('mysql2/promise')
const cors = require("cors");
const { body, validationResult } = require('express-validator');
require('dotenv').config();
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit')
const app = express();
const port = 5000;
const axios = require('axios')

app.use(bodyParser.json());

const allowedOrigins = ['https://texeract.network', 'http://localhost:3000', 'http://localhost:3001'];

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


const jwtDecode = (token) => {
  try {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
      return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));

    return JSON.parse(jsonPayload);
  } catch (error) {
    throw new Error('Invalid token specified');
  }
};

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, 
  max: 5, 
  message: "Too many requests from this IP, please try again later."
});

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

  
// database
const db = mysql.createPool({
    //host: '2a02:4780:28:feaa::1',  // use this in production
    host: 'srv1388.hstgr.io',
    user: 'u350266280_lokidatasetup',           
    password: 'texeract2024LOKI$$$',            
    database: 'u350266280_xeradatabase',    
    waitForConnections: true,
    connectTimeout: 20000, 
    port: 3306,               
    connectionLimit: 10,  
    queueLimit: 0          
  });

async function testConnection() {
    try {
        const connection = await db.getConnection();
        console.log('Database connection successful!');
        connection.release(); // Release the connection back to the pool
    } catch (error) {
        console.error('Database connection failed:', error.message);
    }
}

testConnection();

function generateRandomString(length) {
    return crypto.randomBytes(length).toString('hex').slice(0, length);
}

app.get("/xera/api/user-login", authenticateToken, async (req, res) => {
    try {
      const [allusers] = await db.query("SELECT * FROM xera_user_accounts");
      const userData = allusers.filter(user => user.username.trim() === req.user.username.trim());
  
      if (!userData) {
        return res.status(404).json({ message: "User data not found" });
      }

      const jsonDatapassed = [userData[0].username, userData[0].username];
  
      res.status(200).json(jsonDatapassed);
    } catch (error) {
      console.error('Database error:', error);
      return res.status(500).json({ success: false, message: 'Database connection failed' });
    }
});


app.post('/xera/api/login-basic',limiter, async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(403).json({ success: false, message: "Request Error. Input Field"})
    }

    const loginData = {
        username: username,
        password: password
    }
    const jsonData = JSON.stringify(loginData)
    try {
        axios
            .post("https://engeenx.com/xeraUserLoginBasic.php", jsonData)
            .then((response) => {
                
                const resData = response.data
                
                if (resData.success) {
                    const xeraWallet = resData.xera_wallet
                    const authToken = jwt.sign({ xeraWallet }, jwtSecret, { expiresIn: "7d" });
                    return res.status(200).json({ success: true, message: resData.message, authToken: authToken})
                } else {
                    return res.status(403).json({ success: false, message: resData.message})
                }
            })
    } catch (error) {
        return res.status(500).json({ success: false, message: "Internal Server Error"})
    }
})


app.post('/xera/api/login-prKey',limiter, async (req, res) => {
    const { privateKey } = req.body;

    if (!privateKey) {
        return res.status(403).json({ success: false, message: "Request Error. No private key received"})
    }

    const loginData = {
        userPrivateKey: privateKey,
    }
    const jsonData = JSON.stringify(loginData)
    try {
        axios
            .post("https://engeenx.com/xeraUserLoginPK.php", jsonData)
            .then((response) => {
                
                const resData = response.data
                
                if (resData.success) {
                    const xeraWallet = resData.xera_wallet
                    const authToken = jwt.sign({ xeraWallet }, jwtSecret, { expiresIn: "7d" });
                    return res.status(200).json({ success: true, message: resData.message, authToken: authToken})
                } else {
                    return res.status(403).json({ success: false, message: resData.message})
                }
            })
    } catch (error) {
        return res.status(500).json({ success: false, message: "Internal Server Error"})
    }
})

app.post('/xera/api/login-phrase',limiter, async (req, res) => {
    const { seedPhrase } = req.body;

    if (!seedPhrase) {
        return res.status(403).json({ success: false, message: "Request Error. No private key received"})
    }
    
    try {
        axios
            .post("https://engeenx.com/xeraUserLoginPhrase.php", seedPhrase,
                {headers: {
                    'Content-Type': 'application/json',
                }
            })
            .then((response) => {
                const resData = response.data
                
                if (resData.success) {
                    const xeraWallet = resData.xera_wallet
                    const authToken = jwt.sign({ xeraWallet }, jwtSecret, { expiresIn: "7d" });
                    return res.status(200).json({ success: true, message: resData.message, authToken: authToken})
                } else {
                    return res.status(403).json({ success: false, message: resData.message})
                }
            })
    } catch (error) {
        return res.status(500).json({ success: false, message: "Internal Server Error"})
    }
})

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
  