const mysql = require('mysql2/promise')
require('dotenv').config();

// 46.202.129.137
// ssh root@145.223.100.79
// 2a02:4780:28:feaa::1
// /home/texeractbot/htdocs/texeractbot.xyz
// /home/texeract/htdocs/texeract.network
// pm2 start src/server.js src/airdrop-server.js src/user-server.js src/faucet-server.js src/genesis-server.js src/watcher-server.js
// node start src/server.js src/airdrop-server.js src/user-server.js src/faucet-server.js src/genesis-server.js src/watcher-server.js

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

async function testConnection() {
    try {
        const connection = await db.getConnection();
        console.log('Database connection successful!');
        connection.release();
    } catch (error) {
        console.error('Database connection failed:', error.message);
    }
}

testConnection();

module.exports = db;