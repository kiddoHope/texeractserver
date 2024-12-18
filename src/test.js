const mysql = require('mysql');

const db = mysql.createConnection({
  host: '127.0.0.1',  // Use 127.0.0.1 for local connections
  user: 'root',
  password: 'Johnhope@2002',  // Your MySQL root password
  database: 'texeract_database',  // Database name
  port: 3306
});

db.connect((err) => {
  if (err) {
    console.error('Error connecting to MySQL: ' + err.stack);
    return;
  }
  console.log('Connected to MySQL as id ' + db.threadId);
});
