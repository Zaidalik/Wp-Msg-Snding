const mysql = require('mysql2');
const fs = require('fs');
const path = require('path');

const pool = mysql.createPool({
    host: 'gateway01.ap-southeast-1.prod.aws.tidbcloud.com',
    user: '21L3QXxojKa1zst.root',
    password: 'O9bb1U5E4KX78UMp',
    database: 'AUTH',
    port: 4000,
    ssl: {
        ca: fs.readFileSync(path.join(__dirname, 'certs', 'ca.pem')),
    },
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

const db = pool.promise();
module.exports = db;
