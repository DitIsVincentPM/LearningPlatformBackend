const mysql = require('mysql2/promise'); // Use the promise-based version
require('dotenv').config();

// Create a connection pool
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

const query = async (sql, params) => {
    const [rows] = await pool.execute(sql, params);
    return rows;
};

const checkPermission = async (userId, collectionId, requiredPermission) => {
    // Check if the user is the owner of the collection
    const ownershipCheck = await query('SELECT user_id FROM collections WHERE id = ?', [collectionId]);
    if (ownershipCheck.length > 0 && ownershipCheck[0].user_id === userId) {
        return true; // Owner always has full access
    }

    // Check permissions for shared collections
    const results = await query('SELECT permission FROM sharing WHERE user_id = ? AND collection_id = ?', [userId, collectionId]);
    if (results.length === 0 || results[0].permission < requiredPermission) {
        return false;
    }
    return true;
};


module.exports = {
    query,
    checkPermission
};
