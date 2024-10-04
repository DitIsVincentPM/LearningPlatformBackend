const mysql = require('mysql2/promise'); // Use the promise-based version
require('dotenv').config();

// Create a connection pool
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 30,
    queueLimit: 0
});

const query = async (sql, params) => {
    try {
        console.log(`${process.env.DB_PASSWORD}`);
        console.log(`Executing query: ${sql} with params: ${JSON.stringify(params)}`);
        const [rows] = await pool.execute(sql, params);
        console.log(`Query successful, returned rows: ${JSON.stringify(rows)}`);
        return rows;
    } catch (error) {
        console.error(`Query failed: ${error.message}`);
        throw error; // rethrow the error so the calling function is aware
    }
};

const checkPermission = async (userId, collectionId, requiredPermission) => {
    try {
        console.log(`Checking permission for userId: ${userId}, collectionId: ${collectionId}, requiredPermission: ${requiredPermission}`);

        // Check if the user is the owner of the collection
        const ownershipCheck = await query('SELECT user_id FROM collections WHERE id = ?', [collectionId]);
        console.log(`Ownership check result: ${JSON.stringify(ownershipCheck)}`);

        if (ownershipCheck.length > 0 && ownershipCheck[0].user_id === userId) {
            console.log(`User ${userId} is the owner of collection ${collectionId}. Permission granted.`);
            return true; // Owner always has full access
        }

        // Check permissions for shared collections
        const results = await query('SELECT permission FROM sharing WHERE user_id = ? AND collection_id = ?', [userId, collectionId]);
        console.log(`Permission check result: ${JSON.stringify(results)}`);

        if (results.length === 0 || results[0].permission < requiredPermission) {
            console.log(`User ${userId} does not have sufficient permissions for collection ${collectionId}.`);
            return false;
        }

        console.log(`User ${userId} has sufficient permissions for collection ${collectionId}.`);
        return true;
    } catch (error) {
        console.error(`Error in checkPermission: ${error.message}`);
        throw error; // rethrow to propagate the error
    }
};

module.exports = {
    query,
    checkPermission
};
