// server.js
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
require('dotenv').config();

const app = express();
const port = 8080;

const corsOptions = {
    origin: process.env.WEBSITE_URL,
    methods: 'GET,POST',
    allowedHeaders: 'Content-Type, Authorization'
};

const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

db.connect((err) => {
    if (err) {
        console.error('Error connecting to MySQL:', err);
        return;
    }
    console.log('Connected to MySQL');
});

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

app.use(express.json());

const SECRET_KEY = process.env.SECRET_KEY;

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;

    db.query('SELECT * FROM users WHERE name = ?', [username], (err, results) => {
        if (err) {
            console.error('Error querying the database:', err);
            return res.status(500).json({ message: 'Internal server error' });
        }

        if (results.length > 0) {
            const dbUser = results[0];
            const dbPassword = dbUser.password;

            bcrypt.compare(password, dbPassword, (err, match) => {
                if (err) return res.status(500).json({ message: 'Internal server error' });

                if (match) {
                    const token = jwt.sign({ id: dbUser.id, username: dbUser.name }, SECRET_KEY, { expiresIn: '1h' });
                    res.json({ message: 'Login successful', token });
                    console.log("Login Request Successful");
                } else {
                    res.status(401).json({ message: 'Invalid credentials' });
                    console.log("Login Request Failed: Incorrect password");
                }
            });
        } else {
            res.status(401).json({ message: 'Invalid credentials' });
            console.log("Login Request Failed: User not found");
        }
    });
});

app.post('/api/register', (req, res) => {
    const { name, nameSecond, password } = req.body;

    // First, check if the user already exists
    db.query('SELECT * FROM users WHERE name = ?', [name], (err, results) => {
        if (err) {
            console.error('Error querying the database:', err);
            return res.status(500).json({ message: 'Internal server error' });
        }

        if (results.length > 0) {
            // User already exists
            res.status(400).json({ message: 'User already exists' });
            console.log("Register Request Failed: User already exists");
            return;
        }

        // If user does not exist, proceed with registration
        bcrypt.hash(password, 10, (err, hash) => {
            if (err) {
                console.error('Error hashing the password:', err);
                return res.status(500).json({ message: 'Internal server error' });
            }

            db.query('INSERT INTO users (name, secondName, permissionId, password) VALUES (?, ?, ?, ?)', [name, nameSecond, 1, hash], (err, results) => {
                if (err) {
                    console.error('Error querying the database:', err);
                    return res.status(500).json({ message: 'Internal server error' });
                }

                if (results.affectedRows > 0) {
                    const token = jwt.sign({ id: results.insertId, username: name }, SECRET_KEY, { expiresIn: '1h' });
                    res.json({ message: 'Register successful', token });
                    console.log("Register Request Successful");
                } else {
                    res.status(500).json({ message: 'Registration failed' });
                    console.log("Register Request Failed", results);
                }
            });
        });
    });
});

app.get('/api/getUserData', authenticateToken, (req, res) => {
    res.json({ user: req.user });
    console.log("User data request forfilled");
});

app.get('/api/getCardCollections', authenticateToken, (req, res) => {
    const userId = req.user.id;

    db.query('SELECT * FROM collections WHERE user_id = ?', [userId], (err, results) => {
        if (err) {
            console.error('Error querying the database:', err);
            return res.status(500).json({ message: 'Internal server error' });
        }

        res.json({ cardCollections: results });
        console.log(`Card collections for user ${userId} retrieved`);
    });
});

app.get('/api/getCardData', authenticateToken, (req, res) => {
    const userId = req.user.id;
    const cardId = req.headers['card-id'];

    if (!cardId) {
        return res.status(400).json({ message: 'Card ID is required' });
    }

    // Query to get the specific card by cardId and userId
    db.query('SELECT * FROM cards WHERE id = ? AND user_id = ?', [cardId, userId], (err, results) => {
        if (err) {
            console.error('Error querying the database:', err);
            return res.status(500).json({ message: 'Internal server error' });
        }

        if (results.length === 0) {
            return res.status(404).json({ message: 'Card not found' });
        }

        res.json({ cardData: results[0] }); // Assuming the card data is a single object
        console.log(`Card data for cardId ${cardId} and user ${userId} retrieved`);
    });
});

app.get('/api/getCardsFromCollection', authenticateToken, (req, res) => {
    const userId = req.user.id; // Extract the user ID from the authenticated token
    const collectionId = req.query.collectionId; // Extract collectionId from query parameters

    if (!collectionId) {
        return res.status(400).json({ message: 'Collection ID is required' });
    }

    db.query('SELECT * FROM cards WHERE collection_id = ? AND user_id = ?', [collectionId, userId], (err, results) => {
        if (err) {
            console.error('Error querying the database:', err);
            return res.status(500).json({ message: 'Internal server error' });
        }

        if (results.length === 0) {
            return res.status(404).json({ message: 'No cards found for this collection' });
        }

        res.json({ cards: results });
        console.log(`Cards from collectionId ${collectionId} for user ${userId} retrieved`);
    });
});

app.get('/api/getCollectionData', authenticateToken, (req, res) => {
    const userId = req.user.id; // Extract the user ID from the authenticated token
    const collectionId = req.query.collectionId; // Extract collectionId from query parameters

    if (!collectionId) {
        return res.status(400).json({ message: 'Collection ID is required' });
    }

    db.query('SELECT * FROM collections WHERE id = ? AND user_id = ?', [collectionId, userId], (err, results) => {
        if (err) {
            console.error('Error querying the database:', err);
            return res.status(500).json({ message: 'Internal server error' });
        }

        if (results.length === 0) {
            return res.status(404).json({ message: 'No cards found for this collection' });
        }

        res.json({ collection: results });
        console.log(`Cards from collectionId ${collectionId} for user ${userId} retrieved`);
    });
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});

module.exports = app;
