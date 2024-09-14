// server.js
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');

const app = express();
const port = 8080;

const corsOptions = {
    origin: 'http://localhost:5173',
    methods: 'GET,POST',
    allowedHeaders: 'Content-Type, Authorization'
};

const db = mysql.createConnection({
    host: 'elsdonckbv.be',
    user: 'ide',
    password: 'ide',
    database: 'Leerwebsite'
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

const SECRET_KEY = 'secret';

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

// Example: Simple login using MySQL
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;

    db.query('SELECT * FROM users WHERE name = ? AND password = ?', [username, password], (err, results) => {
        if (err) {
            console.error('Error querying the database:', err);
            return res.status(500).json({ message: 'Internal server error' });
        }

        if (results.length > 0) {
            const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: '1h' });
            res.json({ message: 'Login successful', token });
            console.log("Login Request Successful");
        } else {
            res.status(401).json({ message: 'Invalid credentials' });
            console.log("Login Request Failed", results);
        }
    });
});


app.post('/api/register', (req, res) => {
    const { name, secondName, password } = req.body;

    db.query('INSERT INTO users (name, secondName, permissionId, password) VALUES (?, ?, ?, ?)', [name, secondName, 1, password], (err, results) => {
        if (err) {
            console.error('Error querying the database:', err);
            return res.status(500).json({ message: 'Internal server error' });
        }

        if (results.length > 0) {
            const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: '1h' });

            res.json({ message: 'Register successful', token });
            console.log("Register Request Successful");
        } else {
            res.status(401).json({ message: 'Invalid credentials' });
            console.log("Register Request Failed", results);
        }
    });
});

app.get('/api/getUserData', authenticateToken, (req, res) => {
    res.json({ user: req.user });
    console.log("User data request forfilled");
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});

module.exports = app;
