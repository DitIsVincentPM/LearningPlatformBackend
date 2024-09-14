// server.js
const express = require('express');
const cors = require('cors');
const app = express();
const port = 3000;

const corsOptions = {
    origin: 'http://localhost:5173', // Set this to your Vue.js app's origin
    methods: 'GET,POST',
    allowedHeaders: 'Content-Type'
};

app.use(cors(corsOptions));

// Middleware to parse JSON
app.use(express.json());

// Simple route
app.get('/', (req, res) => {
    res.send('Hello from Express!');
});

// Example route for login
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    if (username === 'admin' && password === 'password') {
        res.json({ message: 'Login successful' });
    } else {
        res.status(401).json({ message: 'Invalid credentials' });
    }
});

// Export the app
module.exports = app;
