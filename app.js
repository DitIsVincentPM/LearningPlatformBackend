const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const dbUtils = require('./dbUtils');

require('dotenv').config();

const app = express();
const port = 8070;

const corsOptions = {
    origin: process.env.WEBSITE_URL,
    methods: 'GET,POST,DELETE,PUT',
    allowedHeaders: 'Content-Type, Authorization'
};

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

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const results = await dbUtils.query('SELECT * FROM users WHERE name = ?', [username]);
        if (results.length > 0) {
            const dbUser = results[0];
            const match = await bcrypt.compare(password, dbUser.password);

            if (match) {
                const token = jwt.sign({ id: dbUser.id, username: dbUser.name }, SECRET_KEY, { expiresIn: '1h' });
                res.json({ message: 'Login successful', token });
                console.log("Login Request Successful");
            } else {
                res.status(401).json({ message: 'Invalid credentials' });
                console.log("Login Request Failed: Incorrect password");
            }
        } else {
            res.status(401).json({ message: 'Invalid credentials' });
            console.log("Login Request Failed: User not found");
        }
    } catch (err) {
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.post('/api/createCardCollection', authenticateToken, async (req, res) => {
    const { name } = req.body;
    const userId = req.user.id; // Get the user ID from the authenticated user

    if (!name || name.trim() === '') {
        return res.status(400).json({ message: 'Collection name is required' });
    }

    try {
        // Insert the new collection into the database
        const result = await dbUtils.query('INSERT INTO collections (name, user_id) VALUES (?, ?)', [name, userId]);

        if (result.affectedRows > 0) {
            // Successfully created the collection
            res.status(201).json({ message: 'Collection created successfully', collectionId: result.insertId });
            console.log(`Collection created with id ${result.insertId} by user ${userId}`);
        } else {
            res.status(500).json({ message: 'Failed to create collection' });
            console.log(`Failed to create collection for user ${userId}`);
        }
    } catch (err) {
        res.status(500).json({ message: 'Internal server error' });
        console.error(`Error creating collection for user ${userId}: ${err.message}`);
    }
});

app.delete('/api/deleteCollection/:collectionId', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    const collectionId = req.params.collectionId;

    try {
        // Ensure the user owns the collection
        const collection = await dbUtils.query('SELECT * FROM collections WHERE id = ? AND user_id = ?', [collectionId, userId]);

        if (collection.length === 0) {
            return res.status(404).json({ message: 'Collection not found or unauthorized' });
        }

        // Delete the collection
        await dbUtils.query('DELETE FROM collections WHERE id = ?', [collectionId]);
        res.status(200).json({ message: 'Collection deleted successfully' });
        console.log(`Collection ${collectionId} deleted by user ${userId}`);
    } catch (err) {
        res.status(500).json({ message: 'Internal server error' });
        console.error(`Error deleting collection for user ${userId}: ${err.message}`);
    }
});

app.post('/api/addCards', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    const { collectionId, cards } = req.body; // 'cards' should be an array of card objects

    if (!Array.isArray(cards) || cards.length === 0) {
        return res.status(400).json({ message: 'No cards provided' });
    }

    try {
        // Ensure the user owns the collection
        const collection = await dbUtils.query('SELECT * FROM collections WHERE id = ? AND user_id = ?', [collectionId, userId]);
        if (collection.length === 0) {
            return res.status(404).json({ message: 'Collection not found or unauthorized' });
        }

        // Prepare the SQL query for bulk insertion
        const values = cards.map(card => [card.name, card.description, collectionId, userId]); // 'disabled' field defaults to false

        // Adjust the SQL query for bulk insert
        const placeholders = values.map(() => '(?, ?, ?, ?)').join(', ');
        const flattenedValues = values.flat(); // Flatten the array for the query

        const query = `INSERT INTO cards (frontText, backText, collection_id, user_id) VALUES ${placeholders}`;
        const result = await dbUtils.query(query, flattenedValues);

        res.status(201).json({ message: 'Cards created successfully', insertedRows: result.affectedRows });
        console.log(`${result.affectedRows} cards added to collection ${collectionId} by user ${userId}`);
    } catch (err) {
        res.status(500).json({ message: 'Internal server error' });
        console.error(`Error adding cards to collection ${collectionId} for user ${userId}: ${err.message}`);
    }
});


app.post('/api/register', async (req, res) => {
    const { name, nameSecond, password } = req.body;

    try {
        const results = await dbUtils.query('SELECT * FROM users WHERE name = ?', [name]);
        if (results.length > 0) {
            res.status(400).json({ message: 'User already exists' });
            console.log("Register Request Failed: User already exists");
            return;
        }

        const hash = await bcrypt.hash(password, 10);
        const result = await dbUtils.query('INSERT INTO users (name, secondName, permissionId, password) VALUES (?, ?, ?, ?)', [name, nameSecond, 1, hash]);

        if (result.affectedRows > 0) {
            const token = jwt.sign({ id: result.insertId, username: name }, SECRET_KEY, { expiresIn: '1h' });
            res.json({ message: 'Register successful', token });
            console.log("Register Request Successful");
        } else {
            res.status(500).json({ message: 'Registration failed' });
            console.log("Register Request Failed", result);
        }
    } catch (err) {
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.get('/api/getUserData', authenticateToken, (req, res) => {
    res.json({ user: req.user });
    console.log("User data request fulfilled");
});

app.get('/api/getCardCollections', authenticateToken, async (req, res) => {
    const userId = req.user.id;

    try {
        const ownedCollections = await dbUtils.query('SELECT * FROM collections WHERE user_id = ?', [userId]);
        const sharedCollections = await dbUtils.query('SELECT c.* FROM collections c JOIN sharing s ON c.id = s.collection_id WHERE s.user_id = ? AND s.permission >= 1', [userId]);

        const allCollections = [...ownedCollections, ...sharedCollections];
        const uniqueCollections = Array.from(new Set(allCollections.map(c => c.id)))
            .map(id => {
                return allCollections.find(c => c.id === id);
            });

        res.json({ cardCollections: uniqueCollections });
        console.log(`Card collections for user ${userId} retrieved`);
    } catch (err) {
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Function to delete a card
app.delete('/api/deleteCard/:cardId', authenticateToken, async (req, res) => {
    const userId = req.user.id; // Get user ID from the authenticated user
    const cardId = req.params.cardId; // Get card ID from request parameters

    try {
        // Ensure the user owns the card
        const card = await dbUtils.query('SELECT * FROM cards WHERE id = ? AND user_id = ?', [cardId, userId]);

        if (card.length === 0) {
            return res.status(404).json({ message: 'Card not found or unauthorized' });
        }

        // Delete the card
        await dbUtils.query('DELETE FROM cards WHERE id = ?', [cardId]);
        res.status(200).json({ message: 'Card deleted successfully' });
        console.log(`Card ${cardId} deleted by user ${userId}`);
    } catch (err) {
        res.status(500).json({ message: 'Internal server error' });
        console.error(`Error deleting card ${cardId} for user ${userId}: ${err.message}`);
    }
});

// Function to edit a card
app.put('/api/editCard/:cardId', authenticateToken, async (req, res) => {
    const userId = req.user.id; // Get user ID from the authenticated user
    const cardId = req.params.cardId; // Get card ID from request parameters
    const { frontText, backText } = req.body; // Extract new front and back text from request body

    if (!frontText || !backText) {
        return res.status(400).json({ message: 'Front text and back text are required' });
    }

    try {
        // Ensure the user owns the card
        const card = await dbUtils.query('SELECT * FROM cards WHERE id = ? AND user_id = ?', [cardId, userId]);

        if (card.length === 0) {
            return res.status(404).json({ message: 'Card not found or unauthorized' });
        }

        // Update the card details
        await dbUtils.query('UPDATE cards SET frontText = ?, backText = ? WHERE id = ?', [frontText, backText, cardId]);

        res.status(200).json({ message: 'Card updated successfully' });
        console.log(`Card ${cardId} updated by user ${userId}`);
    } catch (err) {
        res.status(500).json({ message: 'Internal server error' });
        console.error(`Error updating card ${cardId} for user ${userId}: ${err.message}`);
    }
});

app.get('/api/getCardData', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    const cardId = req.headers['card-id'];

    if (!cardId) {
        return res.status(400).json({ message: 'Card ID is required' });
    }

    try {
        const results = await dbUtils.query('SELECT * FROM cards WHERE id = ? AND user_id = ?', [cardId, userId]);

        if (results.length === 0) {
            return res.status(404).json({ message: 'Card not found' });
        }

        res.json({ cardData: results[0] }); // Assuming the card data is a single object
        console.log(`Card data for cardId ${cardId} and user ${userId} retrieved`);
    } catch (err) {
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.get('/api/getCardsFromCollection', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    const collectionId = req.query.collectionId;

    if (!collectionId) {
        return res.status(400).json({ message: 'Collection ID is required' });
    }

    try {
        const results = await dbUtils.query('SELECT * FROM cards WHERE collection_id = ? AND (user_id = ? OR EXISTS (SELECT 1 FROM sharing WHERE collection_id = ? AND user_id = ? AND permission >= 1))', [collectionId, userId, collectionId, userId]);

        if (results.length === 0) {
            return res.status(404).json({ message: 'No cards found for this collection' });
        }

        res.json({ cards: results });
        console.log(`Cards from collectionId ${collectionId} for user ${userId} retrieved`);
    } catch (err) {
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.get('/api/getCollectionData', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    const collectionId = req.query.collectionId;

    if (!collectionId) {
        return res.status(400).json({ message: 'Collection ID is required' });
    }

    try {
        const results = await dbUtils.query('SELECT * FROM collections WHERE id = ? AND (user_id = ? OR EXISTS (SELECT 1 FROM sharing WHERE collection_id = ? AND user_id = ? AND permission >= 1))', [collectionId, userId, collectionId, userId]);

        if (results.length === 0) {
            return res.status(404).json({ message: 'Collection not found' });
        }

        res.json({ collection: results });
        console.log(`Collection data for collectionId ${collectionId} and user ${userId} retrieved`);
    } catch (err) {
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.post('/api/generate-share-link', authenticateToken, async (req, res) => {
    const { collectionId } = req.body;
    const userId = req.user.id;

    try {
        const hasPermission = await dbUtils.checkPermission(userId, collectionId, 2);
        if (!hasPermission) {
            return res.status(403).json({ message: 'Insufficient permissions' });
        }

        const token = crypto.randomBytes(20).toString('hex'); // Generate a unique token

        // Insert the token into the database
        await dbUtils.query('INSERT INTO shareable_links (collection_id, token) VALUES (?, ?)', [collectionId, token]);

        res.json({ link: `${process.env.WEBSITE_URL}/share/${token}` });
        console.log('Share link generated successfully');
    } catch (err) {
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.get('/api/share/:token', authenticateToken, async (req, res) => {
    const { token } = req.params;
    const userId = req.user?.id;

    if (!userId) {
        return res.status(401).send('Unauthorized');
    }

    try {
        const results = await dbUtils.query('SELECT collection_id FROM shareable_links WHERE token = ?', [token]);

        if (results.length === 0) {
            return res.status(404).send('Link not found');
        }

        const collectionId = results[0].collection_id;

        const hasAccess = await dbUtils.checkPermission(userId, collectionId, 1);
        if (!hasAccess) {
            await dbUtils.query('INSERT INTO sharing (user_id, collection_id, permission) VALUES (?, ?, ?)', [userId, collectionId, 1]);
            res.send('You now have view access to this collection');
            console.log(`View access granted to user ${userId} for collection ${collectionId}`);
        } else {
            res.send('You already have access to this collection');
        }
    } catch (err) {
        res.status(500).send('Internal server error');
    }
});

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});