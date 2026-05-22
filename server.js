if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config();
}

const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// ─── Environment Variables ───────────────────────
const JWT_SECRET = process.env.JWT_SECRET || 'mindbase-secret-key-change-in-production';
const DB_HOST = process.env.DB_HOST || 'localhost';
const DB_USER = process.env.DB_USER || 'root';
const DB_PASSWORD = process.env.DB_PASSWORD || '';
const DB_NAME = process.env.DB_NAME || 'mindbase';
const PORT = process.env.PORT || 3001;

// ─── MySQL Connection Pool ───────────────────────
let pool = null;
if(process.env.ONLINE == 'true'){
    pool = mysql.createPool(process.env.MYSQL_URL);
}else{
    pool = mysql.createPool({
        host: DB_HOST,
        user: DB_USER,
        password: DB_PASSWORD,
        database: DB_NAME,
        waitForConnections: true,
        connectionLimit: 10,
        queueLimit: 0
    });
}

// ─── JWT Authentication Middleware ─────────────────
const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }
    
    try {
        const jwt = require('jsonwebtoken');
        const decoded = jwt.verify(token, JWT_SECRET);
        const [users] = await pool.query('SELECT id, username, email, display_name FROM users WHERE id = ?', [decoded.userId]);
        if (users.length === 0) {
            return res.status(401).json({ error: 'User not found' });
        }
        req.user = users[0];
        next();
    } catch (err) {
        return res.status(403).json({ error: 'Invalid or expired token' });
    }
};

// ─── AUTH ROUTES ───────────────────────────────────

// POST /api/auth/register
app.post('/api/auth/register', async (req, res) => {
    const { username, email, password, displayName } = req.body;
    const bcrypt = require('bcryptjs');
    const jwt = require('jsonwebtoken');
    
    if (!username || !email || !password) {
        return res.status(400).json({ error: 'Username, email, and password are required' });
    }
    if (username.length < 3 || username.length > 30) {
        return res.status(400).json({ error: 'Username must be 3-30 characters' });
    }
    if (password.length < 6) {
        return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({ error: 'Invalid email format' });
    }
    
    try {
        const [existing] = await pool.query(
            'SELECT id FROM users WHERE username = ? OR email = ?',
            [username, email]
        );
        if (existing.length > 0) {
            return res.status(409).json({ error: 'Username or email already taken' });
        }
        
        const hashedPassword = await bcrypt.hash(password, 12);
        const [result] = await pool.query(
            'INSERT INTO users (username, email, password_hash, display_name) VALUES (?, ?, ?, ?)',
            [username, email, hashedPassword, displayName || username]
        );
        
        const token = jwt.sign({ userId: result.insertId }, JWT_SECRET, { expiresIn: '7d' });
        
        res.status(201).json({
            message: 'User registered successfully',
            token,
            user: {
                id: result.insertId,
                username,
                email,
                displayName: displayName || username
            }
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    const bcrypt = require('bcryptjs');
    const jwt = require('jsonwebtoken');
    
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }
    
    try {
        const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
        if (users.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const user = users[0];
        const passwordMatch = await bcrypt.compare(password, user.password_hash);
        if (!passwordMatch) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
        
        res.json({
            message: 'Login successful',
            token,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                displayName: user.display_name
            }
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// GET /api/auth/me
app.get('/api/auth/me', authenticateToken, async (req, res) => {
    res.json({ user: req.user });
});

// ─── PROTECTED NODE/EDGE ROUTES ────────────────────

app.get('/api/data', authenticateToken, async (req, res) => {
    try {
        const [nodes] = await pool.query('SELECT * FROM nodes WHERE user_id = ?', [req.user.id]);
        const [edges] = await pool.query(
            `SELECT e.* FROM edges e 
             JOIN nodes n ON e.source_id = n.id 
             WHERE n.user_id = ?`,
            [req.user.id]
        );
        
        const formattedEdges = edges.map(e => ({
            id: `e${e.id}`,
            source: e.source_id.toString(),
            target: e.target_id.toString()
        }));
        
        const formattedNodes = nodes.map(n => ({
            id: n.id.toString(),
            type: 'default',
            position: { x: n.x, y: n.y },
            data: { label: n.label, title: n.title }
        }));
        
        res.json({ nodes: formattedNodes, edges: formattedEdges });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/nodes', authenticateToken, async (req, res) => {
    const { label, title, x, y } = req.body;
    try {
        const [result] = await pool.query(
            'INSERT INTO nodes (user_id, label, title, x, y) VALUES (?, ?, ?, ?, ?)',
            [req.user.id, label, title || label, x, y]
        );
        res.json({
            id: result.insertId.toString(),
            type: 'default',
            position: { x, y },
            data: { label, title: title || label }
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/edges', authenticateToken, async (req, res) => {
    const { source, target } = req.body;
    try {
        const [nodes] = await pool.query(
            'SELECT id FROM nodes WHERE id IN (?, ?) AND user_id = ?',
            [parseInt(source), parseInt(target), req.user.id]
        );
        if (nodes.length !== 2) {
            return res.status(403).json({ error: 'Unauthorized' });
        }
        
        const [result] = await pool.query(
            'INSERT INTO edges (source_id, target_id) VALUES (?, ?)',
            [parseInt(source), parseInt(target)]
        );
        res.json({
            id: `e${result.insertId}`,
            source,
            target
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/nodes/:id/title', authenticateToken, async (req, res) => {
    const { title } = req.body;
    const id = parseInt(req.params.id);
    try {
        const [nodes] = await pool.query('SELECT id FROM nodes WHERE id = ? AND user_id = ?', [id, req.user.id]);
        if (nodes.length === 0) {
            return res.status(403).json({ error: 'Unauthorized' });
        }
        await pool.query('UPDATE nodes SET title = ? WHERE id = ?', [title, id]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/nodes/:id/position', authenticateToken, async (req, res) => {
    const { x, y } = req.body;
    const id = parseInt(req.params.id);
    try {
        const [nodes] = await pool.query('SELECT id FROM nodes WHERE id = ? AND user_id = ?', [id, req.user.id]);
        if (nodes.length === 0) {
            return res.status(403).json({ error: 'Unauthorized' });
        }
        await pool.query('UPDATE nodes SET x = ?, y = ? WHERE id = ?', [x, y, id]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/nodes/:id', authenticateToken, async (req, res) => {
    const id = parseInt(req.params.id);
    try {
        const [nodes] = await pool.query('SELECT id FROM nodes WHERE id = ? AND user_id = ?', [id, req.user.id]);
        if (nodes.length === 0) {
            return res.status(403).json({ error: 'Unauthorized' });
        }
        await pool.query('DELETE FROM edges WHERE source_id = ? OR target_id = ?', [id, id]);
        await pool.query('DELETE FROM nodes WHERE id = ?', [id]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'ok', time: Date.now() });
});

app.listen(PORT, () => {
    console.log(`MindBase API running on port ${PORT}`);
});