if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config();
}

const mysql = require('mysql2/promise');

const JWT_SECRET = process.env.JWT_SECRET || 'mindbase-secret-key-change-in-production';
const DB_HOST = process.env.DB_HOST || 'localhost';
const DB_USER = process.env.DB_USER || 'root';
const DB_PASSWORD = process.env.DB_PASSWORD || '';
const DB_NAME = process.env.DB_NAME || 'mindbase';

// ─── Pool: use MYSQL_URL only when explicitly online ─────
let pool;
if (process.env.ONLINE === 'true') {
    pool = mysql.createPool(process.env.MYSQL_URL);
} else {
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

const createDefaultMap = async (userId) => {
    const [result] = await pool.query(
        'INSERT INTO maps (user_id, name) VALUES (?, ?)',
        [userId, 'My First Map']
    );
    return result.insertId;
};

module.exports = { pool, authenticateToken, JWT_SECRET, createDefaultMap };