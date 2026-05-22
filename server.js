const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { pool, authenticateToken, JWT_SECRET, createDefaultMap } = require('./db');

const app = express();
app.use(require('cors')());
app.use(express.json());

const PORT = process.env.PORT || 3001;

// ─── AUTH ROUTES ───────────────────────────────────

app.post('/api/auth/register', async (req, res) => {
    const { username, email, password, displayName } = req.body;
    
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
        
        const userId = result.insertId;
        const mapId = await createDefaultMap(userId);
        const token = jwt.sign({ userId }, JWT_SECRET, { expiresIn: '7d' });
        
        res.status(201).json({
            message: 'User registered successfully',
            token,
            user: { id: userId, username, email, displayName: displayName || username },
            defaultMapId: mapId
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    
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

app.get('/api/auth/me', authenticateToken, async (req, res) => {
    res.json({ user: req.user });
});

// ─── MAP ROUTES ────────────────────────────────────

app.get('/api/maps', authenticateToken, async (req, res) => {
    try {
        const [maps] = await pool.query(
            'SELECT id, name, created_at, updated_at FROM maps WHERE user_id = ? ORDER BY updated_at DESC',
            [req.user.id]
        );
        res.json({ maps });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/maps', authenticateToken, async (req, res) => {
    const { name } = req.body;
    const mapName = name?.trim() || 'Untitled Map';
    
    try {
        const [result] = await pool.query(
            'INSERT INTO maps (user_id, name) VALUES (?, ?)',
            [req.user.id, mapName]
        );
        res.status(201).json({
            id: result.insertId,
            name: mapName,
            created_at: new Date(),
            updated_at: new Date()
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/maps/:id', authenticateToken, async (req, res) => {
    const { name } = req.body;
    const mapId = parseInt(req.params.id);
    
    if (!name?.trim()) {
        return res.status(400).json({ error: 'Map name is required' });
    }
    
    try {
        const [maps] = await pool.query('SELECT id FROM maps WHERE id = ? AND user_id = ?', [mapId, req.user.id]);
        if (maps.length === 0) {
            return res.status(403).json({ error: 'Unauthorized' });
        }
        
        await pool.query('UPDATE maps SET name = ? WHERE id = ?', [name.trim(), mapId]);
        res.json({ id: mapId, name: name.trim() });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/maps/:id', authenticateToken, async (req, res) => {
    const mapId = parseInt(req.params.id);
    
    try {
        const [maps] = await pool.query('SELECT id FROM maps WHERE id = ? AND user_id = ?', [mapId, req.user.id]);
        if (maps.length === 0) {
            return res.status(403).json({ error: 'Unauthorized' });
        }
        
        // Cascade: edges and nodes deleted by foreign key constraints
        await pool.query('DELETE FROM maps WHERE id = ?', [mapId]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ─── NODE/EDGE ROUTES (Map-scoped) ─────────────────

app.get('/api/data', authenticateToken, async (req, res) => {
    const mapId = parseInt(req.query.mapId);
    if (!mapId) {
        return res.status(400).json({ error: 'mapId query parameter required' });
    }
    
    try {
        const [mapCheck] = await pool.query('SELECT id FROM maps WHERE id = ? AND user_id = ?', [mapId, req.user.id]);
        if (mapCheck.length === 0) {
            return res.status(403).json({ error: 'Unauthorized or map not found' });
        }
        
        const [nodes] = await pool.query('SELECT * FROM nodes WHERE map_id = ?', [mapId]);
        const [edges] = await pool.query('SELECT * FROM edges WHERE map_id = ?', [mapId]);
        
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
    const { label, title, x, y, mapId } = req.body;
    
    if (!mapId) {
        return res.status(400).json({ error: 'mapId is required' });
    }
    
    try {
        const [mapCheck] = await pool.query('SELECT id FROM maps WHERE id = ? AND user_id = ?', [mapId, req.user.id]);
        if (mapCheck.length === 0) {
            return res.status(403).json({ error: 'Unauthorized' });
        }
        
        const [result] = await pool.query(
            'INSERT INTO nodes (user_id, map_id, label, title, x, y) VALUES (?, ?, ?, ?, ?, ?)',
            [req.user.id, mapId, label, title || label, x, y]
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
    const { source, target, mapId } = req.body;
    
    if (!mapId) {
        return res.status(400).json({ error: 'mapId is required' });
    }
    
    try {
        const [nodes] = await pool.query(
            'SELECT id FROM nodes WHERE id IN (?, ?) AND map_id = ? AND user_id = ?',
            [parseInt(source), parseInt(target), mapId, req.user.id]
        );
        if (nodes.length !== 2) {
            return res.status(403).json({ error: 'Unauthorized or nodes not in map' });
        }
        
        const [result] = await pool.query(
            'INSERT INTO edges (map_id, source_id, target_id) VALUES (?, ?, ?)',
            [mapId, parseInt(source), parseInt(target)]
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
    const { title, mapId } = req.body;
    const id = parseInt(req.params.id);
    
    try {
        const [nodes] = await pool.query(
            'SELECT id FROM nodes WHERE id = ? AND map_id = ? AND user_id = ?',
            [id, mapId, req.user.id]
        );
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
    const { x, y, mapId } = req.body;
    const id = parseInt(req.params.id);
    
    try {
        const [nodes] = await pool.query(
            'SELECT id FROM nodes WHERE id = ? AND map_id = ? AND user_id = ?',
            [id, mapId, req.user.id]
        );
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
    const { mapId } = req.body;
    const id = parseInt(req.params.id);
    
    try {
        const [nodes] = await pool.query(
            'SELECT id FROM nodes WHERE id = ? AND map_id = ? AND user_id = ?',
            [id, mapId, req.user.id]
        );
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

const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`MindBase API running on port ${PORT}`);
});

server.on('error', (err) => {
    console.error('Server error:', err);
});


// const server = app.listen(PORT, '0.0.0.0', () => {
//     console.log(`MindBase API running on port ${PORT}`);
//     console.log(`Binding to: 0.0.0.0:${PORT}`);
// });

// server.on('error', (err) => {
//     console.error('Server error:', err);
// });