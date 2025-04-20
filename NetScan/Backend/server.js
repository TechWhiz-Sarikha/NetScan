// server.js - Express server for NexScanner application

const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));

// Secret key for JWT
const JWT_SECRET = process.env.JWT_SECRET || 'nexscanner-secret-key';

// Database simulation (in production, use a real database)
const DB_PATH = path.join(__dirname, 'db');
const USERS_FILE = path.join(DB_PATH, 'users.json');
const SCANS_DIR = path.join(DB_PATH, 'scans');

// Ensure DB directories exist
if (!fs.existsSync(DB_PATH)) {
    fs.mkdirSync(DB_PATH, { recursive: true });
}
if (!fs.existsSync(SCANS_DIR)) {
    fs.mkdirSync(SCANS_DIR, { recursive: true });
}

// Initialize users file if it doesn't exist
if (!fs.existsSync(USERS_FILE)) {
    fs.writeFileSync(USERS_FILE, JSON.stringify([]), 'utf8');
}

// Helper functions

// Get all users
function getUsers() {
    try {
        const data = fs.readFileSync(USERS_FILE, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        console.error('Error reading users file:', error);
        return [];
    }
}

// Save users
function saveUsers(users) {
    try {
        fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), 'utf8');
        return true;
    } catch (error) {
        console.error('Error saving users file:', error);
        return false;
    }
}

// Get user by ID
function getUserById(userId) {
    const users = getUsers();
    return users.find(user => user.id === userId);
}

// Get user by username
function getUserByUsername(username) {
    const users = getUsers();
    return users.find(user => user.username.toLowerCase() === username.toLowerCase());
}

// Get user scans
function getUserScans(userId) {
    const userScansFile = path.join(SCANS_DIR, `${userId}.json`);
    
    if (!fs.existsSync(userScansFile)) {
        return [];
    }
    
    try {
        const data = fs.readFileSync(userScansFile, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        console.error(`Error reading scans for user ${userId}:`, error);
        return [];
    }
}

// Save user scan
function saveUserScan(userId, scan) {
    const userScansFile = path.join(SCANS_DIR, `${userId}.json`);
    let scans = [];
    
    if (fs.existsSync(userScansFile)) {
        try {
            const data = fs.readFileSync(userScansFile, 'utf8');
            scans = JSON.parse(data);
        } catch (error) {
            console.error(`Error reading scans for user ${userId}:`, error);
        }
    }
    
    // Add new scan at the beginning
    scans.unshift({
        id: uuidv4(),
        ...scan
    });
    
    // Keep only the latest 50 scans
    if (scans.length > 50) {
        scans = scans.slice(0, 50);
    }
    
    try {
        fs.writeFileSync(userScansFile, JSON.stringify(scans, null, 2), 'utf8');
        return true;
    } catch (error) {
        console.error(`Error saving scans for user ${userId}:`, error);
        return false;
    }
}

// Authentication middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ message: 'Authentication token required' });
    }
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid or expired token' });
        }
        
        req.user = user;
        next();
    });
}

// Optional authentication middleware (for endpoints that work both with and without auth)
function optionalAuthentication(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        next();
        return;
    }
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (!err) {
            req.user = user;
        }
        next();
    });
}

// Run nmap scan
function runNmapScan(target, scanType) {
    return new Promise((resolve, reject) => {
        // Map of scan types to their respective commands
        const scanCommands = {
            'ping': '-sP',
            'top-ports': '--top-ports 100',
            'rdns': '-sn -Pn --script fcrdns',
            'headers': '--script http-headers',
            'http-vuln': '--script "http-vuln*"',
            'malware': '-sV --script=http-malware-host',
            'os-detect': '-O',
            'firewall': '-sA',
            'tcp': '-sT',
            'udp': '-sU',
            'udp-version': '-sU -sV',
            'ping-sweep': '-sn',
            'arp': '-PR',
            'data-length': '--data-length 25'
        };
        
        // Validate scan type
        if (!scanCommands[scanType]) {
            return reject(new Error('Invalid scan type'));
        }
        
        // Sanitize input to prevent command injection
        const sanitizedTarget = target.replace(/[;&|`$]/g, '');
        
        // Build command
        const command = `nmap ${scanCommands[scanType]} ${sanitizedTarget}`;
        
        // Execute command
        exec(command, { timeout: 60000 }, (error, stdout, stderr) => {
            if (error && error.killed) {
                reject(new Error('Scan timeout after 60 seconds'));
                return;
            }
            
            if (error) {
                console.error(`Scan error: ${error.message}`);
                // Still return stdout and stderr for debugging
                resolve({
                    output: `Error: ${error.message}\n\n${stdout}\n${stderr}`,
                    timestamp: new Date().getTime()
                });
                return;
            }
            
            resolve({
                output: stdout,
                timestamp: new Date().getTime()
            });
        });
    });
}

// API Endpoints

// User signup
app.post('/api/signup', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // Validate input
        if (!username || !password) {
            return res.status(400).json({ message: 'Username and password are required' });
        }
        
        // Check if username already exists
        if (getUserByUsername(username)) {
            return res.status(400).json({ message: 'Username already exists' });
        }
        
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Create new user
        const newUser = {
            id: uuidv4(),
            username,
            password: hashedPassword,
            created: new Date().toISOString()
        };
        
        // Save user
        const users = getUsers();
        users.push(newUser);
        
        if (saveUsers(users)) {
            // Create empty scans file for user
            const userScansFile = path.join(SCANS_DIR, `${newUser.id}.json`);
            fs.writeFileSync(userScansFile, JSON.stringify([]), 'utf8');
            
            return res.status(201).json({ message: 'User created successfully' });
        } else {
            return res.status(500).json({ message: 'Failed to create user' });
        }
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// User login
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // Validate input
        if (!username || !password) {
            return res.status(400).json({ message: 'Username and password are required' });
        }
        
        // Find user
        const user = getUserByUsername(username);
        
        if (!user) {
            return res.status(401).json({ message: 'Invalid username or password' });
        }
        
        // Check password
        const passwordValid = await bcrypt.compare(password, user.password);
        
        if (!passwordValid) {
            return res.status(401).json({ message: 'Invalid username or password' });
        }
        
        // Generate JWT token
        const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '7d' });
        
        res.json({
            token,
            userId: user.id,
            username: user.username
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Check authentication
app.get('/api/check-auth', authenticateToken, (req, res) => {
    const user = getUserById(req.user.id);
    
    if (!user) {
        return res.status(404).json({ message: 'User not found' });
    }
    
    res.json({
        userId: user.id,
        username: user.username
    });
});

// Get user details
app.get('/api/user/:id', authenticateToken, (req, res) => {
    // Only allow users to access their own info
    if (req.user.id !== req.params.id) {
        return res.status(403).json({ message: 'Unauthorized' });
    }
    
    const user = getUserById(req.params.id);
    
    if (!user) {
        return res.status(404).json({ message: 'User not found' });
    }
    
    res.json({
        id: user.id,
        username: user.username,
        created: user.created
    });
});

// Get user scans
app.get('/api/scans', authenticateToken, (req, res) => {
    const scans = getUserScans(req.user.id);
    res.json(scans);
});

// Save scan
app.post('/api/scans', authenticateToken, (req, res) => {
    const scan = req.body;
    
    // Validate scan data
    if (!scan.target || !scan.scanType || !scan.output) {
        return res.status(400).json({ message: 'Invalid scan data' });
    }
    
    // Ensure timestamp if not provided
    if (!scan.timestamp) {
        scan.timestamp = new Date().getTime();
    }
    
    // Save scan
    if (saveUserScan(req.user.id, scan)) {
        res.status(201).json({ message: 'Scan saved successfully' });
    } else {
        res.status(500).json({ message: 'Failed to save scan' });
    }
});

// Delete scan
app.delete('/api/scans/:id', authenticateToken, (req, res) => {
    const scanId = req.params.id;
    const userScansFile = path.join(SCANS_DIR, `${req.user.id}.json`);
    
    if (!fs.existsSync(userScansFile)) {
        return res.status(404).json({ message: 'No scans found' });
    }
    
    try {
        const data = fs.readFileSync(userScansFile, 'utf8');
        let scans = JSON.parse(data);
        
        // Find scan index
        const scanIndex = scans.findIndex(scan => scan.id === scanId);
        
        if (scanIndex === -1) {
            return res.status(404).json({ message: 'Scan not found' });
        }
        
        // Remove scan
        scans.splice(scanIndex, 1);
        
        // Save updated scans
        fs.writeFileSync(userScansFile, JSON.stringify(scans, null, 2), 'utf8');
        
        res.json({ message: 'Scan deleted successfully' });
    } catch (error) {
        console.error(`Error deleting scan ${scanId}:`, error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Run scan endpoint
app.post('/api/run-scan', optionalAuthentication, async (req, res) => {
    try {
        const { target, scanType } = req.body;
        
        // Validate input
        if (!target || !scanType) {
            return res.status(400).json({ message: 'Target and scan type are required' });
        }
        
        // Run scan
        const scanResult = await runNmapScan(target, scanType);
        
        // Return scan results
        res.json(scanResult);
    } catch (error) {
        console.error('Scan error:', error);
        res.status(500).json({ message: error.message || 'Failed to perform scan' });
    }
});

// Start server
app.listen(PORT, () => {
    console.log(`NexScanner server running on port ${PORT}`);
});