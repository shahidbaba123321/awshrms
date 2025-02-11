const express = require('express');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');

const app = express();

// MySQL connection pool
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Test database connection
async function testConnection() {
    try {
        const connection = await pool.getConnection();
        console.log('Connected to MySQL Database');
        connection.release();
    } catch (err) {
        console.error('Error connecting to database:', err);
    }
}

testConnection();

app.use(express.json());

// Serve static files from the "public" directory
app.use(express.static(path.join(__dirname, 'public')));

// Health check for AWS
app.get('/health', (req, res) => {
    res.status(200).send('OK');
});

// Serve index.html for the root route
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Serve login.html for the login route
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Login endpoint
app.post('/login', async (req, res) => {
    const { email, password, role } = req.body;
    try {
        const [users] = await pool.execute(
            'SELECT * FROM users WHERE email = ? AND role = ?',
            [email, role]
        );

        if (users.length > 0) {
            const user = users[0];
            const isPasswordMatch = await bcrypt.compare(password, user.password);

            if (isPasswordMatch) {
                const token = jwt.sign(
                    { email: user.email, role: user.role },
                    process.env.JWT_SECRET
                );
                res.json({ token });
            } else {
                res.status(401).send('Invalid credentials');
            }
        } else {
            res.status(401).send('Invalid credentials');
        }
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).send('Server error');
    }
});

// Register endpoint
app.post('/register', async (req, res) => {
    const { email, password, role } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.execute(
            'INSERT INTO users (email, password, role) VALUES (?, ?, ?)',
            [email, hashedPassword, role]
        );
        res.status(201).send('User registered');
    } catch (error) {
        console.error('Error during registration:', error);
        res.status(500).send('Server error');
    }
});

// API Endpoint for Payroll Metrics
app.get('/api/payroll-metrics', async (req, res) => {
    try {
        const [metrics] = await pool.execute(`
            SELECT 
                region,
                SUM(amount) as totalAmount,
                AVG(tax_rate) as avgTaxRate
            FROM payroll
            GROUP BY region
        `);
        res.json(metrics);
    } catch (error) {
        console.error('Error fetching payroll metrics:', error);
        res.status(500).send('Server error');
    }
});

// API Endpoint for Performance Analytics
app.get('/api/performance-analytics', async (req, res) => {
    try {
        const [analytics] = await pool.execute(`
            SELECT 
                metric,
                AVG(score) as avgScore
            FROM performance
            GROUP BY metric
        `);
        res.json(analytics);
    } catch (error) {
        console.error('Error fetching performance analytics:', error);
        res.status(500).send('Server error');
    }
});

const PORT = process.env.PORT || 8081;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
