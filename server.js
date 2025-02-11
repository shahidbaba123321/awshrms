const express = require('express');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');

const app = express();

// Security Middleware
app.use(helmet());
app.use(compression());
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

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

// Database initialization function
async function initializeDatabase() {
    try {
        const connection = await pool.getConnection();
        console.log('Connected to MySQL Database');

        // Users Table
        await connection.query(`
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email VARCHAR(255) NOT NULL UNIQUE,
                password VARCHAR(255) NOT NULL,
                role VARCHAR(50) NOT NULL,
                first_name VARCHAR(100),
                last_name VARCHAR(100),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                last_login TIMESTAMP NULL,
                status ENUM('active', 'inactive', 'suspended') DEFAULT 'active'
            )
        `);

        // Employees Table
        await connection.query(`
            CREATE TABLE IF NOT EXISTS employees (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT,
                employee_id VARCHAR(50) UNIQUE,
                department VARCHAR(100),
                position VARCHAR(100),
                hire_date DATE,
                salary DECIMAL(12,2),
                manager_id INT,
                contact_number VARCHAR(20),
                emergency_contact VARCHAR(100),
                address TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (manager_id) REFERENCES employees(id)
            )
        `);

        // Payroll Table
        await connection.query(`
            CREATE TABLE IF NOT EXISTS payroll (
                id INT AUTO_INCREMENT PRIMARY KEY,
                employee_id INT,
                pay_period_start DATE,
                pay_period_end DATE,
                base_salary DECIMAL(12,2),
                overtime_pay DECIMAL(12,2),
                bonuses DECIMAL(12,2),
                deductions DECIMAL(12,2),
                tax_amount DECIMAL(12,2),
                net_pay DECIMAL(12,2),
                payment_date DATE,
                payment_status ENUM('pending', 'processed', 'completed') DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (employee_id) REFERENCES employees(id)
            )
        `);

        // Performance Table
        await connection.query(`
            CREATE TABLE IF NOT EXISTS performance (
                id INT AUTO_INCREMENT PRIMARY KEY,
                employee_id INT,
                review_date DATE,
                reviewer_id INT,
                performance_score DECIMAL(3,2),
                comments TEXT,
                goals TEXT,
                review_period_start DATE,
                review_period_end DATE,
                status ENUM('draft', 'submitted', 'approved') DEFAULT 'draft',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (employee_id) REFERENCES employees(id),
                FOREIGN KEY (reviewer_id) REFERENCES employees(id)
            )
        `);

        // Create default admin user
        const adminPassword = await bcrypt.hash('admin123', 10);
        await connection.query(`
            INSERT IGNORE INTO users (email, password, role, first_name, last_name, status)
            VALUES ('admin@workwise.com', ?, 'admin', 'Admin', 'User', 'active')
        `, [adminPassword]);

        console.log('Database initialized successfully');
        connection.release();
    } catch (error) {
        console.error('Error initializing database:', error);
        throw error;
    }
}

// Middleware to verify JWT
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Routes
app.get('/health', (req, res) => {
    res.status(200).send('OK');
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

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
                    process.env.JWT_SECRET,
                    { expiresIn: '24h' }
                );
                
                // Update last login
                await pool.execute(
                    'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?',
                    [user.id]
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

// Protected routes
app.get('/api/employees', authenticateToken, async (req, res) => {
    try {
        const [employees] = await pool.execute('SELECT * FROM employees');
        res.json(employees);
    } catch (error) {
        console.error('Error fetching employees:', error);
        res.status(500).send('Server error');
    }
});

app.get('/api/payroll', authenticateToken, async (req, res) => {
    try {
        const [payroll] = await pool.execute('SELECT * FROM payroll');
        res.json(payroll);
    } catch (error) {
        console.error('Error fetching payroll:', error);
        res.status(500).send('Server error');
    }
});

app.get('/api/performance', authenticateToken, async (req, res) => {
    try {
        const [performance] = await pool.execute('SELECT * FROM performance');
        res.json(performance);
    } catch (error) {
        console.error('Error fetching performance:', error);
        res.status(500).send('Server error');
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something broke!');
});

// Start server and initialize database
const PORT = process.env.PORT || 8081;
app.listen(PORT, async () => {
    try {
        await initializeDatabase();
        console.log(`Server is running on port ${PORT}`);
    } catch (error) {
        console.error('Failed to initialize application:', error);
        process.exit(1);
    }
});
