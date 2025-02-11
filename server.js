const express = require('express');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { MongoClient } = require('mongodb');

const app = express();

// MongoDB connection
const uri = process.env.MONGODB_URI; // Ensure this environment variable is set
const client = new MongoClient(uri, { useNewUrlParser: true, useUnifiedTopology: true });

async function connectDB() {
  try {
    await client.connect();
    console.log("Connected to MongoDB Atlas");
  } catch (err) {
    console.error("Error connecting to MongoDB Atlas:", err);
  }
}

connectDB();

app.use(express.json());

// Serve static files from the "public" directory
app.use(express.static(path.join(__dirname, 'public')));

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
  const { email, password, role } = req.body; // Change username to email
  try {
    const database = client.db('infocraftorbis');
    const users = database.collection('users');
    const user = await users.findOne({ email, role }); // Use email in the query

    console.log('User found:', user);

    if (user) {
      const isPasswordMatch = await bcrypt.compare(password, user.password);
      console.log('Password match:', isPasswordMatch);

      if (isPasswordMatch) {
        const token = jwt.sign({ email: user.email, role: user.role }, process.env.JWT_SECRET);
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
    const database = client.db('infocraftorbis');
    const users = database.collection('users');
    await users.insertOne({ email, password: hashedPassword, role });
    res.status(201).send('User registered');
  } catch (error) {
    console.error('Error during registration:', error);
    res.status(500).send('Server error');
  }
});



// API Endpoint for Payroll Metrics
app.get('/api/payroll-metrics', async (req, res) => {
  try {
    const database = client.db('infocraftorbis');
    const payroll = database.collection('payroll');
    const metrics = await payroll.aggregate([
      { $group: { _id: "$region", totalAmount: { $sum: "$amount" }, avgTaxRate: { $avg: "$taxRate" } } }
    ]).toArray();
    res.json(metrics);
  } catch (error) {
    console.error('Error fetching payroll metrics:', error);
    res.status(500).send('Server error');
  }
});

// API Endpoint for Performance Analytics
app.get('/api/performance-analytics', async (req, res) => {
  try {
    const database = client.db('infocraftorbis');
    const performance = database.collection('performance');
    const analytics = await performance.aggregate([
      { $group: { _id: "$metric", avgScore: { $avg: "$score" } } }
    ]).toArray();
    res.json(analytics);
  } catch (error) {
    console.error('Error fetching performance analytics:', error);
    res.status(500).send('Server error');
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
