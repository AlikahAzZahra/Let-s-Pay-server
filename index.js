// REPLACE your entire index.js with this minimal working version:

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
const PORT = process.env.PORT || 3001;

// SIMPLE CORS - No complex logic
app.use(cors({
  origin: '*',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Add this for all requests
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, Content-Length, X-Requested-With');
  
  if (req.method === 'OPTIONS') {
    res.sendStatus(200);
  } else {
    next();
  }
});

// HEALTH CHECK - Must work
app.get('/api/health', (req, res) => {
  console.log('Health check called');
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    message: 'Server is running'
  });
});

// CORS TEST
app.get('/api/cors-test', (req, res) => {
  console.log('CORS test called');
  res.json({
    success: true,
    message: 'CORS is working!',
    origin: req.headers.origin || 'No origin'
  });
});

// Simple login endpoint for testing
app.post('/api/login', (req, res) => {
  console.log('Login attempt:', req.body);
  const { username, password } = req.body;
  
  // Hardcoded for testing - REPLACE with real auth later
  if (username === 'admin' && password === 'admin123') {
    res.json({
      success: true,
      token: 'dummy-token-for-testing',
      user: { username: 'admin', role: 'admin' }
    });
  } else {
    res.status(401).json({ message: 'Invalid credentials' });
  }
});

// Simple orders endpoint for testing
app.get('/api/orders', (req, res) => {
  console.log('Orders endpoint called');
  res.json([
    {
      order_id: 1,
      table_number: 'Table 1',
      total_amount: 50000,
      order_status: 'Dalam Proses',
      payment_status: 'Belum Bayar',
      order_time: new Date().toISOString(),
      items: JSON.stringify([
        {
          menu_name: 'Test Item',
          quantity: 1,
          price_at_order: 50000
        }
      ])
    }
  ]);
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ 
    error: 'Internal Server Error',
    message: err.message 
  });
});

// 404 handler
app.use('*', (req, res) => {
  console.log('404 - Route not found:', req.path);
  res.status(404).json({ 
    error: 'Not Found',
    path: req.path,
    message: 'Route not found'
  });
});

// Start server
if (process.env.VERCEL) {
  console.log('Running on Vercel');
  module.exports = app;
} else {
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}