// Import required libraries
const express = require('express'); // Express framework for building web applications
const mongoose = require('mongoose'); // Mongoose for MongoDB object modeling
const authRoutes = require('./../JWT/routes/authRoute'); // Authentication routes
const { authenticateJWT } = require('./../JWT/middlewares/authMiddleware'); // JWT authentication middleware
require('dotenv').config(); // Load environment variables
const app = express(); // Create Express application

// Middleware to parse JSON requests
app.use(express.json());

// Connect to MongoDB database
mongoose.connect('mongodb://localhost:27017/JWT', { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('Connected to MongoDB')) // Success message
    .catch(err => console.error('Error connecting to MongoDB:', err)); // Error message

// Routes
app.use('/api/auth', authRoutes); // Authentication routes

// Protected route accessible only with valid JWT token
app.get('/api/protected', authenticateJWT, (req, res) => {
    res.json({ message: 'This is a protected route' });
});

// Admin-only route accessible only with valid admin JWT token
app.get('/api/adminOnly', authenticateJWT, (req, res) => {
    res.json({ message: 'Welcome Admin' });
});

// Start the server
const PORT = process.env.PORT || 3000; // Set the port number
app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`); // Server start message
});