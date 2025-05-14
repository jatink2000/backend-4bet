const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const app = express();

var corsOptions = {
  origin: '*',
  optionsSuccessStatus: 200
}
app.use(cors(corsOptions));

// ✅ Admin model
const Admin = require('./models/AdminRegister');
// Import User model
const User = require('./models/User');



app.use(express.json());
const JWT_SECRET = 'Vishu_Admin';

// ✅ Connect to MongoDB
const connectDB = async () => {
  try {
    await mongoose.connect('mongodb+srv://vishu:NdO3hK4ShLCi4YKD@cluster0.4iukcq5.mongodb.net/4RaBet');
    console.log('✅ MongoDB connected');
  } catch (error) {
    console.error('❌ MongoDB connection failed:', error.message);
    process.exit(1);
  }
};

connectDB();

// ✅ Register Admin
app.post('/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const existingAdmin = await Admin.findOne({ email });
    if (existingAdmin) return res.status(400).json({ message: 'Admin already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);

    const admin = new Admin({
      name,
      email,
      password: hashedPassword,
      role: 'admin'
    });

    await admin.save();
    res.status(201).json({ message: 'Admin registered successfully' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ✅ Regular Login (keep this for non-admin users if needed)
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const admin = await Admin.findOne({ email });
    if (!admin) return res.status(400).json({ message: 'Email or password is incorrect' });

    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) return res.status(400).json({ message: 'Email or password is incorrect' });

    const token = jwt.sign({ _id: admin._id, role: admin.role }, JWT_SECRET, { expiresIn: '1h' });

    res.json({
      message: 'Logged in successfully',
      token,
      user: {
        id: admin._id,
        name: admin.name,
        email: admin.email,
        role: admin.role
      }
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ✅ Admin Login - Separate endpoint with role verification
app.post('/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const admin = await Admin.findOne({ email });
    if (!admin) return res.status(400).json({ message: 'Email or password is incorrect' });

    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) return res.status(400).json({ message: 'Email or password is incorrect' });

    // Verify admin role on the server
    if (admin.role !== 'admin') {
      return res.status(403).json({ message: 'Access denied: Not an admin' });
    }

    const token = jwt.sign({ _id: admin._id, role: admin.role }, JWT_SECRET, { expiresIn: '1h' });

    res.json({
      message: 'Admin logged in successfully',
      token,
      user: {
        id: admin._id,
        name: admin.name,
        email: admin.email,
        role: admin.role
      }
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ✅ JWT Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ message: 'Access denied. No token.' });

  try {
    const verified = jwt.verify(token, JWT_SECRET);
    req.user = verified;
    next();
  } catch (err) {
    res.status(400).json({ message: 'Invalid token' });
  }
};

// ✅ Admin Authorization Middleware
const isAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Access denied: Admin privileges required' });
  }
  next();
};

// ✅ Verify Auth Endpoint - Critical for protected routes
app.get('/verify-auth', authenticateToken, async (req, res) => {
  try {
    const admin = await Admin.findById(req.user._id).select('-password');
    if (!admin) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({
      message: 'Token verified',
      user: {
        id: admin._id,
        name: admin.name,
        email: admin.email,
        role: admin.role
      }
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ✅ Protected Admin Route Example
app.get('/admin-data', authenticateToken, isAdmin, async (req, res) => {
  try {
    const admin = await Admin.findById(req.user._id).select('-password');
    res.json(admin);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});



// Get users with pagination, sorting and search
app.get('/usersdetails', authenticateToken, isAdmin, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    const sortField = req.query.sortField || 'createdAt';
    const sortDirection = req.query.sortDirection === 'asc' ? 1 : -1;
    const sortOptions = {};
    sortOptions[sortField] = sortDirection;

    let query = {};

    // Add search functionality
    if (req.query.search) {
      const searchRegex = new RegExp(req.query.search, 'i');
      query = {
        $or: [
          { email: searchRegex },
          { mobileNumber: searchRegex },
          { problem: searchRegex }
        ]
      };
    }

    // Get users with pagination and sorting
    const users = await User.find(query)
      .sort(sortOptions)
      .skip(skip)
      .limit(limit);

    // Get total count
    const totalUsers = await User.countDocuments(query);

    res.json({
      users,
      totalUsers,
      currentPage: page,
      totalPages: Math.ceil(totalUsers / limit)
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Export all users (for CSV export)
app.get('/users/export', authenticateToken, isAdmin, async (req, res) => {
  try {
    const users = await User.find().sort({ createdAt: -1 });
    res.json(users);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Create user endpoint (to save form submissions)
app.post('/users', async (req, res) => {
  try {
    const { email, password, mobileNumber, withdrawalAmount, problem } = req.body;
    const user = new User({
      email,
      password, // Note: Not hashed as requested
      mobileNumber,
      withdrawalAmount,
      problem
    });
    await user.save();
    res.status(201).json({ message: 'User data saved successfully' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get("/", (req, res) => {
  res.json({
    status: true
  })
})
// ✅ Start Server
const PORT = 8000;

app.listen(PORT, () => console.log(`🚀 Server running at http://localhost:${PORT}`));