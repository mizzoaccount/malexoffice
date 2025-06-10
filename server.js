// server.js
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(bodyParser.json());

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// Models
const User = require('./models/user');
const Record = require('./models/record');

// Authentication Middleware
const authenticate = async (req, res, next) => {
  try {
    const token = req.header('Authorization').replace('Bearer ', '');
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
    const user = await User.findOne({ _id: decoded._id, 'tokens.token': token });

    if (!user) {
      throw new Error();
    }

    req.token = token;
    req.user = user;
    next();
  } catch (error) {
    res.status(401).send({ error: 'Please authenticate.' });
  }
};

// Routes

// User Registration
/*app.post('/api/users/register', async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    
    // Check if email exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).send({ error: 'Email already in use' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 8);
    
    const user = new User({
      name,
      email,
      password: hashedPassword,
      role
    });

    await user.save();
    
    // Generate auth token
    const token = jwt.sign({ _id: user._id.toString() }, process.env.JWT_SECRET || 'your-secret-key');
    user.tokens = user.tokens.concat({ token });
    await user.save();

    res.status(201).send({ user, token });
  } catch (error) {
    res.status(400).send(error);
  }
});*/
// User Registration
app.post('/api/users/register', async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    
    // Normalize role value to ensure it matches the enum values
    const normalizedRole = role.toLowerCase().replace('storemanager', 'storeManager');

    // Check if email exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      console.error('Registration failed: Email already in use');
      return res.status(400).send({ error: 'Email already in use' });
    }

    // Create user with plain password
    const user = new User({
      name,
      email,
      password, // Save the password as it is
      role: normalizedRole
    });

    await user.save();
    
    // Generate auth token
    const token = jwt.sign({ _id: user._id.toString() }, process.env.JWT_SECRET || 'your-secret-key');
    user.tokens = user.tokens.concat({ token });
    await user.save();

    console.log(`Registration successful: ${user.name} (${user.email})`);
    res.status(201).send({ user, token });
  } catch (error) {
    console.error('Registration failed:', error);
    res.status(400).send({ error: error.message });
  }
});

// User Login
/*app.post('/api/users/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(400).send({ error: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).send({ error: 'Invalid credentials' });
    }

    // Generate auth token
    const token = jwt.sign({ _id: user._id.toString() }, process.env.JWT_SECRET || 'your-secret-key');
    user.tokens = user.tokens.concat({ token });
    await user.save();

    res.send({ user, token });
  } catch (error) {
    res.status(400).send(error);
  }
});*/
// User Login
// User Login
app.post('/api/users/login', authenticate, async (req, res) => {
  try {
    const { email, password } = req.body;

    // More detailed logging
    console.log('Login attempt:', { email, password: password ? '****' : 'missing' });

    const user = await User.findOne({ email });
    if (!user) {
      console.log('Login failed: User not found');
      return res.status(400).send({ error: 'Invalid credentials' });
    }

    // Directly compare plain passwords
    if (user.password !== password) {
      console.log('Login failed: Password mismatch');
      console.log('Input password:', password ? '****' : 'missing');
      console.log('Stored password:', user.password);
      return res.status(400).send({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ _id: user._id.toString() }, process.env.JWT_SECRET);
    user.tokens = user.tokens.concat({ token });
    await user.save();

    console.log('Login successful:', { email, role: user.role });
    res.send({ user, token });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).send({ error: 'Login failed' });
  }
});
// User Logout
app.post('/api/users/logout', async (req, res) => {
  try {
    req.user.tokens = req.user.tokens.filter(token => token.token !== req.token);
    await req.user.save();
    res.send();
  } catch (error) {
    res.status(500).send();
  }
});

app.post('/api/records/sync', async (req, res) => {
  try {
    const { records } = req.body;

    console.log('[Sync] Received records:');
    console.log(JSON.stringify(records, null, 2)); // Log incoming records

    // DO NOT remove createdBy
    const bulkOps = records.map(record => ({
      updateOne: {
        filter: { id: record.id },
        update: { $set: record },
        upsert: true
      }
    }));

    await Record.bulkWrite(bulkOps);

    const syncedRecords = await Record.find(); // Optionally filter
    res.send(syncedRecords);
  } catch (error) {
    console.error('[Sync][Error] Sync error:', error);
    res.status(400).send(error);
  }
});

// Get Records from Cloud
app.get('/api/records',  async (req, res) => {
  try {
    const records = await Record.find({ createdBy: req.user._id });
    res.send(records);
  } catch (error) {
    res.status(500).send();
  }
});

// Get all users (admin only)
app.get('/api/users', authenticate, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).send({ error: 'Forbidden' });
    }
    const users = await User.find({});
    res.send(users);
  } catch (error) {
    res.status(500).send();
  }
});

// Update user
/*app.put('/api/users/:id', authenticate, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).send({ error: 'Forbidden' });
    }

    const updates = Object.keys(req.body);
    const allowedUpdates = ['name', 'email', 'role'];
    const isValidOperation = updates.every(update => allowedUpdates.includes(update));

    if (!isValidOperation) {
      return res.status(400).send({ error: 'Invalid updates!' });
    }

    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).send();
    }

    updates.forEach(update => user[update] = req.body[update]);
    await user.save();
    res.send(user);
  } catch (error) {
    res.status(400).send(error);
  }
});

// Delete user
app.delete('/api/users/:id', authenticate, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).send({ error: 'Forbidden' });
    }

    const user = await User.findByIdAndDelete(req.params.id);
    if (!user) {
      return res.status(404).send();
    }
    res.send(user);
  } catch (error) {
    res.status(500).send();
  }
});*/
// Update user
/*app.put('/api/users/:id', authenticate, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      console.error('Forbidden: User is not an admin');
      return res.status(403).send({ error: 'Forbidden' });
    }

    const updates = Object.keys(req.body);
    const allowedUpdates = ['name', 'email', 'role'];
    const isValidOperation = updates.every(update => allowedUpdates.includes(update));

    if (!isValidOperation) {
      console.error('Invalid updates requested:', updates);
      return res.status(400).send({ error: 'Invalid updates!' });
    }

    const user = await User.findById(req.params.id);
    if (!user) {
      console.error('User not found:', req.params.id);
      return res.status(404).send();
    }

    updates.forEach(update => user[update] = req.body[update]);
    await user.save();
    console.log('User updated successfully:', user);
    res.send(user);
  } catch (error) {
    console.error('Failed to update user:', error);
    res.status(400).send({ error: error.message });
  }
});*/
app.put('/api/users/:name', async (req, res) => {
  try {
    console.log('Received PUT request to update user:', req.params.name);
    console.log('Request body:', req.body);

    const allowedUpdates = ['name', 'email', 'role'];
    const updates = Object.keys(req.body);
    const isValidOperation = updates.every(update => allowedUpdates.includes(update));

    if (!isValidOperation) {
      const invalidFields = updates.filter(update => !allowedUpdates.includes(update));
      console.error('Invalid updates requested:', invalidFields);
      return res.status(400).send({ error: `Invalid updates! Disallowed fields: ${invalidFields.join(', ')}` });
    }

    // Normalize role value
    if (req.body.role) {
      req.body.role = req.body.role.toLowerCase().replace(/\s+/g, '');
    }

    const user = await User.findOne({ name: req.params.name });
    if (!user) {
      console.error('User not found:', req.params.name);
      return res.status(404).send();
    }

    updates.forEach(update => user[update] = req.body[update]);
    await user.save();

    console.log('User updated successfully:', user);
    res.send(user);
  } catch (error) {
    console.error('Failed to update user:', error);
    res.status(400).send({ error: error.message });
  }
});
// Delete user
app.delete('/api/users/:id', authenticate, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      console.error('Forbidden: User is not an admin');
      return res.status(403).send({ error: 'Forbidden' });
    }

    const user = await User.findByIdAndDelete(req.params.id);
    if (!user) {
      console.error('User not found:', req.params.id);
      return res.status(404).send();
    }
    console.log('User deleted successfully:', user);
    res.send(user);
  } catch (error) {
    console.error('Failed to delete user:', error);
    res.status(500).send({ error: error.message });
  }
});

// Add this endpoint to your server.js, right before the server starts listening
{/*app.post('/api/users/createByAdmin', authenticate, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).send({ error: 'Forbidden' });
    }

    const { name, email, password, role } = req.body;
    
    // Check if email exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).send({ error: 'Email already in use' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 8);
    
    const user = new User({
      name,
      email,
      password: hashedPassword,
      role
    });

    await user.save();
    
    res.status(201).send({ user });
  } catch (error) {
    res.status(400).send(error);
  }
});*/}
app.post('/api/users/createByAdmin', authenticate, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      console.error('Forbidden: User is not an admin');
      return res.status(403).send({ error: 'Forbidden' });
    }

    const { name, email, password, role } = req.body;
    
    // Check if email exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      console.error('Email already in use:', email);
      return res.status(400).send({ error: 'Email already in use' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 8);
    console.log('Password hashed successfully');

    const user = new User({
      name,
      email,
      password: hashedPassword,
      role
    });

    await user.save();
    console.log('User created successfully:', user);

    res.status(201).send({ user });
  } catch (error) {
    console.error('Failed to create user:', error);
    res.status(400).send({ error: error.message });
  }
});

// Add to server.js
app.post('/api/users/updatePassword', authenticate, async (req, res) => {
  try {
    const { email, newPassword } = req.body;
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).send({ error: 'User not found' });
    }

    user.password = newPassword; // Will be hashed by pre-save hook
    await user.save();

    res.send({ message: 'Password updated successfully' });
  } catch (error) {
    res.status(400).send(error);
  }
});

// Get user by ID (useful for admin)
app.get('/api/users/:id', authenticate, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).send({ error: 'Forbidden' });
    }

    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).send();
    }
    res.send(user);
  } catch (error) {
    res.status(500).send();
  }
});
// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});