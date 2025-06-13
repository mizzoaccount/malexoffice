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
const authenticate = async (req, res, next) => {
  try {
    console.log('[AUTH] Attempting to authenticate request...');

    const authHeader = req.header('Authorization');
    if (!authHeader) {
      console.log('[AUTH FAILED] No Authorization header found.');
      return res.status(401).send({ error: 'Please authenticate.' });
    }

    const token = authHeader.replace('Bearer ', '');
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');

    const user = await User.findOne({ _id: decoded._id, 'tokens.token': token });

    if (!user) {
      console.log('[AUTH FAILED] No user found for decoded token.');
      throw new Error();
    }

    console.log(`[AUTH SUCCESS] User authenticated: ${user.email || user._id}`);
    
    req.token = token;
    req.user = user;
    next();
  } catch (error) {
    console.log(`[AUTH ERROR] Authentication failed: ${error.message}`);
    res.status(401).send({ error: 'Please authenticate.' });
  }
};

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

// Get User by Email (Public or Protected – your choice)
app.get('/api/users/email/:email', async (req, res) => {
  try {
    const email = req.params.email.toLowerCase();
    const user = await User.findOne({ email });

    if (!user) {
      console.log(`User not found with email: ${email}`);
      return res.status(404).send({ error: 'User not found' });
    }

    console.log(`User retrieved: ${user.email}`);
    res.send({ user });
  } catch (error) {
    console.error('Error fetching user by email:', error);
    res.status(500).send({ error: 'Server error' });
  }
});

// User Login
app.post('/api/users/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    console.log('Login attempt:', { email, password: password ? '****' : 'missing' });

    const user = await User.findOne({ email });
    if (!user) {
      console.log('Login failed: User not found');
      return res.status(400).send({ error: 'Invalid credentials' });
    }

    if (user.password !== password) {
      console.log('Login failed: Password mismatch');
      console.log('Input password:', password ? '****' : 'missing');
      console.log('Stored password:', user.password);
      return res.status(400).send({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ _id: user._id.toString() }, process.env.JWT_SECRET);

    // Fix token bloat: keep only latest 5 tokens
    const MAX_TOKENS = 5;
    user.tokens.push({ token });
    if (user.tokens.length > MAX_TOKENS) {
      user.tokens = user.tokens.slice(-MAX_TOKENS); // keep last 5
    }

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
app.get('/api/records', async (req, res) => {
  try {
    const records = await Record.find(); // Removed the filter

    console.log(`✅ [SUCCESS] Fetched ${records.length} records`);
    res.send(records);
  } catch (error) {
    console.error(`❌ [ERROR] Failed to fetch records. Reason: ${error.message}`);
    res.status(500).send({ error: 'Failed to load records' });
  }
});

app.get('/api/users', async (req, res) => { 
  try {
    console.log(`[INFO] Incoming request to /api/users by user: ${req.user?.email || 'unknown'}`);

    const users = await User.find({});
    console.log(`[SUCCESS] Retrieved ${users.length} users from database.`);
    res.send(users);
    
  } catch (error) {
    console.error('[ERROR] Failed to fetch users:', error);
    res.status(500).send({ error: 'Internal Server Error' });
  }
});



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
app.post('/api/users/createByAdmin', authenticate, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      console.error('Forbidden: User is not an admin');
      return res.status(403).send({ error: 'Forbidden' });
    }

    const { name, email, password, role } = req.body;
    
    // Normalize role value to ensure it matches the enum values
    const normalizedRole = role.toLowerCase().replace('storemanager', 'storeManager');

    // Check if email exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      console.error('Email already in use:', email);
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

// Add this to your server.js file, preferably with the other record-related endpoints
app.put('/api/records/:id',  async (req, res) => {
  try {
    console.log(`[UPDATE RECORD] Attempting to update record ${req.params.id}`);
    console.log('[UPDATE RECORD] Request body:', req.body);

    const updates = req.body;
    const recordId = req.params.id;

    // Validate that we have at least one document type
    const docTypes = [
      updates.invoiceNo ? 1 : 0,
      updates.cashSaleNo ? 1 : 0,
      updates.quotationNo ? 1 : 0,
    ].reduce((a, b) => a + b, 0);

    if (docTypes !== 1) {
      console.error('[UPDATE RECORD] Validation failed: Exactly one document type must be provided');
      return res.status(400).send({ error: 'Exactly one document type must be provided (invoiceNo, cashSaleNo, or quotationNo)' });
    }

    // Find the existing record first
    const existingRecord = await Record.findOne({ id: recordId });
    if (!existingRecord) {
      console.error(`[UPDATE RECORD] Record not found: ${recordId}`);
      return res.status(404).send({ error: 'Record not found' });
    }

    // Prepare the update object
    const updateData = {
      customerName: updates.customerName,
      facilitator: updates.facilitator,
      amount: updates.amount,
      invoiceNo: updates.invoiceNo || null, // Set to null if not provided
      cashSaleNo: updates.cashSaleNo || null,
      quotationNo: updates.quotationNo || null,
    };

    // Update the record
    const updatedRecord = await Record.findOneAndUpdate(
      { id: recordId },
      { $set: updateData },
      { new: true, runValidators: true }
    );

    if (!updatedRecord) {
      console.error(`[UPDATE RECORD] Failed to update record: ${recordId}`);
      return res.status(500).send({ error: 'Failed to update record' });
    }

    console.log(`[UPDATE RECORD] Successfully updated record: ${recordId}`);
    res.send(updatedRecord);
  } catch (error) {
    console.error('[UPDATE RECORD] Error:', error.message);
    res.status(400).send({ error: error.message });
  }
});

// Backend route (Node.js/Express)
app.delete('/api/records/:id', async (req, res) => {
  try {
    const recordId = req.params.id;
    console.log(`[DELETE RECORD] Deleting record ${recordId}`);

    // Find and delete the record
    const deletedRecord = await Record.findOneAndDelete({ id: recordId });

    if (!deletedRecord) {
      console.error(`[DELETE RECORD] Record not found: ${recordId}`);
      return res.status(404).send({ error: 'Record not found' });
    }

    console.log(`[DELETE RECORD] Successfully deleted record: ${recordId}`);
    res.status(200).send({ message: 'Record deleted successfully' });
  } catch (error) {
    console.error('[DELETE RECORD] Error:', error.message);
    res.status(500).send({ error: 'Failed to delete record' });
  }
});
// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});