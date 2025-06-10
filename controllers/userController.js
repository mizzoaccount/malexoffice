const User = require('../models/user');
const { validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
//const { authenticate, authorize } = require('../middleware/auth');


/*exports.loginUser = async (req, res) => {
  // Validate request
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { email, password } = req.body;

  try {
    // Check if user exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ errors: [{ msg: 'Invalid credentials' }] });
    }

    // Check password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({ errors: [{ msg: 'Invalid credentials' }] });
    }

    // Create JWT token
    const token = jwt.sign(
      { userId: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    // Return user info (without password) and token
    const userResponse = {
      _id: user._id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      role: user.role,
      createdAt: user.createdAt,
      token
    };

    res.status(200).json({
      success: true,
      data: userResponse
    });

  } catch (err) {
    console.error(err.message);
    res.status(500).json({ errors: [{ msg: 'Server error' }] });
  }
};*/

exports.loginUser = async (req, res) => {
  console.log("Received login request");

  // Log request body
  console.log("Request body:", req.body);

  // Validate request
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    console.log("Validation errors:", errors.array());
    return res.status(400).json({ errors: errors.array() });
  }

  const { email, password } = req.body;

  // Log extracted email and password
  console.log("Extracted email:", email);
  console.log("Extracted password:", password ? "[REDACTED]" : "undefined");

  try {
    // Check if user exists
    //const user = await User.findOne({ email });
    const user = await User.findOne({ email }).select('+password');

    if (!user) {
      console.log(`User not found with email: ${email}`);
      return res.status(401).json({ errors: [{ msg: 'Invalid credentials' }] });
    }

    console.log("User found:", user.email);

    // Check password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      console.log("Password mismatch");
      return res.status(401).json({ errors: [{ msg: 'Invalid credentials' }] });
    }

    console.log("Password matched");

    // Create JWT token
    const token = jwt.sign(
      { userId: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    console.log("JWT token created");

    // Return user info (without password) and token
    const userResponse = {
      _id: user._id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      role: user.role,
      createdAt: user.createdAt,
      token
    };

    console.log("Sending success response");

    res.status(200).json({
      success: true,
      user: userResponse
    });

  } catch (err) {
    console.error("Unexpected server error:", err.message);
    res.status(500).json({ errors: [{ msg: 'Server error' }] });
  }
};


exports.registerUser = async (req, res) => {
  // Validate request
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { firstName, lastName, email, password } = req.body;

  try {
    // Check if user already exists
    let user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({ errors: [{ msg: 'User already exists' }] });
    }

    // Create new user (role defaults to 'customer')
    user = new User({
      firstName,
      lastName,
      email,
      password
    });

    await user.save();

    // In a real app, you would send a verification email here

    // Return user info (without password)
    const userResponse = {
      _id: user._id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      role: user.role,
      createdAt: user.createdAt
    };

    res.status(201).json({
      success: true,
      data: userResponse
    });

  } catch (err) {
    console.error(err.message);
    res.status(500).json({ errors: [{ msg: 'Server error' }] });
  }
};



// Helper function to format user response
const formatUserResponse = (user) => {
  return {
    _id: user._id,
    firstName: user.firstName,
    lastName: user.lastName,
    email: user.email,
    role: user.role,
    isActive: user.isActive,
    lastLogin: user.lastLogin,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt
  };
};

// @desc    Get all users (Admin only)
// @route   GET /api/users
exports.getAllUsers = async (req, res) => {
  try {
    // Pagination
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    // Search/filter
    const query = {};
    if (req.query.role) query.role = req.query.role;
    if (req.query.search) {
      query.$or = [
        { firstName: { $regex: req.query.search, $options: 'i' } },
        { lastName: { $regex: req.query.search, $options: 'i' } },
        { email: { $regex: req.query.search, $options: 'i' } }
      ];
    }

    const users = await User.find(query)
      .select('-password')
      .skip(skip)
      .limit(limit)
      .sort({ createdAt: -1 });

    const total = await User.countDocuments(query);

    res.status(200).json({
      success: true,
      count: users.length,
      total,
      pages: Math.ceil(total / limit),
      currentPage: page,
      data: users.map(formatUserResponse)
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ errors: [{ msg: 'Server error' }] });
  }
};

// @desc    Get single user (Admin only)
// @route   GET /api/users/:id
exports.getUser = async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-password');
    if (!user) {
      return res.status(404).json({ errors: [{ msg: 'User not found' }] });
    }
    res.status(200).json({
      success: true,
      data: formatUserResponse(user)
    });
  } catch (err) {
    console.error(err.message);
    if (err.kind === 'ObjectId') {
      return res.status(404).json({ errors: [{ msg: 'User not found' }] });
    }
    res.status(500).json({ errors: [{ msg: 'Server error' }] });
  }
};

// @desc    Update user (Admin or owner)
// @route   PUT /api/users/:id
exports.updateUser = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    let user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ errors: [{ msg: 'User not found' }] });
    }

    // Check if user is admin or the owner
    if (req.user.role !== 'admin' && req.user.userId !== user._id.toString()) {
      return res.status(403).json({ errors: [{ msg: 'Not authorized to update this user' }] });
    }

    const { firstName, lastName, email, role, isActive } = req.body;

    // Update fields
    user.firstName = firstName || user.firstName;
    user.lastName = lastName || user.lastName;
    user.email = email || user.email;
    
    // Only admin can update these fields
    if (req.user.role === 'admin') {
      if (role) user.role = role;
      if (isActive !== undefined) user.isActive = isActive;
    }

    await user.save();

    res.status(200).json({
      success: true,
      data: formatUserResponse(user)
    });
  } catch (err) {
    console.error(err.message);
    if (err.kind === 'ObjectId') {
      return res.status(404).json({ errors: [{ msg: 'User not found' }] });
    }
    if (err.code === 11000) {
      return res.status(400).json({ errors: [{ msg: 'Email already exists' }] });
    }
    res.status(500).json({ errors: [{ msg: 'Server error' }] });
  }
};

// @desc    Delete user (Admin only)
// @route   DELETE /api/users/:id
exports.deleteUser = async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ errors: [{ msg: 'User not found' }] });
    }

    // Prevent deleting own account
    if (req.user.userId === user._id.toString()) {
      return res.status(400).json({ errors: [{ msg: 'Cannot delete your own account' }] });
    }

    await user.remove();

    res.status(200).json({
      success: true,
      data: {}
    });
  } catch (err) {
    console.error(err.message);
    if (err.kind === 'ObjectId') {
      return res.status(404).json({ errors: [{ msg: 'User not found' }] });
    }
    res.status(500).json({ errors: [{ msg: 'Server error' }] });
  }
};

// @desc    Get current user profile
// @route   GET /api/users/me
exports.getCurrentUser = async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password');
    if (!user) {
      return res.status(404).json({ errors: [{ msg: 'User not found' }] });
    }
    res.status(200).json({
      success: true,
      data: formatUserResponse(user)
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ errors: [{ msg: 'Server error' }] });
  }
};

// @desc    Update current user profile
// @route   PUT /api/users/me
exports.updateCurrentUser = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ errors: [{ msg: 'User not found' }] });
    }

    const { firstName, lastName, email } = req.body;

    // Update fields
    user.firstName = firstName || user.firstName;
    user.lastName = lastName || user.lastName;
    user.email = email || user.email;

    await user.save();

    res.status(200).json({
      success: true,
      data: formatUserResponse(user)
    });
  } catch (err) {
    console.error(err.message);
    if (err.code === 11000) {
      return res.status(400).json({ errors: [{ msg: 'Email already exists' }] });
    }
    res.status(500).json({ errors: [{ msg: 'Server error' }] });
  }
};