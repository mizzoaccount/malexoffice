/*const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');
const { userRegisterValidator, userLoginValidator } = require('../middleware/validators');
const { authenticate, authorize } = require('../middleware/auth');


// Protected routes
router.use(authenticate);

// Current user routes
router.get('/me', userController.getCurrentUser);
router.put('/me', userController.updateCurrentUser);

// Admin-only routes
router.use(authorize('admin'));

router.get('/', userController.getAllUsers);
router.get('/:id', userController.getUser);
router.put('/:id', userController.updateUser);
router.delete('/:id', userController.deleteUser);

// @route   POST api/users/register
// @desc    Register a user
// @access  Public
router.post('/register', userRegisterValidator, userController.registerUser);

// @route   POST api/users/login
// @desc    Login a user
// @access  Public
router.post('/login', userLoginValidator, userController.loginUser);


module.exports = router;*/

const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');
const { userRegisterValidator, userLoginValidator } = require('../middleware/validators');
const { authenticate, authorize } = require('../middleware/auth');

// Public routes
router.post('/register', userRegisterValidator, userController.registerUser);
router.post('/login', userLoginValidator, userController.loginUser);

// Protected routes
router.use(authenticate);

// Current user routes
router.get('/me', userController.getCurrentUser);
router.put('/me', userController.updateCurrentUser);

// Admin-only routes
router.use(authorize('admin'));

router.get('/', userController.getAllUsers);
router.get('/:id', userController.getUser);
router.put('/:id', userController.updateUser);
router.delete('/:id', userController.deleteUser);

module.exports = router;