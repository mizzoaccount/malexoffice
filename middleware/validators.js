const { check } = require('express-validator');

exports.userUpdateValidator = [
    check('firstName', 'First name is required').optional().not().isEmpty(),
    check('lastName', 'Last name is required').optional().not().isEmpty(),
    check('email', 'Please include a valid email').optional().isEmail(),
    check('role', 'Role must be either customer or admin')
      .optional()
      .isIn(['customer', 'admin']),
    check('isActive', 'isActive must be a boolean').optional().isBoolean()
  ];

exports.userLoginValidator = [
    check('email', 'Please include a valid email').isEmail(),
    check('password', 'Password is required').exists()
  ]; 

exports.userRegisterValidator = [
  check('firstName', 'First name is required').not().isEmpty(),
  check('lastName', 'Last name is required').not().isEmpty(),
  check('email', 'Please include a valid email').isEmail(),
  check('password', 'Password must be at least 8 characters long').isLength({ min: 8 }),
  check('confirmPassword', 'Passwords do not match').custom((value, { req }) => {
    if (value !== req.body.password) {
      throw new Error('Passwords do not match');
    }
    return true;
  })
];