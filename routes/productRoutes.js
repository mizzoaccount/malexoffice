const express = require('express');
const router = express.Router();
const productController = require('../controllers/productController');
const upload = require('../middleware/uploadMiddleware');
const { authorize } = require('../middleware/auth');



//router.use(authorize('admin'));
// Create a new product
router.post('/', upload.array('images', 5), productController.createProduct);
// Simple GET endpoint for all products
router.get('/', productController.getProducts);

module.exports = router;