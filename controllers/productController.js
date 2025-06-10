/*const Product = require('../models/Product');
const cloudinary = require('cloudinary').v2;

// Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.API_KEY,
  api_secret: process.env.API_SECRET,
});

const productController = {
  // Create a new product
  createProduct: async (req, res) => {
    try {
      // Parse the JSON fields from FormData
      const { name, designer, mainCategory, subCategory, brand, price, stock, attributes } = req.body;
      
      // Parse attributes if it's a string
      const parsedAttributes = typeof attributes === 'string' ? JSON.parse(attributes) : attributes;

      // Upload images to Cloudinary
      const imageUrls = [];
      if (req.files && req.files.length > 0) {
        for (const file of req.files) {
          // Upload from buffer since we're using memory storage
          const result = await new Promise((resolve, reject) => {
            const uploadStream = cloudinary.uploader.upload_stream(
              { folder: 'products' },
              (error, result) => {
                if (error) reject(error);
                else resolve(result);
              }
            );
            
            uploadStream.end(file.buffer);
          });
          
          imageUrls.push(result.secure_url);
        }
      }

      // Create new product
      const newProduct = new Product({
        name,
        designer,
        category: {
          main: mainCategory,
          sub: subCategory,
          brand
        },
        price: parseFloat(price),
        stock: parseInt(stock),
        images: imageUrls,
        attributes: parsedAttributes
      });

      await newProduct.save();

      res.status(201).json({
        success: true,
        product: newProduct
      });
    } catch (error) {
      console.error('Error creating product:', error);
      res.status(500).json({
        success: false,
        message: 'Error creating product',
        error: error.message
      });
    }
  },

  // Get all products
 // Get all products (no filters)
getProducts: async (req, res) => {
  try {
    const products = await Product.find().sort({ createdAt: -1 });
    res.status(200).json({
      success: true,
      count: products.length,
      products
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Server Error',
      error: error.message
    });
  }
},
};

module.exports = productController;*/
const Product = require('../models/Product');
const cloudinary = require('cloudinary').v2;

// Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.API_KEY,
  api_secret: process.env.API_SECRET,
});

const productController = {
  // Create a new chemical product
  createProduct: async (req, res) => {
    try {
      // Parse the JSON fields from FormData
      const { 
        mainCategory, 
        subCategory,
        details,
        specifications,
        batchNumber,
        netContent,
        notes,
        certifications
      } = req.body;
      
      // Parse array/object fields if they come as strings
      const parsedDetails = typeof details === 'string' ? JSON.parse(details) : details;
      const parsedSpecs = typeof specifications === 'string' ? JSON.parse(specifications) : specifications;
      const parsedCerts = typeof certifications === 'string' ? JSON.parse(certifications) : certifications;

      // Filter out empty details and specifications
      const filteredDetails = parsedDetails.filter(d => d.name && d.value);
      const filteredSpecs = parsedSpecs.filter(s => s.name && s.value);

      // Upload images to Cloudinary
      const imageUrls = [];
      if (req.files && req.files.length > 0) {
        for (const file of req.files) {
          const result = await new Promise((resolve, reject) => {
            const uploadStream = cloudinary.uploader.upload_stream(
              { folder: 'chemical_products' },
              (error, result) => {
                if (error) reject(error);
                else resolve(result);
              }
            );
            
            uploadStream.end(file.buffer);
          });
          
          imageUrls.push(result.secure_url);
        }
      }

      // Create new product
      const newProduct = new Product({
        mainCategory,
        subCategory,
        details: filteredDetails,
        specifications: filteredSpecs,
        batchNumber,
        netContent,
        notes,
        certifications: parsedCerts,
        images: imageUrls
      });

      await newProduct.save();

      res.status(201).json({
        success: true,
        product: newProduct
      });
    } catch (error) {
      console.error('Error creating product:', error);
      res.status(500).json({
        success: false,
        message: 'Error creating product',
        error: error.message
      });
    }
  },

  // Get all chemical products
  getProducts: async (req, res) => {
    try {
      const products = await Product.find().sort({ createdAt: -1 });
      
      res.status(200).json({
        success: true,
        count: products.length,
        products
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'Server Error',
        error: error.message
      });
    }
  },

  // Get products by main category
  getProductsByMainCategory: async (req, res) => {
    try {
      const { mainCategory } = req.params;
      const products = await Product.find({ mainCategory }).sort({ createdAt: -1 });
      
      res.status(200).json({
        success: true,
        count: products.length,
        products
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'Server Error',
        error: error.message
      });
    }
  },

  // Get products by sub category
  getProductsBySubCategory: async (req, res) => {
    try {
      const { subCategory } = req.params;
      const products = await Product.find({ subCategory }).sort({ createdAt: -1 });
      
      res.status(200).json({
        success: true,
        count: products.length,
        products
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'Server Error',
        error: error.message
      });
    }
  },

  // Get product by ID
  getProductById: async (req, res) => {
    try {
      const product = await Product.findById(req.params.id);
      
      if (!product) {
        return res.status(404).json({
          success: false,
          message: 'Product not found'
        });
      }
      
      res.status(200).json({
        success: true,
        product
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'Server Error',
        error: error.message
      });
    }
  },

  // Update product
  updateProduct: async (req, res) => {
    try {
      const { id } = req.params;
      const updates = req.body;
      
      // Handle image updates if needed
      if (req.files && req.files.length > 0) {
        const imageUrls = [];
        for (const file of req.files) {
          const result = await new Promise((resolve, reject) => {
            const uploadStream = cloudinary.uploader.upload_stream(
              { folder: 'chemical_products' },
              (error, result) => {
                if (error) reject(error);
                else resolve(result);
              }
            );
            
            uploadStream.end(file.buffer);
          });
          
          imageUrls.push(result.secure_url);
        }
        updates.images = imageUrls;
      }
      
      // Parse JSON fields if they exist
      if (updates.details && typeof updates.details === 'string') {
        updates.details = JSON.parse(updates.details);
      }
      if (updates.specifications && typeof updates.specifications === 'string') {
        updates.specifications = JSON.parse(updates.specifications);
      }
      if (updates.certifications && typeof updates.certifications === 'string') {
        updates.certifications = JSON.parse(updates.certifications);
      }
      
      const product = await Product.findByIdAndUpdate(id, updates, {
        new: true,
        runValidators: true
      });
      
      if (!product) {
        return res.status(404).json({
          success: false,
          message: 'Product not found'
        });
      }
      
      res.status(200).json({
        success: true,
        product
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'Server Error',
        error: error.message
      });
    }
  },

  // Delete product
  deleteProduct: async (req, res) => {
    try {
      const product = await Product.findByIdAndDelete(req.params.id);
      
      if (!product) {
        return res.status(404).json({
          success: false,
          message: 'Product not found'
        });
      }
      
      // Delete images from Cloudinary
      if (product.images && product.images.length > 0) {
        await Promise.all(
          product.images.map(imageUrl => {
            const publicId = imageUrl.split('/').pop().split('.')[0];
            return cloudinary.uploader.destroy(`chemical_products/${publicId}`);
          })
        );
      }
      
      res.status(200).json({
        success: true,
        message: 'Product deleted successfully'
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'Server Error',
        error: error.message
      });
    }
  }
};

module.exports = productController;