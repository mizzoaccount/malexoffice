// models/record.js
const mongoose = require('mongoose');

const recordSchema = new mongoose.Schema({
  id: {
    type: String,
    required: true,
    unique: true
  },
  date: {
    type: Date,
    required: true
  },
  time: {
    type: Date,
    required: true
  },
  customerName: {
    type: String,
    required: true
  },
  invoiceNo: String, 
  cashSaleNo: String, 
  quotationNo: String, 
  facilitator: {
    type: String,
    required: true
  },
  amount: {
    type: Number,
    required: true
  },
  createdBy: {
    type: String,
    required: true
  },

  createdAt: {
    type: Date,
    required: true
  }
}, {
  timestamps: true
});

// Add validation for exactly one document type
recordSchema.pre('validate', function(next) {
  const docTypes = [
    this.invoiceNo ? 1 : 0,
    this.cashSaleNo ? 1 : 0,
    this.quotationNo ? 1 : 0
  ].reduce((a, b) => a + b, 0);
  
  if (docTypes !== 1) {
    this.invalidate('documentType', 'Exactly one document type must be provided (invoiceNo, cashSaleNo, or quotationNo)');
  }
  next();
});

const Record = mongoose.model('Record', recordSchema);

module.exports = Record;