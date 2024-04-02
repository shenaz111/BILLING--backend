const mongoose = require("mongoose");
const PRODUCT = require("./admin.products");
const INVOICE = require("./admin.invoice.model");

const customerSchema = new mongoose.Schema(
  {
    customerID: {
      type: Number,
      required: true,
    
    },
    name: {
      type: String,
      required: true,
    },
    email: {
      type: String,
      required: true,
    },
    address: {
      type: String,
      required: true,
    },
    admin: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Admin",
      required: true,
    },
    previouslyOrderedProducts: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "PRODUCT",
      },
    ],
    totalinvoice: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "INVOICE",
      },
    ],
  },
  { timestamps: true }
);
const CUSTOMER = mongoose.model("CUSTOMER", customerSchema);
module.exports = CUSTOMER;
