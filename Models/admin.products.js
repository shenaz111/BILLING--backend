const mongoose = require("mongoose");
const Admin = require("./admin.model");

const productSchema = new mongoose.Schema(
  {
    productID: {
      type: String,
      required: true,
    },
    productname: { type: String, required: true },
    productdescription: { type: String, required: true },
    productcategory: { type: String, required: true },
    productquantity: { type: Number, required: true },
    productprice: { type: Number, required: true },
    initailquantity: { type: Number, required: true },
    admin: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Admin",
      required: true,
    },
  },
  {
    timestamps: true,
  }
);
const PRODUCT = mongoose.model("PRODUCT", productSchema);
module.exports = PRODUCT;
