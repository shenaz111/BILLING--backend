const PRODUCT = require("../Models/admin.products.js");
const errorHandler = require("../Utils/errorHandler");
const ADMIN = require("../Models/admin.model.js");
const mongoose = require("mongoose");

const addProduct = async (req, res, next) => {
  try {
   
console.log('add product params id',req.params.id);
    const checkexistingproduct = await PRODUCT.findOne({
      productID: req.body.productID,
      admin: req.params.id,
    });

    if (checkexistingproduct) {
      return next(errorHandler(404, "Product Already Exists"));
    }
    if (req.body.productquantity < 5) {
      return next(errorHandler(404, "Product Quantity Must be greater than 5"));
    }

    const newproduct = new PRODUCT({
      productID: req.body.productID,
      productname: req.body.productname,
      productdescription: req.body.productdescription,
      productcategory: req.body.productcategory,
      productquantity: req.body.productquantity,
      productprice: req.body.productprice,
      initailquantity: req.body.initailquantity,
      admin: req.params.id,
    });
    await newproduct.save();

    const admin = await ADMIN.findById(req.user);

    admin.products = admin.products || [];

    admin.products.push(newproduct._id);
    // admin.update({ $addToSet: { products: newproduct._id } });

    await admin.save();
    res.status(200).json(newproduct);
  } catch (error) {
    next(error);
  }
};
const getProducts = async (req, res, next) => {
  console.log('inside get product');
  if (req.user != req.params.id) {
    return next(errorHandler(404, "You are not authorized"));
  }

  try {
    const admin = await ADMIN.findById(req.user).populate({
      path: "products",
      options: { sort: { createdAt: -1 } }, // Sort products in descending order based on createdAt
    });
    // Access products directly from the populated array
    const products = admin.products || [];

    // Respond with the desired data
    res.status(200).json(products);
  } catch (error) {
    console.error("Error fetching products:", error);
    next(errorHandler(500, "Internal Server Error"));
  }
};
const editProduct = async (req, res, next) => {
  try {
    console.log(req.params.id);

    const product = await PRODUCT.findOne({ _id: req.params.id });
    console.log(product);
    if (!product) {
      return next(errorHandler(404, "Product not found"));
    }
    res.status(200).json(product);
  } catch (error) {
    next(error);
  }
};

const editproductdone = async (req, res, next) => {
  try {
    const oldproduct = await PRODUCT.findById(req.params.id);

    if (!oldproduct) {
      return next(errorHandler(404, "Product not found"));
    }
    // console.log('from api call product');

    // Dynamically construct the update object based on the fields in the request body
    const updateFields = {};
    if (req.body.productId) updateFields.productId = req.body.productId;
    if (req.body.productname) updateFields.productname = req.body.productname;
    if (req.body.productprice)
      updateFields.productprice = req.body.productprice;
    if (req.body.productquantity)
      updateFields.productquantity = req.body.productquantity;
    if (req.body.productcategory)
      updateFields.productcategory = req.body.productcategory;
    if (req.body.productdescription) ``;
    updateFields.productdescription = req.body.productdescription;

    const updated = await PRODUCT.findByIdAndUpdate(
      req.params.id,
      { $set: updateFields },
      { new: true }
    );
    // console.log("updated", updated);

    res.status(200).json(updated);
  } catch (error) {
    next(error);
  }
};
const deleteProduct = async (req, res, next) => {
  try {
    const admin = await ADMIN.findById({ _id: req.user });
    if (!admin) {
      return next(errorHandler(404, "you can only delete your products"));
    }
    const deleteproductfromADMIN = admin.products.filter(
      (product) => product._id != req.params.id
    );
    admin.products = deleteproductfromADMIN;
    await admin.save();

    const product = await PRODUCT.findByIdAndDelete({ _id: req.params.id });
    if (!product) {
      return next(errorHandler(404, "Product not found"));
    }

    res.status(200).json(" deleted successfully");
  } catch (error) {
    next(error);
  }
};
const getProduct = async (req, res, next) => {
  // console.log('userId from get product',req.params.userid)
  // console.log('productid from get product',req.params.id)

  const product = await PRODUCT.findOne({
    productID: req.params.id,
    admin: req.params.userid,
  });
  var msg;
  if (!product) {
    return next(errorHandler(404, "product not found"));
  }

  if (product.productquantity == 0 || product.productquantity < 0) {
    return next(errorHandler(404, "Out of Stock"));
  }
  if (product.productquantity < 5) {
    msg = `${product.productname} is only ${product.productquantity} left`;
  }
  const { productquantity: quantity, ...rest } = product._doc;
  res.status(200).json({ rest, msg });
};

module.exports = {
  addProduct,
  getProducts,
  editProduct,
  getProducts,
  editproductdone,
  deleteProduct,
  getProduct,
};
