const express= require('express');
const verifyAdmin = require('../Utils/verifyAdmin');
const{addProduct,getProducts,editProduct,editproductdone,deleteProduct,getProduct}=require("../Controller/product.controller.js")
const router=express.Router();
router.post("/addproduct/:id",verifyAdmin,addProduct)
router.get("/getproducts/:id",verifyAdmin,getProducts)
router.get("/editproduct/:id",verifyAdmin,editProduct)
router.post("/editproductdone/:id",verifyAdmin,editproductdone)
router.delete("/deleteproduct/:id",verifyAdmin,deleteProduct)
router.get("/getproduct/:id/:userid",verifyAdmin,getProduct)



module.exports =router