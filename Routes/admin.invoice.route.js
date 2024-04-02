const express = require("express");
const verifyAdmin = require("../Utils/verifyAdmin");
const {
  createInvoice,
  getallInvoices,
  updateinvoice,
  getproductsforexistinginvoice,
  addproductstoexistinginvoice,
  updateexistinginvoice,
  deleteproductfrominvoice,
  updateproductquantityinexisitinginvoice,
  updateproductsdoneinexistinginvoice,
  deleteinvoice,
} = require("../Controller/admin.invoice.controller");
const router = express.Router();
router.post("/createInvoice/:id", verifyAdmin, createInvoice);
router.get("/getAllInvoices/:id", verifyAdmin, getallInvoices);
router.get("/updateinvoice/:id", verifyAdmin, updateinvoice);
router.get(
  "/getproductsforexistinginvoice/:id",
  verifyAdmin,
  getproductsforexistinginvoice
);
router.post(
  "/addproductstoexistinginvoice/:id",
  verifyAdmin,
  addproductstoexistinginvoice
);
router.post("/updateexistinginvoice/:id", verifyAdmin, updateexistinginvoice);
router.delete(
  "/deleteproductfrominvoice/:id",
  verifyAdmin,
  deleteproductfrominvoice
);
router.get(
  "/updateproductquantityinexisitinginvoice/:id",
  verifyAdmin,
  updateproductquantityinexisitinginvoice
);
router.post(
  "/updateproductsdoneinexistinginvoice/:id",
  verifyAdmin,
  updateproductsdoneinexistinginvoice
);
router.delete("/deleteinvoice", deleteinvoice);
module.exports = router;
