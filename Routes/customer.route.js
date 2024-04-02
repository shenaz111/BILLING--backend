const express = require("express");
const router = express.Router();
const {
  addCustomer,
  getallcustomer,
  editcustomer,
  updatecustomer,
  deletecustomer,
  getcustomer,
} = require("../Controller/customer.controller.js");
const verifyAdmin = require("../Utils/verifyAdmin.js");

router.post("/addcustomer/:id", verifyAdmin, addCustomer);
router.get("/getallcustomer/:id", verifyAdmin, getallcustomer);
router.get("/editcustomer/:id", verifyAdmin, editcustomer);
router.post("/updatecustomer/:id", verifyAdmin, updatecustomer);
router.delete("/deletecustomer/:id", verifyAdmin, deletecustomer);
router.get("/getcustomer/:id/:userid", verifyAdmin, getcustomer);

module.exports = router;
