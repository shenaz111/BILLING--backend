const express = require("express");

const CUSTOMER = require("../Models/admin.customer.js");
const errorHandler = require("../Utils/errorHandler.js");
const ADMIN = require("../Models/admin.model.js");
const INVOICE = require("../Models/admin.invoice.model.js");

const addCustomer = async (req, res, next) => {
  try {
    const { customerID, name, email, address } = req.body;
    if (req.params.id != req.user) {
      return next(errorHandler(404, "your not Authorized"));
    }

    const customer = await CUSTOMER.findOne({
      customerID,
      admin: req.params.id,
    });
    if (customer) {
      return next(errorHandler(404, "already existes"));
    } else {
      if (!customerID || !name || !email || !address) {
        return next(errorHandler(404, "must fill all above values"));
      }
      const newcustomer = new CUSTOMER({
        customerID,
        name,
        email,
        address,
        admin: req.params.id,
      });
      await newcustomer.save();
      res.status(200).json(newcustomer);
    }
  } catch (error) {
    next(error);
  }
};
const getallcustomer = async (req, res, next) => {
  try {
    if (req.params.id != req.user) {
      return next(errorHandler(404, "your not Authorized"));
    }
    const customerDetails = await CUSTOMER.find({ admin: req.user }).sort({
      createdAt: -1,
    });
    res.status(200).json(customerDetails);
  } catch (error) {
    next(error);
  }
};
const editcustomer = async (req, res, next) => {
  try {
    const customer = await CUSTOMER.findById(req.params.id);
    if (!customer) {
      return next(errorHandler(404, "customet not found"));
    }
    res.status(200).json(customer);
  } catch (error) {
    next(error);
  }
};
const updatecustomer = async (req, res, next) => {
  try {
   
    const customer = await CUSTOMER.findByIdAndUpdate(
      req.params.id,
      {
        $set: {
          customerID: req.body.customerID,
          name: req.body.name,
          address: req.body.address,
          email: req.body.email,
        },
      },
      { new: true }
    );
    
    res.status(200).json(customer);
  } catch (error) {
    next(error);
  }
};
const deletecustomer = async (req, res, next) => {
  try {
    const customer = await CUSTOMER.findById(req.params.id);
    console.log('cust id during delete' , req.params.id)
    if (!customer) {
      return next(errorHandler(404, "customer_not_found"));
    }
    await customer.deleteOne()


    const customerEmail = customer.email;

    const invoices = await INVOICE.find({ "customer.email": customerEmail });

    await INVOICE.deleteMany({ "customer.email": customerEmail });

    res.status(200).json("deleted successfully........");
  } catch (error) {
    next(error);
  }
};

const getcustomer = async (req, res, next) => {
  const customer = await CUSTOMER.findOne({
    customerID: req.params.id,
    admin: req.params.userid,
  });
  if (!customer) {
    return next(errorHandler(404, "Customer not Found"));
  }

  res.status(200).json(customer);
};

module.exports = {
  addCustomer,
  getallcustomer,
  editcustomer,
  updatecustomer,
  deletecustomer,
  getcustomer,
};
