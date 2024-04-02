const mongoose = require("mongoose");

const INVOICE = require("../Models/admin.invoice.model.js");
const { format, parseISO } = require("date-fns");
const errorHandler = require("../Utils/errorHandler.js");
const PRODUCT = require("../Models/admin.products.js");
const CUSTOMER = require("../Models/admin.customer.js");
const Admin = require("../Models/admin.model.js");



const createInvoice = async (req, res, next) => {
  try {
    let existingInvoice;
    let newInvoiceNumber;

    // Generate a unique invoice number based on the last invoice number
    let lastInvoice = await INVOICE.findOne(
      {},
      {},
      { sort: { invoiceNumber: -1 } }
    );
    let lastInvoiceNumber = lastInvoice
      ? parseInt(lastInvoice.invoiceNumber.slice(4))
      : 0;

    // If parseInt returns NaN, default to 1
    if (isNaN(lastInvoiceNumber)) {
      lastInvoiceNumber = 0;
    }

    do {
      newInvoiceNumber = (lastInvoiceNumber + 1).toString().padStart(2, "0");
      existingInvoice = await INVOICE.findOne({
        invoiceNumber: newInvoiceNumber,
      });

      if (existingInvoice) {
        lastInvoiceNumber++;
      }
    } while (existingInvoice);

    // Create a new invoice with a unique invoice number
    const currentDate = format(new Date(), "yyyy/MM/dd");
    const dueDate = format(parseISO(req.body.date), "yyyy/MM/dd");
    const addProductsToCustomer = await CUSTOMER.findOne({
      _id: req.body.currentCustomer._id,
    });

    for (const product of req.body.prevProducts) {
      addProductsToCustomer.previouslyOrderedProducts.push(product._id);
    }
    const adminemail = await Admin.findById(req.params.id);
    console.log(adminemail);

    for (const product of req.body.prevProducts) {
      const quantityCheck = await PRODUCT.findOne({ _id: product._id });
      console.log(product.productquantity);

      if (quantityCheck.productquantity < product.productquantity) {
        return next(
          errorHandler(
            404,
            `Product quantity is less than your required quantity ${quantityCheck.productname}`
          )
        );
      }

      if (quantityCheck.productquantity < 5) {
        const addProductQuantityLink = `http://localhost:5173/editproduct/${quantityCheck._id}`;
       

       
      }
    }

    const newInvoice = new INVOICE({
      invoiceNumber: newInvoiceNumber,
      issuedate: currentDate.toString(),
      products: req.body.prevProducts,
      customer: req.body.currentCustomer,
      status: "Pending",
      admin: req.params.id,
      dueDate: dueDate.toString(),
    });

    await newInvoice.save();

    for (const product of req.body.prevProducts) {
      const productQuantityDecreasing = await PRODUCT.findByIdAndUpdate(
        product._id,
        {
          $inc: {
            productquantity: -product.productquantity,
          },
        },
        {
          new: true,
        }
      );
    }

    addProductsToCustomer.totalinvoice.push(newInvoice._id);
    await addProductsToCustomer.save();

    res.status(200).json({ newInvoice });
  } catch (error) {
    next(error);
  }
};

const getallInvoices = async (req, res, next) => {
  try {
    console.log(req.params.id);
    if (req.user != req.params.id) {
      return next(errorHandler(404, "unauthorized"));
    }
    // Extract filtering parameters from the request query
    const { invoiceNumber, issuedate, dueDate, status } = req.query;

    // Build the filter object
    let filter = {};

    if (invoiceNumber !== "" && invoiceNumber !== undefined) {
      filter.invoiceNumber = invoiceNumber;
    }

    if (issuedate !== "" && issuedate !== undefined) {
      // Parse the date from the client-side format (yy/mm/dd) to server-side format (MM/dd/yyyy)
      const parsedIssuedate = issuedate.split("-").join("/");

      filter.issuedate = { $eq: parsedIssuedate.toString() }; // Use the parsed date for filtering
    }

    if (dueDate !== "" && dueDate !== undefined) {
      // Parse the due date using the same logic as issuedate
      const parsedDueDate = dueDate.split("-").join("/");

      filter.dueDate = { $eq: parsedDueDate.toString() };
    }

    if (status !== "" && status !== undefined) {
      filter.status = { $in: [status] };
    }

    // Fetch invoices based on the filter or return all invoices
    const invoices = Object.keys(filter).length
      ? await INVOICE.find(filter)
      : await INVOICE.find({ admin: req.params.id });

    res.status(200).json(invoices);
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
};
const updateinvoice = async (req, res, next) => {
  try {
    const invoice = await INVOICE.findOne({ _id: req.params.id });
    if (invoice) {
      res.status(200).json({ invoice });
    } else {
      next(errorHandler(404, "InvoiceNotFound"));
    }
  } catch (error) {
    next(error);
  }
};
const getproductsforexistinginvoice = async (req, res, next) => {
  try {
    const invoice = await INVOICE.findOne({ _id: req.params.id });
    if (!invoice) {
      return next(errorHandler(404, "InvoiceNotFound"));
    }
    res.status(200).json(invoice.products);
  } catch (error) {
    next(error);
  }
};
const addproductstoexistinginvoice = async (req, res, next) => {
  const currentInvoice = await INVOICE.findByIdAndUpdate(
    req.params.id,
    {
      $set: {
        products: req.body.prevProducts,
      },
    },
    { new: true }
  );
  res.status(200).json(currentInvoice);
};
const updateexistinginvoice = async (req, res, next) => {
  try {
    const invoice = await INVOICE.findOne({ _id: req.params.id });

    if (!invoice) {
      return next(errorHandler(404, "Invoice not found"));
    }

    const updateproductsincustomer = await CUSTOMER.findOne({
      email: invoice.customer.email,
    });
    if (!updateproductsincustomer) {
      return next(errorHandler(404, "Customer not found"));
    }
    if (req.body.formdata != "") {
      invoice.status = req.body.formdata;
    }

    await invoice.save();

    // Respond with the updated invoice
    res.status(200).json({ success: true, invoice: invoice });
  } catch (error) {
    next(error);
  }
};

const deleteproductfrominvoice = async (req, res, json) => {
  const invoice = await INVOICE.findById(req.params.id);
  try {
    if (!invoice) {
      next(errorHandler(404, "invoice not found"));
    }
    const productIDtoDelete = req.query.delete_id;
    const deleteproduct = invoice.products.find(
      (product) => product._id == productIDtoDelete
    );
    if (!deleteproduct) {
      next(errorHandler(404, "product not found"));
    }
    //increase the qunatity in poduct collections
    const updateproduct = await PRODUCT.findByIdAndUpdate(
      deleteproduct._id,
      {
        $inc: { productquantity: deleteproduct.productquantity },
      },
      { new: true }
    );
    invoice.products.pull({ _id: deleteproduct._id });
    invoice.save();
    res.status(200).json(invoice);
  } catch (error) {
    next(error);
  }
};

const updateproductquantityinexisitinginvoice = async (req, res, next) => {
  const invoice = await INVOICE.findOne({ _id: req.params.id });

  if (!invoice) {
    return next(errorHandler(404, "Invoice not found"));
  }

  const product = invoice.products.find((product) => {
    return product._id == req.query.productid;
  });
  for (const products of invoice.products) {
    const updateproductquantity = await PRODUCT.findByIdAndUpdate(
      products._id,
      {
        $inc: {
          productquantity: +products.productquantity,
        },
      },
      { new: true }
    );
    await updateproductquantity.save();
  }

  res.status(200).json(product);
};
const updateproductsdoneinexistinginvoice = async (req, res, next) => {
  const invoice = await INVOICE.findOne({ _id: req.params.id });
  if (!invoice) {
    return next(errorHandler(404, "Invoice Not Found"));
  }
  let currentproductquantity = 0;
  for (const product of invoice.products) {
    if (product._id == req.query.productid) {
      product.productquantity = req.body.prevProductsDetails.productquantity;
      currentproductquantity = product.productquantity;
    }
  }

  const product = await PRODUCT.findOne({ _id: req.query.productid });

  if (
    product.productquantity == 0 ||
    product.productquantity < currentproductquantity
  ) {
    return next(errorHandler(404, "no stock quantity"));
  }
  const updatedproduct = await PRODUCT.findByIdAndUpdate(
    req.query.productid,

    {
      $inc: {
        productquantity: -currentproductquantity,
      },
    },
    { new: true }
  );
  await updatedproduct.save();
  await invoice.save();

  res.status(200).json(invoice);
};
const deleteinvoice = async (req, res, next) => {
  try {
    const { deleteid } = req.query;

    // Check if the invoice exists
    const deleteinvoice = await INVOICE.findOne({ _id: deleteid });
    if (!deleteinvoice) {
      return next(errorHandler(404, "Invoice not found"));
    }

    // Use Promise.all to await multiple asynchronous operations concurrently
    await Promise.all(
      deleteinvoice.products.map(async (product) => {
        // Increment product quantity for each product in the invoice
        const updatedProduct = await PRODUCT.findByIdAndUpdate(
          product._id,
          {
            $inc: {
              productquantity: +product.productquantity,
            },
          },
          { new: true }
        );

        // Check if the product was updated successfully
        if (!updatedProduct) {
          throw new Error("Failed to update product quantity");
        }
      })
    );

    // Remove products from customer's previouslyOrderedProducts array
    const productsdeletefromcustomer = await CUSTOMER.findOne({
      email: deleteinvoice.customer.email,
    });
    if (!productsdeletefromcustomer) {
      return next(errorHandler(404, "Customer Not Found"));
    }

    const updatedPreviouslyOrderedProducts =
      productsdeletefromcustomer.previouslyOrderedProducts.filter(
        (prevproductofcustomer) =>
          !deleteinvoice.products.some((product) =>
            product._id.equals(prevproductofcustomer)
          )
      );

    productsdeletefromcustomer.previouslyOrderedProducts =
      updatedPreviouslyOrderedProducts;

    // Remove the invoice from the customer's totalinvoice array
    const updatedTotalInvoices = productsdeletefromcustomer.totalinvoice.filter(
      (previnvoiceofcustomer) => !previnvoiceofcustomer.equals(deleteid)
    );

    productsdeletefromcustomer.totalinvoice = updatedTotalInvoices;

    // Save the changes to the customer document
    await productsdeletefromcustomer.save();

    // Delete the invoice
    const deletedInvoice = await INVOICE.findByIdAndDelete(deleteid);

    if (deletedInvoice) {
      res.status(200).json({ success: true });
    } else {
      return next(errorHandler(404, "Invoice not found"));
    }
  } catch (error) {
    console.error(error);
    ``;
    return next(errorHandler(500, "Internal Server Error"));
  }
};

module.exports = {
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
};
