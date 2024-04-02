const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const body_parser = require("body-parser");
const dotenv = require("dotenv").config();
const adminRoutes = require("./Routes/admin.route.js");
const productsRoutes = require("./Routes/product.route.js");
const customerRouter = require("./Routes/customer.route.js");
const invoicerouter = require("./Routes/admin.invoice.route.js");
const dashboardRoutes=require("./Routes/admin.dashboard.route.js")
const PORT = 5000;
const path=require("path");
const cookieparser = require("cookie-parser");
const app = express();
app.use(body_parser.json());
app.use(express.json());
app.use(cors());
app.use(cookieparser());
const mondbconnection = mongoose
  .connect(process.env.URL)
  .then(() => {
    console.log("db connection established");
  })
  .catch((Error) => {
    console.log("error connecting", Error);
  });

app.use("/api/admin", adminRoutes);
app.use("/api/products", productsRoutes);
app.use("/api/customers", customerRouter);
app.use("/api/invoices", invoicerouter);
app.use("/api/dashboard", dashboardRoutes);
app.use(express.static(path.join(__dirname, '../Front-End/my-App/dist')));
// app.get('*', (req, res) => {
//   res.sendFile(path.join(__dirname, '../Front-End/my-App/dist/index.html'));
// });

app.use((err, req, res, next) => {
  const statusCode = err.statusCode || 500;
  const message = err.message || "Internal Server Error";
  return res.status(400).json({
    success: false,
    message,
    statusCode,
  });
});

app.listen(PORT, (req, res) => {
  console.log("port running", PORT);
});
