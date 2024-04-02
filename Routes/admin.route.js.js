const express = require("express");
const {
  signupRouter,
  loginRouter,
  updateRouter,
  logoutRouter,
  reset_password,
  newpasswordchange,
  verifyUser,
  verificationstatus,
} = require("../Controller/admin.controller");
const verifyAdmin = require("../Utils/verifyAdmin.js");
const router = express.Router();

router.post("/signup", signupRouter);
router.post("/login", loginRouter);
router.post("/update/:id", verifyAdmin, updateRouter);
router.get("/logout", verifyAdmin, logoutRouter);
router.post("/reset-password", reset_password);
router.post("/newpassword/:id", newpasswordchange);
router.get("/verify/:id/:token", verifyUser);
router.get("/verificationstatus/:id/:token", verificationstatus);

module.exports = router;
