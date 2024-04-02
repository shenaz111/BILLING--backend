// middleware/authMiddleware.js

const jwt = require("jsonwebtoken");
const JWT_KEY = "f8d3e9b2a1f4c7e5b9a3c1f6e8d5b2a7c9f3e1d8b4a6c2f9e7d1a5b3c8f6d9e2b7a4c5f1e3d6b9a2c4f8e6d1b3a7c2f9e5d8a1b6c4f7e2d9b1a8c5f3e6b4a2c7f9e3d8a5c1f7e9d6b3a1c4f8d5e9b7a2c3f6e1a7c9f2d8b6a3c5f9e4d1f6c3b7a8c2f9e5d6c8f3b1a7c2f6e9a1c3f8e7d9b6a2c4f9e1d7a5c2f8a3b9c1f6e8d5a2c7f1e3c6f9a5e8b3c1f5e9d7a2c6f2e8b5a1c3f7d9e6c4b1a2c7f9e5d3a7c1f8e2b5a9d6c3f7e9d4a8c1f2e7d5b3a6c8f9e2d7f3c6a2c5f8e1d4b9a3c6f2e8d5c1f7e9a2c4f6e3b8a5c2f9a1c3f7e9d2c4f1e5d8a6c2f9e7a3c5f1e9d6c8f3e7a5c2f8e1b6d3a9c7f2d8a4c1f6e9d5b7a2c4f9e3a6c1f7e9a3c5f2d8e4c6f1a9d7c3f8e6b9a2c7f5e9d3b8a5c1f8e3b6a2c5f9e1d3f7c5a8b2c6f2e9d5c3f8a6b9c2f1e4d8c1f6e9b3a7c5f4e8b1c2f6a9d1e3f7c5b8a3d9c1f2e8b6d3f7a2e9d5c6f1e8d4b9a2c3f7e9d4b8c6f2e5d9c1f7e3a6b2c5f1a8e9c3f6e1a7c9f3d8b4a2c6f8e3a1c7f5d9e2c3f8a9b5c2f7e6d3c1f5a7e8b9c6f3e1b8a2c7f9e4d1f5c3b7a8c2f9e5d6c8f3b1a7c2f6e9a1c3f8e7d9b6a2c4f9e1d7a5c2f8a3b9c1f6e8d5a2c7f1e3c6f9a5e8b3c1f5e9d7a2c6f2e8b5a1c3f7d9e6c4b1a2c7f9e5d3a7c1f8e2b5a9d6c3f7e9d4a8c1f2e7d5b3a6c8f9e";

const authMiddleware = (req, res, next) => {
  // Get the access_token from the Authorization header
  const authHeader = req.headers.authorization;
  

  if (!authHeader) {
    return res
      .status(401)
      .json({ message: "Unauthorized: No access_token provided" });
  }

  // Extract the token from the "Bearer" scheme
  const token = authHeader.split(" ")[1];


  if (!token) {
    return res
      .status(401)
      .json({ message: "Unauthorized: Invalid access_token format" });
  }

  try {
    // Verify the access_token
    const decoded = jwt.verify(token, JWT_KEY); // Use the same secret key as used during token generation

    // Attach user information to the request object
    req.user = decoded.id;
   
    next();
  } catch (error) {
    console.error("Error during access_token verification:", error);
    return res
      .status(401)
      .json({ message: "Unauthorized: Invalid access_token" });
  }
};

module.exports = authMiddleware;
