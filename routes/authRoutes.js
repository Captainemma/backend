const express = require("express");
const { protect } = require("../middleware/authMiddleware");
const authController = require("../controllers/authController");
const upload = require("../middleware/uploadMiddleware");

const router = express.Router();

const {
  registerUser,
  loginUser,
  getUserInfo,
  updateUserProfile,
  changePassword,
  forgotPassword, 
  resetPassword,
} = authController;

// Register
router.post("/register", registerUser);

// Login
router.post("/login", loginUser);

// Get logged-in user info
router.get("/getUser", protect, getUserInfo);

// Update profile
router.put("/updateUser", protect, updateUserProfile);

// Change password
router.put("/change-password", protect, changePassword);

// Forgot password
router.post("/forgot-password", forgotPassword);

// Reset password
router.post("/reset-password/:token", resetPassword);

// Upload profile picture
router.post(
  "/upload-image",
  protect,
  upload.single("image"),
  async (req, res) => {
    if (!req.file) {
      return res.status(400).json({ message: "No file uploaded" });
    }

    const imageUrl = `${req.protocol}://${req.get("host")}/uploads/${req.file.filename}`;

    try {
      req.user.profileImageUrl = imageUrl;
      await req.user.save();

      res.status(200).json({
        success: true,
        imageUrl,
        message: "Profile picture updated successfully",
      });
    } catch (error) {
      console.error("Error updating profile picture:", error);
      res.status(500).json({ message: "Error updating profile picture" });
    }
  }
);

module.exports = router;
