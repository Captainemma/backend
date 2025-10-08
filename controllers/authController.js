const asyncHandler = require("express-async-handler");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const crypto = require("crypto");
const nodemailer = require("nodemailer");

// Generate JWT
const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: "30d",
  });
};

// @desc    Register new user
// @route   POST /api/auth/register
// @access  Public
// Register user
const registerUser = async (req, res) => {
  try {
    let { fullName, email, password } = req.body;

    if (!fullName || !email || !password) {
      return res.status(400).json({ message: "Please add all fields" });
    }

    email = email.toLowerCase().trim();

    const userExists = await User.findOne({ email });
    if (userExists) return res.status(400).json({ message: "User already exists" });

    // Create user without hashing manually
    const user = await User.create({
      fullName: fullName.trim(),
      email,
      password: password.trim(),  // ✅ raw password, pre-save hook will hash it
    });

    if (user) {
      return res.status(201).json({
        _id: user._id,
        fullName: user.fullName,
        email: user.email,
        token: generateToken(user._id),
      });
    } else {
      return res.status(400).json({ message: "Invalid user data" });
    }
  } catch (error) {
    console.error("Register error:", error.message);
    return res.status(500).json({ message: "Server error" });
  }
};

// @desc    Login user
// @route   POST /api/auth/login
// @access  Public
const loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate input
    if (!email || !password) {
      return res.status(400).json({ message: "Please add all fields" });
    }

    // Find user
    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    // Compare password
    const isMatch = await bcrypt.compare(password, user.password);
    console.log("Login attempt:", { email, password });
    console.log("Stored hashed password:", user.password);
    console.log("Password match result:", isMatch);

    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    // Success
    res.status(200).json({
      _id: user.id,
      fullName: user.fullName,
      email: user.email,
      token: generateToken(user._id),
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
};

// @desc    Get user info
// @route   GET /api/auth/me
// @access  Private
const getUserInfo = async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.status(200).json(user);
  } catch (error) {
    console.error("Get user info error:", error.message);
    res.status(500).json({ message: "Server error" });
  }
};

// @desc    Update user profile
// @route   PUT /api/auth/updateUser
// @access  Private
const updateUserProfile = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);

  if (user) {
    user.fullName = req.body.fullName || user.fullName;
    user.email = req.body.email || user.email;

    if (req.body.password) {
      const salt = await bcrypt.genSalt(10);
      user.password = await bcrypt.hash(req.body.password, salt);
    }

    const updatedUser = await user.save();

    res.json({
      _id: updatedUser._id,
      fullName: updatedUser.fullName,
      email: updatedUser.email,
      profileImageUrl: updatedUser.profileImageUrl,
    });
  } else {
    res.status(404);
    throw new Error("User not found");
  }
});

// @desc    Change password
// @route   PUT /api/auth/change-password
// @access  Private
const changePassword = async (req, res) => {
  try {
    const userId = req.user.id;
    const { oldPassword, newPassword } = req.body;

    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: "User not found" });

    const isMatch = await bcrypt.compare(oldPassword, user.password);
    if (!isMatch) return res.status(400).json({ error: "Old password is incorrect" });

    // Just assign the plain new password
    user.password = newPassword;

    await user.save(); // pre-save hook hashes it automatically

    return res.json({ message: "Password changed successfully" });
  } catch (error) {
    console.error("Error changing password:", error);
    res.status(500).json({ error: "Server error" });
  }
};


// @desc    Forgot password
// @route   POST /api/v1/auth/forgot-password
// @access  Public
const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) return res.status(400).json({ message: "Please provide an email" });

    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user) return res.status(404).json({ message: "User not found" });

    // Generate reset token (expires in 1 hour)
    const resetToken = crypto.randomBytes(32).toString("hex");
    const resetTokenExpiry = Date.now() + 3600000; // 1 hour

    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = resetTokenExpiry;
    await user.save();

    // Frontend reset password URL
    const resetUrl = `http://localhost:5173/reset-password/${resetToken}`;

    // Mailtrap transporter
    const transporter = nodemailer.createTransport({
      host: "sandbox.smtp.mailtrap.io",
      port: 2525,
      auth: {
        user: "f1bfb95b7f5bfa", // Mailtrap username
        pass: "e692b3029f80ec", // Mailtrap password
      },
    });

    // Send reset email
    await transporter.sendMail({
      from: `"Expense Tracker" <no-reply@expensetracker.com>`,
      to: user.email,
      subject: "Password Reset Request",
      html: `<p>You requested a password reset. Click this link to reset your password:</p>
             <a href="${resetUrl}">${resetUrl}</a>
             <p>This link expires in 1 hour.</p>`,
    });

    res.json({ message: "Password reset email sent! Check Mailtrap inbox." });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error sending reset email" });
  }
};

// @desc    Reset password
// @route   POST /api/v1/auth/reset-password/:token
// @access  Public
const resetPassword = async (req, res) => {
  try {
    const { token } = req.params;
    const { newPassword } = req.body;

    if (!newPassword) return res.status(400).json({ message: "Please provide a new password" });

    const user = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() },
    });

    if (!user) return res.status(400).json({ message: "Invalid or expired token" });

    // Assign plain password — pre-save hook will hash it
    user.password = newPassword;

    // Remove token fields
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;

    await user.save();

    res.json({ message: "Password reset successfully!" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error resetting password" });
  }
};

module.exports = {
  registerUser,
  loginUser,
  getUserInfo,
  updateUserProfile,
  changePassword,
  forgotPassword,
  resetPassword,
};
