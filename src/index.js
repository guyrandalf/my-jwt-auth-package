const { signToken, verifyToken } = require("./utils");
const { registerUser } = require("./register");
const { loginUser } = require("./login");
const { createAuthMiddleware } = require("./middleware");
const {
  generateRefreshToken,
  verifyRefreshToken,
  generateTokenPair,
  refreshAccessToken,
} = require("./refreshToken");
const {
  generateResetToken,
  hashResetToken,
  verifyResetToken,
  requestPasswordReset,
  resetPassword,
} = require("./passwordReset");
const {
  TokenBlacklist,
  BlacklistAdapter,
  tokenBlacklist,
  logout,
  isBlacklisted,
} = require("./tokenBlacklist");
const {
  AuthError,
  ValidationError,
  TokenError,
  NotFoundError,
} = require("./errors");
const { getConfig } = require("./config");

module.exports = {
  // Core JWT utilities
  signToken,
  verifyToken,

  // Authentication
  registerUser,
  loginUser,

  // Middleware
  createAuthMiddleware,

  // Refresh tokens
  generateRefreshToken,
  verifyRefreshToken,
  generateTokenPair,
  refreshAccessToken,

  // Password reset
  generateResetToken,
  hashResetToken,
  verifyResetToken,
  requestPasswordReset,
  resetPassword,

  // Token blacklist
  TokenBlacklist,
  BlacklistAdapter,
  tokenBlacklist,
  logout,
  isBlacklisted,

  // Error classes
  AuthError,
  ValidationError,
  TokenError,
  NotFoundError,

  // Configuration
  getConfig,
};
