const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const { ValidationError, TokenError } = require("./errors");

/**
 * Generate a password reset token
 * @returns {string} Random secure token
 */
const generateResetToken = () => {
  return crypto.randomBytes(32).toString("hex");
};

/**
 * Hash a password reset token (for storage in database)
 * @param {string} token - Plain reset token
 * @returns {string} Hashed token
 */
const hashResetToken = (token) => {
  return crypto.createHash("sha256").update(token).digest("hex");
};

/**
 * Verify a password reset token
 * @param {string} token - Plain reset token from user
 * @param {string} hashedToken - Hashed token from database
 * @returns {boolean} True if tokens match
 */
const verifyResetToken = (token, hashedToken) => {
  const tokenHash = hashResetToken(token);
  return crypto.timingSafeEqual(
    Buffer.from(tokenHash),
    Buffer.from(hashedToken)
  );
};

/**
 * Request password reset - generates token and stores it in database
 * @param {string} email - User email
 * @param {Object} dbAdapter - Database adapter with findByEmail and update methods
 * @param {number} expiresInHours - Token expiration in hours (default: 1)
 * @returns {Object} Reset token and expiration info
 */
const requestPasswordReset = async (email, dbAdapter, expiresInHours = 1) => {
  const user = await dbAdapter.findByEmail(email);
  if (!user) {
    // Don't reveal if user exists (security best practice)
    return {
      token: generateResetToken(),
      expiresAt: new Date(Date.now() + expiresInHours * 60 * 60 * 1000),
      message: "If an account exists, a reset link has been sent",
    };
  }

  const resetToken = generateResetToken();
  const hashedToken = hashResetToken(resetToken);
  const expiresAt = new Date(Date.now() + expiresInHours * 60 * 60 * 1000);

  // Store hashed token and expiration in database
  await dbAdapter.update(user.id, {
    resetPasswordToken: hashedToken,
    resetPasswordExpires: expiresAt,
  });

  return {
    token: resetToken, // Return plain token for email (don't store this!)
    expiresAt,
    user: { id: user.id, email: user.email },
  };
};

/**
 * Reset password using reset token
 * @param {string} token - Reset token from email
 * @param {string} newPassword - New password
 * @param {Object} dbAdapter - Database adapter with findByEmail and update methods
 * @param {Object} passwordSchema - Optional Joi schema for password validation
 * @returns {Object} Updated user info
 */
const resetPassword = async (
  token,
  newPassword,
  dbAdapter,
  passwordSchema = null
) => {
  if (!token) {
    throw new ValidationError("Reset token is required", "token");
  }

  if (!newPassword) {
    throw new ValidationError("New password is required", "password");
  }

  // Validate password if schema provided
  if (passwordSchema) {
    const Joi = require("joi");
    const schema = Joi.object({ password: passwordSchema });
    const { error } = schema.validate({ password: newPassword });
    if (error) {
      throw new ValidationError(error.details[0].message, "password");
    }
  }

  const hashedToken = hashResetToken(token);

  // Find user by reset token (you'll need to implement findByResetToken in your adapter)
  // For now, we'll use a generic find method
  const user =
    (await dbAdapter.findByResetToken?.(hashedToken)) ||
    (await dbAdapter.findByField?.("resetPasswordToken", hashedToken));

  if (!user) {
    throw new TokenError(
      "Invalid or expired reset token",
      "INVALID_RESET_TOKEN"
    );
  }

  // Check if token expired
  if (
    user.resetPasswordExpires &&
    new Date(user.resetPasswordExpires) < new Date()
  ) {
    throw new TokenError("Reset token has expired", "EXPIRED_RESET_TOKEN");
  }

  // Hash new password
  const hashedPassword = await bcrypt.hash(newPassword, 10);

  // Update user password and clear reset token
  const updatedUser = await dbAdapter.update(user.id, {
    password: hashedPassword,
    resetPasswordToken: null,
    resetPasswordExpires: null,
  });

  return {
    user: {
      id: updatedUser.id,
      email: updatedUser.email,
    },
  };
};

module.exports = {
  generateResetToken,
  hashResetToken,
  verifyResetToken,
  requestPasswordReset,
  resetPassword,
};
