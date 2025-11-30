const jwt = require("jsonwebtoken");
const { TokenError } = require("./errors");

/**
 * Sign a JWT token with the given payload and secret
 * @param {Object} payload - Data to encode in the token
 * @param {string} secret - Secret key for signing the token
 * @param {Object} [options={ expiresIn: "1h" }] - JWT signing options
 * @param {string|number} [options.expiresIn="1h"] - Token expiration time (e.g., "1h", "7d", 3600)
 * @returns {string} Signed JWT token
 */
const signToken = (payload, secret, options = { expiresIn: "1h" }) => {
  return jwt.sign(payload, secret, options);
};

/**
 * Verify and decode a JWT token
 * @param {string} token - JWT token to verify
 * @param {string} secret - Secret key used to sign the token
 * @returns {Object} Decoded token payload
 * @throws {TokenError} If token is invalid, expired, or verification fails
 */
const verifyToken = (token, secret) => {
  try {
    return jwt.verify(token, secret);
  } catch (error) {
    if (error.name === "TokenExpiredError") {
      throw new TokenError("Token has expired", "TOKEN_EXPIRED", 401);
    }
    if (error.name === "JsonWebTokenError") {
      throw new TokenError("Invalid token", "INVALID_TOKEN", 403);
    }
    throw new TokenError(
      "Token verification failed",
      "TOKEN_VERIFICATION_FAILED",
      403
    );
  }
};

module.exports = { signToken, verifyToken };
