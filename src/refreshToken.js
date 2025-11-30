const { signToken, verifyToken } = require("./utils");
const { TokenError } = require("./errors");

/**
 * Generate a refresh token (long-lived token for obtaining new access tokens)
 * @param {Object} payload - Token payload (typically user id)
 * @param {string} secret - Secret key for signing
 * @param {Object} options - JWT options (default: expiresIn: "7d")
 * @returns {string} Refresh token
 */
const generateRefreshToken = (
  payload,
  secret,
  options = { expiresIn: "7d" }
) => {
  return signToken(payload, secret, options);
};

/**
 * Verify a refresh token
 * @param {string} token - Refresh token to verify
 * @param {string} secret - Secret key for verification
 * @returns {Object} Decoded token payload
 * @throws {TokenError} If token is invalid or expired
 */
const verifyRefreshToken = (token, secret) => {
  try {
    return verifyToken(token, secret);
  } catch {
    throw new TokenError(
      "Invalid or expired refresh token",
      "INVALID_REFRESH_TOKEN"
    );
  }
};

/**
 * Generate both access and refresh tokens
 * @param {Object} payload - Token payload
 * @param {string} accessSecret - Secret for access token
 * @param {string} refreshSecret - Secret for refresh token (can be same as accessSecret)
 * @param {Object} accessOptions - Options for access token (default: expiresIn: "15m")
 * @param {Object} refreshOptions - Options for refresh token (default: expiresIn: "7d")
 * @returns {Object} Object with accessToken and refreshToken
 */
const generateTokenPair = (
  payload,
  accessSecret,
  refreshSecret,
  accessOptions = { expiresIn: "15m" },
  refreshOptions = { expiresIn: "7d" }
) => {
  const accessToken = signToken(payload, accessSecret, accessOptions);
  const refreshToken = generateRefreshToken(
    payload,
    refreshSecret,
    refreshOptions
  );

  return {
    accessToken,
    refreshToken,
  };
};

/**
 * Refresh an access token using a refresh token
 * @param {string} refreshToken - The refresh token
 * @param {string} refreshSecret - Secret for refresh token verification
 * @param {string} accessSecret - Secret for new access token signing
 * @param {Object} accessOptions - Options for new access token (default: expiresIn: "15m")
 * @returns {Object} New access token and optionally new refresh token
 */
const refreshAccessToken = (
  refreshToken,
  refreshSecret,
  accessSecret,
  accessOptions = { expiresIn: "15m" }
) => {
  const decoded = verifyRefreshToken(refreshToken, refreshSecret);

  // Extract user info from decoded token (remove iat, exp, etc.)
  // iat and exp are intentionally unused - we only need userPayload
  // eslint-disable-next-line no-unused-vars
  const { iat, exp, ...userPayload } = decoded;

  const newAccessToken = signToken(userPayload, accessSecret, accessOptions);

  return {
    accessToken: newAccessToken,
    user: userPayload,
  };
};

module.exports = {
  generateRefreshToken,
  verifyRefreshToken,
  generateTokenPair,
  refreshAccessToken,
};
