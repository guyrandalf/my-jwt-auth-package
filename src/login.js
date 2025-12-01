const bcrypt = require("bcryptjs");
const { signToken } = require("./utils");
const { generateTokenPair } = require("./refreshToken");
const { AuthError } = require("./errors");

/**
 * Authenticate a user and generate JWT tokens
 * @param {Object} credentials - User credentials
 * @param {string} credentials.email - User email address
 * @param {string} credentials.password - User password
 * @param {Object} dbAdapter - Database adapter with findByEmail method
 * @param {Function} dbAdapter.findByEmail - Method to find user by email
 * @param {string} secret - JWT secret key for signing tokens
 * @param {Object} [options={}] - Login options
 * @param {boolean} [options.useRefreshTokens=false] - Whether to generate refresh tokens
 * @param {string|null} [options.refreshSecret=null] - Secret for refresh token (required if useRefreshTokens is true)
 * @param {Object} [options.accessTokenOptions={ expiresIn: "15m" }] - Options for access token
 * @param {Object} [options.refreshTokenOptions={ expiresIn: "7d" }] - Options for refresh token
 * @returns {Promise<Object>} Object containing tokens and user info
 * @returns {string} [returns.token] - Single JWT token (if refresh tokens disabled)
 * @returns {string} [returns.accessToken] - Access token (if refresh tokens enabled)
 * @returns {string} [returns.refreshToken] - Refresh token (if refresh tokens enabled)
 * @returns {Object} returns.user - User object (id, email)
 * @throws {AuthError} If credentials are invalid
 */
const loginUser = async (credentials, dbAdapter, secret, options = {}) => {
  const {
    useRefreshTokens = false,
    refreshSecret = null,
    accessTokenOptions = { expiresIn: "15m" },
    refreshTokenOptions = { expiresIn: "7d" },
  } = options;

  const user = await dbAdapter.findByEmail(credentials.email);
  if (!user) {
    throw new AuthError(
      "Invalid email or password",
      "INVALID_CREDENTIALS",
      401
    );
  }

  const isMatch = await bcrypt.compare(credentials.password, user.password);
  if (!isMatch) {
    throw new AuthError(
      "Invalid email or password",
      "INVALID_CREDENTIALS",
      401
    );
  }

  const payload = { id: user.id, email: user.email }; // Add custom fields if needed

  if (useRefreshTokens && refreshSecret) {
    const tokens = generateTokenPair(
      payload,
      secret,
      refreshSecret,
      accessTokenOptions,
      refreshTokenOptions
    );
    return {
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      user,
    };
  }

  // Legacy single token support
  const token = signToken(payload, secret, accessTokenOptions);
  return { token, user };
};

module.exports = { loginUser };
