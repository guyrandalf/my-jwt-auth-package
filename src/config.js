/**
 * Configuration utility for JWT Auth package
 * Supports environment variables and default values
 */

/**
 * Get configuration for JWT Auth package
 * @param {Object} [options={}] - Configuration options (overrides environment variables)
 * @param {string} [options.accessTokenSecret] - Secret for access tokens (defaults to JWT_SECRET or JWT_ACCESS_SECRET env var)
 * @param {string} [options.refreshTokenSecret] - Secret for refresh tokens (defaults to JWT_REFRESH_SECRET or JWT_SECRET env var)
 * @param {string} [options.accessTokenExpiresIn="15m"] - Access token expiration (defaults to JWT_ACCESS_EXPIRES_IN env var)
 * @param {string} [options.refreshTokenExpiresIn="7d"] - Refresh token expiration (defaults to JWT_REFRESH_EXPIRES_IN env var)
 * @param {number} [options.passwordResetExpiresInHours=1] - Password reset token expiration in hours (defaults to PASSWORD_RESET_EXPIRES_IN_HOURS env var)
 * @param {number} [options.passwordMinLength=8] - Minimum password length (defaults to PASSWORD_MIN_LENGTH env var)
 * @param {number} [options.bcryptRounds=10] - Number of bcrypt rounds (defaults to BCRYPT_ROUNDS env var)
 * @param {boolean} [options.useRefreshTokens=false] - Whether to use refresh tokens (defaults to USE_REFRESH_TOKENS env var)
 * @returns {Object} Configuration object
 * @returns {string} returns.accessTokenSecret - Access token secret (required)
 * @returns {string} returns.refreshTokenSecret - Refresh token secret
 * @returns {string} returns.accessTokenExpiresIn - Access token expiration
 * @returns {string} returns.refreshTokenExpiresIn - Refresh token expiration
 * @returns {number} returns.passwordResetExpiresInHours - Password reset expiration hours
 * @returns {number} returns.passwordMinLength - Minimum password length
 * @returns {number} returns.bcryptRounds - Bcrypt rounds
 * @returns {boolean} returns.useRefreshTokens - Whether refresh tokens are enabled
 * @throws {Error} If accessTokenSecret is not provided
 */
const getConfig = (options = {}) => {
  const {
    // Secrets
    accessTokenSecret = process.env.JWT_SECRET ||
      process.env.JWT_ACCESS_SECRET ||
      null,
    refreshTokenSecret = process.env.JWT_REFRESH_SECRET ||
      process.env.JWT_SECRET ||
      null,

    // Token expiration
    accessTokenExpiresIn = process.env.JWT_ACCESS_EXPIRES_IN || "15m",
    refreshTokenExpiresIn = process.env.JWT_REFRESH_EXPIRES_IN || "7d",

    // Password reset
    passwordResetExpiresInHours = parseInt(
      process.env.PASSWORD_RESET_EXPIRES_IN_HOURS || "1",
      10
    ),

    // Password requirements
    passwordMinLength = parseInt(process.env.PASSWORD_MIN_LENGTH || "8", 10),

    // Security
    bcryptRounds = parseInt(process.env.BCRYPT_ROUNDS || "10", 10),

    // Features
    useRefreshTokens = process.env.USE_REFRESH_TOKENS === "true" || false,
  } = options;

  if (!accessTokenSecret) {
    throw new Error(
      "JWT_SECRET or JWT_ACCESS_SECRET environment variable is required, " +
        "or provide accessTokenSecret in options"
    );
  }

  return {
    accessTokenSecret,
    refreshTokenSecret: refreshTokenSecret || accessTokenSecret,
    accessTokenExpiresIn,
    refreshTokenExpiresIn,
    passwordResetExpiresInHours,
    passwordMinLength,
    bcryptRounds,
    useRefreshTokens,
  };
};

module.exports = { getConfig };
