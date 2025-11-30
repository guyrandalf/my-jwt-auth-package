const { verifyToken } = require("./utils");
const { isBlacklisted } = require("./tokenBlacklist");
const { TokenError } = require("./errors");

/**
 * Create Express middleware for protecting routes with JWT authentication
 * @param {string} secret - JWT secret key for token verification
 * @param {Object} [options={}] - Middleware options
 * @param {Object|null} [options.blacklistAdapter=null] - Custom blacklist adapter for token revocation
 * @param {Function|null} [options.errorHandler=null] - Custom error handler function (req, res, error) => void
 * @returns {Function} Express middleware function
 * @example
 * const authMiddleware = createAuthMiddleware(secret);
 * app.get('/protected', authMiddleware, (req, res) => {
 *   res.json({ user: req.user });
 * });
 */
const createAuthMiddleware = (secret, options = {}) => {
  const {
    blacklistAdapter = null,
    errorHandler = null, // Custom error handler function
  } = options;

  return async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      if (errorHandler) {
        return errorHandler(
          req,
          res,
          new TokenError(
            "Missing or invalid authorization header",
            "MISSING_TOKEN",
            401
          )
        );
      }
      return res
        .status(401)
        .json({ error: "Unauthorized", code: "MISSING_TOKEN" });
    }

    const token = authHeader.split(" ")[1];

    // Check blacklist
    try {
      const blacklisted = await isBlacklisted(token, blacklistAdapter);
      if (blacklisted) {
        const error = new TokenError(
          "Token has been revoked",
          "TOKEN_REVOKED",
          401
        );
        if (errorHandler) {
          return errorHandler(req, res, error);
        }
        return res
          .status(401)
          .json({ error: "Token has been revoked", code: "TOKEN_REVOKED" });
      }
    } catch (error) {
      // If blacklist check fails, log but continue (fail open for availability)
      console.warn("Blacklist check failed:", error.message);
    }

    try {
      const decoded = verifyToken(token, secret);
      req.user = decoded;
      next();
    } catch (error) {
      if (errorHandler) {
        return errorHandler(req, res, error);
      }
      const statusCode = error.statusCode || 403;
      return res.status(statusCode).json({
        error: error.message || "Forbidden",
        code: error.code || "TOKEN_ERROR",
      });
    }
  };
};

module.exports = { createAuthMiddleware };
