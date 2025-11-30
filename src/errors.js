/**
 * Authentication error class
 * @class
 * @extends Error
 */
class AuthError extends Error {
  /**
   * Create an authentication error
   * @param {string} message - Error message
   * @param {string} [code="AUTH_ERROR"] - Error code
   * @param {number} [statusCode=401] - HTTP status code
   */
  constructor(message, code = "AUTH_ERROR", statusCode = 401) {
    super(message);
    this.name = "AuthError";
    this.code = code;
    this.statusCode = statusCode;
    Error.captureStackTrace(this, this.constructor);
  }
}

/**
 * Validation error class
 * @class
 * @extends Error
 */
class ValidationError extends Error {
  /**
   * Create a validation error
   * @param {string} message - Error message
   * @param {string|null} [field=null] - Field name that failed validation
   */
  constructor(message, field = null) {
    super(message);
    this.name = "ValidationError";
    this.code = "VALIDATION_ERROR";
    this.field = field;
    this.statusCode = 400;
    Error.captureStackTrace(this, this.constructor);
  }
}

/**
 * Token error class
 * @class
 * @extends Error
 */
class TokenError extends Error {
  /**
   * Create a token error
   * @param {string} message - Error message
   * @param {string} [code="TOKEN_ERROR"] - Error code
   * @param {number} [statusCode=403] - HTTP status code
   */
  constructor(message, code = "TOKEN_ERROR", statusCode = 403) {
    super(message);
    this.name = "TokenError";
    this.code = code;
    this.statusCode = statusCode;
    Error.captureStackTrace(this, this.constructor);
  }
}

/**
 * Not found error class
 * @class
 * @extends Error
 */
class NotFoundError extends Error {
  /**
   * Create a not found error
   * @param {string} [message="Resource not found"] - Error message
   */
  constructor(message = "Resource not found") {
    super(message);
    this.name = "NotFoundError";
    this.code = "NOT_FOUND";
    this.statusCode = 404;
    Error.captureStackTrace(this, this.constructor);
  }
}

module.exports = {
  AuthError,
  ValidationError,
  TokenError,
  NotFoundError,
};
