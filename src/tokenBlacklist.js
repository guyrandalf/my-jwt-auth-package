/**
 * In-memory token blacklist (for single-server deployments)
 * For production with multiple servers, use Redis or a shared database
 */
class TokenBlacklist {
  constructor() {
    this.blacklist = new Set();
    this.expirationTimes = new Map(); // Track when tokens expire naturally
  }

  /**
   * Add a token to the blacklist
   * @param {string} token - Token to blacklist
   * @param {number} expiresInMs - Token expiration time in milliseconds (optional, for cleanup)
   */
  add(token, expiresInMs = null) {
    this.blacklist.add(token);
    if (expiresInMs) {
      this.expirationTimes.set(token, Date.now() + expiresInMs);
      // Auto-remove after expiration
      setTimeout(() => {
        this.remove(token);
      }, expiresInMs);
    }
  }

  /**
   * Check if a token is blacklisted
   * @param {string} token - Token to check
   * @returns {boolean} True if token is blacklisted
   */
  has(token) {
    return this.blacklist.has(token);
  }

  /**
   * Remove a token from blacklist
   * @param {string} token - Token to remove
   */
  remove(token) {
    this.blacklist.delete(token);
    this.expirationTimes.delete(token);
  }

  /**
   * Clear all expired tokens (cleanup method)
   */
  clearExpired() {
    const now = Date.now();
    for (const [token, expiresAt] of this.expirationTimes.entries()) {
      if (expiresAt < now) {
        this.remove(token);
      }
    }
  }

  /**
   * Clear entire blacklist
   */
  clear() {
    this.blacklist.clear();
    this.expirationTimes.clear();
  }

  /**
   * Get blacklist size (for monitoring)
   * @returns {number} Number of blacklisted tokens
   */
  size() {
    return this.blacklist.size;
  }
}

// Singleton instance
const tokenBlacklist = new TokenBlacklist();

/**
 * Create a blacklist adapter interface for custom implementations (Redis, database, etc.)
 */
class BlacklistAdapter {
  /**
   * Add token to blacklist
   * @param {string} token - Token to blacklist
   * @param {number} expiresInMs - Expiration time in milliseconds
   */
  // eslint-disable-next-line no-unused-vars
  async add(token, expiresInMs) {
    throw new Error("BlacklistAdapter.add() must be implemented");
  }

  /**
   * Check if token is blacklisted
   * @param {string} token - Token to check
   * @returns {boolean} True if blacklisted
   */
  // eslint-disable-next-line no-unused-vars
  async has(token) {
    throw new Error("BlacklistAdapter.has() must be implemented");
  }

  /**
   * Remove token from blacklist
   * @param {string} token - Token to remove
   */
  // eslint-disable-next-line no-unused-vars
  async remove(token) {
    throw new Error("BlacklistAdapter.remove() must be implemented");
  }
}

/**
 * Logout - add token to blacklist
 * @param {string} token - Access token to blacklist
 * @param {Object} blacklistAdapter - Blacklist adapter (default: in-memory)
 * @param {number} expiresInMs - Token expiration time in milliseconds
 */
const logout = async (token, blacklistAdapter = null, expiresInMs = null) => {
  const adapter = blacklistAdapter || tokenBlacklist;

  if (typeof adapter.add === "function") {
    // Custom adapter (async)
    await adapter.add(token, expiresInMs);
  } else {
    // In-memory blacklist (sync)
    adapter.add(token, expiresInMs);
  }
};

/**
 * Check if token is blacklisted
 * @param {string} token - Token to check
 * @param {Object} blacklistAdapter - Blacklist adapter (default: in-memory)
 * @returns {boolean} True if blacklisted
 */
const isBlacklisted = async (token, blacklistAdapter = null) => {
  const adapter = blacklistAdapter || tokenBlacklist;

  if (typeof adapter.has === "function") {
    // Custom adapter (async)
    return await adapter.has(token);
  } else {
    // In-memory blacklist (sync)
    return adapter.has(token);
  }
};

module.exports = {
  TokenBlacklist,
  BlacklistAdapter,
  tokenBlacklist,
  logout,
  isBlacklisted,
};
