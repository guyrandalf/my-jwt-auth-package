const chai = require("chai");
const { describe, it, beforeEach } = require("mocha");
const {
  generateRefreshToken,
  verifyRefreshToken,
  generateTokenPair,
  refreshAccessToken,
  requestPasswordReset,
  resetPassword,
  logout,
  isBlacklisted,
  AuthError,
  ValidationError,
  TokenError,
  NotFoundError,
  getConfig,
  loginUser,
  createAuthMiddleware,
} = require("../src/index");
const { signToken } = require("../src/utils");
const bcrypt = require("bcryptjs");

const { expect } = chai;

describe("Refresh Tokens", () => {
  const secret = "refresh-secret-key";

  describe("generateRefreshToken", () => {
    it("should generate a refresh token", () => {
      const payload = { id: 1, email: "test@example.com" };
      const token = generateRefreshToken(payload, secret);
      expect(token).to.be.a("string");
      expect(token.split(".")).to.have.lengthOf(3);
    });

    it("should generate token with custom expiration", () => {
      const payload = { id: 1 };
      const token = generateRefreshToken(payload, secret, { expiresIn: "30d" });
      expect(token).to.be.a("string");
    });
  });

  describe("verifyRefreshToken", () => {
    it("should verify a valid refresh token", () => {
      const payload = { id: 1, email: "test@example.com" };
      const token = generateRefreshToken(payload, secret);
      const decoded = verifyRefreshToken(token, secret);
      expect(decoded.id).to.equal(1);
      expect(decoded.email).to.equal("test@example.com");
    });

    it("should throw TokenError for invalid refresh token", () => {
      expect(() => verifyRefreshToken("invalid.token", secret)).to.throw(
        TokenError
      );
    });
  });

  describe("generateTokenPair", () => {
    it("should generate both access and refresh tokens", () => {
      const payload = { id: 1, email: "test@example.com" };
      const tokens = generateTokenPair(payload, secret, secret);
      expect(tokens).to.have.property("accessToken");
      expect(tokens).to.have.property("refreshToken");
      expect(tokens.accessToken).to.be.a("string");
      expect(tokens.refreshToken).to.be.a("string");
    });

    it("should use different secrets for access and refresh tokens", () => {
      const payload = { id: 1 };
      const accessSecret = "access-secret";
      const refreshSecret = "refresh-secret";
      const tokens = generateTokenPair(payload, accessSecret, refreshSecret);
      expect(tokens.accessToken).to.be.a("string");
      expect(tokens.refreshToken).to.be.a("string");
    });
  });

  describe("refreshAccessToken", () => {
    it("should generate new access token from refresh token", () => {
      const payload = { id: 1, email: "test@example.com" };
      const refreshToken = generateRefreshToken(payload, secret);
      const result = refreshAccessToken(refreshToken, secret, secret);
      expect(result).to.have.property("accessToken");
      expect(result).to.have.property("user");
      expect(result.user.id).to.equal(1);
      expect(result.user.email).to.equal("test@example.com");
    });

    it("should throw TokenError for invalid refresh token", () => {
      expect(() => {
        refreshAccessToken("invalid.token", secret, secret);
      }).to.throw(TokenError);
    });
  });
});

describe("Password Reset", () => {
  let mockDbAdapter;

  beforeEach(() => {
    mockDbAdapter = {
      findByEmail: async (email) => {
        if (email === "existing@example.com") {
          return { id: 1, email: "existing@example.com", password: "hashed" };
        }
        return null;
      },
      update: async (id, data) => {
        return { id, ...data };
      },
      findByResetToken: async (token) => {
        // Mock implementation - in real app, you'd hash the token
        if (token === "valid-hashed-token") {
          return {
            id: 1,
            email: "user@example.com",
            resetPasswordExpires: new Date(Date.now() + 3600000), // 1 hour from now
          };
        }
        if (token === "expired-hashed-token") {
          return {
            id: 1,
            email: "user@example.com",
            resetPasswordExpires: new Date(Date.now() - 3600000), // 1 hour ago
          };
        }
        return null;
      },
      findByField: async (field, value) => {
        if (field === "resetPasswordToken" && value === "valid-hashed-token") {
          return {
            id: 1,
            email: "user@example.com",
            resetPasswordExpires: new Date(Date.now() + 3600000),
          };
        }
        return null;
      },
    };
  });

  describe("generateResetToken", () => {
    it("should generate a random token", () => {
      const { generateResetToken } = require("../src/passwordReset");
      const token1 = generateResetToken();
      const token2 = generateResetToken();
      expect(token1).to.be.a("string");
      expect(token1.length).to.be.greaterThan(32);
      expect(token1).to.not.equal(token2);
    });
  });

  describe("hashResetToken and verifyResetToken", () => {
    it("should hash and verify reset tokens", () => {
      const {
        hashResetToken,
        verifyResetToken,
      } = require("../src/passwordReset");
      const token = "test-token-123";
      const hashed = hashResetToken(token);
      expect(hashed).to.be.a("string");
      expect(hashed).to.not.equal(token);
      expect(verifyResetToken(token, hashed)).to.be.true;
      expect(verifyResetToken("wrong-token", hashed)).to.be.false;
    });
  });

  describe("requestPasswordReset", () => {
    it("should generate reset token for existing user", async () => {
      const result = await requestPasswordReset(
        "existing@example.com",
        mockDbAdapter,
        1
      );
      expect(result).to.have.property("token");
      expect(result).to.have.property("expiresAt");
      expect(result).to.have.property("user");
      expect(result.user.email).to.equal("existing@example.com");
    });

    it("should return token even for non-existent user (security)", async () => {
      const result = await requestPasswordReset(
        "nonexistent@example.com",
        mockDbAdapter,
        1
      );
      expect(result).to.have.property("token");
      expect(result).to.have.property("expiresAt");
      // Should not reveal if user exists
    });
  });

  describe("resetPassword", () => {
    it("should reset password with valid token", async () => {
      const { hashResetToken } = require("../src/passwordReset");
      const token = "valid-reset-token";
      const hashedToken = hashResetToken(token);

      // Create a fresh mock adapter for this test
      const testDbAdapter = {
        findByResetToken: async (hashed) => {
          if (hashed === hashedToken) {
            return {
              id: 1,
              email: "user@example.com",
              resetPasswordExpires: new Date(Date.now() + 3600000),
            };
          }
          return null;
        },
        findByField: async (field, value) => {
          if (field === "resetPasswordToken" && value === hashedToken) {
            return {
              id: 1,
              email: "user@example.com",
              resetPasswordExpires: new Date(Date.now() + 3600000),
            };
          }
          return null;
        },
        update: async (id, data) => {
          return { id, ...data };
        },
      };

      const result = await resetPassword(
        token,
        "newPassword123",
        testDbAdapter
      );
      expect(result).to.have.property("user");
      expect(result.user.id).to.equal(1);
    });

    it("should throw ValidationError for missing token", async () => {
      try {
        await resetPassword("", "newPassword123", mockDbAdapter);
        expect.fail("Should have thrown ValidationError");
      } catch (error) {
        expect(error).to.be.instanceOf(ValidationError);
        expect(error.field).to.equal("token");
      }
    });

    it("should throw ValidationError for missing password", async () => {
      try {
        await resetPassword("token", "", mockDbAdapter);
        expect.fail("Should have thrown ValidationError");
      } catch (error) {
        expect(error).to.be.instanceOf(ValidationError);
        expect(error.field).to.equal("password");
      }
    });

    it("should throw TokenError for invalid token", async () => {
      mockDbAdapter.findByResetToken = async () => null;
      try {
        await resetPassword("invalid-token", "newPassword123", mockDbAdapter);
        expect.fail("Should have thrown TokenError");
      } catch (error) {
        expect(error).to.be.instanceOf(TokenError);
      }
    });
  });
});

describe("Token Blacklist", () => {
  describe("TokenBlacklist class", () => {
    let blacklist;

    beforeEach(() => {
      blacklist = new (require("../src/tokenBlacklist").TokenBlacklist)();
    });

    it("should add token to blacklist", () => {
      blacklist.add("token123");
      expect(blacklist.has("token123")).to.be.true;
      expect(blacklist.has("token456")).to.be.false;
    });

    it("should remove token from blacklist", () => {
      blacklist.add("token123");
      blacklist.remove("token123");
      expect(blacklist.has("token123")).to.be.false;
    });

    it("should track size", () => {
      expect(blacklist.size()).to.equal(0);
      blacklist.add("token1");
      blacklist.add("token2");
      expect(blacklist.size()).to.equal(2);
      blacklist.remove("token1");
      expect(blacklist.size()).to.equal(1);
    });

    it("should clear all tokens", () => {
      blacklist.add("token1");
      blacklist.add("token2");
      blacklist.clear();
      expect(blacklist.size()).to.equal(0);
    });
  });

  describe("logout", () => {
    it("should add token to default blacklist", async () => {
      const token = "test-token-123";
      await logout(token);
      const blacklisted = await isBlacklisted(token);
      expect(blacklisted).to.be.true;
    });

    it("should work with custom blacklist adapter", async () => {
      const customBlacklist = {
        tokens: new Set(),
        async add(token) {
          this.tokens.add(token);
        },
        async has(token) {
          return this.tokens.has(token);
        },
        async remove(token) {
          this.tokens.delete(token);
        },
      };

      const token = "test-token-456";
      await logout(token, customBlacklist);
      const blacklisted = await isBlacklisted(token, customBlacklist);
      expect(blacklisted).to.be.true;
    });
  });
});

describe("Error Classes", () => {
  describe("AuthError", () => {
    it("should create AuthError with default code and status", () => {
      const error = new AuthError("Authentication failed");
      expect(error.message).to.equal("Authentication failed");
      expect(error.code).to.equal("AUTH_ERROR");
      expect(error.statusCode).to.equal(401);
      expect(error).to.be.instanceOf(Error);
    });

    it("should create AuthError with custom code and status", () => {
      const error = new AuthError(
        "Invalid credentials",
        "INVALID_CREDENTIALS",
        403
      );
      expect(error.code).to.equal("INVALID_CREDENTIALS");
      expect(error.statusCode).to.equal(403);
    });
  });

  describe("ValidationError", () => {
    it("should create ValidationError with field", () => {
      const error = new ValidationError("Email is required", "email");
      expect(error.message).to.equal("Email is required");
      expect(error.field).to.equal("email");
      expect(error.code).to.equal("VALIDATION_ERROR");
      expect(error.statusCode).to.equal(400);
    });
  });

  describe("TokenError", () => {
    it("should create TokenError", () => {
      const error = new TokenError("Token expired");
      expect(error.message).to.equal("Token expired");
      expect(error.code).to.equal("TOKEN_ERROR");
      expect(error.statusCode).to.equal(403);
    });
  });

  describe("NotFoundError", () => {
    it("should create NotFoundError", () => {
      const error = new NotFoundError("User not found");
      expect(error.message).to.equal("User not found");
      expect(error.code).to.equal("NOT_FOUND");
      expect(error.statusCode).to.equal(404);
    });
  });
});

describe("Configuration", () => {
  describe("getConfig", () => {
    it("should return config with defaults", () => {
      const config = getConfig({ accessTokenSecret: "test-secret" });
      expect(config.accessTokenSecret).to.equal("test-secret");
      expect(config.refreshTokenSecret).to.equal("test-secret");
      expect(config.accessTokenExpiresIn).to.equal("15m");
      expect(config.refreshTokenExpiresIn).to.equal("7d");
      expect(config.passwordResetExpiresInHours).to.equal(1);
      expect(config.passwordMinLength).to.equal(8);
    });

    it("should throw error if secret not provided", () => {
      const originalEnv = process.env.JWT_SECRET;
      delete process.env.JWT_SECRET;
      expect(() => getConfig({})).to.throw("JWT_SECRET");
      if (originalEnv) process.env.JWT_SECRET = originalEnv;
    });

    it("should use environment variables", () => {
      const originalSecret = process.env.JWT_SECRET;
      process.env.JWT_SECRET = "env-secret";
      const config = getConfig();
      expect(config.accessTokenSecret).to.equal("env-secret");
      if (originalSecret) {
        process.env.JWT_SECRET = originalSecret;
      } else {
        delete process.env.JWT_SECRET;
      }
    });
  });
});

describe("Updated Login with Refresh Tokens", () => {
  let mockDbAdapter;
  const secret = "login-secret";

  beforeEach(async () => {
    const hashedPassword = await bcrypt.hash("correctpassword", 10);
    mockDbAdapter = {
      findByEmail: async (email) => {
        if (email === "existing@example.com") {
          return {
            id: 1,
            email: "existing@example.com",
            password: hashedPassword,
          };
        }
        return null;
      },
    };
  });

  it("should return access and refresh tokens when enabled", async () => {
    const result = await loginUser(
      { email: "existing@example.com", password: "correctpassword" },
      mockDbAdapter,
      secret,
      {
        useRefreshTokens: true,
        refreshSecret: secret,
      }
    );

    expect(result).to.have.property("accessToken");
    expect(result).to.have.property("refreshToken");
    expect(result).to.have.property("user");
    expect(result.accessToken).to.be.a("string");
    expect(result.refreshToken).to.be.a("string");
  });

  it("should return single token when refresh tokens disabled", async () => {
    const result = await loginUser(
      { email: "existing@example.com", password: "correctpassword" },
      mockDbAdapter,
      secret
    );

    expect(result).to.have.property("token");
    expect(result).to.have.property("user");
    expect(result.token).to.be.a("string");
  });

  it("should throw AuthError for invalid credentials", async () => {
    try {
      await loginUser(
        { email: "existing@example.com", password: "wrongpassword" },
        mockDbAdapter,
        secret
      );
      expect.fail("Should have thrown AuthError");
    } catch (error) {
      expect(error).to.be.instanceOf(AuthError);
      expect(error.code).to.equal("INVALID_CREDENTIALS");
    }
  });
});

describe("Updated Middleware with Blacklist", () => {
  let req, res, nextMock;
  const middlewareSecret = "middleware-secret";

  beforeEach(() => {
    req = { headers: {}, user: undefined };
    res = {
      status: function (code) {
        this.statusCode = code;
        return this;
      },
      json: function (data) {
        this.body = data;
        return this;
      },
      statusCode: null,
      body: null,
    };
    nextMock = {
      called: false,
      call: function () {
        this.called = true;
      },
    };
    // Reset called flag for each test
    nextMock.called = false;
  });

  it("should reject blacklisted token", async () => {
    const token = signToken({ id: 1 }, middlewareSecret);
    await logout(token); // Blacklist the token

    req.headers.authorization = `Bearer ${token}`;
    const middleware = createAuthMiddleware(middlewareSecret);
    await middleware(req, res, () => nextMock.call());

    expect(nextMock.called).to.be.false;
    expect(res.statusCode).to.equal(401);
    expect(res.body.code).to.equal("TOKEN_REVOKED");
  });

  it("should allow non-blacklisted token", async () => {
    // Create a fresh token that's definitely not blacklisted
    const token = signToken({ id: 999 }, middlewareSecret);
    req.headers.authorization = `Bearer ${token}`;
    req.user = undefined; // Reset user

    const middleware = createAuthMiddleware(middlewareSecret);
    await middleware(req, res, () => nextMock.call());

    expect(nextMock.called).to.be.true;
    expect(req.user).to.exist;
    expect(req.user.id).to.equal(999);
  });
});
