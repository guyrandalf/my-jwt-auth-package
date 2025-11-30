const chai = require("chai");
const { signToken, verifyToken } = require("../src/utils");
const { registerUser } = require("../src/register");
const { loginUser } = require("../src/login");
const { createAuthMiddleware } = require("../src/middleware");
const { describe, it, beforeEach } = require("mocha");
const bcrypt = require("bcryptjs");

const { expect } = chai;
const secret = "test-secret-key-for-jwt";

describe("JWT Utils", () => {
  describe("signToken", () => {
    it("should sign a token with default options", () => {
      const payload = { id: 1, email: "test@example.com" };
      const token = signToken(payload, secret);
      expect(token).to.be.a("string");
      expect(token.split(".")).to.have.lengthOf(3); // JWT has 3 parts
    });

    it("should sign a token with custom options", () => {
      const payload = { id: 2 };
      const token = signToken(payload, secret, { expiresIn: "2h" });
      expect(token).to.be.a("string");
    });
  });

  describe("verifyToken", () => {
    it("should verify and decode a valid token", () => {
      const payload = { id: 1, email: "test@example.com" };
      const token = signToken(payload, secret);
      const decoded = verifyToken(token, secret);
      expect(decoded.id).to.equal(1);
      expect(decoded.email).to.equal("test@example.com");
      expect(decoded.iat).to.exist; // issued at
      expect(decoded.exp).to.exist; // expiration
    });

    it("should throw TokenError for invalid token", () => {
      const { TokenError } = require("../src/errors");
      expect(() => verifyToken("invalid.token.here", secret)).to.throw(
        TokenError
      );
    });

    it("should throw TokenError for token signed with different secret", () => {
      const { TokenError } = require("../src/errors");
      const token = signToken({ id: 1 }, "different-secret");
      expect(() => verifyToken(token, secret)).to.throw(TokenError);
    });
  });
});

describe("registerUser", () => {
  let mockDbAdapter;

  beforeEach(() => {
    mockDbAdapter = {
      create: async (userData) => {
        return { id: 1, ...userData };
      },
    };
  });

  it("should register a user with valid data", async () => {
    const userData = {
      email: "test@example.com",
      password: "password123",
    };

    const result = await registerUser(userData, {}, mockDbAdapter);

    expect(result).to.have.property("id");
    expect(result).to.have.property("email", "test@example.com");
    expect(result.password).to.not.equal("password123"); // Should be hashed
    expect(result.password).to.be.a("string");
    // Verify password was hashed
    const isHashed = await bcrypt.compare("password123", result.password);
    expect(isHashed).to.be.true;
  });

  it("should register a user with custom schema fields", async () => {
    const Joi = require("joi");
    const customSchema = {
      name: Joi.string().min(2).required(),
      age: Joi.number().min(18).required(),
    };

    const userData = {
      email: "test@example.com",
      password: "password123",
      name: "John Doe",
      age: 25,
    };

    const result = await registerUser(userData, customSchema, mockDbAdapter);

    expect(result.name).to.equal("John Doe");
    expect(result.age).to.equal(25);
    expect(result.email).to.equal("test@example.com");
  });

  it("should throw ValidationError for invalid email", async () => {
    const { ValidationError } = require("../src/errors");
    const userData = {
      email: "invalid-email",
      password: "password123",
    };

    try {
      await registerUser(userData, {}, mockDbAdapter);
      expect.fail("Should have thrown ValidationError");
    } catch (error) {
      expect(error).to.be.instanceOf(ValidationError);
      expect(error.message).to.include("email");
    }
  });

  it("should throw ValidationError for password too short", async () => {
    const { ValidationError } = require("../src/errors");
    const userData = {
      email: "test@example.com",
      password: "short",
    };

    try {
      await registerUser(userData, {}, mockDbAdapter);
      expect.fail("Should have thrown ValidationError");
    } catch (error) {
      expect(error).to.be.instanceOf(ValidationError);
      expect(error.message).to.include("password");
    }
  });

  it("should throw ValidationError for missing required fields", async () => {
    const { ValidationError } = require("../src/errors");
    const userData = {
      email: "test@example.com",
      // missing password
    };

    try {
      await registerUser(userData, {}, mockDbAdapter);
      expect.fail("Should have thrown ValidationError");
    } catch (error) {
      expect(error).to.be.instanceOf(ValidationError);
      expect(error.message).to.include("password");
    }
  });

  it("should remove passwordConfirm from userToSave", async () => {
    const Joi = require("joi");
    const customSchema = {
      passwordConfirm: Joi.string().valid(Joi.ref("password")).required(),
    };

    const userData = {
      email: "test@example.com",
      password: "password123",
      passwordConfirm: "password123",
    };

    const result = await registerUser(userData, customSchema, mockDbAdapter);

    expect(result.passwordConfirm).to.be.undefined;
    expect(result.password).to.exist;
  });

  it("should handle database adapter errors", async () => {
    const errorDbAdapter = {
      create: async () => {
        throw new Error("Database connection failed");
      },
    };

    const userData = {
      email: "test@example.com",
      password: "password123",
    };

    try {
      await registerUser(userData, {}, errorDbAdapter);
      expect.fail("Should have thrown an error");
    } catch (error) {
      expect(error.message).to.equal("Database connection failed");
    }
  });
});

describe("loginUser", () => {
  let mockDbAdapter;
  const testSecret = "login-secret-key";

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

  it("should login user with valid credentials", async () => {
    const credentials = {
      email: "existing@example.com",
      password: "correctpassword",
    };

    const result = await loginUser(credentials, mockDbAdapter, testSecret);

    expect(result).to.have.property("token");
    expect(result).to.have.property("user");
    expect(result.user.id).to.equal(1);
    expect(result.user.email).to.equal("existing@example.com");
    expect(result.token).to.be.a("string");

    // Verify token is valid
    const decoded = verifyToken(result.token, testSecret);
    expect(decoded.id).to.equal(1);
    expect(decoded.email).to.equal("existing@example.com");
  });

  it("should throw AuthError when user not found", async () => {
    const { AuthError } = require("../src/errors");
    const credentials = {
      email: "nonexistent@example.com",
      password: "anypassword",
    };

    try {
      await loginUser(credentials, mockDbAdapter, testSecret);
      expect.fail("Should have thrown AuthError");
    } catch (error) {
      expect(error).to.be.instanceOf(AuthError);
      expect(error.code).to.equal("INVALID_CREDENTIALS");
    }
  });

  it("should throw AuthError for invalid password", async () => {
    const { AuthError } = require("../src/errors");
    const credentials = {
      email: "existing@example.com",
      password: "wrongpassword",
    };

    try {
      await loginUser(credentials, mockDbAdapter, testSecret);
      expect.fail("Should have thrown AuthError");
    } catch (error) {
      expect(error).to.be.instanceOf(AuthError);
      expect(error.code).to.equal("INVALID_CREDENTIALS");
    }
  });

  it("should return user without password in response", async () => {
    const credentials = {
      email: "existing@example.com",
      password: "correctpassword",
    };

    const result = await loginUser(credentials, mockDbAdapter, testSecret);

    expect(result.user).to.not.have.property("password");
    expect(result.user).to.have.property("id");
    expect(result.user).to.have.property("email");
  });
});

describe("createAuthMiddleware", () => {
  let req, res, nextMock;
  const middlewareSecret = "middleware-secret-key";

  beforeEach(() => {
    req = {
      headers: {},
    };
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

  it("should call next() for valid token", async () => {
    const payload = { id: 1, email: "test@example.com" };
    const token = signToken(payload, middlewareSecret);
    req.headers.authorization = `Bearer ${token}`;

    const middleware = createAuthMiddleware(middlewareSecret);
    await middleware(req, res, () => nextMock.call());

    expect(nextMock.called).to.be.true;
    expect(req.user).to.exist;
    expect(req.user.id).to.equal(1);
    expect(req.user.email).to.equal("test@example.com");
    expect(res.statusCode).to.be.null;
  });

  it("should return 401 for missing authorization header", async () => {
    req.headers.authorization = undefined;

    const middleware = createAuthMiddleware(middlewareSecret);
    await middleware(req, res, () => nextMock.call());

    expect(nextMock.called).to.be.false;
    expect(res.statusCode).to.equal(401);
    expect(res.body).to.deep.equal({
      error: "Unauthorized",
      code: "MISSING_TOKEN",
    });
    expect(req.user).to.be.undefined;
  });

  it("should return 401 for authorization header without Bearer prefix", async () => {
    req.headers.authorization = "Token some-token";

    const middleware = createAuthMiddleware(middlewareSecret);
    await middleware(req, res, () => nextMock.call());

    expect(nextMock.called).to.be.false;
    expect(res.statusCode).to.equal(401);
    expect(res.body).to.deep.equal({
      error: "Unauthorized",
      code: "MISSING_TOKEN",
    });
  });

  it("should return 401 for empty authorization header", async () => {
    req.headers.authorization = "";

    const middleware = createAuthMiddleware(middlewareSecret);
    await middleware(req, res, () => nextMock.call());

    expect(nextMock.called).to.be.false;
    expect(res.statusCode).to.equal(401);
  });

  it("should return 403 for invalid token", async () => {
    req.headers.authorization = "Bearer invalid.token.here";

    const middleware = createAuthMiddleware(middlewareSecret);
    await middleware(req, res, () => nextMock.call());

    expect(nextMock.called).to.be.false;
    expect(res.statusCode).to.equal(403);
    expect(res.body).to.have.property("error");
    expect(res.body).to.have.property("code");
    expect(req.user).to.be.undefined;
  });

  it("should return 403 for token signed with different secret", async () => {
    const token = signToken({ id: 1 }, "different-secret");
    req.headers.authorization = `Bearer ${token}`;

    const middleware = createAuthMiddleware(middlewareSecret);
    await middleware(req, res, () => nextMock.call());

    expect(nextMock.called).to.be.false;
    expect(res.statusCode).to.equal(403);
    expect(res.body).to.have.property("error");
    expect(res.body).to.have.property("code");
  });

  it("should return 403 for expired token", async () => {
    // Create an expired token by setting exp to past time
    const jwt = require("jsonwebtoken");
    const payload = { id: 1, exp: Math.floor(Date.now() / 1000) - 3600 }; // Expired 1 hour ago
    const token = jwt.sign(payload, middlewareSecret);

    req.headers.authorization = `Bearer ${token}`;

    const middleware = createAuthMiddleware(middlewareSecret);
    await middleware(req, res, () => nextMock.call());

    expect(nextMock.called).to.be.false;
    expect(res.statusCode).to.equal(401); // Expired tokens return 401, not 403
    expect(res.body).to.have.property("error");
    expect(res.body).to.have.property("code");
  });

  it("should extract token correctly from Bearer header", async () => {
    const payload = { id: 2, email: "user@example.com" };
    const token = signToken(payload, middlewareSecret);
    req.headers.authorization = `Bearer ${token}`;

    const middleware = createAuthMiddleware(middlewareSecret);
    await middleware(req, res, () => nextMock.call());

    expect(req.user.id).to.equal(2);
    expect(req.user.email).to.equal("user@example.com");
  });
});
