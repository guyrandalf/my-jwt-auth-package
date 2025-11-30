# @guyrandalf/my-jwt-auth

A production-ready, reusable JWT authentication module for Node.js with support for refresh tokens, password reset, token blacklisting, and more.

## Features

- ✅ User registration with customizable validation
- ✅ User login with password hashing (bcrypt)
- ✅ JWT token generation and verification
- ✅ Refresh token support
- ✅ Password reset functionality
- ✅ Token blacklisting (logout)
- ✅ Express middleware for route protection
- ✅ Custom error classes
- ✅ TypeScript support
- ✅ Environment variable configuration
- ✅ Database-agnostic (adapter pattern)

## Installation

```bash
npm install @guyrandalf/my-jwt-auth
```

Or from GitHub:

```bash
npm install git+https://github.com/guyrandalf/my-jwt-auth-package.git
```

## Quick Start

### Basic Setup

```javascript
const {
  registerUser,
  loginUser,
  createAuthMiddleware,
  getConfig,
} = require("@guyrandalf/my-jwt-auth");

// Get configuration (supports environment variables)
const config = getConfig({
  accessTokenSecret: process.env.JWT_SECRET, // Required
});

// Database adapter (example with Mongoose)
const dbAdapter = {
  async create(userData) {
    return await User.create(userData);
  },
  async findByEmail(email) {
    return await User.findOne({ email });
  },
  async update(id, data) {
    return await User.findByIdAndUpdate(id, data, { new: true });
  },
};

// Register a user
const user = await registerUser(
  {
    email: "user@example.com",
    password: "password123",
  },
  {}, // Custom schema (optional)
  dbAdapter
);

// Login
const result = await loginUser(
  {
    email: "user@example.com",
    password: "password123",
  },
  dbAdapter,
  config.accessTokenSecret
);

// Protected route middleware
const authMiddleware = createAuthMiddleware(config.accessTokenSecret);
app.get("/protected", authMiddleware, (req, res) => {
  res.json({ user: req.user });
});
```

## Environment Variables

```bash
JWT_SECRET=your-secret-key                    # Required: Access token secret
JWT_ACCESS_SECRET=your-access-secret         # Optional: Override access token secret
JWT_REFRESH_SECRET=your-refresh-secret       # Optional: Refresh token secret
JWT_ACCESS_EXPIRES_IN=15m                    # Optional: Access token expiration (default: 15m)
JWT_REFRESH_EXPIRES_IN=7d                    # Optional: Refresh token expiration (default: 7d)
PASSWORD_RESET_EXPIRES_IN_HOURS=1            # Optional: Password reset expiration (default: 1)
PASSWORD_MIN_LENGTH=8                        # Optional: Minimum password length (default: 8)
BCRYPT_ROUNDS=10                             # Optional: Bcrypt rounds (default: 10)
USE_REFRESH_TOKENS=true                      # Optional: Enable refresh tokens (default: false)
```

## API Reference

### Core Functions

#### `registerUser(userData, customSchema, dbAdapter)`

Register a new user with validation and password hashing.

**Parameters:**

- `userData` (object): User data including email and password
- `customSchema` (object, optional): Additional Joi schema fields
- `dbAdapter` (object): Database adapter with `create` method

**Returns:** Promise resolving to created user

**Example:**

```javascript
const Joi = require("joi");

const user = await registerUser(
  {
    email: "user@example.com",
    password: "password123",
    name: "John Doe",
    age: 25,
  },
  {
    name: Joi.string().min(2).required(),
    age: Joi.number().min(18).required(),
  },
  dbAdapter
);
```

#### `loginUser(credentials, dbAdapter, secret, options)`

Authenticate a user and generate tokens.

**Parameters:**

- `credentials` (object): `{ email, password }`
- `dbAdapter` (object): Database adapter with `findByEmail` method
- `secret` (string): JWT secret key
- `options` (object, optional): Login options

**Returns:** Promise resolving to `{ token, user }` or `{ accessToken, refreshToken, user }`

**Example with refresh tokens:**

```javascript
const result = await loginUser(
  { email: "user@example.com", password: "password123" },
  dbAdapter,
  config.accessTokenSecret,
  {
    useRefreshTokens: true,
    refreshSecret: config.refreshTokenSecret,
    accessTokenOptions: { expiresIn: "15m" },
    refreshTokenOptions: { expiresIn: "7d" },
  }
);
```

#### `createAuthMiddleware(secret, options)`

Create Express middleware for protecting routes.

**Parameters:**

- `secret` (string): JWT secret key
- `options` (object, optional): Middleware options

**Returns:** Express middleware function

**Example:**

```javascript
const authMiddleware = createAuthMiddleware(secret, {
  blacklistAdapter: redisBlacklist, // Optional: Custom blacklist adapter
  errorHandler: (req, res, error) => {
    // Custom error handling
    res.status(error.statusCode).json({ error: error.message });
  },
});

app.get("/protected", authMiddleware, (req, res) => {
  res.json({ user: req.user });
});
```

### Refresh Tokens

#### `generateTokenPair(payload, accessSecret, refreshSecret, accessOptions, refreshOptions)`

Generate both access and refresh tokens.

```javascript
const { generateTokenPair } = require("@guyrandalf/my-jwt-auth");

const tokens = generateTokenPair(
  { id: user.id, email: user.email },
  accessSecret,
  refreshSecret,
  { expiresIn: "15m" },
  { expiresIn: "7d" }
);
```

#### `refreshAccessToken(refreshToken, refreshSecret, accessSecret, accessOptions)`

Refresh an access token using a refresh token.

```javascript
const { refreshAccessToken } = require("@guyrandalf/my-jwt-auth");

const result = await refreshAccessToken(
  refreshToken,
  refreshSecret,
  accessSecret,
  { expiresIn: "15m" }
);
// Returns: { accessToken, user }
```

### Password Reset

#### `requestPasswordReset(email, dbAdapter, expiresInHours)`

Request a password reset token.

```javascript
const { requestPasswordReset } = require("@guyrandalf/my-jwt-auth");

const result = await requestPasswordReset(
  "user@example.com",
  dbAdapter,
  1 // expires in 1 hour
);
// Returns: { token, expiresAt, user }
// Send 'token' to user via email
```

#### `resetPassword(token, newPassword, dbAdapter, passwordSchema)`

Reset password using reset token.

```javascript
const { resetPassword } = require("@guyrandalf/my-jwt-auth");
const Joi = require("joi");

const result = await resetPassword(
  resetTokenFromEmail,
  "newPassword123",
  dbAdapter,
  Joi.string().min(8).required() // Optional password validation
);
```

### Token Blacklist (Logout)

#### `logout(token, blacklistAdapter, expiresInMs)`

Add a token to the blacklist (logout).

```javascript
const { logout, tokenBlacklist } = require("@guyrandalf/my-jwt-auth");

// Using in-memory blacklist (default)
await logout(token, null, 15 * 60 * 1000); // Expires in 15 minutes

// Using custom adapter (Redis, database, etc.)
await logout(token, redisBlacklistAdapter, expiresInMs);
```

#### `isBlacklisted(token, blacklistAdapter)`

Check if a token is blacklisted.

```javascript
const { isBlacklisted } = require("@guyrandalf/my-jwt-auth");

const blacklisted = await isBlacklisted(token, blacklistAdapter);
```

### Error Classes

The package exports custom error classes:

- `AuthError`: Authentication errors (401)
- `ValidationError`: Validation errors (400)
- `TokenError`: Token-related errors (403)
- `NotFoundError`: Resource not found (404)

**Example:**

```javascript
const { AuthError, ValidationError } = require("@guyrandalf/my-jwt-auth");

try {
  await loginUser(credentials, dbAdapter, secret);
} catch (error) {
  if (error instanceof AuthError) {
    res.status(error.statusCode).json({
      error: error.message,
      code: error.code,
    });
  }
}
```

## Database Adapter Interface

Your database adapter must implement these methods:

```javascript
const dbAdapter = {
  // Required
  async create(userData) {
    // Create and return user
  },

  async findByEmail(email) {
    // Find user by email, return null if not found
  },

  async update(id, data) {
    // Update user and return updated user
  },

  // Optional (for password reset)
  async findByResetToken(token) {
    // Find user by reset token
  },

  async findByField(field, value) {
    // Generic find by field
  },
};
```

## Examples

### Express.js Example

```javascript
const express = require("express");
const {
  registerUser,
  loginUser,
  createAuthMiddleware,
  getConfig,
} = require("@guyrandalf/my-jwt-auth");

const app = express();
app.use(express.json());

const config = getConfig();
const authMiddleware = createAuthMiddleware(config.accessTokenSecret);

// Register
app.post("/register", async (req, res) => {
  try {
    const user = await registerUser(req.body, {}, dbAdapter);
    res.status(201).json({ user });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Login
app.post("/login", async (req, res) => {
  try {
    const result = await loginUser(
      req.body,
      dbAdapter,
      config.accessTokenSecret,
      { useRefreshTokens: true, refreshSecret: config.refreshTokenSecret }
    );
    res.json(result);
  } catch (error) {
    res.status(error.statusCode || 401).json({ error: error.message });
  }
});

// Protected route
app.get("/profile", authMiddleware, (req, res) => {
  res.json({ user: req.user });
});
```

### Next.js API Route Example

```javascript
// pages/api/auth/login.js
import { loginUser, getConfig } from "@guyrandalf/my-jwt-auth";

const config = getConfig();

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  try {
    const result = await loginUser(
      req.body,
      dbAdapter,
      config.accessTokenSecret
    );
    res.json(result);
  } catch (error) {
    res.status(error.statusCode || 401).json({ error: error.message });
  }
}
```

### Custom Blacklist Adapter (Redis)

```javascript
const redis = require("redis");
const { BlacklistAdapter } = require("@guyrandalf/my-jwt-auth");

class RedisBlacklistAdapter extends BlacklistAdapter {
  constructor(redisClient) {
    super();
    this.client = redisClient;
  }

  async add(token, expiresInMs) {
    if (expiresInMs) {
      await this.client.setex(
        `blacklist:${token}`,
        Math.floor(expiresInMs / 1000),
        "1"
      );
    } else {
      await this.client.set(`blacklist:${token}`, "1");
    }
  }

  async has(token) {
    const result = await this.client.get(`blacklist:${token}`);
    return result !== null;
  }

  async remove(token) {
    await this.client.del(`blacklist:${token}`);
  }
}

const redisClient = redis.createClient();
const redisBlacklist = new RedisBlacklistAdapter(redisClient);

const authMiddleware = createAuthMiddleware(secret, {
  blacklistAdapter: redisBlacklist,
});
```

## TypeScript Support

TypeScript definitions are included. Import types as needed:

```typescript
import {
  DatabaseAdapter,
  LoginOptions,
  MiddlewareOptions,
  AuthError,
} from "@guyrandalf/my-jwt-auth";

const dbAdapter: DatabaseAdapter = {
  async create(userData) {
    // ...
  },
  // ...
};
```

## Security Best Practices

1. **Always use HTTPS** in production
2. **Use strong secrets** (at least 32 characters, random)
3. **Set appropriate token expiration times** (short for access tokens, longer for refresh tokens)
4. **Implement rate limiting** on login/register endpoints
5. **Use token blacklisting** for logout functionality
6. **Store refresh tokens securely** (httpOnly cookies recommended)
7. **Validate and sanitize all inputs**
8. **Use environment variables** for secrets (never commit secrets)

## License

MIT

## Author

Randalf Ehigiator
