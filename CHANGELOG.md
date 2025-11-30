# Changelog

All notable changes to this project will be documented in this file.

## [1.0.0] - 2024

### Added

#### Core Features
- **Refresh Token System**: Full support for refresh tokens with `generateTokenPair`, `refreshAccessToken`, and related utilities
- **Password Reset**: Complete password reset functionality with secure token generation and validation
- **Token Blacklisting**: Logout functionality with in-memory and custom adapter support (Redis, database, etc.)
- **Custom Error Classes**: `AuthError`, `ValidationError`, `TokenError`, `NotFoundError` with proper error codes and status codes
- **Configuration System**: `getConfig()` function with environment variable support
- **TypeScript Support**: Complete TypeScript type definitions (`index.d.ts`)

#### Enhanced Features
- **Improved Login**: Support for refresh tokens with configurable options
- **Enhanced Middleware**: Token blacklist checking, custom error handlers
- **Better Error Handling**: More descriptive errors with error codes for client handling
- **Environment Variables**: Support for all configuration via environment variables

#### Documentation
- Comprehensive README with examples for Express.js, Next.js
- API reference documentation
- Security best practices guide
- Database adapter interface documentation

#### Testing
- Comprehensive test suite covering all new features
- Tests for refresh tokens, password reset, token blacklist, error classes
- Updated existing tests to work with new error classes

### Changed
- **Breaking**: `loginUser` now throws `AuthError` instead of generic `Error`
- **Breaking**: `registerUser` now throws `ValidationError` instead of generic `Error`
- **Breaking**: `verifyToken` now throws `TokenError` instead of generic `Error`
- **Breaking**: `createAuthMiddleware` is now async and supports blacklist checking
- Improved error messages with error codes

### Security
- Token blacklisting for secure logout
- Secure password reset token generation using crypto
- Timing-safe token comparison
- Better error messages that don't reveal user existence

## [0.1.0] - Initial Release

### Added
- Basic JWT authentication
- User registration with validation
- User login with password hashing
- Express middleware for route protection
- Basic test suite

