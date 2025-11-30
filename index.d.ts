/**
 * TypeScript definitions for @guyrandalf/my-jwt-auth
 */

export interface DatabaseAdapter {
  create(userData: any): Promise<any>;
  findByEmail(email: string): Promise<any | null>;
  update(id: any, data: any): Promise<any>;
  findByResetToken?(token: string): Promise<any | null>;
  findByField?(field: string, value: any): Promise<any | null>;
}

export interface BlacklistAdapter {
  add(token: string, expiresInMs?: number | null): Promise<void>;
  has(token: string): Promise<boolean>;
  remove(token: string): Promise<void>;
}

export interface TokenOptions {
  expiresIn?: string | number;
  [key: string]: any;
}

export interface LoginOptions {
  useRefreshTokens?: boolean;
  refreshSecret?: string | null;
  accessTokenOptions?: TokenOptions;
  refreshTokenOptions?: TokenOptions;
}

export interface MiddlewareOptions {
  blacklistAdapter?: BlacklistAdapter | null;
  errorHandler?: (req: any, res: any, error: TokenError) => void;
}

export interface ConfigOptions {
  accessTokenSecret?: string;
  refreshTokenSecret?: string;
  accessTokenExpiresIn?: string;
  refreshTokenExpiresIn?: string;
  passwordResetExpiresInHours?: number;
  passwordMinLength?: number;
  bcryptRounds?: number;
  useRefreshTokens?: boolean;
}

export interface Config {
  accessTokenSecret: string;
  refreshTokenSecret: string;
  accessTokenExpiresIn: string;
  refreshTokenExpiresIn: string;
  passwordResetExpiresInHours: number;
  passwordMinLength: number;
  bcryptRounds: number;
  useRefreshTokens: boolean;
}

export class AuthError extends Error {
  code: string;
  statusCode: number;
  constructor(message: string, code?: string, statusCode?: number);
}

export class ValidationError extends Error {
  code: string;
  field: string | null;
  statusCode: number;
  constructor(message: string, field?: string | null);
}

export class TokenError extends Error {
  code: string;
  statusCode: number;
  constructor(message: string, code?: string, statusCode?: number);
}

export class NotFoundError extends Error {
  code: string;
  statusCode: number;
  constructor(message?: string);
}

export class TokenBlacklist {
  add(token: string, expiresInMs?: number | null): void;
  has(token: string): boolean;
  remove(token: string): void;
  clearExpired(): void;
  clear(): void;
  size(): number;
}

export class BlacklistAdapter {
  add(token: string, expiresInMs?: number | null): Promise<void>;
  has(token: string): Promise<boolean>;
  remove(token: string): Promise<void>;
}

// Core JWT utilities
export function signToken(
  payload: object,
  secret: string,
  options?: TokenOptions
): string;

export function verifyToken(token: string, secret: string): any;

// Authentication
export function registerUser(
  userData: any,
  customSchema?: object,
  dbAdapter?: DatabaseAdapter
): Promise<any>;

export function loginUser(
  credentials: { email: string; password: string },
  dbAdapter: DatabaseAdapter,
  secret: string,
  options?: LoginOptions
): Promise<{
  token?: string;
  accessToken?: string;
  refreshToken?: string;
  user: { id: any; email: string };
}>;

// Middleware
export function createAuthMiddleware(
  secret: string,
  options?: MiddlewareOptions
): (req: any, res: any, next: () => void) => Promise<void>;

// Refresh tokens
export function generateRefreshToken(
  payload: object,
  secret: string,
  options?: TokenOptions
): string;

export function verifyRefreshToken(token: string, secret: string): any;

export function generateTokenPair(
  payload: object,
  accessSecret: string,
  refreshSecret: string,
  accessOptions?: TokenOptions,
  refreshOptions?: TokenOptions
): {
  accessToken: string;
  refreshToken: string;
};

export function refreshAccessToken(
  refreshToken: string,
  refreshSecret: string,
  accessSecret: string,
  accessOptions?: TokenOptions
): {
  accessToken: string;
  user: any;
};

// Password reset
export function generateResetToken(): string;

export function hashResetToken(token: string): string;

export function verifyResetToken(token: string, hashedToken: string): boolean;

export function requestPasswordReset(
  email: string,
  dbAdapter: DatabaseAdapter,
  expiresInHours?: number
): Promise<{
  token: string;
  expiresAt: Date;
  user?: { id: any; email: string };
  message?: string;
}>;

export function resetPassword(
  token: string,
  newPassword: string,
  dbAdapter: DatabaseAdapter,
  passwordSchema?: any
): Promise<{
  user: { id: any; email: string };
}>;

// Token blacklist
export const tokenBlacklist: TokenBlacklist;

export function logout(
  token: string,
  blacklistAdapter?: BlacklistAdapter | null,
  expiresInMs?: number | null
): Promise<void>;

export function isBlacklisted(
  token: string,
  blacklistAdapter?: BlacklistAdapter | null
): Promise<boolean>;

// Configuration
export function getConfig(options?: ConfigOptions): Config;

