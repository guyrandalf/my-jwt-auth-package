const bcrypt = require("bcryptjs");
const Joi = require("joi");
const { ValidationError } = require("./errors");

/**
 * Register a new user with validation and password hashing
 * @param {Object} userData - User data including email and password
 * @param {string} userData.email - User email address
 * @param {string} userData.password - User password (minimum 8 characters)
 * @param {Object} [customSchema={}] - Additional Joi schema fields for validation
 * @param {Object} dbAdapter - Database adapter with create method
 * @param {Function} dbAdapter.create - Method to create user in database
 * @returns {Promise<Object>} Created user object (password will be hashed)
 * @throws {ValidationError} If validation fails
 */
const registerUser = async (userData, customSchema = {}, dbAdapter) => {
  const baseSchema = {
    email: Joi.string().email().required(),
    password: Joi.string().min(8).required(),
  };
  const schema = Joi.object({ ...baseSchema, ...customSchema }).unknown(true);
  const { error } = schema.validate(userData);
  if (error) {
    throw new ValidationError(
      error.details[0].message,
      error.details[0].path[0]
    );
  }

  const hashedPassword = await bcrypt.hash(userData.password, 10);
  const userToSave = { ...userData, password: hashedPassword };
  delete userToSave.passwordConfirm; // If added in custom

  return dbAdapter.create(userToSave); // e.g., Mongoose model or Prisma
};

module.exports = { registerUser };
