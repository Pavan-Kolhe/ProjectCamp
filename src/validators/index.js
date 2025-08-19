import { body } from "express-validator";

const userRegisterValidator = () => {
  return [
    body("username")
      .trim()
      .notEmpty()
      .withMessage("username is required")
      .isLowercase()
      .withMessage("username must be lowercase")
      .isLength({ min: 3 })
      .withMessage("username must be at least 3 characters long"),
    body("email")
      .trim()
      .notEmpty()
      .withMessage("email is required")
      .isEmail()
      .withMessage("email is Invalid"),
    body("password")
      .trim()
      .notEmpty()
      .withMessage("password is required")
      .isLength({ min: 8 })
      .withMessage("password must be at least 8 characters long")
      .matches(
        /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,
      )
      .withMessage(
        "password must contain at least one uppercase letter, one lowercase letter, one number, and one special character",
      ),
    body("fullName")
      .optional()
      .trim()
      .notEmpty()
      .withMessage("fullName is required")
      .isLength({ min: 3 })
      .withMessage("fullName must be at least 3 characters long"),
  ];
};

const userLoginValidator = () => {
  return [
    body("indentifier").custom((value, { req }) => {
      if (!req.body.email && !req.body.username) {
        throw new Error("Either email or username is required");
      }
      return true;
    }),

    body("email").optional().isEmail().withMessage("Invalid email format"),

    // If username is provided, validate rules
    body("username")
      .optional()
      .isLowercase()
      .withMessage("Username must be lowercase")
      .isLength({ min: 3 })
      .withMessage("Username must be at least 3 characters long"),

    // Password required
    body("password").trim().notEmpty().withMessage("Password is required"),
  ];
};

export { userRegisterValidator, userLoginValidator };
