import { validationResult } from "express-validator";
import { ApiError } from "../utils/api-error.js";

export const validate = (req, res, next) => {
  // middleware function
  const errors = validationResult(req);
  if (errors.isEmpty()) {
    return next();
  }
  const extractedErrors = [];
  errors.array().map((error) =>
    extractedErrors.push({
      [error.path]: error.msg,
    }),
  );
  return res.status(400).json({
    status: "fail",
    message: "Validation Error",
    errors: extractedErrors,
  });
};
