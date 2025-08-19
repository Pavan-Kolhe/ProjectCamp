import { Router } from "express";
import {
  resendEmailVerification,
  resetForgotPassword,
  changeCurrentPassword,
  forgotPasswordRequest,
  getCurrentUser,
  refreshAccessToken,
  registerUser,
  verifyEmail,
} from "../controllers/auth.controllers.js";
import { validate } from "../middlewares/validators.middlewares.js";
import {
  userForgotPasswordValidator,
  userChangeCurrentPasswordValidator,
  userRegisterValidator,
  userResetForgotPasswordValidator,
  userLoginValidator,
} from "../validators/index.js";
import { loginUser, logoutUser } from "../controllers/auth.controllers.js";

import { verifyJWT } from "../middlewares/auth.middlewares.js";

const router = Router();

// public routes unsecured
router.route("/register").post(userRegisterValidator(), validate, registerUser);
// when register route is called, first userRegisterValidator function is called, then validate middleware is called then controller
// the erros are collected by the userRegisterValidator function and sent to validate middleware which then throws an errors

router.route("/login").post(userLoginValidator(), validate, loginUser);
router.route("/verify-email/:verificationToken").post(verifyEmail);
router.route("/refresh-token").post(refreshAccessToken);
router
  .route("/forgot-password")
  .post(userForgotPasswordValidator(), validate, forgotPasswordRequest);

router
  .route("/reset-password/:resetToken")
  .post(userResetForgotPasswordValidator(), validate, resetForgotPassword);

// secure routes
router.route("/logout").post(verifyJWT, logoutUser); //middleaew we dont execute we just pass the ref of it in routes
router.route("/current-user").get(verifyJWT, getCurrentUser);
router
  .route("/change-password")
  .post(
    verifyJWT,
    userChangeCurrentPasswordValidator(),
    validate,
    changeCurrentPassword,
  );

router
  .route("/resend-email-verification")
  .post(verifyJWT, resendEmailVerification);
export default router;
