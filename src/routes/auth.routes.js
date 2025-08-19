import { Router } from "express";
import { registerUser } from "../controllers/auth.controllers.js";
import { validate } from "../middlewares/validators.middlewares.js";
import { userRegisterValidator } from "../validators/index.js";
import { login } from "../controllers/auth.controllers.js";
import { userLoginValidator } from "../validators/index.js";

const router = Router();

router.route("/register").post(userRegisterValidator(), validate, registerUser);
// when register route is called, first userRegisterValidator function is called, then validate middleware is called then controller
// the erros are collected by the userRegisterValidator function and sent to validate middleware which then throws an errors

router.route("/login").post(userLoginValidator(), validate, login);
export default router;
