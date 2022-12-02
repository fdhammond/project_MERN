import express from "express";
const router = express.Router();
import {
  register,
  authenticate,
  confirm,
  forgotPassword,
  checkToken,
  newPassword,
} from "../controllers/userController.js";

// Users creation, register and confirmation
router.post("/", register); //create new user
router.post("/login", authenticate);
router.get("/confirm/:token", confirm);
router.post("/forgot-password", forgotPassword);

router.route("/forgot-password/:token").get(checkToken).post(newPassword);

export default router;
