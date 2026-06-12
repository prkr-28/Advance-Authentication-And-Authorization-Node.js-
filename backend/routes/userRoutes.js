import express from 'express';
import { loginUser, registerUser, verifyEmail, verifyOtp } from '../controllers/userControler.js';


const router = express.Router();
router.post('/register', registerUser);
router.post('/verify/:token', verifyEmail)
router.post('/login', loginUser);
router.post('/verify-otp', verifyOtp);

export default router;