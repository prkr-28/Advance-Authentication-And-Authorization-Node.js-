import express from 'express';
import { loginUser, myProfile, registerUser, verifyEmail, verifyOtp } from '../controllers/userControler.js';
import { isAuthenticated } from '../middleware/isAuth.js';


const router = express.Router();
router.post('/register', registerUser);
router.post('/verify/:token', verifyEmail)
router.post('/login', loginUser);
router.post('/verify-otp', verifyOtp);
router.get('/profile', isAuthenticated, myProfile);

export default router;