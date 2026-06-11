import express from 'express';
import { registerUser, verifyEmail } from '../controllers/userControler.js';


const router = express.Router();
router.post('/register', registerUser);
router.post('/verify/:token', verifyEmail)

export default router;