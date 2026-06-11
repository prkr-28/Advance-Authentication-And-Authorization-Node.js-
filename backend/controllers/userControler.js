import TryCatch from '../middleware/trycatch.js'
import sanize from 'mongo-sanitize';
import { registerUserSchema } from '../config/zod.js';
import { redisClient } from '../index.js';
import User from '../models/userModel.js';
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import { sendMail } from '../config/sendMail.js';
import { getVerifyEmailHtml } from '../config/html.js';


export const registerUser = TryCatch(async (req, res) => {
    const sanitizedBody = sanize(req.body);
    const validation = registerUserSchema.safeParse(sanitizedBody);
    const zodError = validation.error;

    let firstError = "Validation failed";
    let allErrors = [];
    if (zodError?.issues && Array.isArray(zodError.issues)) {
        allErrors = zodError.issues.map(issue => ({
            field: issue.path?.join('.'),
            message: issue.message || 'Invalid value',
            code: issue.code || 'invalid'
        }));

        firstError = allErrors[0]?.message || firstError;
    }

    if (!validation.success) {
        return res.status(400).json({ message: firstError, errors: allErrors });
    }
    const { name, email, password } = validation.data;

    const rateLimitKey = `register-rate-limit:${req.ip}:${email}`;

    if (await redisClient.exists(rateLimitKey)) {
        return res.status(429).json({ message: 'Too many registration attempts. Please try again later.' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
        return res.status(400).json({ message: 'Email is already registered' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const verificationToken = crypto.randomBytes(32).toString('hex');

    const verifyKey = `verify:${verificationToken}`;
    const dataToStore = JSON.stringify({ name, email, password: hashedPassword });
    await redisClient.set(verifyKey, dataToStore, { EX: 300 });

    const subject = 'Verify Your Email';
    const html = getVerifyEmailHtml({ email, token: verificationToken });

    await sendMail(email, subject, html);

    await redisClient.set(rateLimitKey, 'true', { EX: 60 });

    res.status(201).json({
        message: 'If your Email is valid, you will receive a verification link shortly. Please check your inbox. It will be valid for 5 minutes.',
        user: {
            name,
            email,
            password: hashedPassword
        }
    });
});

export const verifyEmail = TryCatch(async (req, res) => {
    const { token } = req.params;
    if (!token) {
        return res.status(400).json({ message: 'Verification token is required' });
    }

    const verifyKey = `verify:${token}`;
    const userData = await redisClient.get(verifyKey);
    if (!userData) {
        return res.status(400).json({ message: 'Invalid or expired verification token' });
    }
    await redisClient.del(verifyKey);

    const userDataObj = JSON.parse(userData);
    const existingUser = await User.findOne({ email: userDataObj.email });
    if (existingUser) {
        return res.status(400).json({ message: 'Email is already registered' });
    }

    const newUser = new User({
        name: userDataObj.name,
        email: userDataObj.email,
        password: userDataObj.password
    });
    await newUser.save();


    res.status(201).json({ message: 'Email verified and user registered successfully', user: { _id: newUser._id, name: newUser.name, email: newUser.email } });
});