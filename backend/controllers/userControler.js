import TryCatch from '../middleware/trycatch.js'
import sanize from 'mongo-sanitize';
import { loginUserSchema, registerUserSchema } from '../config/zod.js';
import { redisClient } from '../index.js';
import User from '../models/userModel.js';
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import { sendMail } from '../config/sendMail.js';
import { getOtpHtml, getVerifyEmailHtml } from '../config/html.js';
import jwt from 'jsonwebtoken';
import { generateToken } from '../config/generateToken.js';

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

export const loginUser = TryCatch(async (req, res) => {
    const sanitizedBody = sanize(req.body);
    const validation = loginUserSchema.safeParse(sanitizedBody);
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
    const { email, password } = validation.data;

    const rateLimitKey = `login-rate-limit:${req.ip}:${email}`;
    if (await redisClient.exists(rateLimitKey)) {
        return res.status(429).json({ message: 'Too many login attempts. Please try again later.' });
    }

    const user = await User.findOne({ email });
    if (!user) {
        return res.status(400).json({ message: 'Invalid email or password' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        return res.status(400).json({ message: 'Invalid email or password' });
    }

    const otp = crypto.randomBytes(4).toString('hex');
    const otpKey = `otp:${email}`;
    await redisClient.set(otpKey, JSON.stringify({ otp }), { EX: 300 });

    const subject = 'Your Login OTP';
    const html = getOtpHtml({ email, otp });

    await sendMail(email, subject, html);

    await redisClient.set(rateLimitKey, 'true', { EX: 60 });

    res.status(200).json({ message: 'OTP sent to your email. Please check your inbox. It will be valid for 5 minutes.' });
});

export const verifyOtp = TryCatch(async (req, res) => {
    const { email, otp } = req.body;
    if (!email || !otp) {
        return res.status(400).json({ message: 'Email and OTP are required' });
    }
    const otpKey = `otp:${email}`;
    const storedOtpData = await redisClient.get(otpKey);
    if (!storedOtpData) {
        return res.status(400).json({ message: 'OTP has expired or is invalid' });
    }
    const { otp: storedOtp } = JSON.parse(storedOtpData);
    if (otp !== storedOtp) {
        return res.status(400).json({ message: 'Invalid OTP' });
    }
    await redisClient.del(otpKey);

    const user = await User.findOne({ email });
    if (!user) {
        return res.status(400).json({ message: 'User not found' });
    }

    const token = generateToken(user, res);

    res.status(200).json({ message: 'Login successful', user, ...token });
});

export const myProfile = TryCatch(async (req, res) => {
    res.status(200).json({ user: req.user });
});