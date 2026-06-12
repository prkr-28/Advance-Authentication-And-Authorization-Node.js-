import jwt from 'jsonwebtoken';
import { redisClient } from '../index.js';

export const isAuthenticated = async (req, res, next) => {
    try {
        const token = req.cookies.accessToken;
        if (!token) {
            return res.status(403).json({ message: 'Access denied. No token provided.' });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        if (!decoded) {
            return res.status(400).json({ message: 'Invalid token.' });
        }
        const cashedUser = await redisClient.get(`user:${decoded.id}`);
        if (cashedUser) {
            req.user = JSON.parse(cashedUser);
            return next();
        }
        const user = await User.findById(decoded.id).select('-password');
        if (!user) {
            return res.status(400).json({ message: 'User not found.' });
        }
        await redisClient.set(`user:${user._id}`, JSON.stringify(user), 'EX', 60 * 60);
        req.user = user;
        next();
    } catch (error) {
        return res.status(500).json({ message: error.message });
    }
}