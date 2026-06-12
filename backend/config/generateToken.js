import jwt from 'jsonwebtoken';

export const generateToken = async (user, res) => {
    const accessToken = jwt.sign(
        { userId: user._id, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: '1m' }
    );

    const refreshToken = jwt.sign(
        { userId: user._id, role: user.role },
        process.env.JWT_REFRESH_SECRET,
        { expiresIn: '7d' }
    );

    const refreshTokenKey = `refreshToken:${user._id}`;
    await redisClient.set(refreshTokenKey, refreshToken, 'EX', 7 * 24 * 60 * 60);
    res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000
    });
};