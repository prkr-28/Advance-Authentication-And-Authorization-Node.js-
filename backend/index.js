import express from 'express';
import dotenv from 'dotenv';
import connectDB from './config/db.js';
import userRoutes from './routes/userRoutes.js';
import { createClient } from 'redis';

dotenv.config();
await connectDB();

const redisUrl = process.env.REDIS_URL;

if (!redisUrl) {
    console.error('REDIS_URL is not defined in the environment variables');
    process.exit(1);
}

export const redisClient = createClient({
    url: redisUrl
});

redisClient.connect().then(() => {
    console.log('Connected to Redis successfully');
}).catch((err) => {
    console.error('Failed to connect to Redis:', err);
    process.exit(1);
});

const app = express();
app.use(express.json());
app.use("/api/v1", userRoutes);


app.get('/api', (req, res) => {
    res.json({ message: 'Hello from the backend!' });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});