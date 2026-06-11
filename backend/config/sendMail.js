import { createTransport } from 'nodemailer';

export const sendMail = async (email, subject, html) => {
    const transport = createTransport({
        host: process.env.EMAIL_HOST,
        port: process.env.EMAIL_PORT,
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS
        },
    });

    await transport.sendMail({
        from: process.env.EMAIL_FROM,
        to: email,
        subject: subject,
        html: html
    });
};