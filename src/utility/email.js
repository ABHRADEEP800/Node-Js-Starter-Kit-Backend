import nodemailer from "nodemailer";

let transporter = null;

const initTransporter = async () => {
  if (process.env.SMTP_USER && process.env.SMTP_PASS) {
    transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST || "smtp.ethereal.email",
      port: process.env.SMTP_PORT || 587,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
    });
  } else {
    // Automatically generate ethereal account for local dev testing
    const testAccount = await nodemailer.createTestAccount();
    transporter = nodemailer.createTransport({
      host: "smtp.ethereal.email",
      port: 587,
      secure: false,
      auth: {
        user: testAccount.user,
        pass: testAccount.pass,
      },
    });
  }
};

export const sendEmail = async (to, subject, text, html) => {
  try {
    if (!transporter) await initTransporter();
    
    const info = await transporter.sendMail({
      from: `"Starter Kit" <${process.env.SMTP_USER || "no-reply@starterkit.com"}>`,
      to,
      subject,
      text,
      html,
    });
    console.log("Message sent: %s", info.messageId);
    
    // Automatically log the preview URL for Ethereal!
    if (!process.env.SMTP_USER) {
      console.log("📧 Ethereal Preview URL: %s", nodemailer.getTestMessageUrl(info));
    }
  } catch (error) {
    console.error("Error sending email", error);
  }
};
