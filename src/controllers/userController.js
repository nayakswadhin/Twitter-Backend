import crypto from 'crypto';
import nodemailer from 'nodemailer';
import { ObjectId } from 'mongodb';
import requestIp from 'request-ip';
import axios from 'axios'; // Add axios import for geolocation

// Improved geolocation function with better error handling
async function fetchGeolocation(ip) {
  try {
    // Skip geolocation for localhost/development
    if (ip === '127.0.0.1' || ip === '::1') {
      return { latitude: '0', longitude: '0' };
    }

    const response = await axios.get(`https://ipinfo.io/117.99.42.186?token=a293b4fa2f2e78`);
    const { loc } = response.data;
    
    if (!loc) {
      console.warn('No location data received from ipinfo.io');
      return { latitude: '0', longitude: '0' };
    }

    const [latitude, longitude] = loc.split(',');
    return { latitude, longitude };
  } catch (error) {
    console.error('Geolocation fetch error:', error);
    return { latitude: '0', longitude: '0' }; // Return default values instead of null
  }
}

// Rest of the helper functions remain the same
function generateOTP() {
  return crypto.randomInt(100000, 999999).toString();
}

function getOTPExpiry() {
  const expiry = new Date();
  expiry.setMinutes(expiry.getMinutes() + 10);
  return expiry;
}

async function sendOTPEmail(userEmail, otp) {
  try {
    const transporter = nodemailer.createTransport({
      host: 'smtp.gmail.com',
      port: 465,
      secure: true,
      auth: {
        user: "mangarajanmol666@gmail.com",
        pass: "dcud kflh ldbw kpua",
      },
      tls: {
        rejectUnauthorized: true
      }
    });

    await transporter.verify();

    const mailOptions = {
      from: {
        name: 'Twitter Backend',
        address: 'mangarajanmol666@gmail.com'
      },
      to: userEmail,
      subject: "Your OTP Code",
      text: `Your OTP code is ${otp}. It is valid for 10 minutes.`,
      html: `
        <div style="font-family: Arial, sans-serif; padding: 20px; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #1da1f2;">Your OTP Verification Code</h2>
          <p>Hello,</p>
          <p>Your OTP code is: <strong style="font-size: 24px; color: #1da1f2;">${otp}</strong></p>
          <p>This code will expire in 10 minutes.</p>
          <p style="color: #666; font-size: 12px;">If you didn't request this code, please ignore this email.</p>
        </div>
      `
    };

    const info = await transporter.sendMail(mailOptions);
    console.log('Email sent successfully:', info.messageId);
    return true;

  } catch (error) {
    console.error('Email sending error:', error);
    throw new Error(`Failed to send OTP email: ${error.message}`);
  }
}


// Create User Function with enhanced error handling
export async function createUser(req, res) {
  try {
    const db = req.app.get("db");
    const { name, email, dateOfBirth, password } = req.body;

    if (!name?.trim() || !email?.trim() || !password || !dateOfBirth) {
      return res.status(400).json({ message: "All fields are required!" });
    }

    // Basic email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ message: "Invalid email format" });
    }

    const existingUser = await db.collection("user").findOne({ 
      email: email.toLowerCase().trim() 
    });

    if (existingUser) {
      return res.status(400).json({ message: "Email Id already exists." });
    }

    // Get user's IP and geolocation
    const userIP = requestIp.getClientIp(req);
    const geoLocation = await fetchGeolocation(userIP);
    
    console.log(`User IP: ${userIP}, Location: ${JSON.stringify(geoLocation)}`);

    // Generate OTP for email verification
    const otp = generateOTP();
    const otpExpiry = getOTPExpiry();

    // Create unverified user
    const newUser = await db.collection("user").insertOne({
      name: name.trim(),
      email: email.toLowerCase().trim(),
      dateOfBirth,
      password, // Note: In production, you should hash the password
      isMFAEnabled: true,
      otp,
      otpExpiresAt: otpExpiry,
      emailVerified: false,
      otpVerified: false,
      createdAt: new Date(),
      updatedAt: new Date(),
      location: {
        latitude: geoLocation.latitude,
        longitude: geoLocation.longitude,
        place: geoLocation.place
      }
    });

    if (!newUser.acknowledged) {
      throw new Error('Failed to create user');
    }

    try {
      // Send verification OTP
      await sendOTPEmail(email.toLowerCase().trim(), otp);

      return res.status(201).json({
        message: "Please verify your email with the OTP sent to your email address",
        userId: newUser.insertedId.toString(),
      });
    } catch (emailError) {
      // If email fails, delete the created user
      await db.collection("user").deleteOne({ _id: newUser.insertedId });
      throw new Error(`Failed to send verification email: ${emailError.message}`);
    }

  } catch (error) {
    console.error('Create user error:', error);
    return res.status(500).json({ 
      message: "An error occurred while creating user",
      error: error.message
    });
  }
}

// New function to verify email during signup
export async function verifySignupOTP(req, res) {
  try {
    const db = req.app.get("db");
    const { userId, otp } = req.body;

    if (!userId?.trim() || !otp?.trim()) {
      return res.status(400).json({ 
        message: "User ID and OTP are required" 
      });
    }

    const user = await db.collection("user").findOne({ 
      _id: new ObjectId(userId) 
    });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (user.emailVerified) {
      return res.status(400).json({ 
        message: "Email is already verified" 
      });
    }

    if (!user.otp || !user.otpExpiresAt) {
      return res.status(400).json({ 
        message: "No OTP request found. Please request a new OTP." 
      });
    }

    if (new Date() > new Date(user.otpExpiresAt)) {
      // If OTP is expired, delete the unverified user
      await db.collection("user").deleteOne({ _id: user._id });
      return res.status(400).json({ 
        message: "OTP has expired. Please register again." 
      });
    }

    if (otp !== user.otp) {
      return res.status(401).json({ message: "Invalid OTP" });
    }

    // Verify email and update user
    await db.collection("user").updateOne(
      { _id: user._id },
      { 
        $set: { 
          emailVerified: true,
          otp: null,
          otpExpiresAt: null,
          updatedAt: new Date()
        } 
      }
    );

    return res.status(200).json({
      message: "Email verified successfully. You can now login.",
      userId: user._id.toString(),
      name: user.name
    });

  } catch (error) {
    console.error('Signup OTP verification error:', error);
    return res.status(500).json({ 
      message: "An error occurred during email verification",
      error: error.message
    });
  }
}

// Function to resend OTP if expired during signup
export async function resendSignupOTP(req, res) {
  try {
    const db = req.app.get("db");
    const { userId } = req.body;

    if (!userId?.trim()) {
      return res.status(400).json({ 
        message: "User ID is required" 
      });
    }

    const user = await db.collection("user").findOne({ 
      _id: new ObjectId(userId) 
    });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (user.emailVerified) {
      return res.status(400).json({ 
        message: "Email is already verified" 
      });
    }

    // Generate new OTP
    const otp = generateOTP();
    const otpExpiry = getOTPExpiry();

    // Update user with new OTP
    await db.collection("user").updateOne(
      { _id: user._id },
      {
        $set: {
          otp,
          otpExpiresAt: otpExpiry,
          updatedAt: new Date()
        }
      }
    );

    await sendOTPEmail(user.email, otp);

    return res.status(200).json({
      message: "New OTP has been sent to your email",
      userId: user._id.toString()
    });

  } catch (error) {
    console.error('Resend signup OTP error:', error);
    return res.status(500).json({ 
      message: "An error occurred while resending OTP",
      error: error.message
    });
  }
}

// Login Function with enhanced error handling
// Function to handle login
export async function loginController(req, res) {
  try {
    const db = req.app.get("db");
    const { email, password } = req.body;

    // Get user's IP and geolocation
    const userIP = requestIp.getClientIp(req);
    const geoLocation = await fetchGeolocation(userIP);
    
    console.log(`Login attempt from IP: ${userIP}, Location: ${JSON.stringify(geoLocation)}`);

    if (!email?.trim() || !password) {
      return res.status(400).json({
        message: "Email and password are required"
      });
    }

    const user = await db.collection("user").findOne({
      email: email.toLowerCase().trim()
    });

    if (!user) {
      return res.status(401).json({
        message: "Invalid credentials"
      });
    }

    if (password !== user.password) { // Note: In production, use proper password comparison
      return res.status(401).json({
        message: "Invalid credentials"
      });
    }

    // Update user with location data
    await db.collection("user").updateOne(
      { _id: user._id },
      {
        $set: {
          lastLoginIP: userIP,
          lastLoginLocation: geoLocation,
          lastLoginAt: new Date()
        }
      }
    );

    if (user.isMFAEnabled) {
      try {
        const otp = generateOTP();
        const otpExpiry = getOTPExpiry();

        await db.collection("user").updateOne(
          { _id: user._id },
          {
            $set: {
              otp,
              otpExpiresAt: otpExpiry,
              otpVerified: false,
              updatedAt: new Date()
            },
          }
        );

        await sendOTPEmail(user.email, otp);

        return res.status(200).json({
          message: "OTP has been sent to your email. Please verify.",
          userId: user._id.toString(),
        });
      } catch (emailError) {
        console.error('OTP email error:', emailError);
        return res.status(500).json({
          message: "Failed to send OTP email. Please try again later."
        });
      }
    }

    // Return location data with successful login
    return res.status(200).json({
      message: "Successfully Logged In",
      userId: user._id.toString(),
      name: user.name,
      location: geoLocation
    });

  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({
      message: "An error occurred during login",
      error: error.message
    });
  }
}



// Verify OTP Function with enhanced error handling
export async function verifyOTP(req, res) {
  try {
    const db = req.app.get("db");
    const { userId, otp } = req.body;

    if (!userId?.trim() || !otp?.trim()) {
      return res.status(400).json({ 
        message: "User ID and OTP are required" 
      });
    }

    const user = await db.collection("user").findOne({ 
      _id: new ObjectId(userId) 
    });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (!user.otp || !user.otpExpiresAt) {
      return res.status(400).json({ 
        message: "No OTP request found. Please request a new OTP." 
      });
    }

    if (new Date() > new Date(user.otpExpiresAt)) {
      return res.status(400).json({ 
        message: "OTP has expired. Please request a new one." 
      });
    }

    if (otp !== user.otp) {
      return res.status(401).json({ message: "Invalid OTP" });
    }

    await db.collection("user").updateOne(
      { _id: user._id },
      { 
        $set: { 
          otpVerified: true,
          otp: null,
          otpExpiresAt: null,
          updatedAt: new Date()
        } 
      }
    );

    return res.status(200).json({
      message: "OTP verified. Login successful.",
      userId: user._id.toString(),
      name: user.name
    });

  } catch (error) {
    console.error('OTP verification error:', error);
    return res.status(500).json({ 
      message: "An error occurred during OTP verification",
      error: error.message
    });
  }
}