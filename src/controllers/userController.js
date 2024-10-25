import crypto from 'crypto';
import nodemailer from 'nodemailer';
import { ObjectId } from 'mongodb';
import requestIp from 'request-ip';
import axios from 'axios'; // Add axios import for geolocation
import UAParser from 'ua-parser-js';


export const AuditEventType = {
  USER_LOGIN: 'USER_LOGIN',
  USER_LOGOUT: 'USER_LOGOUT',
  USER_CREATED: 'USER_CREATED',
  USER_UPDATED: 'USER_UPDATED',
  USER_DELETED: 'USER_DELETED',
  IP_BLOCKED: 'IP_BLOCKED',
  IP_UNBLOCKED: 'IP_UNBLOCKED',
  SECURITY_ALERT: 'SECURITY_ALERT',
  ADMIN_ACTION: 'ADMIN_ACTION'
};

// Audit severity levels
export const AuditSeverity = {
  INFO: 'INFO',
  WARNING: 'WARNING',
  CRITICAL: 'CRITICAL'
};

export class AuditLogger {
  constructor(db) {
    this.db = db;
    this.collection = db.collection('audit_trails');
  }

  /**
   * Create an audit log entry
   * @param {Object} params Audit log parameters
   * @returns {Promise<ObjectId>} The ID of the created audit log
   */
  async createLog({
    eventType,
    userId = null,
    ip,
    userAgent,
    severity = AuditSeverity.INFO,
    details = {},
    metadata = {}
  }) {
    const auditLog = {
      eventType,
      userId: userId ? new ObjectId(userId) : null,
      ip,
      userAgent,
      severity,
      details,
      metadata,
      timestamp: new Date(),
      correlationId: new ObjectId() // For tracking related events
    };

    const result = await this.collection.insertOne(auditLog);
    return result.insertedId;
  }

  /**
   * Query audit logs with filtering options
   */
  async queryLogs({
    eventTypes = [],
    userId = null,
    ip = null,
    severity = null,
    startDate = null,
    endDate = null,
    limit = 100,
    skip = 0
  }) {
    const query = {};

    if (eventTypes.length > 0) {
      query.eventType = { $in: eventTypes };
    }
    if (userId) {
      query.userId = new ObjectId(userId);
    }
    if (ip) {
      query.ip = ip;
    }
    if (severity) {
      query.severity = severity;
    }
    if (startDate || endDate) {
      query.timestamp = {};
      if (startDate) {
        query.timestamp.$gte = new Date(startDate);
      }
      if (endDate) {
        query.timestamp.$lte = new Date(endDate);
      }
    }

    return this.collection.find(query)
      .sort({ timestamp: -1 })
      .skip(skip)
      .limit(limit)
      .toArray();
  }
}

// Middleware factory for audit logging
export const createAuditMiddleware = (auditLogger) => {
  return async (req, res, next) => {
    // Store the original send function
    const originalSend = res.send;

    // Override the send function to capture response
    res.send = function (data) {
      res.locals.responseBody = data;
      return originalSend.apply(res, arguments);
    };

    // Continue processing
    next();

    // Log after response is sent
    res.on('finish', () => {
      const userId = req.user ? req.user._id : null;
      
      auditLogger.createLog({
        eventType: 'API_REQUEST',
        userId,
        ip: req.ip,
        userAgent: req.get('user-agent'),
        severity: AuditSeverity.INFO,
        details: {
          method: req.method,
          path: req.path,
          query: req.query,
          statusCode: res.statusCode
        },
        metadata: {
          headers: req.headers,
          requestBody: req.body,
          responseBody: res.locals.responseBody
        }
      }).catch(error => {
        console.error('Audit logging error:', error);
      });
    });
  };
};

const IP_MONITORING = {
  SUSPICIOUS_THRESHOLD: {
    REQUESTS_PER_MINUTE: 60,
    FAILED_ATTEMPTS: 5,
    DIFFERENT_USERS: 3,
    TIME_WINDOW: 15 * 60 * 1000 // 15 minutes
  },
  BLOCK_DURATION: 60 * 60 * 1000 // 1 hour
};

// Track IP activities in memory (consider using Redis in production)
const ipActivities = new Map();

// Monitor and analyze IP activity
export  async function monitorIPActivity(db, req, activityType) {
  try {
    const ip = requestIp.getClientIp(req);
    const timestamp = new Date();
    
    // Skip monitoring for localhost in development
    if (ip === '127.0.0.1' || ip === '::1') {
      return { risk: 'low', blocked: false };
    }

    // Get or initialize IP activity record
    let activity = ipActivities.get(ip) || {
      requests: [],
      failedAttempts: 0,
      uniqueUsers: new Set(),
      firstSeen: timestamp,
      lastSeen: timestamp,
      blocked: false,
      blockExpiry: null
    };

    // Check if IP is currently blocked
    if (activity.blocked && activity.blockExpiry > timestamp) {
      return { risk: 'critical', blocked: true };
    }

    // Update activity record
    activity.requests.push(timestamp);
    activity.lastSeen = timestamp;

    // Clean up old requests outside the time window
    const timeWindow = timestamp.getTime() - IP_MONITORING.SUSPICIOUS_THRESHOLD.TIME_WINDOW;
    activity.requests = activity.requests.filter(time => time.getTime() > timeWindow);

    // Update metrics based on activity type
    switch (activityType) {
      case 'failed_login':
      case 'failed_otp':
        activity.failedAttempts++;
        break;
      case 'successful_login':
        const userId = req.body.userId || req.params.userId;
        if (userId) activity.uniqueUsers.add(userId);
        activity.failedAttempts = 0; // Reset failed attempts on success
        break;
    }

    // Analyze risk level
    const risk = await analyzeIPRisk(db, ip, activity);
    
    // Update IP activities map
    ipActivities.set(ip, activity);

    // Log IP activity
    await logIPActivity(db, ip, activity, risk, activityType);

    // Block IP if risk is critical
    if (risk === 'critical' && !activity.blocked) {
      activity.blocked = true;
      activity.blockExpiry = new Date(timestamp.getTime() + IP_MONITORING.BLOCK_DURATION);
      ipActivities.set(ip, activity);

      // Log blocking event
      await db.collection("security_logs").insertOne({
        ip,
        event: 'ip_blocked',
        reason: 'suspicious_activity',
        timestamp,
        blockExpiry: activity.blockExpiry
      });
    }

    return { risk, blocked: activity.blocked };

  } catch (error) {
    console.error('IP monitoring error:', error);
    return { risk: 'medium', blocked: false }; // Default to medium risk on error
  }
}

// Analyze IP risk level
async function analyzeIPRisk(db, ip, activity) {
  const requestsPerMinute = activity.requests.length;
  const uniqueUserCount = activity.uniqueUsers.size;
  
  // Critical risk indicators
  if (
    requestsPerMinute >= IP_MONITORING.SUSPICIOUS_THRESHOLD.REQUESTS_PER_MINUTE ||
    activity.failedAttempts >= IP_MONITORING.SUSPICIOUS_THRESHOLD.FAILED_ATTEMPTS ||
    uniqueUserCount >= IP_MONITORING.SUSPICIOUS_THRESHOLD.DIFFERENT_USERS
  ) {
    return 'critical';
  }

  // High risk indicators
  if (
    requestsPerMinute >= IP_MONITORING.SUSPICIOUS_THRESHOLD.REQUESTS_PER_MINUTE / 2 ||
    activity.failedAttempts >= IP_MONITORING.SUSPICIOUS_THRESHOLD.FAILED_ATTEMPTS / 2 ||
    uniqueUserCount >= IP_MONITORING.SUSPICIOUS_THRESHOLD.DIFFERENT_USERS / 2
  ) {
    return 'high';
  }

  // Check historical IP reputation
  const recentViolations = await db.collection("security_logs").countDocuments({
    ip,
    event: { $in: ['ip_blocked', 'suspicious_activity'] },
    timestamp: { $gt: new Date(Date.now() - 24 * 60 * 60 * 1000) } // Last 24 hours
  });

  if (recentViolations > 0) {
    return 'high';
  }

  return 'low';
}

// Log IP activity to database
async function logIPActivity(db, ip, activity, risk, activityType) {
  await db.collection("ip_activity_logs").insertOne({
    ip,
    timestamp: new Date(),
    activityType,
    requestCount: activity.requests.length,
    failedAttempts: activity.failedAttempts,
    uniqueUsers: Array.from(activity.uniqueUsers),
    riskLevel: risk,
    blocked: activity.blocked,
    blockExpiry: activity.blockExpiry
  });
}

// Get IP activity history
export  async function getIPActivityHistory(db, ip) {
  return await db.collection("ip_activity_logs")
    .find({ ip })
    .sort({ timestamp: -1 })
    .limit(100)
    .toArray();
}

// Unblock IP address
export async function unblockIP(db, ip) {
  const activity = ipActivities.get(ip);
  if (activity) {
    activity.blocked = false;
    activity.blockExpiry = null;
    activity.failedAttempts = 0;
    ipActivities.set(ip, activity);
  }

  await db.collection("security_logs").insertOne({
    ip,
    event: 'ip_unblocked',
    timestamp: new Date()
  });

  return { message: 'IP unblocked successfully' };
}

// Suspicious behavior patterns and thresholds
const THRESHOLDS = {
  LOGIN_ATTEMPTS: {
    TIME_WINDOW: 15 * 60 * 1000, // 15 minutes
    MAX_ATTEMPTS: 5,
    LOCKOUT_DURATION: 30 * 60 * 1000 // 30 minutes
  },
  LOCATION_CHANGES: {
    TIME_WINDOW: 24 * 60 * 60 * 1000, // 24 hours
    MAX_CHANGES: 3
  },
  DEVICE_CHANGES: {
    TIME_WINDOW: 24 * 60 * 60 * 1000, // 24 hours
    MAX_CHANGES: 3
  },
  OTP_ATTEMPTS: {
    TIME_WINDOW: 10 * 60 * 1000, // 10 minutes
    MAX_ATTEMPTS: 3,
    LOCKOUT_DURATION: 15 * 60 * 1000 // 15 minutes
  }
};

// Calculate distance between two geographical points
function calculateDistance(lat1, lon1, lat2, lon2) {
  const R = 6371; // Earth's radius in km
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLon = (lon2 - lon1) * Math.PI / 180;
  const a = 
    Math.sin(dLat/2) * Math.sin(dLat/2) +
    Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) * 
    Math.sin(dLon/2) * Math.sin(dLon/2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
  return R * c;
}

// Check if location change is suspicious
async function isLocationSuspicious(db, userId, newLocation, previousLocation) {
  if (!previousLocation || !newLocation) return false;

  const distance = calculateDistance(
    parseFloat(previousLocation.latitude),
    parseFloat(previousLocation.longitude),
    parseFloat(newLocation.latitude),
    parseFloat(newLocation.longitude)
  );

  // If distance > 500km in less than 1 hour, consider it suspicious
  const SPEED_THRESHOLD = 500; // km
  const TIME_THRESHOLD = 60 * 60 * 1000; // 1 hour in milliseconds

  const recentLogin = await db.collection("security_logs").findOne({
    userId: new ObjectId(userId),
    event: 'successful_login',
    timestamp: { $gt: new Date(Date.now() - TIME_THRESHOLD) }
  });

  return recentLogin && distance > SPEED_THRESHOLD;
}

// Track and analyze suspicious behavior
export async function trackSuspiciousBehavior(db, userId, event, data) {
  try {
    const now = new Date();
    const user = await db.collection("user").findOne({ _id: new ObjectId(userId) });
    if (!user) return null;

    // Create behavior tracking entry
    const behaviorEntry = {
      userId: new ObjectId(userId),
      event,
      timestamp: now,
      data,
      risk_level: 'low'
    };

    // Analyze different types of suspicious behavior
    const analyses = await Promise.all([
      analyzeLoginAttempts(db, userId, data),
      analyzeLocationChanges(db, userId, data),
      analyzeDeviceChanges(db, userId, data),
      analyzeOTPAttempts(db, userId, data)
    ]);

    // Combine risk assessments
    const riskLevels = analyses.map(a => a.risk_level).filter(Boolean);
    behaviorEntry.risk_factors = analyses.reduce((acc, curr) => {
      if (curr.factors) acc.push(...curr.factors);
      return acc;
    }, []);

    // Determine overall risk level
    if (riskLevels.includes('critical')) {
      behaviorEntry.risk_level = 'critical';
    } else if (riskLevels.includes('high')) {
      behaviorEntry.risk_level = 'high';
    } else if (riskLevels.includes('medium')) {
      behaviorEntry.risk_level = 'medium';
    }

    // Store behavior tracking entry
    await db.collection("behavior_tracking").insertOne(behaviorEntry);

    // Update user's risk profile
    await updateUserRiskProfile(db, userId, behaviorEntry);

    return behaviorEntry;

  } catch (error) {
    console.error('Error tracking suspicious behavior:', error);
    return null;
  }
}

// Analyze login attempts
async function analyzeLoginAttempts(db, userId, data) {
  const window = new Date(Date.now() - THRESHOLDS.LOGIN_ATTEMPTS.TIME_WINDOW);
  
  const attempts = await db.collection("security_logs")
    .find({
      userId: new ObjectId(userId),
      event: { $in: ['failed_login_attempt', 'blocked_login_attempt'] },
      timestamp: { $gt: window }
    })
    .toArray();

  const analysis = {
    risk_level: 'low',
    factors: []
  };

  if (attempts.length >= THRESHOLDS.LOGIN_ATTEMPTS.MAX_ATTEMPTS) {
    analysis.risk_level = 'high';
    analysis.factors.push('excessive_login_attempts');
  }

  return analysis;
}

// Analyze location changes
async function analyzeLocationChanges(db, userId, data) {
  const window = new Date(Date.now() - THRESHOLDS.LOCATION_CHANGES.TIME_WINDOW);
  
  const locations = await db.collection("security_logs")
    .find({
      userId: new ObjectId(userId),
      event: 'successful_login',
      timestamp: { $gt: window }
    })
    .sort({ timestamp: -1 })
    .toArray();

  const analysis = {
    risk_level: 'low',
    factors: []
  };

  if (locations.length >= 2) {
    const uniqueLocations = new Set(
      locations.map(log => `${log.location.latitude},${log.location.longitude}`)
    );

    if (uniqueLocations.size > THRESHOLDS.LOCATION_CHANGES.MAX_CHANGES) {
      analysis.risk_level = 'high';
      analysis.factors.push('rapid_location_changes');
    }

    // Check for impossible travel
    if (data.location) {
      const isSuspicious = await isLocationSuspicious(
        db,
        userId,
        data.location,
        locations[0]?.location
      );
      if (isSuspicious) {
        analysis.risk_level = 'critical';
        analysis.factors.push('impossible_travel_detected');
      }
    }
  }

  return analysis;
}

// Analyze device changes
async function analyzeDeviceChanges(db, userId, data) {
  const window = new Date(Date.now() - THRESHOLDS.DEVICE_CHANGES.TIME_WINDOW);
  
  const devices = await db.collection("device_history")
    .find({
      userId: new ObjectId(userId),
      lastUsed: { $gt: window }
    })
    .toArray();

  const analysis = {
    risk_level: 'low',
    factors: []
  };

  if (devices.length > THRESHOLDS.DEVICE_CHANGES.MAX_CHANGES) {
    analysis.risk_level = 'medium';
    analysis.factors.push('multiple_devices');
  }

  // Check for concurrent sessions from different devices
  const activeSessions = devices.filter(d => 
    Date.now() - d.lastUsed.getTime() < 5 * 60 * 1000 // Active in last 5 minutes
  );

  if (activeSessions.length > 1) {
    analysis.risk_level = 'high';
    analysis.factors.push('concurrent_sessions');
  }

  return analysis;
}

// Analyze OTP attempts
async function analyzeOTPAttempts(db, userId, data) {
  const window = new Date(Date.now() - THRESHOLDS.OTP_ATTEMPTS.TIME_WINDOW);
  
  const attempts = await db.collection("security_logs")
    .find({
      userId: new ObjectId(userId),
      event: 'failed_otp_verification',
      timestamp: { $gt: window }
    })
    .toArray();

  const analysis = {
    risk_level: 'low',
    factors: []
  };

  if (attempts.length >= THRESHOLDS.OTP_ATTEMPTS.MAX_ATTEMPTS) {
    analysis.risk_level = 'high';
    analysis.factors.push('excessive_otp_attempts');
  }

  return analysis;
}

// Update user's risk profile
async function updateUserRiskProfile(db, userId, behaviorEntry) {
  const riskScore = calculateRiskScore(behaviorEntry);
  
  await db.collection("user").updateOne(
    { _id: new ObjectId(userId) },
    {
      $set: {
        riskScore,
        lastRiskUpdate: new Date(),
        riskFactors: behaviorEntry.risk_factors,
        securityLevel: determineSecurityLevel(riskScore)
      }
    }
  );
}

// Calculate risk score based on behavior
function calculateRiskScore(behaviorEntry) {
  const baseScore = {
    'low': 0,
    'medium': 30,
    'high': 60,
    'critical': 90
  }[behaviorEntry.risk_level];

  // Add points for each risk factor
  const factorPoints = behaviorEntry.risk_factors.length * 5;

  return Math.min(100, baseScore + factorPoints);
}

// Determine security level based on risk score
function determineSecurityLevel(riskScore) {
  if (riskScore >= 80) return 'maximum';
  if (riskScore >= 50) return 'high';
  if (riskScore >= 30) return 'medium';
  return 'standard';
}

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
async function isDisposableEmail(email) {
  try {
    const domain = email.split('@')[1];
    
    // First check against common disposable email patterns
    const commonDisposablePatterns = [
      'tempmail', 'throwaway', 'temporary', 
      'dispose', 'mailinator', 'guerrilla',
      'temp-mail', '10minutemail', 'yopmail',
      'sharklasers', 'grr', 'guerrillamail'
    ];
    
    if (commonDisposablePatterns.some(pattern => domain.includes(pattern))) {
      return true;
    }

    // Use Abstract API to verify email
    const response = await axios.get(`https://emailvalidation.abstractapi.com/v1`, {
      params: {
        api_key: 'YOUR_ABSTRACT_API_KEY', // Replace with your API key
        email: email
      }
    });

    // Check various risk factors
    const data = response.data;
    
    // If any of these are true, consider it disposable
    return (
      data.is_disposable_email.value === true ||
      data.is_free_email.value === true && data.email_quality_score < 0.5 ||
      data.deliverability === "UNDELIVERABLE" ||
      data.is_role_email.value === true // Checks for role-based emails like admin@, info@, etc.
    );

  } catch (error) {
    console.error('Email validation error:', error);
    // In case of API failure, do secondary check against basic patterns
    return isBasicDisposablePattern(email);
  }
}

// Fallback function for basic pattern checking
function isBasicDisposablePattern(email) {
  const domain = email.split('@')[1];
  
  // Extended list of disposable email domains
  const disposableDomains = new Set([
    'tempmail.com', 'temp-mail.org', 'guerrillamail.com',
    'mailinator.com', 'yopmail.com', 'throwawaymail.com',
    '10minutemail.com', 'trashmail.com', 'sharklasers.com',
    'getairmail.com', 'grr.la', 'trash-mail.com',
    'fakeinbox.com', 'guerrillamail.info', 'tempr.email',
    'dispostable.com', 'mailnesia.com', 'tempmailaddress.com',
    'tmpmail.org', 'dropmail.me', 'wegwerfemail.de',
    '临时邮箱.com', 'tempmail.ninja', 'disposablemail.com'
  ]);

  return disposableDomains.has(domain.toLowerCase());
}

// Modified createUser function with disposable email detection
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

    // Check for disposable email
    const isDisposable = await isDisposableEmail(email);
    if (isDisposable) {
      // Log attempted registration with disposable email
      await db.collection("security_logs").insertOne({
        email: email.toLowerCase().trim(),
        event: 'blocked_disposable_email_registration',
        timestamp: new Date()
      });

      return res.status(400).json({ 
        message: "Please use a permanent email address. Temporary or disposable email addresses are not allowed." 
      });
    }

    const existingUser = await db.collection("user").findOne({ 
      email: email.toLowerCase().trim() 
    });

    if (existingUser) {
      return res.status(400).json({ message: "Email Id already exists." });
    }

    // Get user's IP and geolocation
    const userIP = requestIp.getClientIp(req);
    const [geoLocation, ipReputation] = await Promise.all([
      fetchGeolocation(userIP),
      checkIPReputation(userIP)
    ]);
    
    console.log(`New registration attempt from IP: ${userIP}, Location: ${JSON.stringify(geoLocation)}`);

    // Generate OTP for email verification
    const otp = generateOTP();
    const otpExpiry = getOTPExpiry();

    // Create unverified user with additional security fields
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
      registrationIP: userIP,
      registrationLocation: geoLocation,
      registrationIPReputation: ipReputation,
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

      // Log successful registration attempt
      await db.collection("security_logs").insertOne({
        userId: newUser.insertedId,
        email: email.toLowerCase().trim(),
        ip: userIP,
        location: geoLocation,
        reputation: ipReputation,
        event: 'successful_registration',
        timestamp: new Date()
      });

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

// New IP reputation checking function
async function checkIPReputation(ip) {
  try {
    // Skip check for localhost/development
    if (ip === '127.0.0.1' || ip === '::1') {
      return { risk: 'low', score: 0 };
    }

    // Using AbuseIPDB API for IP reputation check
    const response = await axios.get('https://api.abuseipdb.com/api/v2/check', {
      params: {
        ipAddress: ip,
        maxAgeInDays: 90
      },
      headers: {
        'Key': 'a21c00301d5f7f86b7542f1128d72486516c6126bf5a322543ff8cf9dcba1ffde57d19b25add30f5', // Replace with your API key
        'Accept': 'application/json'
      }
    });

    const data = response.data.data;
    const abuseScore = data.abuseConfidenceScore;

    // Calculate risk level based on abuse score
    let risk = 'low';
    if (abuseScore > 80) {
      risk = 'high';
    } else if (abuseScore > 40) {
      risk = 'medium';
    }

    return {
      risk,
      score: abuseScore,
      reports: data.totalReports,
      lastReported: data.lastReportedAt
    };
  } catch (error) {
    console.error('IP reputation check error:', error);
    // Default to medium risk if the check fails
    return { risk: 'medium', score: 50 };
  }
}

// Rate limiting helper
const loginAttempts = new Map();

function updateLoginAttempts(ip) {
  const now = Date.now();
  const attempts = loginAttempts.get(ip) || { count: 0, firstAttempt: now };
  
  // Reset if last attempt was more than 15 minutes ago
  if (now - attempts.firstAttempt > 15 * 60 * 1000) {
    attempts.count = 0;
    attempts.firstAttempt = now;
  }
  
  attempts.count++;
  loginAttempts.set(ip, attempts);
  
  return attempts;
}


// Helper function to generate device fingerprint
function generateDeviceFingerprint(req) {
  const ua = new UAParser(req.headers['user-agent']);
  const deviceInfo = {
    browser: ua.getBrowser(),
    os: ua.getOS(),
    device: ua.getDevice(),
    screenResolution: req.headers['sec-ch-viewport-width'] 
      ? `${req.headers['sec-ch-viewport-width']}x${req.headers['sec-ch-viewport-height']}`
      : 'unknown',
    timezone: req.headers['time-zone'] || 'unknown',
    language: req.headers['accept-language'] || 'unknown',
    platform: ua.getEngine().name || 'unknown'
  };

  // Create a unique device identifier
  const deviceString = JSON.stringify(deviceInfo);
  return crypto.createHash('sha256').update(deviceString).digest('hex');
}

// Function to check if device is trusted
async function isDeviceTrusted(db, userId, deviceFingerprint) {
  const device = await db.collection("device_history").findOne({
    userId: new ObjectId(userId),
    fingerprint: deviceFingerprint,
    trusted: true
  });
  return !!device;
}

// Modified loginController with device tracking
export async function loginController(req, res) {
  try {
    const db = req.app.get("db");
    const { email, password } = req.body;

    // Get user's IP and device information
    const userIP = requestIp.getClientIp(req);
    const deviceFingerprint = generateDeviceFingerprint(req);
    const ua = new UAParser(req.headers['user-agent']);
    
    const attempts = updateLoginAttempts(userIP);
    if (attempts.count > 5) {
      return res.status(429).json({
        message: "Too many login attempts. Please try again later."
      });
    }

    // Parallel execution of security checks
    const [geoLocation, ipReputation] = await Promise.all([
      fetchGeolocation(userIP),
      checkIPReputation(userIP)
    ]);

    if (ipReputation.risk === 'high') {
      await db.collection("security_logs").insertOne({
        ip: userIP,
        email: email?.toLowerCase().trim(),
        location: geoLocation,
        reputation: ipReputation,
        deviceFingerprint,
        deviceInfo: ua.getResult(),
        event: 'blocked_login_attempt',
        timestamp: new Date()
      });

      return res.status(403).json({
        message: "Access denied due to security concerns"
      });
    }

    if (!email?.trim() || !password) {
      return res.status(400).json({
        message: "Email and password are required"
      });
    }

    const user = await db.collection("user").findOne({
      email: email.toLowerCase().trim()
    });

    // Track suspicious behavior if user exists
    if (user) {
      const behaviorTracking = await trackSuspiciousBehavior(db, user._id, 'login_attempt', {
        ip: userIP,
        location: geoLocation,
        deviceFingerprint,
        deviceInfo: ua.getResult()
      });

      // Block attempt if behavior is critically suspicious
      if (behaviorTracking?.risk_level === 'critical') {
        await db.collection("security_logs").insertOne({
          userId: user._id,
          ip: userIP,
          location: geoLocation,
          deviceFingerprint,
          event: 'blocked_suspicious_behavior',
          risk_level: 'critical',
          risk_factors: behaviorTracking.risk_factors,
          timestamp: new Date()
        });

        return res.status(403).json({
          message: "Access denied due to suspicious activity"
        });
      }
    }

    if (!user || password !== user.password) {
      await db.collection("security_logs").insertOne({
        userId: user?._id,
        ip: userIP,
        location: geoLocation,
        reputation: ipReputation,
        deviceFingerprint,
        deviceInfo: ua.getResult(),
        event: 'failed_login_attempt',
        timestamp: new Date()
      });

      return res.status(401).json({
        message: "Invalid credentials"
      });
    }

    // Check if device is trusted
    const deviceTrusted = await isDeviceTrusted(db, user._id, deviceFingerprint);
    
    // Determine if MFA should be enforced
    const shouldEnforceMFA = user.isMFAEnabled || 
                           ipReputation.risk === 'medium' || 
                           !deviceTrusted;

    // Record device history
    await db.collection("device_history").updateOne(
      { 
        userId: user._id,
        fingerprint: deviceFingerprint
      },
      {
        $set: {
          lastUsed: new Date(),
          deviceInfo: ua.getResult(),
          trusted: deviceTrusted,
          location: geoLocation
        },
        $inc: { loginCount: 1 },
        $setOnInsert: {
          firstSeen: new Date(),
          initialLocation: geoLocation
        }
      },
      { upsert: true }
    );

    // Update user login info
    await db.collection("user").updateOne(
      { _id: user._id },
      {
        $set: {
          lastLoginIP: userIP,
          lastLoginLocation: geoLocation,
          lastLoginReputation: ipReputation,
          lastLoginDevice: deviceFingerprint,
          lastLoginDeviceInfo: ua.getResult(),
          lastLoginAt: new Date(),
          isMFAEnabled: shouldEnforceMFA
        }
      }
    );

    // Log successful login
    await db.collection("security_logs").insertOne({
      userId: user._id,
      ip: userIP,
      location: geoLocation,
      reputation: ipReputation,
      deviceFingerprint,
      deviceInfo: ua.getResult(),
      event: 'successful_login',
      timestamp: new Date()
    });

    if (shouldEnforceMFA) {
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
          mfaReason: !deviceTrusted ? 'new_device' : 
                     ipReputation.risk === 'medium' ? 'security_check' : 
                     'user_enabled'
        });
      } catch (emailError) {
        console.error('OTP email error:', emailError);
        return res.status(500).json({
          message: "Failed to send OTP email. Please try again later."
        });
      }
    }

    return res.status(200).json({
      message: "Successfully Logged In",
      userId: user._id.toString(),
      name: user.name,
      location: geoLocation,
      deviceTrusted
    });

  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({
      message: "An error occurred during login",
      error: error.message
    });
  }
}
// Add a new endpoint to manage trusted devices
export async function manageTrustedDevices(req, res) {
  try {
    const db = req.app.get("db");
    const { userId } = req.params;
    const { action, deviceId } = req.body;

    const user = await db.collection("user").findOne({ 
      _id: new ObjectId(userId) 
    });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (action === 'trust') {
      await db.collection("device_history").updateOne(
        { 
          userId: user._id,
          fingerprint: deviceId
        },
        {
          $set: {
            trusted: true,
            updatedAt: new Date()
          }
        }
      );
      
      return res.status(200).json({
        message: "Device added to trusted devices"
      });
    } 
    
    if (action === 'revoke') {
      await db.collection("device_history").updateOne(
        { 
          userId: user._id,
          fingerprint: deviceId
        },
        {
          $set: {
            trusted: false,
            updatedAt: new Date()
          }
        }
      );

      return res.status(200).json({
        message: "Device removed from trusted devices"
      });
    }

    return res.status(400).json({
      message: "Invalid action specified"
    });

  } catch (error) {
    console.error('Manage trusted devices error:', error);
    return res.status(500).json({
      message: "An error occurred while managing trusted devices",
      error: error.message
    });
  }
}

// Get user's device history
export async function getDeviceHistory(req, res) {
  try {
    const db = req.app.get("db");
    const { userId } = req.params;

    const user = await db.collection("user").findOne({ 
      _id: new ObjectId(userId) 
    });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const devices = await db.collection("device_history")
      .find({ userId: user._id })
      .sort({ lastUsed: -1 })
      .toArray();

    return res.status(200).json({
      devices: devices.map(device => ({
        id: device.fingerprint,
        deviceInfo: device.deviceInfo,
        trusted: device.trusted,
        firstSeen: device.firstSeen,
        lastUsed: device.lastUsed,
        loginCount: device.loginCount,
        initialLocation: device.initialLocation,
        currentLocation: device.location
      }))
    });

  } catch (error) {
    console.error('Get device history error:', error);
    return res.status(500).json({
      message: "An error occurred while fetching device history",
      error: error.message
    });
  }
}



// Verify OTP Function with enhanced error handling
export async function verifyOTP(req, res) {
  try {
    const db = req.app.get("db");
    const { userId, otp, deviceFingerprint } = req.body;

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

    // NEW CODE: Track OTP verification attempt
    await trackSuspiciousBehavior(db, user._id, 'otp_verification', {
      success: otp === user.otp,
      deviceFingerprint,
      attemptTime: new Date()
    });

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

    // If OTP is invalid, track it as a failed attempt
    if (otp !== user.otp) {
      await db.collection("security_logs").insertOne({
        userId: user._id,
        deviceFingerprint,
        event: 'failed_otp_verification',
        timestamp: new Date()
      });

      return res.status(401).json({ message: "Invalid OTP" });
    }

    // OTP is valid, update user
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