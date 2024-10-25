import express from "express";
import { MongoClient, ObjectId } from "mongodb";
import userRoutes from "./src/routes/user.js";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import morgan from "morgan";
import { monitorIPActivity, getIPActivityHistory, unblockIP } from './src/controllers/userController.js';

const app = express();
const port = 8080;

// Configuration constants
const mongoUri = "mongodb+srv://nayakswadhin25:1111111q@cluster0.3q077.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";
const corsOrigin = "http://localhost:5173";

// Audit Trail Configuration
const AuditEventType = {
  IP_BLOCKED: 'IP_BLOCKED',
  IP_UNBLOCKED: 'IP_UNBLOCKED',
  LOGIN_ATTEMPT: 'LOGIN_ATTEMPT',
  USER_ACTIVITY: 'USER_ACTIVITY',
  SECURITY_ALERT: 'SECURITY_ALERT',
  ADMIN_ACTION: 'ADMIN_ACTION',
  SYSTEM_ERROR: 'SYSTEM_ERROR'
};

const AuditSeverity = {
  INFO: 'INFO',
  WARNING: 'WARNING',
  CRITICAL: 'CRITICAL'
};

// Audit Trail Logger
class AuditLogger {
  constructor(db) {
    this.collection = db.collection('audit_trails');
  }

  async log(eventType, severity, details, req) {
    const auditLog = {
      eventType,
      timestamp: new Date(),
      ip: req.ip,
      userAgent: req.get('user-agent'),
      path: req.path,
      method: req.method,
      userId: req.user?.id || null,
      severity,
      details,
      riskLevel: req.ipRiskLevel || 'unknown',
      correlationId: new ObjectId()
    };

    return await this.collection.insertOne(auditLog);
  }
}

// Enhanced IP Monitoring Middleware with Audit
const ipMonitoringMiddleware = async (req, res, next) => {
  try {
    const db = req.app.get('db');
    const auditLogger = req.app.get('auditLogger');
    const { risk, blocked } = await monitorIPActivity(db, req, 'request');
    
    if (blocked) {
      await auditLogger.log(
        AuditEventType.IP_BLOCKED,
        AuditSeverity.CRITICAL,
        { reason: 'Suspicious activity', risk },
        req
      );

      return res.status(403).json({
        error: 'Access denied',
        message: 'Your IP has been blocked due to suspicious activity'
      });
    }

    req.ipRiskLevel = risk;
    
    // Log normal activity
    await auditLogger.log(
      AuditEventType.USER_ACTIVITY,
      AuditSeverity.INFO,
      { risk },
      req
    );
    
    next();
  } catch (error) {
    console.error('IP monitoring error:', error);
    const auditLogger = req.app.get('auditLogger');
    await auditLogger.log(
      AuditEventType.SYSTEM_ERROR,
      AuditSeverity.CRITICAL,
      { error: error.message, stack: error.stack },
      req
    );
    next(error);
  }
};

// Enhanced User Routes with Audit Trail
const enhanceUserRoutes = (router) => {
  const originalStack = router.stack;
  router.stack = originalStack.map(layer => {
    if (layer.route) {
      const originalHandler = layer.route.stack[0].handle;
      layer.route.stack[0].handle = async (req, res, next) => {
        try {
          const db = req.app.get('db');
          const auditLogger = req.app.get('auditLogger');
          const activityType = req.method === 'POST' && req.path === '/login' 
            ? 'login_attempt'
            : 'user_activity';
          
          await monitorIPActivity(db, req, activityType);
          
          // Audit log for the activity
          await auditLogger.log(
            activityType === 'login_attempt' ? AuditEventType.LOGIN_ATTEMPT : AuditEventType.USER_ACTIVITY,
            AuditSeverity.INFO,
            { path: req.path, method: req.method },
            req
          );
          
          return originalHandler(req, res, next);
        } catch (error) {
          next(error);
        }
      };
    }
    return layer;
  });
  return router;
};

async function startApp() {
  try {
    // Security Middleware
    app.use(helmet());
    app.use(morgan('dev'));
    app.use(cors({ origin: corsOrigin, credentials: true }));
    app.use(express.json());

    // Rate Limiting
    const limiter = rateLimit({ 
      windowMs: 15 * 60 * 1000, 
      max: 100 
    });
    app.use(limiter);

    // MongoDB Connection
    const mongo = await MongoClient.connect(mongoUri);
    const db = mongo.db();
    app.set("db", db);

    // Initialize Audit Logger
    const auditLogger = new AuditLogger(db);
    app.set("auditLogger", auditLogger);

    // Setup Security Collections
    await db.createCollection("security_logs");
    await db.createCollection("ip_activity_logs");
    await db.createCollection("audit_trails");
    
    // Create Indexes
    await db.collection("security_logs").createIndex({ ip: 1, timestamp: -1 });
    await db.collection("ip_activity_logs").createIndex({ ip: 1, timestamp: -1 });
    await db.collection("audit_trails").createIndex({ timestamp: -1 });
    await db.collection("audit_trails").createIndex({ eventType: 1 });
    await db.collection("audit_trails").createIndex({ ip: 1 });
    await db.collection("audit_trails").createIndex({ userId: 1 });
    await db.collection("audit_trails").createIndex({ severity: 1 });

    // Health Check Route
    app.get("/health", (req, res) => {
      res.status(200).json({ message: "The health is Good." });
    });

    // Apply IP Monitoring
    app.use(ipMonitoringMiddleware);

    // Enhanced User Routes
    app.use("/user", enhanceUserRoutes(userRoutes));

    // Admin Routes with Audit Trail
    app.get("/admin/ip/:ip/history", async (req, res) => {
      try {
        const history = await getIPActivityHistory(db, req.params.ip);
        await auditLogger.log(
          AuditEventType.ADMIN_ACTION,
          AuditSeverity.INFO,
          { action: 'IP_HISTORY_CHECK', targetIp: req.params.ip },
          req
        );
        res.json(history);
      } catch (error) {
        await auditLogger.log(
          AuditEventType.SYSTEM_ERROR,
          AuditSeverity.CRITICAL,
          { error: error.message, action: 'IP_HISTORY_CHECK' },
          req
        );
        res.status(500).json({ error: "Failed to fetch IP history" });
      }
    });

    app.post("/admin/ip/:ip/unblock", async (req, res) => {
      try {
        const result = await unblockIP(db, req.params.ip);
        await auditLogger.log(
          AuditEventType.IP_UNBLOCKED,
          AuditSeverity.WARNING,
          { targetIp: req.params.ip, adminAction: true },
          req
        );
        res.json(result);
      } catch (error) {
        await auditLogger.log(
          AuditEventType.SYSTEM_ERROR,
          AuditSeverity.CRITICAL,
          { error: error.message, action: 'IP_UNBLOCK' },
          req
        );
        res.status(500).json({ error: "Failed to unblock IP" });
      }
    });

    // Audit Trail Query Route (Admin Only)
    app.get("/admin/audit", async (req, res) => {
      try {
        const {
          eventType,
          severity,
          startDate,
          endDate,
          ip,
          limit = 100,
          skip = 0
        } = req.query;

        const query = {};
        if (eventType) query.eventType = eventType;
        if (severity) query.severity = severity;
        if (ip) query.ip = ip;
        if (startDate || endDate) {
          query.timestamp = {};
          if (startDate) query.timestamp.$gte = new Date(startDate);
          if (endDate) query.timestamp.$lte = new Date(endDate);
        }

        const audits = await db.collection('audit_trails')
          .find(query)
          .sort({ timestamp: -1 })
          .skip(parseInt(skip))
          .limit(parseInt(limit))
          .toArray();

        res.json(audits);
      } catch (error) {
        res.status(500).json({ error: "Failed to fetch audit trails" });
      }
    });

    // Error Handling Middleware with Audit
    app.use(async (err, req, res, next) => {
      console.error(err.stack);
      const auditLogger = req.app.get('auditLogger');
      
      await auditLogger.log(
        AuditEventType.SYSTEM_ERROR,
        AuditSeverity.CRITICAL,
        { 
          error: err.message,
          stack: err.stack,
          risk: req.ipRiskLevel 
        },
        req
      );
      
      res.status(500).json({ 
        message: "Something went wrong!",
        risk: req.ipRiskLevel
      });
    });

    // Start Server
    app.listen(port, () => {
      console.log(`APP is listening at http://localhost:${port}/`);
    });

  } catch (error) {
    console.error("Application Startup Error:", error);
    process.exit(1);
  }
}

startApp();