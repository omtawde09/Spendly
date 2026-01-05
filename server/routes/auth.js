const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const https = require('https');
const querystring = require('querystring');
const url = require('url');
const { getDatabase } = require('../database/init');

const router = express.Router();

// In-memory OTP storage (in production, use Redis or database)
const otpStore = new Map();

// Generate 6-digit OTP
const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

// Hash OTP for secure storage
const hashOTP = (otp) => {
  return crypto.createHash('sha256').update(otp).digest('hex');
};

// Send Email OTP
const sendEmailOTP = async (email, otp) => {
  try {
    let transporter;

    // Check for real email config, otherwise use Ethereal
    if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
      transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.EMAIL_PASS
        }
      });
    } else {
      // Create test account for development
      const testAccount = await nodemailer.createTestAccount();
      transporter = nodemailer.createTransport({
        host: testAccount.smtp.host,
        port: testAccount.smtp.port,
        secure: testAccount.smtp.secure,
        auth: {
          user: testAccount.user,
          pass: testAccount.pass
        }
      });
    }

    const info = await transporter.sendMail({
      from: '"Spendly Security" <security@spendly.app>',
      to: email,
      subject: 'Spendly Password Reset OTP',
      text: `Your OTP for password reset is: ${otp}. Valid for 10 minutes.`,
      html: `
        <div style="font-family: Arial, sans-serif; padding: 20px;">
          <h2>Password Reset Request</h2>
          <p>Your One-Time Password (OTP) is:</p>
          <h1 style="color: #4F46E5; letter-spacing: 5px;">${otp}</h1>
          <p>This code is valid for 10 minutes.</p>
          <p>If you didn't request this, please ignore this email.</p>
        </div>
      `
    });

    console.log("📧 Email sent: %s", info.messageId);

    // Preview URL for Ethereal
    const previewUrl = nodemailer.getTestMessageUrl(info);
    if (previewUrl) {
      console.log("🔗 Preview URL: %s", previewUrl);
      return { success: true, previewUrl };
    }

    return { success: true };
  } catch (error) {
    console.error('❌ Email sending failed:', error);
    throw error;
  }
};

// Register
router.post('/register', async (req, res) => {
  try {
    console.log('📥 Register request received:', { body: { ...req.body, password: '[HIDDEN]' } });

    const { email, password, name, phone } = req.body;

    if (!email || !password || !name) {
      console.log('❌ Missing required fields');
      return res.status(400).json({
        error: 'Missing required fields',
        message: 'Email, password, and name are required'
      });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      console.log('❌ Invalid email format:', email);
      return res.status(400).json({
        error: 'Invalid email',
        message: 'Please enter a valid email address'
      });
    }

    // Validate password strength
    if (password.length < 6) {
      console.log('❌ Password too short');
      return res.status(400).json({
        error: 'Weak password',
        message: 'Password must be at least 6 characters long'
      });
    }

    console.log('✅ Validation passed for registration');
    const db = getDatabase();

    // Check if user already exists
    db.get('SELECT id FROM users WHERE email = ?', [email], async (err, existingUser) => {
      try {
        if (err) {
          console.error('❌ Database error during user check:', err);
          return res.status(500).json({
            error: 'Database error',
            message: 'Failed to check existing user: ' + err.message
          });
        }

        if (existingUser) {
          console.log('❌ User already exists:', email);
          return res.status(409).json({
            error: 'User exists',
            message: 'User with this email already exists'
          });
        }

        // Check if phone number already exists
        if (phone) {
          const phoneCheck = new Promise((resolve, reject) => {
            db.get('SELECT id FROM users WHERE phone = ?', [phone], (err, row) => {
              if (err) reject(err);
              else resolve(row);
            });
          });

          try {
            const existingPhoneUser = await phoneCheck;
            if (existingPhoneUser) {
              console.log('❌ Phone already exists:', phone);
              return res.status(409).json({
                error: 'Phone exists',
                message: 'User with this phone number already exists'
              });
            }
          } catch (phoneErr) {
            console.error('❌ Database error during phone check:', phoneErr);
            return res.status(500).json({
              error: 'Database error',
              message: 'Failed to check existing phone'
            });
          }
        }

        try {
          console.log('🔐 Hashing password...');
          // Hash password
          const saltRounds = 12;
          const hashedPassword = await bcrypt.hash(password, saltRounds);
          console.log('✅ Password hashed successfully');

          // Insert user
          db.run(
            'INSERT INTO users (email, password, name, phone) VALUES (?, ?, ?, ?)',
            [email, hashedPassword, name, phone || null],
            function (err) {
              try {
                if (err) {
                  console.error('❌ Failed to create user:', err);
                  return res.status(500).json({
                    error: 'Registration failed',
                    message: 'Failed to create user account: ' + err.message
                  });
                }

                console.log('✅ User created with ID:', this.lastID);

                // Generate JWT token
                const token = jwt.sign(
                  { userId: this.lastID, email },
                  process.env.JWT_SECRET,
                  { expiresIn: '30d' }
                );

                console.log('✅ User registered successfully:', email);
                res.status(201).json({
                  message: 'User registered successfully',
                  token,
                  user: {
                    id: this.lastID,
                    email,
                    name,
                    phone: phone || null
                  }
                });
              } catch (tokenError) {
                console.error('❌ Token generation error:', tokenError);
                res.status(500).json({
                  error: 'Registration failed',
                  message: 'Failed to generate token: ' + tokenError.message
                });
              }
            }
          );
        } catch (hashError) {
          console.error('❌ Password hashing error:', hashError);
          res.status(500).json({
            error: 'Registration failed',
            message: 'Failed to process password: ' + hashError.message
          });
        }
      } catch (innerError) {
        console.error('❌ Inner error in register:', innerError);
        res.status(500).json({
          error: 'Registration failed',
          message: 'Internal error: ' + innerError.message
        });
      }
    });
  } catch (error) {
    console.error('❌ Registration error:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: 'Registration failed: ' + error.message
    });
  }
});

// Login
router.post('/login', (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error: 'Missing credentials',
        message: 'Email and password are required'
      });
    }

    const db = getDatabase();

    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
      if (err) {
        console.error('❌ Database error:', err);
        return res.status(500).json({
          error: 'Database error',
          message: 'Login failed'
        });
      }

      if (!user) {
        return res.status(401).json({
          error: 'Invalid credentials',
          message: 'Invalid email or password'
        });
      }

      try {
        // Verify password
        const isValidPassword = await bcrypt.compare(password, user.password);

        if (!isValidPassword) {
          return res.status(401).json({
            error: 'Invalid credentials',
            message: 'Invalid email or password'
          });
        }

        // Generate JWT token
        const token = jwt.sign(
          { userId: user.id, email: user.email },
          process.env.JWT_SECRET,
          { expiresIn: '30d' }
        );

        console.log('✅ User logged in:', email);
        res.json({
          message: 'Login successful',
          token,
          user: {
            id: user.id,
            email: user.email,
            name: user.name,
            phone: user.phone
          }
        });
      } catch (compareError) {
        console.error('❌ Password comparison error:', compareError);
        res.status(500).json({
          error: 'Login failed',
          message: 'Authentication error'
        });
      }
    });
  } catch (error) {
    console.error('❌ Login error:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: 'Login failed'
    });
  }
});

// Send OTP for password reset (Email)
router.post('/send-otp', async (req, res) => {
  try {
    console.log('📥 Send OTP request received:', { body: req.body });

    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        error: 'Email is required'
      });
    }

    const db = getDatabase();

    // Check if user exists with this email
    db.get('SELECT id FROM users WHERE email = ?', [email], async (err, user) => {
      try {
        if (err) {
          console.error('❌ Database error:', err);
          return res.status(500).json({
            success: false,
            error: 'Database error'
          });
        }

        if (!user) {
          return res.status(404).json({
            success: false,
            error: 'Email address not registered'
          });
        }

        console.log('✅ User found for email:', email);

        // Generate OTP
        const otp = generateOTP();
        const hashedOTP = hashOTP(otp);
        const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes

        // Store hashed OTP
        otpStore.set(email, {
          otp: hashedOTP,
          expiresAt,
          attempts: 0,
          verified: false
        });

        try {
          // Send Email
          const emailResult = await sendEmailOTP(email, otp);

          res.json({
            success: true,
            message: 'OTP sent successfully to your email',
            previewUrl: emailResult.previewUrl // For dev/testing
          });
        } catch (emailError) {
          console.error('❌ Email sending failed:', emailError);
          otpStore.delete(email);
          res.status(500).json({
            success: false,
            error: 'Unable to send OTP email. Please try again later.'
          });
        }
      } catch (innerError) {
        console.error('❌ Inner error:', innerError);
        res.status(500).json({ success: false, error: 'Internal error' });
      }
    });
  } catch (error) {
    console.error('❌ Send OTP error:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// Verify OTP
router.post('/verify-otp', (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({
        success: false,
        error: 'Email and OTP are required'
      });
    }

    const otpData = otpStore.get(email);

    if (!otpData) {
      return res.status(400).json({
        success: false,
        error: 'OTP not found or expired'
      });
    }

    // Check if OTP is expired
    if (Date.now() > otpData.expiresAt) {
      otpStore.delete(email);
      return res.status(400).json({
        success: false,
        error: 'OTP has expired'
      });
    }

    // Check attempts
    if (otpData.attempts >= 3) {
      otpStore.delete(email);
      return res.status(400).json({
        success: false,
        error: 'Too many failed attempts'
      });
    }

    // Verify OTP
    const hashedInputOTP = hashOTP(otp);
    if (otpData.otp !== hashedInputOTP) {
      otpData.attempts += 1;
      return res.status(400).json({
        success: false,
        error: 'Invalid OTP'
      });
    }

    // Mark as verified
    otpStore.delete(email);

    res.json({
      success: true,
      message: 'OTP verified successfully'
    });
  } catch (error) {
    console.error('❌ Verify OTP error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
});

// Reset password
router.post('/reset-password', (req, res) => {
  try {
    const { email, newPassword } = req.body;

    if (!email || !newPassword) {
      return res.status(400).json({
        success: false,
        error: 'Email and new password are required'
      });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({
        success: false,
        error: 'Password must be at least 6 characters long'
      });
    }

    const db = getDatabase();

    db.get('SELECT id FROM users WHERE email = ?', [email], async (err, user) => {
      if (err) return res.status(500).json({ success: false, error: 'Database error' });

      if (!user) {
        return res.status(404).json({
          success: false,
          error: 'Email not registered'
        });
      }

      try {
        const saltRounds = 12;
        const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

        db.run(
          'UPDATE users SET password = ? WHERE email = ?',
          [hashedPassword, email],
          function (err) {
            if (err) return res.status(500).json({ success: false, error: 'Failed' });

            console.log(`✅ Password reset successfully for ${email}`);
            res.json({
              success: true,
              message: 'Password reset successfully'
            });
          }
        );
      } catch (error) {
        console.error('❌ Reset error:', error);
        res.status(500).json({ success: false, error: 'Internal error' });
      }
    });
  } catch (error) {
    console.error('❌ Reset password error:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

module.exports = router;