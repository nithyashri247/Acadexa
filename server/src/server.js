import 'dotenv/config';
import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import rateLimit from 'express-rate-limit';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  User,
  Activity,
  Message,
  Notification,
  AuditLog
} from './models.js';

import { auth, roles } from './middleware.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

app.use(helmet());
app.use(cors({
  origin: process.env.CLIENT_ORIGIN || 'http://localhost:5173'
}));
app.use(express.json({ limit: '1mb' }));
app.use(morgan('dev'));
const frontendPath = path.resolve(__dirname, '../../client/dist');
app.use(express.static(frontendPath));
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/')) return next();
  res.sendFile(path.join(frontendPath, 'index.html'));
});

app.use(
  '/api/auth',
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 40
  })
);

const asyncRoute = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

const notify = async (user, title, body, link = '') =>
  Notification.create({ user, title, body, link });

const audit = async (actor, action, target, metadata = {}) =>
  AuditLog.create({
    actor: actor ? actor._id : null,
    action,
    target,
    metadata
  });

// Health check
app.get('/api/health', (req, res) => {
  res.json({ ok: true, app: 'ACADEXA' });
});

// Register HOD or Faculty
app.post('/api/auth/register', asyncRoute(async (req, res) => {
  let {
    name,
    email,
    employeeId,
    institution,
    department,
    designation,
    role,
    password
  } = req.body;

  name = String(name || '').trim();
  email = String(email || '').trim().toLowerCase();
  employeeId = String(employeeId || '').trim();
  institution = String(institution || '').trim();
  department = String(department || '').trim();
  designation = String(designation || '').trim();
  role = String(role || '').toUpperCase();

  if (
    !name || !email || !employeeId || !institution ||
    !department || !designation || !password
  ) {
    return res.status(400).json({
      message: 'Complete all required fields.'
    });
  }

  if (!['HOD', 'FACULTY'].includes(role)) {
    return res.status(400).json({
      message: 'Public registration is available for HOD and Faculty only.'
    });
  }

  if (String(password).length < 8) {
    return res.status(400).json({
      message: 'Password must contain at least 8 characters.'
    });
  }

  const existingUser = await User.findOne({
    $or: [{ email }, { employeeId }]
  });

  if (existingUser) {
    return res.status(409).json({
      message: 'Email or employee ID is already registered.'
    });
  }

  const user = await User.create({
    name,
    email,
    employeeId,
    institution,
    department,
    designation,
    role,
    passwordHash: await bcrypt.hash(String(password), 12),
    status: 'PENDING'
  });

  const recipients = role === 'HOD'
    ? await User.find({ role: 'ADMIN', status: 'APPROVED' })
    : await User.find({
        role: 'HOD',
        status: 'APPROVED',
        institution,
        department
      });

  for (const recipient of recipients) {
    await notify(
      recipient,
      role === 'HOD' ? 'HOD access request' : 'Faculty access request',
      `${name} has requested ${role === 'HOD' ? 'HOD' : 'faculty'} access for ${department}.`,
      '/approvals'
    );
  }

  await audit(user, 'REGISTER_REQUEST', user._id.toString(), {
    role,
    department
  });

  return res.status(201).json({
    message: role === 'HOD'
      ? 'Registration submitted. Admin approval is required before login.'
      : 'Registration submitted. Your HOD must approve your account before login.'
  });
}));

// Login — corrected
app.post('/api/auth/login', asyncRoute(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');

  if (!email || !password) {
    return res.status(400).json({
      message: 'Email and password are required.'
    });
  }

  const user = await User.findOne({ email });

  if (!user) {
    return res.status(401).json({
      message: 'Invalid email or password.'
    });
  }

  if (!user.passwordHash) {
    console.error(`Missing passwordHash for user: ${user.email}`);

    return res.status(500).json({
      message: 'Account password setup is incomplete. Contact the administrator.'
    });
  }

  const passwordMatches = await bcrypt.compare(
    password,
    user.passwordHash
  );

  if (!passwordMatches) {
    return res.status(401).json({
      message: 'Invalid email or password.'
    });
  }

  if (user.role !== 'ADMIN' && user.status !== 'APPROVED') {
    return res.status(403).json({
      message: user.status === 'REJECTED'
        ? `Access request rejected. ${user.reviewReason || 'Contact your reviewer.'}`
        : 'Your access request is pending approval.'
    });
  }

  if (!process.env.JWT_SECRET) {
    throw new Error('JWT_SECRET is missing from server/.env');
  }

  const token = jwt.sign(
    { id: user._id },
    process.env.JWT_SECRET,
    { expiresIn: '8h' }
  );

  await audit(user, 'LOGIN', user._id.toString());

  return res.json({
    token,
    user: {
      id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
      department: user.department,
      institution: user.institution
    }
  });
}));

// Initial Admin setup
app.post('/api/auth/setup-admin', asyncRoute(async (req, res) => {
  if (
    !process.env.ADMIN_SETUP_KEY ||
    req.headers['x-setup-key'] !== process.env.ADMIN_SETUP_KEY
  ) {
    return res.status(403).json({
      message: 'Invalid setup key.'
    });
  }

  if (await User.exists({ role: 'ADMIN' })) {
    return res.status(409).json({
      message: 'Admin already exists.'
    });
  }

  const {
    name,
    email,
    employeeId,
    institution,
    department,
    designation,
    password
  } = req.body;

  if (
    !name || !email || !employeeId || !institution ||
    !department || !designation || !password ||
    String(password).length < 12
  ) {
    return res.status(400).json({
      message: 'Provide all fields and a password of at least 12 characters.'
    });
  }

  const user = await User.create({
    name: String(name).trim(),
    email: String(email).trim().toLowerCase(),
    employeeId: String(employeeId).trim(),
    institution: String(institution).trim(),
    department: String(department).trim(),
    designation: String(designation).trim(),
    role: 'ADMIN',
    status: 'APPROVED',
    passwordHash: await bcrypt.hash(String(password), 12)
  });

  return res.status(201).json({
    message: 'Initial Admin created. Remove/rotate ADMIN_SETUP_KEY after setup.',
    id: user._id
  });
}));

// Current authenticated user
app.get('/api/auth/me', auth, (req, res) => {
  res.json({ user: req.user });
});

// Pending approval requests
app.get('/api/approvals', auth, roles('ADMIN', 'HOD'),
  asyncRoute(async (req, res) => {
    const query = req.user.role === 'ADMIN'
      ? { role: 'HOD', status: 'PENDING' }
      : {
          role: 'FACULTY',
          status: 'PENDING',
          institution: req.user.institution,
          department: req.user.department
        };

    const users = await User.find(query)
      .select('name email employeeId institution department designation role status createdAt')
      .sort({ createdAt: 1 });

    res.json(users);
  })
);

// Approve or reject account requests
app.patch('/api/approvals/:id', auth, roles('ADMIN', 'HOD'),
  asyncRoute(async (req, res) => {
    const { decision, reason = '' } = req.body;

    if (!['APPROVED', 'REJECTED'].includes(decision)) {
      return res.status(400).json({
        message: 'Decision must be APPROVED or REJECTED.'
      });
    }

    const target = await User.findById(req.params.id);

    if (!target) {
      return res.status(404).json({ message: 'Request not found.' });
    }

    const allowed = req.user.role === 'ADMIN'
      ? target.role === 'HOD'
      : target.role === 'FACULTY' &&
        target.institution === req.user.institution &&
        target.department === req.user.department;

    if (!allowed || target.status !== 'PENDING') {
      return res.status(403).json({
        message: 'You cannot review this request.'
      });
    }

    target.status = decision;
    target.reviewedBy = req.user._id;
    target.reviewReason = String(reason).slice(0, 500);

    await target.save();

    await notify(
      target,
      decision === 'APPROVED' ? 'Access approved' : 'Access request rejected',
      decision === 'APPROVED'
        ? 'Your ACADEXA access is now enabled.'
        : `Reason: ${target.reviewReason || 'Please contact your reviewer.'}`,
      '/'
    );

    await audit(
      req.user,
      `ACCOUNT_${decision}`,
      target._id.toString(),
      { reason: target.reviewReason }
    );

    return res.json({
      message: `Account ${decision.toLowerCase()}.`
    });
  })
);

// Authorized contacts
app.get('/api/users/reviewers', auth, asyncRoute(async (req, res) => {
  const query = req.user.role === 'FACULTY'
    ? {
        role: 'HOD',
        status: 'APPROVED',
        institution: req.user.institution,
        department: req.user.department
      }
    : req.user.role === 'HOD'
      ? { role: 'ADMIN', status: 'APPROVED' }
      : {
          role: { $in: ['HOD', 'FACULTY'] },
          status: 'APPROVED'
        };

  const users = await User.find(query)
    .select('name email role department institution')
    .sort({ name: 1 });

  res.json(users);
}));

// List academic activities
app.get('/api/activities', auth, asyncRoute(async (req, res) => {
  const query = req.user.role === 'FACULTY'
    ? { owner: req.user._id }
    : req.user.role === 'HOD'
      ? { department: req.user.department, owner: { $ne: req.user._id } }
      : {};

  if (req.query.status) {
    query.status = req.query.status;
  }

  const activities = await Activity.find(query)
    .populate('owner', 'name email department designation')
    .sort({ updatedAt: -1 });

  res.json(activities);
}));

// Create academic activity
app.post('/api/activities', auth, roles('FACULTY'),
  asyncRoute(async (req, res) => {
    const {
      category,
      title,
      details,
      academicYear,
      proofUrl,
      submit
    } = req.body;

    if (!category || !String(title || '').trim()) {
      return res.status(400).json({
        message: 'Category and title are required.'
      });
    }

    const activity = await Activity.create({
      owner: req.user._id,
      department: req.user.department,
      category,
      title: String(title).trim(),
      details: String(details || '').slice(0, 5000),
      academicYear: String(academicYear || ''),
      proofUrl: String(proofUrl || ''),
      status: submit ? 'SUBMITTED' : 'DRAFT'
    });

    if (submit) {
      const hod = await User.findOne({
        role: 'HOD',
        status: 'APPROVED',
        institution: req.user.institution,
        department: req.user.department
      });

      if (hod) {
        await notify(
          hod,
          'Academic record submitted',
          `${req.user.name} submitted: ${activity.title}`,
          '/activities'
        );
      }
    }

    await audit(
      req.user,
      submit ? 'ACTIVITY_SUBMITTED' : 'ACTIVITY_DRAFT',
      activity._id.toString()
    );

    return res.status(201).json(activity);
  })
);

// Edit academic activity
app.put('/api/activities/:id', auth, roles('FACULTY'),
  asyncRoute(async (req, res) => {
    const activity = await Activity.findOne({
      _id: req.params.id,
      owner: req.user._id
    });

    if (!activity) {
      return res.status(404).json({ message: 'Record not found.' });
    }

    if (!['DRAFT', 'CHANGES_REQUESTED', 'REJECTED'].includes(activity.status)) {
      return res.status(409).json({
        message: 'Only drafts or records returned for changes can be edited.'
      });
    }

    for (const key of [
      'category',
      'title',
      'details',
      'academicYear',
      'proofUrl'
    ]) {
      if (req.body[key] !== undefined) {
        activity[key] = req.body[key];
      }
    }

    if (req.body.submit) {
      activity.status = 'SUBMITTED';

      const hod = await User.findOne({
        role: 'HOD',
        status: 'APPROVED',
        institution: req.user.institution,
        department: req.user.department
      });

      if (hod) {
        await notify(
          hod,
          'Academic record submitted',
          `${req.user.name} submitted: ${activity.title}`,
          '/activities'
        );
      }
    }

    await activity.save();
    return res.json(activity);
  })
);

// Delete draft activity
app.delete('/api/activities/:id', auth, roles('FACULTY'),
  asyncRoute(async (req, res) => {
    const activity = await Activity.findOne({
      _id: req.params.id,
      owner: req.user._id,
      status: 'DRAFT'
    });

    if (!activity) {
      return res.status(404).json({
        message: 'Only your draft records can be deleted.'
      });
    }

    await activity.deleteOne();

    return res.json({ message: 'Draft deleted.' });
  })
);

// HOD reviews submitted academic records
app.patch('/api/activities/:id/review', auth, roles('HOD'),
  asyncRoute(async (req, res) => {
    const { decision, comment = '' } = req.body;

    if (!['APPROVED', 'CHANGES_REQUESTED', 'REJECTED'].includes(decision)) {
      return res.status(400).json({
        message: 'Invalid review decision.'
      });
    }

    const activity = await Activity.findOne({
      _id: req.params.id,
      department: req.user.department,
      status: 'SUBMITTED'
    }).populate('owner');

    if (
      !activity ||
      !activity.owner ||
      activity.owner.institution !== req.user.institution
    ) {
      return res.status(404).json({
        message: 'Submitted record not found in your department.'
      });
    }

    activity.status = decision;
    activity.reviewComment = String(comment).slice(0, 1000);
    activity.reviewedBy = req.user._id;
    activity.reviewedAt = new Date();

    await activity.save();

    await notify(
      activity.owner,
      'Academic record reviewed',
      `${activity.title}: ${decision.replace('_', ' ').toLowerCase()}. ${activity.reviewComment}`,
      '/activities'
    );

    await audit(
      req.user,
      `ACTIVITY_${decision}`,
      activity._id.toString(),
      { comment: activity.reviewComment }
    );

    return res.json({
      message: 'Review saved.',
      activity
    });
  })
);

// List messages
app.get('/api/messages', auth, asyncRoute(async (req, res) => {
  const messages = await Message.find({
    $or: [
      { sender: req.user._id },
      { recipient: req.user._id }
    ]
  })
    .populate('sender', 'name role department')
    .populate('recipient', 'name role department')
    .sort({ createdAt: 1 })
    .limit(500);

  res.json(messages);
}));

// Send message
app.post('/api/messages', auth, asyncRoute(async (req, res) => {
  const { recipientId, body } = req.body;
  const recipient = await User.findById(recipientId);

  if (
    !recipient ||
    recipient.status !== 'APPROVED' ||
    (recipient.role === 'ADMIN' && req.user.role === 'ADMIN')
  ) {
    return res.status(400).json({
      message: 'Recipient is unavailable.'
    });
  }

  const linked =
    (
      req.user.role === 'FACULTY' &&
      (
        (
          recipient.role === 'HOD' &&
          recipient.department === req.user.department &&
          recipient.institution === req.user.institution
        ) ||
        recipient.role === 'ADMIN'
      )
    ) ||
    (
      req.user.role === 'HOD' &&
      (
        recipient.role === 'ADMIN' ||
        (
          recipient.role === 'FACULTY' &&
          recipient.department === req.user.department &&
          recipient.institution === req.user.institution
        )
      )
    ) ||
    (
      req.user.role === 'ADMIN' &&
      ['HOD', 'FACULTY'].includes(recipient.role)
    );

  if (!linked) {
    return res.status(403).json({
      message: 'Messaging is limited to your authorized academic contacts.'
    });
  }

  if (!String(body || '').trim()) {
    return res.status(400).json({
      message: 'Message cannot be empty.'
    });
  }

  const message = await Message.create({
    sender: req.user._id,
    recipient: recipient._id,
    body: String(body).trim().slice(0, 3000)
  });

  await notify(
    recipient,
    'New message',
    `Message from ${req.user.name}.`,
    '/messages'
  );

  return res.status(201).json(
    await message.populate([
      { path: 'sender', select: 'name role department' },
      { path: 'recipient', select: 'name role department' }
    ])
  );
}));

// Mark message as read
app.patch('/api/messages/:id/read', auth, asyncRoute(async (req, res) => {
  const message = await Message.findOneAndUpdate(
    {
      _id: req.params.id,
      recipient: req.user._id,
      readAt: null
    },
    { readAt: new Date() },
    { new: true }
  );

  res.json({ ok: true, updated: !!message });
}));

// Notifications
app.get('/api/notifications', auth, asyncRoute(async (req, res) => {
  const notifications = await Notification.find({
    user: req.user._id
  })
    .sort({ createdAt: -1 })
    .limit(100);

  res.json(notifications);
}));

// Mark notification as read
app.patch('/api/notifications/:id/read', auth,
  asyncRoute(async (req, res) => {
    await Notification.updateOne(
      { _id: req.params.id, user: req.user._id },
      { readAt: new Date() }
    );

    res.json({ ok: true });
  })
);

// Dashboard summary
app.get('/api/summary', auth, asyncRoute(async (req, res) => {
  const ownerQuery = req.user.role === 'FACULTY'
    ? { owner: req.user._id }
    : req.user.role === 'HOD'
      ? { department: req.user.department }
      : {};

  const [records, pending, unread] = await Promise.all([
    Activity.countDocuments(ownerQuery),
    Activity.countDocuments({
      ...ownerQuery,
      status: 'SUBMITTED'
    }),
    Notification.countDocuments({
      user: req.user._id,
      readAt: null
    })
  ]);

  const extra = req.user.role === 'ADMIN'
    ? {
        pendingRequests: await User.countDocuments({
          role: 'HOD',
          status: 'PENDING'
        })
      }
    : req.user.role === 'HOD'
      ? {
          pendingRequests: await User.countDocuments({
            role: 'FACULTY',
            status: 'PENDING',
            institution: req.user.institution,
            department: req.user.department
          })
        }
      : {};

  res.json({
    records,
    pending,
    unread,
    ...extra
  });
}));

// Admin audit logs
app.get('/api/audit', auth, roles('ADMIN'),
  asyncRoute(async (req, res) => {
    const logs = await AuditLog.find()
      .populate('actor', 'name email role')
      .sort({ createdAt: -1 })
      .limit(200);

    res.json(logs);
  })
);

// Central error handler
app.use((err, req, res, next) => {
  console.error(err);

  if (err.code === 11000) {
    return res.status(409).json({
      message: 'A record with this unique value already exists.'
    });
  }

  return res.status(500).json({
    message: 'Unexpected server error. Check server logs.'
  });
});

// Start server
const port = process.env.PORT || 5000;

if (!process.env.JWT_SECRET) {
  console.warn('WARNING: Set JWT_SECRET in server/.env');
}

mongoose.connect(
  process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/acadexa'
)
  .then(() => {
    app.listen(port, () => {
      console.log(`ACADEXA API running on http://localhost:${port}`);
    });
  })
  .catch((err) => {
    console.error('MongoDB connection failed:', err.message);
    process.exit(1);
  });
