
require('dotenv').config();

const connectDB = require('./config/db');
const app = require('./app');
const ScoringRule = require('./models/ScoringRule');
const defaultRules = require('./config/defaultRules');

const PORT = process.env.PORT || 5000;

if (!process.env.JWT_SECRET) {
  console.warn(
    '[ACADEXA] WARNING: JWT_SECRET is missing. Set a secure JWT_SECRET in Render environment variables.'
  );
}

async function ensureRules() {
  const count = await ScoringRule.countDocuments();

  if (count === 0) {
    await ScoringRule.insertMany(defaultRules);
    console.log('[ACADEXA] Default appraisal rules created');
  }
}

async function startServer() {
  try {
    await connectDB();
    await ensureRules();

    app.listen(PORT, () => {
      console.log(`[ACADEXA] Server running on port ${PORT}`);
    });
  } catch (err) {
    console.error(
      '[ACADEXA] Could not start the server:',
      err.message
    );
    process.exit(1);
  }
}

startServer();
