/**
 * DATABASE HELPERS – Extract repeated query patterns (eliminates ~100 lines of duplication)
 */

const { normalizeEmail } = require("./shared-helpers.cjs");

// Get rating stats for an expert (replace 4+ duplications)
const getRatingStats = async (Rating, expertEmailRaw) => {
  const expertEmail = normalizeEmail(expertEmailRaw);
  if (!expertEmail) return { avgRating: 0, ratingsCount: 0 };
  
  const summary = await Rating.aggregate([
    { $match: { expertEmail } },
    { $group: { _id: "$expertEmail", avgRating: { $avg: "$score" }, ratingsCount: { $sum: 1 } } },
  ]);
  
  const stats = summary[0] || { avgRating: 0, ratingsCount: 0 };
  return {
    avgRating: Number((stats.avgRating || 0).toFixed(2)),
    ratingsCount: stats.ratingsCount || 0,
  };
};

// Find user account (User OR Expert) - replace 3+ duplications
const findUserAccount = async (User, Expert, emailRaw) => {
  const email = normalizeEmail(emailRaw);
  if (!email) return { model: null, account: null, role: null };
  
  let account = await User.findOne({ email });
  if (account) return { model: "User", account, role: "client" };
  
  account = await Expert.findOne({ email });
  if (account) return { model: "Expert", account, role: "expert" };
  
  return { model: null, account: null, role: null };
};

// Get approved expert - replace 5+ duplications
const getApprovedExpert = async (Expert, emailRaw) => {
  const email = normalizeEmail(emailRaw);
  if (!email) return null;
  
  const expert = await Expert.findOne({ email }).select("-password");
  return expert && expert.status === "approved" ? expert : null;
};

// Build expert profile with ratings - replace 3+ duplications
const buildExpertProfile = async (expert, Rating) => {
  if (!expert) return null;
  
  const stats = await getRatingStats(Rating, expert.email);
  return {
    ...expert.toObject?.() || expert,
    avgRating: stats.avgRating,
    ratingsCount: stats.ratingsCount,
  };
};

// Batch get rating stats for multiple experts - optimize home data query
const getRatingStatsBatch = async (Rating, expertEmails) => {
  if (!expertEmails || expertEmails.length === 0) return new Map();
  
  const normalizedEmails = expertEmails.map(normalizeEmail).filter(Boolean);
  const stats = await Rating.aggregate([
    { $match: { expertEmail: { $in: normalizedEmails } } },
    { $group: { _id: "$expertEmail", avgRating: { $avg: "$score" }, ratingsCount: { $sum: 1 } } },
  ]);
  
  return new Map(
    stats.map((s) => [
      normalizeEmail(s._id),
      {
        avgRating: Number((s.avgRating || 0).toFixed(2)),
        ratingsCount: s.ratingsCount || 0,
      },
    ])
  );
};

module.exports = {
  getRatingStats,
  findUserAccount,
  getApprovedExpert,
  buildExpertProfile,
  getRatingStatsBatch,
};
