require("dotenv").config({ quiet: true });

const mongoose = require("mongoose");
const { connectDatabase, Expert } = require("../models/app-models.cjs");

const expertProfiles = [
  { name: "Aarav Mehta", email: "aarav.mehta@experts.solvenut.demo", field: "programming", experience: 11, price: 1299, headline: "Staff engineer for scalable web products and practical architecture decisions.", skills: ["React", "Node.js", "System design"], languages: ["English", "Hindi"], availability: "Available today", sessionCount: 184 },
  { name: "Priya Nair", email: "priya.nair@experts.solvenut.demo", field: "programming", experience: 8, price: 999, headline: "Full-stack mentor helping developers debug, ship, and level up confidently.", skills: ["JavaScript", "Python", "Code reviews"], languages: ["English", "Malayalam"], availability: "Replies within 2 hours", sessionCount: 142 },
  { name: "Kabir Shah", email: "kabir.shah@experts.solvenut.demo", field: "programming", experience: 9, price: 1099, headline: "Backend specialist for APIs, databases, and reliable product foundations.", skills: ["APIs", "PostgreSQL", "Performance"], languages: ["English", "Gujarati"], availability: "Available this week", sessionCount: 119 },
  { name: "Neha Kapoor", email: "neha.kapoor@experts.solvenut.demo", field: "devops", experience: 10, price: 1399, headline: "Cloud and DevOps advisor for dependable releases without overengineering.", skills: ["AWS", "Docker", "CI/CD"], languages: ["English", "Hindi"], availability: "Available today", sessionCount: 176 },
  { name: "Rohan Iyer", email: "rohan.iyer@experts.solvenut.demo", field: "devops", experience: 7, price: 1099, headline: "SRE coach for observability, incident response, and production readiness.", skills: ["Kubernetes", "Terraform", "Monitoring"], languages: ["English", "Tamil"], availability: "Replies within 4 hours", sessionCount: 97 },
  { name: "Isha Verma", email: "isha.verma@experts.solvenut.demo", field: "academics", experience: 12, price: 899, headline: "Research and study strategist for high-stakes exams and graduate applications.", skills: ["Study plans", "Research", "Applications"], languages: ["English", "Hindi"], availability: "Available this week", sessionCount: 216 },
  { name: "Arjun Sen", email: "arjun.sen@experts.solvenut.demo", field: "academics", experience: 6, price: 699, headline: "Learning systems mentor for focused preparation and better academic habits.", skills: ["Exam prep", "Learning systems", "Time management"], languages: ["English", "Bengali"], availability: "Available tomorrow", sessionCount: 88 },
  { name: "Meera Joshi", email: "meera.joshi@experts.solvenut.demo", field: "career", experience: 13, price: 1199, headline: "Career strategist for transitions, interviews, and senior-level positioning.", skills: ["Interviews", "Career change", "Compensation"], languages: ["English", "Hindi"], availability: "Available today", sessionCount: 241 },
  { name: "Vikram Rao", email: "vikram.rao@experts.solvenut.demo", field: "career", experience: 9, price: 999, headline: "Leadership coach for managers building clarity, influence, and momentum.", skills: ["Leadership", "Communication", "Job search"], languages: ["English", "Telugu"], availability: "Replies within 2 hours", sessionCount: 163 },
  { name: "Sana Qureshi", email: "sana.qureshi@experts.solvenut.demo", field: "business", experience: 14, price: 1499, headline: "Startup operator for validation, pricing, and practical growth strategy.", skills: ["Go-to-market", "Pricing", "Operations"], languages: ["English", "Urdu"], availability: "Available this week", sessionCount: 205 },
  { name: "Dev Malhotra", email: "dev.malhotra@experts.solvenut.demo", field: "business", experience: 8, price: 1199, headline: "Product and business advisor for early teams making smarter bets.", skills: ["Product strategy", "Market research", "Roadmaps"], languages: ["English", "Hindi"], availability: "Available tomorrow", sessionCount: 132 },
  { name: "Dr. Ananya Bose", email: "ananya.bose@experts.solvenut.demo", field: "medical", experience: 11, price: 1499, headline: "Health education and care-navigation guidance for informed next steps.", skills: ["Care navigation", "Wellness", "Health education"], languages: ["English", "Bengali"], availability: "Available this week", sessionCount: 154 },
];

async function seedExperts() {
  await connectDatabase(process.env.MONGO_URI || "mongodb://localhost:27017/solutionhub");

  await Expert.bulkWrite(
    expertProfiles.map((profile) => ({
      updateOne: {
        filter: { email: profile.email },
        update: { $set: { ...profile, role: "expert", status: "approved" } },
        upsert: true,
      },
    }))
  );

  console.log(`Seeded ${expertProfiles.length} approved expert profiles.`);
}

seedExperts()
  .catch((error) => {
    console.error("Unable to seed experts:", error.message);
    process.exitCode = 1;
  })
  .finally(() => mongoose.disconnect());
