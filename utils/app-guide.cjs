/**
 * Application guide and knowledge base for the help chatbot.
 */

const APP_GUIDE = {
  app_name: "Solvenut",
  tagline: "Connect with experts for decisions, projects, and career guidance",

  main_features: {
    expert_booking: {
      title: "How to Book an Expert",
      description: "Find and book experts for consultations.",
      steps: [
        "Sign up as a client, or log in if you already have an account.",
        "Open the Experts page.",
        "Review expert profiles, specialties, rates, and ratings.",
        "Choose an expert and start the booking flow.",
        "Complete payment when prompted.",
        "After payment, open Client Chat to continue with that expert.",
      ],
      faq: [
        {
          q: "How much does it cost?",
          a: "Pricing depends on the expert. Check the rate shown on each expert profile.",
        },
        {
          q: "Can I cancel a booking?",
          a: "Cancellation depends on the booking state and platform policy. Check the booking details before the session begins.",
        },
      ],
    },

    payments: {
      title: "Payments",
      description: "Pay securely for expert access and consultations.",
      steps: [
        "Choose the expert you want to work with.",
        "Continue to payment from the booking flow.",
        "Complete the Razorpay checkout using an available payment method.",
        "Return to Solvenut after payment confirmation.",
        "If payment succeeds, the related expert chat becomes available.",
      ],
      faq: [
        {
          q: "Which payment methods are supported?",
          a: "The checkout supports methods made available by Razorpay, such as cards, UPI, and wallets.",
        },
        {
          q: "What if payment fails?",
          a: "Check the payment details, available balance, and network connection, then try again. If money is deducted but access is missing, contact support with the payment details.",
        },
      ],
    },

    messaging: {
      title: "How to Chat with Experts",
      description: "Use real-time messaging with an expert after access is available.",
      steps: [
        "Complete the required booking or payment flow for an expert.",
        "Open Client Chat.",
        "Select the expert conversation.",
        "Type your message and send it.",
        "Use attachments when you need to share files.",
        "Start a video call from the conversation when a live discussion is better.",
      ],
      features: [
        "Real-time messages",
        "Attachments",
        "Conversation history",
        "Read and presence signals when available",
      ],
    },

    video_calling: {
      title: "How to Use Video Calls",
      description: "Start a live consultation from chat.",
      steps: [
        "Open the chat with the expert.",
        "Choose the video call action.",
        "Allow camera and microphone access if the browser asks.",
        "Wait for the expert to accept the call.",
        "Use the call controls for camera, microphone, and ending the call.",
      ],
      requirements: [
        "Stable internet connection",
        "Camera and microphone access",
        "A modern browser with media permissions enabled",
      ],
    },

    expert_dashboard: {
      title: "Expert Dashboard",
      description: "Manage your expert account and client activity.",
      steps: [
        "Sign up as an expert and complete your profile.",
        "Add your expertise, pricing, and profile details.",
        "Use the dashboard to review client activity and conversations.",
        "Respond to chats and incoming calls from clients.",
        "Keep profile information current so clients know what you offer.",
      ],
      profile_tips: [
        "Use a clear professional photo.",
        "Write a specific bio that explains what you help with.",
        "Keep pricing and expertise details accurate.",
        "Reply promptly to build trust with clients.",
      ],
    },

    client_dashboard: {
      title: "Client Dashboard",
      description: "Keep track of your work with experts.",
      features: [
        "Review active and previous expert relationships",
        "Open chats with experts",
        "Track useful decision context",
        "Return to expert conversations quickly",
      ],
    },

    signup_and_auth: {
      title: "Getting Started",
      description: "Create an account or sign in.",
      for_clients: {
        steps: [
          "Choose Sign Up as Client.",
          "Enter your details and create a password, or use Google sign-in if available.",
          "Complete any requested verification.",
          "Finish your profile and start browsing experts.",
        ],
      },
      for_experts: {
        steps: [
          "Choose Sign Up as Expert.",
          "Create your account and complete verification.",
          "Add your expertise, bio, photo, and pricing details.",
          "Finish setup so clients can discover you.",
        ],
      },
    },

    troubleshooting: {
      title: "Troubleshooting",
      description: "Try these checks for common issues.",
      common_issues: [
        {
          issue: "Video call will not connect",
          solution: "Check the internet connection, allow camera and microphone permissions, then refresh and try again.",
        },
        {
          issue: "Payment failed",
          solution: "Verify payment details, balance, and network connection, then try another supported method if needed.",
        },
        {
          issue: "Chat messages are not sending",
          solution: "Check the connection, refresh the page, and retry after a moment.",
        },
        {
          issue: "I cannot find an expert conversation",
          solution: "Open Client Chat and check the conversation list for the expert you booked or paid for.",
        },
      ],
    },
  },

  contact_support: {
    email: "support@solvenut.com",
  },
};

const INTENT_RULES = [
  {
    key: "video_calling",
    terms: ["video call", "camera", "microphone", "mic", "call", "meeting"],
  },
  {
    key: "payments",
    terms: ["payment", "pay", "paid", "razorpay", "upi", "refund", "money"],
  },
  {
    key: "messaging",
    terms: ["chat", "message", "messages", "attachment", "file", "conversation"],
  },
  {
    key: "expert_dashboard",
    terms: ["expert dashboard", "expert profile", "earnings", "availability", "become expert"],
  },
  {
    key: "client_dashboard",
    terms: ["client dashboard", "my bookings", "booking history"],
  },
  {
    key: "signup_and_auth",
    terms: ["signup", "sign up", "register", "login", "log in", "password", "account"],
  },
  {
    key: "expert_booking",
    terms: ["book", "booking", "browse experts", "find expert", "hire expert"],
  },
  {
    key: "troubleshooting",
    terms: ["help", "issue", "problem", "error", "not working", "failed", "cannot", "can't"],
  },
];

const TROUBLESHOOTING_TERMS = [
  "issue",
  "problem",
  "error",
  "not working",
  "failed",
  "cannot",
  "can't",
  "wont",
  "won't",
  "not sending",
  "not connect",
];

const NUMBERED_TOPIC_MAP = {
  "1": "expert_booking",
  "2": "messaging",
  "3": "video_calling",
  "4": "signup_and_auth",
  "5": "client_dashboard",
  "6": "troubleshooting",
  "7": "payments",
};

function normalizeQuestion(userQuestion) {
  return String(userQuestion || "")
    .toLowerCase()
    .replace(/[^\w\s']/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function scoreIntent(question, rule) {
  return rule.terms.reduce((score, term) => {
    return question.includes(term) ? score + (term.includes(" ") ? 2 : 1) : score;
  }, 0);
}

function getRelevantGuide(userQuestion) {
  const question = normalizeQuestion(userQuestion);

  if (NUMBERED_TOPIC_MAP[question]) {
    return APP_GUIDE.main_features[NUMBERED_TOPIC_MAP[question]];
  }

  if (TROUBLESHOOTING_TERMS.some((term) => question.includes(term))) {
    return APP_GUIDE.main_features.troubleshooting;
  }

  let bestMatch = null;

  for (const rule of INTENT_RULES) {
    const score = scoreIntent(question, rule);
    if (!score) continue;

    if (!bestMatch || score > bestMatch.score) {
      bestMatch = { key: rule.key, score };
    }
  }

  return bestMatch ? APP_GUIDE.main_features[bestMatch.key] : null;
}

function formatList(items) {
  return items.map((item) => `- ${item}`).join("\n");
}

function formatGuide(guide) {
  if (!guide) {
    return `Welcome to ${APP_GUIDE.app_name} Help.

Type a number to see help:
1. Booking experts
2. Chat and messaging
3. Video calls
4. Account setup and signup
5. Dashboard features
6. Troubleshooting
7. Payments

You can also type your own question.`;
  }

  let formatted = `${guide.title}\n${guide.description}\n`;

  if (guide.steps) {
    formatted += `\nSteps:\n${formatList(guide.steps)}\n`;
  }

  if (guide.features) {
    formatted += `\nWhat you can do:\n${formatList(guide.features)}\n`;
  }

  if (guide.requirements) {
    formatted += `\nYou will need:\n${formatList(guide.requirements)}\n`;
  }

  if (guide.profile_tips) {
    formatted += `\nTips:\n${formatList(guide.profile_tips)}\n`;
  }

  if (guide.common_issues) {
    formatted += "\nCommon fixes:\n";
    guide.common_issues.forEach((item) => {
      formatted += `- ${item.issue}: ${item.solution}\n`;
    });
  }

  if (guide.faq && guide.faq.length > 0) {
    formatted += "\nFAQ:\n";
    guide.faq.forEach((item) => {
      formatted += `- ${item.q} ${item.a}\n`;
    });
  }

  if (guide.for_clients || guide.for_experts) {
    if (guide.for_clients?.steps) {
      formatted += `\nFor clients:\n${formatList(guide.for_clients.steps)}\n`;
    }

    if (guide.for_experts?.steps) {
      formatted += `\nFor experts:\n${formatList(guide.for_experts.steps)}\n`;
    }
  }

  return `${formatted.trim()}\n\nStill stuck? Contact ${APP_GUIDE.contact_support.email}.`;
}

module.exports = {
  APP_GUIDE,
  getRelevantGuide,
  formatGuide,
};
