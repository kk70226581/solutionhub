/* global process */

const SYSTEM_PROMPT = `You are Solvenut AI Expert.

Your role is to behave like a senior consultant helping users make important decisions.

Rules:
- Ask clarifying questions before giving advice if information is missing.
- Explain reasoning clearly.
- Compare multiple options.
- Discuss risks and tradeoffs.
- Create practical action plans.
- Avoid hallucinations.
- Admit uncertainty when needed.
- Recommend a human expert when confidence is low.
- Focus on actionable solutions instead of generic advice.

When the user needs medical, legal, tax, or investment advice, provide educational guidance only, explain uncertainty, and recommend a verified human expert when risk is meaningful.
Speak naturally, professionally, and directly.`;

const DOMAIN_CONTEXT = {
  career: "Career strategy, transitions, interviews, compensation, workplace decisions, and professional growth.",
  business: "Business strategy, startups, operations, market validation, pricing, and execution planning.",
  finance: "Personal finance education, budgeting, investment decision frameworks, and risk tradeoffs.",
  programming: "Software engineering, architecture, debugging strategy, learning plans, and project planning.",
  devops: "Cloud, CI/CD, infrastructure, reliability, deployment, monitoring, and operational maturity.",
  academics: "Study planning, research direction, exam preparation, learning systems, and academic choices.",
  medical: "General medical guidance, symptom triage education, care navigation, and risk awareness.",
  "medical guidance": "General medical guidance, symptom triage education, care navigation, and risk awareness.",
  "personal growth": "Habits, confidence, leadership, communication, life decisions, and personal development.",
};

const BEDROCK_MODEL_ID = process.env.BEDROCK_MODEL_ID || "google.gemma-3-4b-it";
const AI_EXPERT_PROVIDER = process.env.AI_EXPERT_PROVIDER || "bedrock";
const AWS_REGION = process.env.AWS_REGION || "us-east-1";
const BEDROCK_PROJECT_API_KEY = String(
  process.env.BEDROCK_PROJECT_API_KEY || process.env.Bedrock_project_API_key || ""
).trim();
const BEDROCK_MANTLE_BASE_URL = String(
  process.env.BEDROCK_MANTLE_BASE_URL ||
    `https://bedrock-mantle.${AWS_REGION}.api.aws/v1`
).replace(/\/$/, "");
const MAX_HISTORY_MESSAGES = 18;
const MAX_TOKENS = Number(process.env.AI_EXPERT_MAX_TOKENS || 800);
const TEMPERATURE = Number(process.env.AI_EXPERT_TEMPERATURE || 0.35);

let cachedBedrock = null;
let cachedCommands = null;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function normalizeDomain(domainRaw) {
  const value = String(domainRaw || "").trim().toLowerCase();
  if (!value) return "career";
  if (value.includes("medical")) return "medical guidance";
  if (value.includes("personal")) return "personal growth";
  return DOMAIN_CONTEXT[value] ? value : "career";
}

function getDomainContext(domainRaw) {
  const domain = normalizeDomain(domainRaw);
  return DOMAIN_CONTEXT[domain] || DOMAIN_CONTEXT.career;
}

function getAIProvider() {
  if (BEDROCK_PROJECT_API_KEY) return "bedrock-mantle";
  return String(AI_EXPERT_PROVIDER || "bedrock").trim().toLowerCase();
}

function estimateConfidence({ text, domain, userMessage, hadError = false }) {
  if (hadError) return 35;

  let score = 78;
  const answer = String(text || "").toLowerCase();
  const prompt = String(userMessage || "").trim();

  if (prompt.length < 40) score -= 14;
  if (answer.includes("?") && answer.includes("clarify")) score -= 8;
  if (answer.includes("i'm not sure") || answer.includes("uncertain") || answer.includes("cannot determine")) score -= 12;
  if (answer.includes("human expert") || answer.includes("verified expert")) score -= 8;
  if (answer.includes("step") || answer.includes("plan") || answer.includes("option")) score += 5;
  if (normalizeDomain(domain).includes("medical")) score -= 10;

  return Math.max(30, Math.min(95, Math.round(score)));
}

function getEscalationReason({ confidenceScore, text, domain, userMessage, hadError = false }) {
  const answer = String(text || "").toLowerCase();
  const prompt = String(userMessage || "").toLowerCase();

  if (hadError) return "service_unavailable";
  if (/\b(human|real person|consultant|specialist|expert)\b/.test(prompt)) return "human_requested";
  if (normalizeDomain(domain).includes("medical") || /\b(legal|tax|diagnosis|emergency)\b/.test(prompt)) return "high_stakes";
  if (Number(confidenceScore || 0) < 70) return "low_confidence";
  if (answer.includes("recommend a human expert") || answer.includes("verified human expert")) {
    return "ai_recommendation";
  }
  return "";
}

function buildSystemPrompt(domain) {
  const normalizedDomain = normalizeDomain(domain);
  const domainContext = getDomainContext(normalizedDomain);

  return `${SYSTEM_PROMPT}

Consultation domain: ${normalizedDomain}
Domain context: ${domainContext}

Response format:
- Start with the useful answer immediately.
- If information is missing, ask up to 3 sharp follow-up questions and explain why they matter.
- When enough information exists, provide options, tradeoffs, risks, and a practical action plan.
- End with a short confidence note such as "Confidence: high/medium/low" and whether a human expert would help.`;
}

function buildConverseRequest({ domain, messages }) {
  const systemPrompt = buildSystemPrompt(domain);
  const conversationMessages = messages
    .filter((message) => ["user", "assistant"].includes(message.role) && String(message.content || "").trim())
    .slice(-MAX_HISTORY_MESSAGES)
    .map((message) => ({
      role: message.role === "assistant" ? "assistant" : "user",
      content: [{ text: String(message.content).slice(0, 8000) }],
    }));

  return {
    modelId: BEDROCK_MODEL_ID,
    system: [{ text: systemPrompt }],
    messages: conversationMessages,
    // Converse provides one request shape across supported Bedrock providers.
    inferenceConfig: { maxTokens: MAX_TOKENS, temperature: TEMPERATURE },
  };
}

function buildMantleMessages({ domain, messages }) {
  return [
    { role: "system", content: buildSystemPrompt(domain) },
    ...messages
      .filter((message) =>
        ["user", "assistant"].includes(message.role) && String(message.content || "").trim()
      )
      .slice(-MAX_HISTORY_MESSAGES)
      .map((message) => ({
        role: message.role === "assistant" ? "assistant" : "user",
        content: String(message.content).slice(0, 8000),
      })),
  ];
}

async function requestMantle(body) {
  const response = await fetch(`${BEDROCK_MANTLE_BASE_URL}/chat/completions`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${BEDROCK_PROJECT_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    const error = new Error(
      payload?.error?.message || `Bedrock project API request failed (${response.status})`
    );
    error.name = payload?.error?.code || "BedrockMantleError";
    error.status = response.status;
    throw error;
  }

  return response;
}

async function getBedrockRuntime() {
  if (cachedBedrock && cachedCommands) {
    return { bedrock: cachedBedrock, ...cachedCommands };
  }

  const sdk = await import("@aws-sdk/client-bedrock-runtime");
  const {
    BedrockRuntimeClient,
    ConverseCommand,
    ConverseStreamCommand,
  } = sdk;

  cachedBedrock = new BedrockRuntimeClient({
    region: AWS_REGION,
    maxAttempts: 5,
    retryMode: "adaptive",
  });
  cachedCommands = {
    ConverseCommand,
    ConverseStreamCommand,
  };
  return { bedrock: cachedBedrock, ...cachedCommands };
}

async function sendWithRetry(factory, { retries = 2 } = {}) {
  let lastError = null;
  for (let attempt = 0; attempt <= retries; attempt += 1) {
    try {
      return await factory();
    } catch (err) {
      lastError = err;
      const status = Number(err?.$metadata?.httpStatusCode || 0);
      const isDailyQuotaExhausted = /too many tokens per day/i.test(String(err?.message || ""));
      const retryable =
        !isDailyQuotaExhausted &&
        (status === 429 ||
          status >= 500 ||
          ["ThrottlingException", "TooManyRequestsException", "ServiceUnavailableException"].includes(err?.name));
      if (!retryable || attempt === retries) break;
      await sleep(350 * Math.pow(2, attempt));
    }
  }
  throw lastError;
}

function parseResponse(payload) {
  // Mistral format - choices array
  if (Array.isArray(payload?.choices) && payload.choices.length > 0) {
    const content = payload.choices[0]?.message?.content || "";
    if (content) return content;
  }

  // Mistral format - outputs array
  if (payload?.outputs) {
    const text = payload.outputs
      .map((output) => output?.text || "")
      .filter(Boolean)
      .join("\n")
      .trim();
    if (text) return text;
  }

  // Mistral format alternative
  if (payload?.output?.message?.content) {
    const text = payload.output.message.content
      .map((part) => part?.text || "")
      .filter(Boolean)
      .join("\n")
      .trim();
    if (text) return text;
  }

  // Claude format
  const content = Array.isArray(payload?.content) ? payload.content : [];
  const claudeText = content
    .map((part) => (part?.type === "text" ? part.text : ""))
    .filter(Boolean)
    .join("\n")
    .trim();
  if (claudeText) return claudeText;

  // Fallback: log and return something
  console.error("Unknown response format:", JSON.stringify(payload).slice(0, 500));
  return "Unable to parse response from AI service";
}

function normalizeUsage(usage = {}) {
  const inputTokens = Number(usage.input_tokens || usage.inputTokens || usage.prompt_tokens || 0);
  const outputTokens = Number(
    usage.output_tokens || usage.outputTokens || usage.completion_tokens || 0
  );
  return {
    inputTokens,
    outputTokens,
    totalTokens: Number(usage.total_tokens || inputTokens + outputTokens),
  };
}

async function askMantleAIExpert({ domain, messages, userMessage }) {
  const response = await requestMantle({
    model: BEDROCK_MODEL_ID,
    messages: buildMantleMessages({ domain, messages }),
    max_tokens: MAX_TOKENS,
    temperature: TEMPERATURE,
  });
  const payload = await response.json();
  const text = String(payload?.choices?.[0]?.message?.content || "").trim();
  if (!text) throw new Error("Bedrock project API returned an empty response");

  const confidenceScore = estimateConfidence({ text, domain, userMessage });
  const escalationReason = getEscalationReason({ confidenceScore, text, domain, userMessage });
  return {
    text,
    confidenceScore,
    recommendEscalation: Boolean(escalationReason),
    escalationReason,
    tokenUsage: normalizeUsage(payload?.usage),
    modelId: payload?.model || BEDROCK_MODEL_ID,
    raw: { provider: getAIProvider() },
  };
}

async function streamMantleAIExpert({ domain, messages, userMessage, onToken }) {
  const response = await requestMantle({
    model: BEDROCK_MODEL_ID,
    messages: buildMantleMessages({ domain, messages }),
    max_tokens: MAX_TOKENS,
    temperature: TEMPERATURE,
    stream: true,
    stream_options: { include_usage: true },
  });
  if (!response.body) throw new Error("Bedrock project API returned no response stream");

  const decoder = new TextDecoder();
  let buffer = "";
  let text = "";
  let usage = {};

  const consumeEvent = (eventText) => {
    for (const line of eventText.split("\n")) {
      if (!line.startsWith("data:")) continue;
      const data = line.slice(5).trim();
      if (!data || data === "[DONE]") continue;
      const chunk = JSON.parse(data);
      const token = chunk?.choices?.[0]?.delta?.content || "";
      if (token) {
        text += token;
        onToken?.(token);
      }
      if (chunk?.usage) usage = { ...usage, ...chunk.usage };
    }
  };

  for await (const chunk of response.body) {
    buffer += decoder.decode(chunk, { stream: true }).replace(/\r\n/g, "\n");
    const events = buffer.split("\n\n");
    buffer = events.pop() || "";
    events.forEach(consumeEvent);
  }
  buffer += decoder.decode();
  if (buffer.trim()) consumeEvent(buffer);

  const finalText = text.trim();
  if (!finalText) throw new Error("Bedrock project API returned an empty response stream");
  const confidenceScore = estimateConfidence({ text: finalText, domain, userMessage });
  const escalationReason = getEscalationReason({
    confidenceScore,
    text: finalText,
    domain,
    userMessage,
  });
  return {
    text: finalText,
    confidenceScore,
    recommendEscalation: Boolean(escalationReason),
    escalationReason,
    tokenUsage: normalizeUsage(usage),
    modelId: BEDROCK_MODEL_ID,
    raw: { provider: getAIProvider() },
  };
}

async function askBedrockAIExpert({ domain, messages, userMessage }) {
  const { bedrock, ConverseCommand } = await getBedrockRuntime();
  const response = await sendWithRetry(() =>
    bedrock.send(new ConverseCommand(buildConverseRequest({ domain, messages })))
  );
  const text = parseResponse(response);
  const confidenceScore = estimateConfidence({ text, domain, userMessage });
  const escalationReason = getEscalationReason({ confidenceScore, text, domain, userMessage });

  return {
    text,
    confidenceScore,
    recommendEscalation: Boolean(escalationReason),
    escalationReason,
    tokenUsage: normalizeUsage(response?.usage),
    modelId: BEDROCK_MODEL_ID,
    raw: { stopReason: response?.stopReason, provider: getAIProvider() },
  };
}

async function streamBedrockAIExpert({ domain, messages, userMessage, onToken }) {
  const { bedrock, ConverseStreamCommand } = await getBedrockRuntime();
  const response = await sendWithRetry(() =>
    bedrock.send(new ConverseStreamCommand(buildConverseRequest({ domain, messages })))
  );
  let text = "";
  let usage = {};

  for await (const event of response.stream) {
    const token = event?.contentBlockDelta?.delta?.text || "";
    if (token) {
      text += token;
      onToken?.(token);
    }
    if (event?.metadata?.usage) usage = { ...usage, ...event.metadata.usage };
  }

  const confidenceScore = estimateConfidence({ text, domain, userMessage });
  const escalationReason = getEscalationReason({ confidenceScore, text, domain, userMessage });

  return {
    text: text.trim(),
    confidenceScore,
    recommendEscalation: Boolean(escalationReason),
    escalationReason,
    tokenUsage: normalizeUsage(usage),
    modelId: BEDROCK_MODEL_ID,
    raw: { provider: getAIProvider() },
  };
}

const askAIExpert = BEDROCK_PROJECT_API_KEY ? askMantleAIExpert : askBedrockAIExpert;
const streamAIExpert = BEDROCK_PROJECT_API_KEY
  ? streamMantleAIExpert
  : streamBedrockAIExpert;

export {
  askAIExpert,
  streamAIExpert,
  normalizeDomain,
  getDomainContext,
};
