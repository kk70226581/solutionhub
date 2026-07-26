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

const BEDROCK_MODEL_ID = process.env.BEDROCK_MODEL_ID || "amazon.nova-lite-v1:0";
const AI_EXPERT_PROVIDER = process.env.AI_EXPERT_PROVIDER || "bedrock";
const AWS_REGION = process.env.AWS_REGION || "us-east-1";
const MAX_HISTORY_MESSAGES = 18;
const MAX_TOKENS = Number(process.env.AI_EXPERT_MAX_TOKENS || 1400);
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

function isNovaModel(modelId = BEDROCK_MODEL_ID) {
  return String(modelId || "").toLowerCase().startsWith("amazon.nova-");
}

function getAIProvider() {
  return isNovaModel() ? "amazon-nova" : AI_EXPERT_PROVIDER;
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

function shouldEscalate(input) {
  return Boolean(getEscalationReason(input));
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
    // Amazon Nova accepts temperature or topP; use one predictable setting.
    inferenceConfig: { maxTokens: MAX_TOKENS, temperature: TEMPERATURE },
  };
}

function buildRequestBody({ domain, messages }) {
  const systemPrompt = buildSystemPrompt(domain);

  // Mistral format - does NOT support system parameter
  if (BEDROCK_MODEL_ID.includes("mistral")) {
    // Format messages for Mistral
    const formattedMessages = messages
      .filter((message) => ["user", "assistant"].includes(message.role) && String(message.content || "").trim())
      .slice(-MAX_HISTORY_MESSAGES)
      .map((message) => ({
        role: message.role === "assistant" ? "assistant" : "user",
        content: String(message.content).slice(0, 8000),
      }));

    // Prepend system prompt to first user message
    const firstUserIndex = formattedMessages.findIndex((m) => m.role === "user");
    if (firstUserIndex >= 0) {
      formattedMessages[firstUserIndex].content = `${systemPrompt}\n\nUser message: ${formattedMessages[firstUserIndex].content}`;
    }

    return {
      max_tokens: MAX_TOKENS,
      temperature: TEMPERATURE,
      top_p: 0.9,
      messages: formattedMessages,
    };
  }

  // Claude format (default)
  return {
    anthropic_version: "bedrock-2023-05-31",
    max_tokens: MAX_TOKENS,
    temperature: TEMPERATURE,
    system: systemPrompt,
    messages: messages
      .filter((message) => ["user", "assistant"].includes(message.role) && String(message.content || "").trim())
      .slice(-MAX_HISTORY_MESSAGES)
      .map((message) => ({
        role: message.role === "assistant" ? "assistant" : "user",
        content: [{ type: "text", text: String(message.content).slice(0, 8000) }],
      })),
  };
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
    InvokeModelCommand,
    InvokeModelWithResponseStreamCommand,
  } = sdk;

  cachedBedrock = new BedrockRuntimeClient({ region: AWS_REGION });
  cachedCommands = {
    ConverseCommand,
    ConverseStreamCommand,
    InvokeModelCommand,
    InvokeModelWithResponseStreamCommand,
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
      const retryable =
        status === 429 ||
        status >= 500 ||
        ["ThrottlingException", "TooManyRequestsException", "ServiceUnavailableException"].includes(err?.name);
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
  const inputTokens = Number(usage.input_tokens || usage.inputTokens || 0);
  const outputTokens = Number(usage.output_tokens || usage.outputTokens || 0);
  return {
    inputTokens,
    outputTokens,
    totalTokens: inputTokens + outputTokens,
  };
}

async function askAIExpert({ domain, messages, userMessage }) {
  const { bedrock, ConverseCommand, InvokeModelCommand } = await getBedrockRuntime();

  if (isNovaModel()) {
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

  const requestBody = buildRequestBody({ domain, messages });

  // Verify no system parameter for Mistral
  if (BEDROCK_MODEL_ID.includes("mistral") && requestBody.system) {
    console.warn("WARNING: System parameter detected for Mistral model, removing it");
    delete requestBody.system;
  }

  console.log("AI Expert request body:", JSON.stringify(requestBody).slice(0, 300));

  const response = await sendWithRetry(() =>
    bedrock.send(
      new InvokeModelCommand({
        modelId: BEDROCK_MODEL_ID,
        contentType: "application/json",
        accept: "application/json",
        body: JSON.stringify(requestBody),
      })
    )
  );

  const payload = JSON.parse(new TextDecoder().decode(response.body));
  console.log("AI Expert raw response:", JSON.stringify(payload).slice(0, 300));

  const text = parseResponse(payload);
  console.log("AI Expert parsed text:", text.slice(0, 100));

  const confidenceScore = estimateConfidence({ text, domain, userMessage });
  const escalationReason = getEscalationReason({ confidenceScore, text, domain, userMessage });
  const recommendEscalation = Boolean(escalationReason);

  return {
    text,
    confidenceScore,
    recommendEscalation,
    escalationReason,
    tokenUsage: normalizeUsage(payload?.usage),
    modelId: BEDROCK_MODEL_ID,
    raw: {
      stopReason: payload?.stop_reason,
      id: payload?.id,
      type: payload?.type,
    },
  };
}

async function streamAIExpert({ domain, messages, userMessage, onToken }) {
  const { bedrock, ConverseStreamCommand, InvokeModelWithResponseStreamCommand } = await getBedrockRuntime();

  if (isNovaModel()) {
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
    };
  }

  const requestBody = buildRequestBody({ domain, messages });

  console.log("streamAIExpert called for domain:", domain);
  console.log("Using model:", BEDROCK_MODEL_ID);

  const response = await sendWithRetry(() =>
    bedrock.send(
      new InvokeModelWithResponseStreamCommand({
        modelId: BEDROCK_MODEL_ID,
        contentType: "application/json",
        accept: "application/json",
        body: JSON.stringify(requestBody),
      })
    )
  );

  let text = "";
  let usage = {};
  const decoder = new TextDecoder();
  let tokenBuffer = "";
  const BUFFER_SIZE = 20;
  let eventCount = 0;
  let lastLength = 0; // For Mistral accumulated text tracking

  for await (const event of response.body) {
    if (!event.chunk?.bytes) continue;
    eventCount++;
    
    let payload;
    try {
      payload = JSON.parse(decoder.decode(event.chunk.bytes));
    } catch (err) {
      console.error("Failed to parse chunk:", err);
      continue;
    }

    console.log(`Event ${eventCount}:`, JSON.stringify(payload).slice(0, 200));

    // Mistral streaming format - FULL TEXT in choices[0].message.content
    // Extract only new portion since Mistral sends accumulated text
    if (payload?.choices?.[0]?.message?.content !== undefined) {
      const fullContent = payload.choices[0].message.content;
      if (fullContent && fullContent.length > lastLength) {
        const newToken = fullContent.slice(lastLength);
        text += newToken;
        lastLength = fullContent.length;
        tokenBuffer += newToken;

        console.log(`Mistral token: "${newToken.slice(0, 50)}..."`);

        // Send buffered tokens when buffer reaches threshold or ends with punctuation
        if (tokenBuffer.length >= BUFFER_SIZE || tokenBuffer.match(/[.!?]\s*$/)) {
          if (onToken) {
            console.log(`Sending buffered token: "${tokenBuffer.slice(0, 50)}..."`);
            onToken(tokenBuffer);
          }
          tokenBuffer = "";
        }
      }
    }

    // Claude streaming format - content_block_delta with text_delta
    if (payload.type === "content_block_delta" && payload.delta?.type === "text_delta") {
      const token = payload.delta.text || "";
      if (token) {
        text += token;
        tokenBuffer += token;

        // Send buffered tokens when buffer reaches threshold or ends with punctuation
        if (tokenBuffer.length >= BUFFER_SIZE || tokenBuffer.match(/[.!?]\s*$/)) {
          if (onToken) {
            onToken(tokenBuffer);
          }
          tokenBuffer = "";
        }
      }
    }

    // Claude usage tracking
    if (payload.type === "message_delta" && payload.usage) {
      usage = { ...usage, ...payload.usage };
    }

    if (payload.type === "message_start" && payload.message?.usage) {
      usage = { ...usage, ...payload.message.usage };
    }
  }

  // Send any remaining buffered tokens
  if (tokenBuffer && onToken) {
    console.log(`Sending final buffered token: "${tokenBuffer.slice(0, 50)}..."`);
    onToken(tokenBuffer);
  }

  console.log(`streamAIExpert finished. Events: ${eventCount}, Text length: ${text.length}, Final lastLength: ${lastLength}`);

  const confidenceScore = estimateConfidence({ text, domain, userMessage });
  const escalationReason = getEscalationReason({ confidenceScore, text, domain, userMessage });
  const recommendEscalation = Boolean(escalationReason);

  return {
    text: text.trim(),
    confidenceScore,
    recommendEscalation,
    escalationReason,
    tokenUsage: normalizeUsage(usage),
    modelId: BEDROCK_MODEL_ID,
  };
}

export {
  askAIExpert,
  streamAIExpert,
  normalizeDomain,
  getDomainContext,
};
