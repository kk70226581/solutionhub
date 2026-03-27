/**
 * EMAIL SERVICE – Send password reset emails
 */

const sendPasswordResetEmail = (fetch) => {
  const EMAIL_PROVIDER = String(process.env.EMAIL_PROVIDER || "none").trim().toLowerCase();
  const EMAIL_FROM = String(process.env.EMAIL_FROM || "").trim();
  const RESEND_API_KEY = String(process.env.RESEND_API_KEY || "").trim();
  const SENDGRID_API_KEY = String(process.env.SENDGRID_API_KEY || "").trim();

  return async ({ toEmail, resetLink }) => {
    const subject = "Reset your Solvenut password";
    const text = [
      "We received a request to reset your Solvenut password.",
      "",
      "Use the link below to reset it (valid for 15 minutes):",
      resetLink,
      "",
      "If you did not request this, you can ignore this email.",
    ].join("\n");
    const html = `
      <div style="font-family:Arial,sans-serif;line-height:1.5;color:#111827">
        <h2 style="margin:0 0 12px">Reset your Solvenut password</h2>
        <p>We received a request to reset your Solvenut password.</p>
        <p>
          <a href="${resetLink}" style="display:inline-block;padding:10px 14px;background:#0ea5e9;color:#fff;text-decoration:none;border-radius:8px">
            Reset Password
          </a>
        </p>
        <p style="font-size:12px;color:#6b7280">This link expires in 15 minutes.</p>
        <p style="font-size:12px;color:#6b7280">If you did not request this, you can ignore this email.</p>
      </div>
    `;

    if (EMAIL_PROVIDER === "none") {
      return { ok: false, error: "EMAIL_PROVIDER is not configured" };
    }
    if (!EMAIL_FROM) {
      return { ok: false, error: "EMAIL_FROM is missing" };
    }

    if (EMAIL_PROVIDER === "resend") {
      if (!RESEND_API_KEY) {
        return { ok: false, error: "RESEND_API_KEY is missing" };
      }
      const r = await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${RESEND_API_KEY}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          from: EMAIL_FROM,
          to: [toEmail],
          subject,
          html,
          text,
        }),
      });
      if (!r.ok) {
        const body = await r.text().catch(() => "");
        return { ok: false, error: `Resend error (${r.status}): ${body}` };
      }
      return { ok: true };
    }

    if (EMAIL_PROVIDER === "sendgrid") {
      if (!SENDGRID_API_KEY) {
        return { ok: false, error: "SENDGRID_API_KEY is missing" };
      }
      const r = await fetch("https://api.sendgrid.com/v3/mail/send", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${SENDGRID_API_KEY}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          personalizations: [{ to: [{ email: toEmail }] }],
          from: { email: EMAIL_FROM },
          subject,
          content: [
            { type: "text/plain", value: text },
            { type: "text/html", value: html },
          ],
        }),
      });
      if (!r.ok) {
        const body = await r.text().catch(() => "");
        return { ok: false, error: `SendGrid error (${r.status}): ${body}` };
      }
      return { ok: true };
    }

    return { ok: false, error: `Unsupported EMAIL_PROVIDER: ${EMAIL_PROVIDER}` };
  };
};

module.exports = { sendPasswordResetEmail };
