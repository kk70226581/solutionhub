# Solvent Dashboard Technical Guide

## 1. Project Overview

Solvent Dashboard is a full-stack expert consultation platform with:

- A React + Vite frontend
- An Express + Node.js backend
- MongoDB for persistent storage
- Socket.IO for real-time chat and call signaling
- Razorpay for payments
- Gemini API integration for AI assistance
- Optional Redis for caching and online presence support

The platform supports three main roles:

- Client
- Expert
- Admin

Core user capabilities include:

- User and expert registration
- Login and role-based access
- Expert approval workflow
- Expert profile and public listing
- Chat and call features
- Payment-gated consultation access
- Ratings and reviews
- Admin login with Google OAuth token validation + TOTP

---

## 2. Tech Stack

### Frontend

- React 19
- React Router DOM
- Vite
- Lucide React
- Plain CSS modules by page/component file
- Socket.IO client

### Backend

- Node.js
- Express 5
- Socket.IO
- Mongoose
- JWT
- bcryptjs
- cookie-parser
- multer
- node-fetch
- Razorpay SDK
- Redis client

### Tooling

- ESLint
- Node test runner
- concurrently

---

## 3. High-Level Architecture

```text
Frontend (React/Vite)
    |
    | HTTP API + Socket.IO
    v
Backend (Express + Socket.IO)
    |
    +-- MongoDB (users, experts, messages, payments, ratings)
    +-- Redis (optional cache + presence)
    +-- Razorpay (payment flow)
    +-- Gemini API (AI prompt endpoint)
    +-- Email provider (password reset)
```

### Architectural Style

This project uses a modular monolith structure:

- One backend app
- Logic split by responsibility into folders
- Shared helpers to reduce duplication
- Domain routes grouped into route modules

This is a good interview-friendly structure because it is simple to deploy, but still organized and scalable for a medium-sized project.

---

## 4. Backend Folder Responsibilities

### `server.cjs`

Main backend entry point.

Responsibilities:

- Loads environment variables
- Creates Express app and HTTP server
- Creates Socket.IO server
- Sets up middleware
- Initializes Redis
- Connects MongoDB
- Registers route modules
- Registers real-time socket handlers
- Starts server

### `config/`

- `upload-config.cjs`

Responsibilities:

- Multer configuration
- File upload destination logic
- File type validation
- Upload directory initialization
- Local file to data URL conversion

### `middleware/`

- `auth-middleware.cjs`
  - JWT-based user authentication
  - Admin auth checks

- `cache-middleware.cjs`
  - In-memory rate limiter
  - Redis JSON cache helpers

- `admin-totp.cjs`
  - TOTP verification
  - Per-admin/global 2FA secret resolution

### `models/`

- `app-models.cjs`

Defines:

- `User`
- `Expert`
- `Message`
- `Payment`
- `Rating`

Also exports `connectDatabase()`.

### `routes/`

- `auth-routes.cjs`
  - register/login
  - expert signup
  - password policy
  - forgot/reset password
  - expert profile update
  - profile photo update
  - admin auth config
  - Google token verification for admin
  - admin TOTP verification

- `public-routes.cjs`
  - public health/docs
  - profile fetch
  - messages
  - conversations
  - public experts
  - public home data
  - ratings
  - Gemini AI endpoint

- `admin-payment-routes.cjs`
  - expert status moderation
  - admin health
  - presence lookup
  - create order
  - verify payment
  - payment status
  - payment access check
  - user payment history
  - Razorpay webhook

### `socket/`

- `realtime-handlers.cjs`
  - chat events
  - call signaling events
  - user authentication on socket
  - room join/leave logic
  - message broadcast
  - payment-gated chat/call access

- `presence-store.cjs`
  - online user tracking
  - local socket map management
  - Redis-backed presence storage

### `utils/`

- `shared-helpers.cjs`
  - email normalization
  - room parsing
  - initials
  - relative time formatting
  - attachment parsing
  - base32 decoding for TOTP

- `db-query-helpers.cjs`
  - repeated DB query patterns
  - rating summary helpers

- `payment-access-helpers.cjs`
  - Razorpay signature verification
  - webhook event processing
  - client-expert 24-hour access logic

- `password-reset-email-service.cjs`
  - password reset email transport
  - provider abstraction for Resend/SendGrid

---

## 5. Frontend Structure

### Core files

- `src/main.jsx`: React entry point
- `src/App.jsx`: route definitions

### Main frontend areas

- `src/pages/`
  - login/signup
  - home
  - expert listing
  - dashboards
  - chat
  - admin pages

- `src/components/`
  - `ProtectedRoute`
  - `VideoCall`
  - `GlobalCallNotifier`
  - `ChatBot`

- `src/utils/`
  - attachment handling
  - incoming call local storage

---

## 6. Data Models

### User

Purpose:

- Standard client account

Key fields:

- `name`
- `email`
- `password`
- `role`
- `resetPasswordTokenHash`
- `resetPasswordExpires`

### Expert

Purpose:

- Expert account and public profile

Key fields:

- `name`
- `email`
- `password`
- `field`
- `experience`
- `headline`
- `summary`
- `location`
- `linkedin`
- `resumePath`
- `avatar`
- `status`
- `price`

### Message

Purpose:

- Chat history and attachments

Key fields:

- `room`
- `author`
- `authorRole`
- `message`
- `messageType`
- `attachmentUrl`
- `attachmentName`
- `attachmentMime`

### Payment

Purpose:

- Consultation payment records

Key fields:

- `orderId`
- `paymentId`
- `signature`
- `amount`
- `currency`
- `status`
- `clientEmail`
- `expertEmail`
- `verified`
- `notes`

### Rating

Purpose:

- Client rating for expert

Key fields:

- `expertEmail`
- `clientEmail`
- `room`
- `score`
- `review`

---

## 7. Core Functional Flows

### 7.1 Client Registration/Login

Flow:

1. Client registers through `/api/register`
2. Password is validated against password policy
3. Password is hashed with bcrypt
4. User document is stored in MongoDB
5. Login generates JWT with role and identity info

### 7.2 Expert Signup and Approval

Flow:

1. Expert submits profile + resume + photo
2. Backend validates fields and uploads files
3. Photo can be converted to data URL for easy UI rendering
4. Expert is stored with `status: pending`
5. Admin approves/rejects through `/api/admin/expert-status`

### 7.3 Password Reset

Flow:

1. User submits email to `/api/forgot-password`
2. Backend generates short-lived JWT reset token
3. SHA-256 hash of token is stored in DB
4. Email service sends reset link
5. `/api/reset-password` verifies token and updates password

Why it is good:

- Raw token is not stored in DB
- Token expires
- Supports both client and expert accounts

### 7.4 Real-Time Chat

Flow:

1. Frontend authenticates socket using JWT
2. User joins private room
3. Messages are persisted in MongoDB
4. Socket broadcasts new messages to room participants
5. Attachment type is inferred from MIME/data URL

### 7.5 Video Call Signaling

Flow:

1. Users join a private room
2. Socket events relay:
   - offer
   - answer
   - ICE candidate
   - call-ended
3. Access is validated before joining/signaling

Important:

Socket.IO is used only for signaling and presence, not media transport itself.

### 7.6 Payment-Gated Access

Flow:

1. Client creates order using Razorpay
2. Backend stores payment record
3. Client completes payment
4. Backend verifies signature
5. `Payment` record is updated to `paid` and `verified`
6. Chat/call access helper checks whether client is allowed to continue

Access rule:

- Client gets access after valid payment
- Access window is based on the first expert reply and lasts 24 hours

### 7.7 Admin Authentication

Flow:

1. Admin sends Google ID token
2. Backend validates token via Google tokeninfo API
3. Email must be verified and allowed
4. Backend issues short-lived pre-2FA token
5. Admin submits TOTP code
6. Backend validates TOTP and creates admin session JWT

This is a strong interview talking point because it shows multi-step authentication.

### 7.8 Public Home Data Aggregation

Flow:

1. Backend aggregates experts, payments, ratings, and messages
2. Computes stats for homepage
3. Computes top experts and recent activity
4. Caches result in Redis if available

---

## 8. Security Features

This project includes several practical security features:

- bcrypt password hashing
- JWT-based authentication
- Password reset token hashing
- Strong password policy
- Role-based route protection
- Admin Google token verification
- TOTP-based 2FA for admin
- Rate limiting on API and auth endpoints
- Payment signature verification
- Limited file type validation for uploads
- Optional Redis-backed cache and presence handling

Interview angle:

Be ready to explain not just what you used, but why:

- bcrypt for secure password hashing
- JWT for stateless auth
- TOTP for stronger admin protection
- rate limiting to reduce brute-force abuse
- signature verification to avoid forged payment confirmations

---

## 9. Performance and Scalability Considerations

### What the project already does

- Caches experts list
- Caches public home data
- Uses helper functions to reduce repeated DB logic
- Splits route logic into modules
- Uses WebSocket presence abstraction

### Current limitations

- Some routes still do direct query logic in route files
- In-memory rate limiting is not horizontally scalable by itself
- `onlineUsers` local object is only fully accurate for one process without Redis
- File uploads are local, not cloud-based
- AI route is a simple proxy and not queue-based

### Improvement ideas for interview

- Move to route-controller-service pattern
- Add schema validation with Zod/Joi
- Use Redis for distributed rate limiting
- Move uploads to S3/Cloudinary
- Add structured logging
- Add request tracing and monitoring
- Add refresh tokens / secure cookie sessions
- Add pagination for message history and expert list

---

## 10. Environment Variables

Important environment variable groups:

### Core backend

- `PORT`
- `MONGO_URI`
- `JWT_SECRET`
- `PASSWORD_SALT_ROUNDS`

### Rate limiting / cache

- `RATE_LIMIT_WINDOW_MS`
- `RATE_LIMIT_MAX_GLOBAL`
- `RATE_LIMIT_MAX_AUTH`
- `REDIS_URL`
- `CACHE_EXPERTS_TTL_SEC`
- `CACHE_HOME_TTL_SEC`

### Email

- `EMAIL_PROVIDER`
- `EMAIL_FROM`
- `RESEND_API_KEY`
- `SENDGRID_API_KEY`
- `FRONTEND_URL`
- `PUBLIC_APP_URL`
- `FRONTEND_ROUTER_MODE`

### Payments

- `RAZORPAY_KEY_ID`
- `RAZORPAY_KEY_SECRET`
- `RAZORPAY_WEBHOOK_SECRET`

### AI

- `GEMINI_API_KEY`
- `GEMINI_MODEL`

### Admin

- `GOOGLE_CLIENT_ID`
- `ADMIN_ALLOWED_EMAILS`
- `ADMIN_2FA_SECRET`
- `ADMIN_2FA_SECRETS`
- `ADMIN_SECRET`

---

## 11. Testing

Current tests cover:

- public health endpoint
- password policy endpoint
- OpenAPI docs endpoint
- global rate limiter behavior

Test file:

- `tests/api.basic.test.cjs`

Good interview explanation:

"I added lightweight API tests for health, docs, security policy, and rate limiting to ensure basic backend stability after refactoring."

---

## 12. Refactoring Value in This Project

One of the strongest technical stories in this project is the backend refactor.

Before:

- large `server.cjs`
- repeated logic
- mixed responsibilities

After:

- modularized backend
- route grouping by domain
- helper extraction
- dedicated middleware/config/socket/model modules

Why this matters in interview:

It shows that you understand maintainability, not just feature-building.

---

## 13. What You Should Learn for Interview

Focus on these topics before presenting this project:

### Must know well

- Express fundamentals
- React routing and protected routes
- JWT authentication
- bcrypt hashing
- Mongoose schema/model design
- REST API design
- Socket.IO basics
- Razorpay payment verification
- TOTP basics
- Redis caching basics
- environment variable management

### Learn conceptually

- How WebRTC signaling works
- Difference between authentication and authorization
- Why token hashing is used in password reset
- Why rate limiting matters
- Why Redis helps with cache and presence
- How webhook verification works
- How role-based systems are designed

### Learn to explain design decisions

You should be able to answer:

- Why did you split backend code into modules?
- Why use MongoDB here?
- Why use Socket.IO?
- Why is admin auth stronger than normal user auth?
- Why do you need payment verification on backend, not just frontend?
- Why store ratings separately instead of embedding them in expert documents?

---

## 14. Interview Questions You Should Prepare

### Project overview

- What problem does this project solve?
- What are the main modules?
- What was your contribution?

### Backend

- How does authentication work?
- How do you protect admin routes?
- How does the password reset flow work?
- How do you handle uploads?
- How do you validate payments?
- How do you manage real-time presence?

### Database

- Why these models?
- Why separate `User` and `Expert`?
- How are chat rooms identified?
- How are ratings aggregated?

### Real-time features

- How does Socket.IO fit into the project?
- How do you ensure only valid users join rooms?
- How are calls handled?

### Security

- How are passwords stored?
- How are reset links secured?
- How are payment webhooks verified?
- How do you prevent abuse on auth routes?

### Scalability / improvement

- What would you improve next?
- How would you scale this to multiple servers?
- How would you improve test coverage?

---

## 15. Good Interview Summary You Can Say

Use something like this:

> "This project is a full-stack expert consultation platform built with React, Express, MongoDB, and Socket.IO. It supports clients, experts, and admins. I organized the backend into modular route, middleware, socket, config, model, and utility layers. It includes JWT auth, bcrypt password hashing, admin login with Google token verification and TOTP, payment-gated expert access via Razorpay, Redis-backed caching, and real-time messaging/call signaling. One of my main engineering contributions was refactoring the backend from a large entry file into a cleaner modular architecture that is easier to maintain and explain."

---

## 16. Best Things to Highlight in Interview

- modular backend refactor
- role-based architecture
- real-time chat/call support
- payment integration
- security improvements
- admin authentication with 2FA
- helper extraction and cleaner code organization

---

## 17. Weak Areas You Should Be Honest About

If asked deeply, you can say:

- test coverage is basic and can be expanded
- some route logic can still be moved into service layers
- local uploads are okay for development, but cloud storage is better for production
- in-memory rate limiting should be distributed for multi-instance deployment

That answer sounds mature, not weak.

---

## 18. Final Preparation Checklist

Before interview, make sure you can explain:

- project purpose in 30 seconds
- full backend flow in 1 minute
- auth flow
- payment flow
- socket flow
- data models
- security decisions
- why your refactor improved maintainability

If you can explain those clearly, this project becomes a strong interview project.
