# AI Psychology Assistant & Enhanced Google Login

## Overview

This implementation adds two major enhancements to Solvenut:

1. **Enhanced Google Login UI** - Modern, polished Google authentication button with improved visual design
2. **AI Psychology Assistant** - An empathetic AI companion that helps users work through their problems before escalating to real experts

## Features

### 1. Enhanced Google Login UI

**Improvements:**
- Modern gradient button with smooth animations
- Better visual hierarchy and affordance
- Improved hover states with shadow effects
- Responsive design for all screen sizes
- Professional appearance with proper spacing and typography

**Pages Updated:**
- Login page (`src/pages/Login.jsx`)
- Signup Client page (`src/pages/SignupClient.jsx`)

**Styling:**
- Gradient backgrounds (135deg, #667eea → #764ba2)
- Smooth transitions and transforms
- Enhanced shadow effects for depth
- Accessible color contrast

### 2. AI Psychology Assistant

**Core Features:**

#### Empathetic AI Companion
- Acts as "Dr. Empathy" - a supportive psychology assistant
- Provides genuine, human-like responses
- Validates user feelings and experiences
- Suggests practical coping strategies
- Uses natural, conversational language

#### Multi-Level Support System
```
User Problem
    ↓
AI Psychology Assistant (Tier 1)
    ↓
If not satisfied
    ↓
Real Expert Escalation (Tier 2)
```

#### Smart Escalation Flow
- After 2-3 user messages, shows escalation CTA
- Users can move to real experts if needed
- Guides them to expert booking page
- Professional handoff messaging

#### Emergency Detection
- Detects crisis keywords (suicide, self-harm, etc.)
- Provides immediate emergency resources guidance
- Encourages professional help when needed

**Components:**

1. **PsychologyAssistant.jsx** (`src/components/PsychologyAssistant.jsx`)
   - Main modal component
   - Message management and UI
   - Expert escalation flow
   - Emergency response handling

2. **FloatingAssistant.jsx** (`src/components/FloatingAssistant.jsx`)
   - Floating action button (FAB) on all pages
   - Menu with options: "Talk to Dr. Empathy" and "Need Help?"
   - Integration with both HelpBot and Psychology Assistant

3. **Backend Endpoint** (`routes/public-routes.cjs`)
   - `/api/psychology-assist` - POST endpoint
   - Uses AWS Bedrock for AI responses
   - Fallback empathetic responses if AI unavailable
   - Conversation history support

## Component Structure

### PsychologyAssistant Component

```jsx
<PsychologyAssistant 
  open={boolean}
  onClose={() => {}}
/>
```

**Features:**
- Message history management
- Typing indicators
- Expert CTA after 2-3 exchanges
- Smooth animations
- Mobile-responsive modal

**CSS Classes:**
- `.psychology-assistant-overlay` - Semi-transparent backdrop
- `.psychology-assistant-modal` - Main modal container
- `.psychology-assistant-header` - Purple gradient header
- `.psychology-assistant-messages` - Message feed
- `.psychology-assistant-input-container` - Input area

### FloatingAssistant Component

```jsx
<FloatingAssistant />
```

**Features:**
- Floating button in bottom-right corner
- Menu expands on click
- Options for Psychology Assistant or HelpBot
- Smooth menu animations
- Mobile-optimized sizing

## API Integration

### Psychology Assistant Endpoint

**URL:** `/api/psychology-assist`

**Method:** POST

**Request Body:**
```json
{
  "message": "I'm feeling overwhelmed at work",
  "systemPrompt": "You are Dr. Empathy, a compassionate AI...",
  "conversationHistory": [
    { "role": "user", "content": "..." },
    { "role": "assistant", "content": "..." }
  ]
}
```

**Response:**
```json
{
  "response": "I hear you. That sounds really challenging...",
  "needsEmergencyResponse": false,
  "success": true
}
```

## Styling & Colors

### Psychology Assistant Theme
- **Primary Gradient:** `linear-gradient(135deg, #667eea 0%, #764ba2 100%)`
- **User Messages:** `#667eea` background with white text
- **Assistant Messages:** White background with dark text
- **Accent Color:** `#764ba2` (secondary purple)

### Google Button Theme
- **Normal:** White with subtle gradient
- **Hover:** Lifted with enhanced shadow
- **Active:** Subtle gradient overlay
- **Disabled:** Reduced opacity

## System Prompt

The AI Psychology Assistant uses a comprehensive system prompt that guides behavior:

```
You are Dr. Empathy, a compassionate AI psychology assistant with a warm, supportive personality.

Your role is to:
1. LISTEN with genuine empathy and understanding
2. VALIDATE the user's feelings and experiences
3. GUIDE them toward clarity and self-understanding
4. SUGGEST practical, actionable coping strategies
5. Know when to escalate to real experts

Communication Style:
- Be warm, human, and genuinely caring
- Use their name when they share it
- Ask follow-up questions to understand better
- Normalize their feelings and experiences
- Use a conversational, non-judgmental tone
- Avoid clinical jargon unless necessary
```

## Fallback Responses

If AWS Bedrock is unavailable, the system uses empathetic fallback responses:

- "I hear you. That sounds really challenging. Can you tell me more about what's going on?"
- "Thank you for sharing that. It takes courage to open up. What part feels most overwhelming?"
- "I'm really listening. What would help you feel better?"
- "That's a lot to carry. What's your biggest concern right now?"
- "I appreciate your honesty. What would you like to focus on first?"

## Mobile Responsiveness

**Breakpoints:**
- Desktop (1024px+): Full-size modal and button
- Tablet (640px - 1024px): Adjusted modal width, optimized menu
- Mobile (< 640px): 95% width modal, compact button and menu

**Button Sizing:**
- Desktop: 56x56px
- Tablet: 52x52px
- Mobile: 48x48px

## Integration Steps

### 1. Backend Setup

Ensure AWS Bedrock is configured:
```bash
AWS_ACCESS_KEY_ID=your_key
AWS_SECRET_ACCESS_KEY=your_secret
AWS_REGION=us-east-1
BEDROCK_MODEL_ID=anthropic.claude-3-5-sonnet-20240620-v1:0
```

### 2. Frontend Integration

The FloatingAssistant is already added to `App.jsx`:
```jsx
import FloatingAssistant from './components/FloatingAssistant';

// In App component:
<FloatingAssistant />
```

### 3. Testing

**Google Login Button:**
- Test on Login page
- Test on Signup Client page
- Verify hover animations
- Check mobile responsiveness

**Psychology Assistant:**
- Click floating button to open menu
- Select "Talk to Dr. Empathy"
- Send messages and verify responses
- Check expert escalation after 3 messages
- Test emergency keyword detection

## User Experience Flow

### For Psychology Assistant:

1. **User discovers** floating button in bottom-right
2. **Opens menu** with two options
3. **Selects Psychology Assistant**
4. **Chat opens** with Dr. Empathy greeting
5. **Shares problem** and gets empathetic response
6. **Continues conversation** (2-3 exchanges)
7. **Sees expert escalation CTA**
8. **Can choose** to:
   - Continue talking to AI
   - Connect with real expert
9. **If escalating**, redirected to `/experts` page

### For Google Login:

1. **User sees** modern Google button
2. **Hovers** for visual feedback
3. **Clicks** to authenticate
4. **Google popup** appears
5. **Authenticates** and returns to dashboard

## Accessibility

- ARIA labels for all interactive elements
- Keyboard navigation support
- Semantic HTML structure
- Color contrast WCAG AA compliant
- Screen reader friendly messages
- Proper focus management

## Performance Optimizations

- Lazy loading of chat messages
- Debounced typing indicators
- Message history limit (last 10 for context)
- CSS animations use transform/opacity (GPU accelerated)
- Optimized re-renders with React.memo (if needed)

## Browser Support

- Chrome/Edge: Full support
- Firefox: Full support
- Safari: Full support
- Mobile browsers: Optimized UI

## Error Handling

- Network timeout: 15 seconds for psychology requests
- Failed API calls: Fallback empathetic responses
- Emergency detection: Always shows safety guidance
- Session management: Handles disconnects gracefully

## Future Enhancements

- [ ] User preferences (tone, expertise area)
- [ ] Conversation export/save
- [ ] Multi-language support
- [ ] Analytics on escalation rates
- [ ] Integration with expert calendar
- [ ] Sentiment analysis tracking
- [ ] Personalization based on history

## Support

For issues or questions:
- Check console for error messages
- Verify AWS Bedrock configuration
- Test with fallback responses enabled
- Contact: support@solvenut.com
