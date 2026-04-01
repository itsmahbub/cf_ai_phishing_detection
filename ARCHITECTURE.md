# PhishGuard Documentation

This document explains what the application does today, how it is implemented, how the request pipeline works, and where the project can be improved next.

## Overview

PhishGuard is a Cloudflare-native phishing review app for suspicious SMS, email, and screenshots.

The product has two main surfaces:

- Public client app at `/`
- Private admin portal at `/admin`

The public app lets a user paste message content or upload a screenshot and receive a phishing verdict. The admin portal lets an operator review stored URLs, static and dynamic analysis results, and manage stored records.

## Main features

### Public client

- Accept suspicious SMS/email text
- Accept screenshot uploads
- Extract URLs and key phishing indicators using Workers AI
- Check a shared URL/message reputation store before running deeper analysis
- Return a short verdict for the user:
  - likely phishing
  - likely legitimate
  - needs human review
- Show a lightweight step-by-step progress UI while analysis is running
- Keep per-session chat history

### Shared reputation database

- Store normalized URLs
- Store message fingerprints
- Reuse known verdicts on future submissions
- Save both static-analysis results and background dynamic-analysis results

### Dynamic URL analysis

- Queue new URLs into a Cloudflare Workflow
- Open URLs with Cloudflare Browser Rendering
- Capture:
  - Final URL
  - Page title
  - Visible texts
  - Screenshot
- Use Workers AI to infer the brand being represented by the rendered page
- Compare brand inference with the URL/domain
- Store dynamic-analysis verdict and rationale

### Admin portal

- Protected by Cloudflare Access
- Shows a simple review table
- Filter records by:
  - all
  - phishing
  - legitimate
- Display columns such as:
  - URL
  - static verdict
  - dynamic analysis state
  - dynamic analysis verdict
  - live/not-live
  - tags
- open full record details in a new tab
- delete one or more selected records

## Cloudflare services used

### Workers

The Worker is the main request entrypoint. It serves the app, handles chat requests, exposes the admin API, and coordinates the rest of the system.

### Agents SDK

The chat experience is built on Cloudflare Agents. The `ChatAgent` class handles the message lifecycle and keeps per-session state such as recent assessments and counts.

### Workers AI

Workers AI is used in three model calls:

1. To extract structured phishing-review data from the user submission, using a vision-capable model for image-only screenshots
2. To generate the main phishing verdict from the extracted structured data
3. To analyze rendered landing-page metadata and visible text in the background workflow to infer impersonated brand and phishing risk

### Durable Objects

Durable Objects are used for two kinds of state:

- Session-oriented agent state
- Global URL reputation storage

The `UrlReputationStore` Durable Object acts as the shared database for URL records and duplicate-message fingerprints.

### Workflows

Workflows are used for background URL inspection. This keeps the user-facing verdict fast while letting the system do a second-stage page review asynchronously.

### Browser Rendering

Cloudflare Browser Rendering is used to load suspicious URLs in Cloudflare’s managed browser environment so the app can inspect the resolved page, collect rendered content, and capture a screenshot.

## Current implementation

### `src/server.ts`

This is the main backend file. It contains:

- request routing
- type definitions for stored records
- JSON schemas for AI extraction and verdicts
- URL normalization
- duplicate-message fingerprinting
- `UrlReputationStore` Durable Object
- `ChatAgent`
- admin API routes

Key responsibilities:

- extract the latest user submission
- convert image uploads into model-friendly message parts
- call Workers AI for structured extraction
- check the reputation store
- return cached results when possible
- call Workers AI for a fresh verdict when needed
- persist new records
- trigger background workflow analysis

### `src/workflow.ts`

This file contains the background dynamic-analysis workflow.

Key responsibilities:

- mark URL analysis status as `queued`
- mark URL analysis status as `inspecting`
- load the URL in Browser Rendering
- capture title, screenshot, and visible page text
- call Workers AI to infer brand and phishing risk
- store the dynamic-analysis result
- mark failures if inspection cannot complete

### `src/app.tsx`

This file contains both frontend surfaces:

- the public chat UI
- the admin portal UI

Public client responsibilities:

- render a very small chat-first interface
- send text and screenshots to the agent
- show message history
- show a user-friendly progress checklist while analysis is running

Admin responsibilities:

- fetch stored reputation records
- render the simple operations table
- filter records
- bulk-delete selected records
- open record details in a new tab

### `src/styles.css`

Contains all custom UI styling for both the public app and admin portal.

### `wrangler.jsonc`

Defines the Cloudflare deployment shape:

- AI binding
- Browser Rendering binding
- workflow binding
- durable object bindings
- assets settings

## Data model

Each stored URL record includes:

- static verdict
- static confidence
- static summary and reasons
- extracted message text
- extracted indicators
- extraction rationale
- normalized URLs
- timestamps
- hit count
- dynamic analysis object

The dynamic analysis object includes:

- status
- live status
- final URL
- page title
- screenshot
- visible text sample
- inferred brand
- brand/domain match signal
- dynamic verdict
- dynamic reasons
- error details when inspection fails

## Request flow

### Public analysis flow

1. User submits a message or screenshot.
2. The agent extracts structured information with Workers AI.
3. URLs are normalized.
4. The message text is normalized and fingerprinted.
5. The app checks the shared reputation database.
6. If a known URL or duplicate message exists:
   - return the stored result immediately
   - if dynamic analysis already completed, prefer that richer stored verdict
7. If no stored match exists:
   - run the static phishing verdict AI call
   - return the verdict to the user
8. Persist the record in the shared store.
9. Trigger background dynamic analysis for any extracted URLs.

### Dynamic analysis flow

1. Workflow marks URL status as `queued`.
2. Workflow marks URL status as `inspecting`.
3. Browser Rendering loads the target URL.
4. The workflow captures:
   - final URL
   - title
   - screenshot
   - visible text
5. Workers AI infers brand and phishing risk.
6. Store status becomes:
   - `completed`, with result details
   - or `failed`, with failure details

### Admin review flow

1. Admin loads `/admin`.
2. Frontend requests `/admin/api/reputation`.
3. Worker checks admin authorization.
4. Durable Object returns stored records.
5. Admin can:
   - filter records
   - open details
   - bulk delete records

## Security and abuse controls

### Prompt-injection resistance

User content is always treated as untrusted data. Prompts explicitly tell the model not to follow instructions embedded in the submitted content or rendered page text.

### Scope control

The app is intended only for phishing review. The extraction model decides whether the content is even relevant to the phishing-review task.

### Admin protection

The admin portal is intended to be protected with Cloudflare Access.

### Operational safety

Dynamic URL inspection runs in the background instead of blocking the user-facing result. This reduces user-facing latency and isolates dynamic review logic from the main chat experience.

## Future improvements

- Stronger URL/domain enrichment such as ASN, registrar age, redirect chains, and domain reputation
- Domain-to-brand verification against official known domains
- Better screenshot OCR and visual-logo matching
- More nuanced treatment of legitimate-but-urgent messages
- Campaign clustering beyond exact duplicate fingerprints
- Add analytics tables for verdict trends and repeat campaigns
- Keep deletion audit trails for admin operations
- Move to a more query-friendly SQL-backed schema for admin reporting
- Rate limiting for public submissions
- Abuse monitoring for repeated non-phishing usage
- Retry and backoff policy tuning for background task
- Human-review queue for uncertain cases
