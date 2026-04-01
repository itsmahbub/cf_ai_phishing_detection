# PhishGuard Documentation

This document explains what the application does today, how it is implemented, how the request pipeline works, and where the project can be improved next.

## Overview

PhishGuard is a Cloudflare-native phishing review app for suspicious SMS, email, and screenshots.

The product has two main surfaces:

- public client app at `/`
- private admin portal at `/admin`

The public app lets a user paste message content or upload a screenshot and receive a phishing verdict. The admin portal lets an operator review stored URLs, static and dynamic analysis results, and manage stored records.

## Main features

### Public client

- accept suspicious SMS/email text
- accept screenshot uploads
- extract URLs and key phishing indicators using Workers AI
- check a shared URL/message reputation store before running deeper analysis
- return a short verdict for the user:
  - likely phishing
  - likely legitimate
  - needs human review
- show a lightweight step-by-step progress UI while analysis is running
- keep per-session chat history

### Shared reputation database

- store normalized URLs
- store duplicate-message fingerprints
- reuse known verdicts on future submissions
- save both static-analysis results and background dynamic-analysis results

### Dynamic URL analysis

- queue new URLs into a Cloudflare Workflow
- open URLs with Cloudflare Browser Rendering
- capture:
  - final URL
  - page title
  - visible text sample
  - screenshot
- use Workers AI to infer the brand being represented by the rendered page
- compare brand inference with the URL/domain
- store dynamic-analysis verdict and rationale

### Admin portal

- protected by Cloudflare Access
- shows a simple review table
- filter records by:
  - all
  - phishing
  - legitimate
- display columns such as:
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

Workers AI is used in two places:

1. static extraction from the submitted message or screenshot
2. final phishing verdict generation

It is also used during dynamic analysis to infer the brand represented by the rendered destination page.

### Durable Objects

Durable Objects are used for two kinds of state:

- session-oriented agent state
- global URL reputation storage

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

The admin portal is intended to be protected with Cloudflare Access. An optional `ADMIN_EMAIL` check can be used as an additional server-side guard.

### Operational safety

Dynamic URL inspection runs in the background instead of blocking the user-facing result. This reduces user-facing latency and isolates dynamic review logic from the main chat experience.

## Known limitations

- The user-facing progress checklist is currently UI-timed, not backend-driven.
- Dynamic analysis is only performed for URLs, not for message-only submissions.
- Fingerprint cleanup during delete is simple and based on URL membership.
- Screenshots are stored inline as data URLs instead of a dedicated blob store such as R2.
- The reputation store currently uses Durable Object storage directly rather than a more query-friendly relational design.
- OCR-like extraction quality for screenshots depends on the model and screenshot clarity.
- Dynamic page inspection is useful, but it is not a full malware sandbox.

## Future improvements

### Product improvements

- backend-driven progress events instead of timed UI progress steps
- search and sorting in admin by URL, date, hit count, or risk
- pagination in admin for larger datasets
- richer user verdict cards instead of plain markdown-like text
- extension-first UX for checking links directly from browser pages

### Detection improvements

- stronger URL/domain enrichment such as ASN, registrar age, redirect chains, and domain reputation
- domain-to-brand verification against official known domains
- better screenshot OCR and visual-logo matching
- more nuanced treatment of legitimate-but-urgent messages
- campaign clustering beyond exact duplicate fingerprints

### Storage improvements

- move screenshots to R2
- add analytics tables for verdict trends and repeat campaigns
- move to a more query-friendly SQL-backed schema for admin reporting
- keep deletion audit trails for admin operations

### Security improvements

- signed admin actions and audit logs
- stricter admin API authorization model
- rate limiting for public submissions
- abuse monitoring for repeated non-phishing usage

### Workflow improvements

- retry and backoff policy tuning
- explicit workflow stage timestamps in admin
- dynamic verdict refresh for stale URLs
- optional human-review queue for uncertain cases

## Recommended maintenance guidelines

- keep prompts narrow and task-specific
- treat all user/page content as untrusted
- prefer simple data structures that are easy to inspect in code review
- keep the public UX fast, and move expensive investigation into background workflows
- favor deterministic operational behavior over clever UI complexity
