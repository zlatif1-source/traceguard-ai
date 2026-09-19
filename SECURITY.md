# Security policy

TraceGuard AI is an educational defensive-security project. It is not a replacement for a
production SIEM, incident-response process, or professional judgment.

## Safe demo data

Only synthetic documentation-example IP ranges are used in the included scenarios. Do not upload
real secrets, customer data, credentials, or regulated data to a public deployment.

## Built-in safeguards

- API keys are read from environment variables and `.env` is excluded from Git.
- Common password, token, API-key, and private-key patterns are redacted before model calls.
- Security logs are clearly marked as untrusted data in the model prompt.
- Live answers must stay grounded in deterministic detections and retrieved sources.
- The API limits the accepted input size.

To report a vulnerability, open a GitHub issue without including sensitive exploit details.

