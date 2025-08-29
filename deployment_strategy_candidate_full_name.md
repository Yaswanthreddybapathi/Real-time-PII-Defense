# Project Guardian 2.0 – PII Redaction Deployment Plan

## Architecture & Placement

1. **API Gateway Plugin (Primary Defense)**
   - Integrate the PII Detector/Redactor as a plugin at the API Gateway (e.g., Kong, NGINX, AWS API Gateway).
   - Every incoming and outgoing payload is scanned; detected PII is redacted before reaching backend services or being sent to third parties.
   - Ensures low latency by leveraging optimized C/C++ or Python bindings, and scales with gateway traffic.

2. **Sidecar Container in Microservices**
   - For internal/external logs, deploy the PII redactor as a Sidecar alongside application pods (especially for logging microservices).
   - The Sidecar processes log streams in real-time, scrubbing PII before logs are stored or exported.

## Justification

- **Latency:** Gateway plugins process data in-the-fly, ensuring sub-millisecond delays for most requests.
- **Scalability:** Plugins scale horizontally with gateway, while Sidecars can be deployed selectively for high-risk services.
- **Cost-Effectiveness:** No need for extensive service rewrites; can integrate with both legacy and new microservices.
- **Ease of Integration:** Requires minimal changes to application code – most integration occurs at gateway or orchestration configuration level.
- **Defense-in-Depth:** Combines perimeter scanning (API Gateway) with in-depth protection (Sidecar), maximizing security coverage.

## Summary

**Deploy the PII Redactor as an API Gateway Plugin for all external-facing payloads and as a Sidecar container for sensitive internal log and data streams requiring additional PII control. This hybrid approach balances security, latency, and ease of deployment.**
