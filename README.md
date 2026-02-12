# Solace Adapter

Provider-agnostic Policy Enforcement Point (PEP) that fail-closes side effects unless Solace Core returns PERMIT.

## Modes

### 1) HTTP Gateway (drop-in)
Run as a sidecar / gateway:

- Requires env: SOLACE_CORE_URL
- Exposes: POST /v1/gate

Request:
```json
{
  "intent": { "...": "..." },
  "execute": { "...": "..." },
  "acceptance": { "...": "..." }
}
