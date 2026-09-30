# Security policy

Please report a vulnerability privately through GitHub's "Report a vulnerability" (Security tab)
rather than in a public issue. Include what an attacker can do, and the steps to reproduce it.

What counts, for this project:

- a way to make the service pass content its policy should hold or remove (a bypass), other than
  the judging model simply answering wrongly;
- a way to read or change another tenant's reviews, audit records or policy;
- a way to change audit records without `verify()` detecting it;
- personal data reaching logs, the audit log or webhooks against the configured `store_content`;
- secrets (API keys, webhook secrets) exposed by the service.

A model's miss on a single piece of content is a calibration matter: open an ordinary issue with
the text (redacted) and the verdict.

Operational advice: run the service behind TLS, set API keys for every role, bind reviewer keys to
their tenant, keep a copy of the audit head (`GET /v1/audit/head`) outside the service, and set
`residency.allow` to what your data-protection assessment permits.
