# R.A.D.O.N.

**Risk Analysis & Detection Orchestration Node**

A free, self-hosted cloud security posture scanner for Google Cloud Platform that turns raw misconfiguration findings into plain-English risk assessments using a locally hosted LLM.
Try the live static demo [here](https://404Haze.github.io/RADON/).

## Why R.A.D.O.N. Exists

Cloud security posture management is locked behind six-figure contracts. Wiz (median ~$158k/year), Orca, and Prisma Cloud charge hundreds of thousands of dollars annually and process your configuration data in their clouds. The free open source scanners (Prowler, Scout Suite) do the scanning but stop at raw findings: a wall of JSON and HTML that still needs a human to interpret.

The interpretation layer usually means shipping your GCP configuration, including every vulnerability and misconfiguration, to a third party. A single breach at that vendor exposes your entire cloud posture to the world. Even Scout Suite requires its own cloud if you want its AI.

R.A.D.O.N. fills that gap. Run the scan yourself and get the interpretation layer too. A local LLM reads each finding and produces a severity rating, a plain-English explanation of the risk, and concrete remediation steps. Because the model runs locally via llama.cpp, your security data never leaves your machine. Deploy the container inside your own cloud and it is fully air-gapped.

## Notable Features

- **100% Air-Gapped**: deploy it inside your own cloud and your security data never leaves.
- **50+ Security Checks**: spanning IAM, Cloud Storage, Compute Engine, and Cloud Run.
- **Local LLM Triage**: every finding becomes a plain-English risk assessment with remediation steps, generated on-device by llama.cpp running LFM 2.5 1.2B (swappable to 8B and 26B models).
- **Standardized Severity**: findings scored with CVSS v4.0 and mapped to CIS GCP Foundations Benchmarks and MITRE ATT&CK techniques.
- **MongoDB Persistence**: findings, scan history, and remediation state stored in MongoDB, or in-memory for quick trials.
- **Web Dashboard**: findings, trends, a 0-100 posture score, AI chat, and remediation tracking in a dependency-free vanilla JavaScript frontend.
- **Bundled Emulator**: a deliberately misconfigured fake GCP project for testing, so you can try R.A.D.O.N. without touching a live account.

## GCP Services Covered

- **IAM**: public roles (allUsers, allAuthenticatedUsers), overprivileged and dormant service accounts, unrotated and orphaned service account keys.
- **Cloud Storage**: public buckets and objects, missing uniform bucket-level access, disabled versioning, unencrypted buckets, missing access logging.
- **Compute Engine**: instances with public IPs, open firewall rules (0.0.0.0/0), default service accounts, disabled shielded VMs, serial port access.
- **Cloud Run**: unauthenticated services, open ingress, secrets in environment variables, missing resource limits and VPC connectors.

## Vulnerability Classification

Findings are rated against recognized industry standards, not an in-house scale:

| Standard | Role |
|---|---|
| CIS GCP Foundations Benchmarks | The specific hardening control a finding violates |
| CVSS v4.0 | The severity band (Critical / High / Medium / Low) |
| MITRE ATT&CK | The adversary technique a misconfiguration enables |

A publicly readable GCS bucket, for example, maps to CIS 5.1.1, scores High on CVSS v4.0, and enables ATT&CK T1530 (Data from Cloud Storage). Findings for services CIS does not cover fall back to NIST SP 800-53.

## Quick start

Prerequisites: Docker or Podman, plus Docker Compose (or podman-compose).

```bash
docker compose up
```

Open http://localhost:8000. The bundled emulator starts with the stack and serves a deliberately misconfigured demo project, so you can run a scan immediately with no GCP account.

To point R.A.D.O.N. at a real project, set the endpoint in Settings > Connection, or via the RADON_ENDPOINT environment variable.

## Open Core

The repository is the free, self-hosted core, licensed Apache 2.0. Metal Origami maintains a commercial version on top of it.

| Capability | Open core | Commercial |
|---|---|---|
| 50+ checks across IAM, Storage, Compute, Cloud Run | ✅ | ✅ |
| Local, air-gapped LLM triage | ✅ | ✅ |
| GKE, BigQuery, org hierarchy, continuous scanning | ❌ | ✅ |
| Fine-tuned models trained on GCP security data | ❌ | ✅ |
| Live access to the latest GCP documentation | ❌ | ✅ |
| Automated remediation via GCP API calls | ❌ | ✅ |

The bundled LFM model weights ship under the LFM Open License v1.0, and llama.cpp is MIT. Provided as-is, without warranty.

## Architecture

| Component | Role |
|---|---|
| Audit Engine (Python) | Collects GCP configuration over HTTP and runs the 50+ checks |
| LLM Triage (llama.cpp, LFM 2.5) | Turns each finding into a plain-English assessment with remediation |
| MongoDB | Stores findings and scan history |
| FastAPI + JS Dashboard | Serves findings, the posture score, and the AI chat |
| GCP Emulator | A fake, misconfigured GCP project for offline testing |

The audit engine pulls configuration from a GCP-compatible endpoint (the bundled emulator, or a real project via RADON_ENDPOINT). Findings land in MongoDB with severity and resource context, the local LLM triages each one into a plain-English assessment, and the dashboard presents the results.
