# Drystone - Workflow Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                        ENTRY POINT                                  │
│  python -m drystone audit                                           │
│  __main__.py → cli/main.py → audit()                               │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  PHASE 0: WIZARD                          cli/ui/wizard.py         │
│                                                                     │
│  Menu A: Project & AWS Scope        Menu B: AI Configuration        │
│  ├─ Client name                     ├─ Provider (CLI / API)         │
│  ├─ AWS credentials (4 methods)     └─ API key (if API)             │
│  ├─ Region                                                          │
│  ├─ Skills (13 disponibles)                                         │
│  ├─ Output formats (md/json)                                        │
│  └─ Report type (general/pci-dss/pentest)                           │
│                                                                     │
│  Output: WizardConfig (Pydantic) → ~/.drystone/config.json          │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  PHASE 1: AWS VALIDATION               cloud/aws/client.py         │
│                                                                     │
│  boto3 → STS get_caller_identity()                                  │
│  Output: account_id + AuditSession created                          │
│          audit-logs/{client}_{timestamp}/                            │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  PHASE 1a: EVIDENCE COLLECTION    skills/{skill}/__init__.py        │
│  (ThreadPoolExecutor - parallel)                                    │
│                                                                     │
│  ┌──────┐ ┌──────────┐ ┌─────────┐ ┌───────┐ ┌──────────┐         │
│  │ IAM  │ │ Exposure │ │ Network │ │ Vulns │ │ Alerting │ ...      │
│  └──┬───┘ └────┬─────┘ └────┬────┘ └───┬───┘ └────┬─────┘         │
│     │          │            │           │          │                 │
│     ▼          ▼            ▼           ▼          ▼                 │
│  skill.collect(aws_client, session) → boto3 → AWS APIs              │
│                                                                     │
│  Output: evidence/{skill}/*.json                                    │
│  (users.json, roles.json, buckets.json, vpcs.json, ...)             │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  PHASE 1b: 3-TIER ANALYSIS              skills/base.py → analyze() │
│  (ThreadPoolExecutor - parallel per skill)                          │
│                                                                     │
│  For each skill:                                                    │
│  ┌─────────────────────────────────────────────────────┐            │
│  │                                                     │            │
│  │  ┌─────────────────────────────────────────────┐    │            │
│  │  │  TIER 1: PRE-CHECKS (deterministic, <1s)    │    │            │
│  │  │  validation/pre_checks.py                    │    │            │
│  │  │                                              │    │            │
│  │  │  evidence + checklist → run_pre_checks()     │    │            │
│  │  │  Output: PreCheckResult[] (PASS/FAIL/SKIP)   │    │            │
│  │  │                                              │    │            │
│  │  │  69 checks across 13 skills:                 │    │            │
│  │  │  IAM(8) HRD(11) ALR(2) EXP(9) NET(3)        │    │            │
│  │  │  WAF(5) VULN(3) SM(2) ECR(4) KMS(4)         │    │            │
│  │  │  MSG(4) CICD(2) COMP(5)                      │    │            │
│  │  └──────────────────────┬──────────────────────┘    │            │
│  │                         │                            │            │
│  │                         ▼                            │            │
│  │  ┌─────────────────────────────────────────────┐    │            │
│  │  │  TIER 2: AI ANALYSIS (constrained)           │    │            │
│  │  │  agent/client.py                             │    │            │
│  │  │                                              │    │            │
│  │  │  Prompt = XML template + evidence            │    │            │
│  │  │        + <pre_computed_facts> (Tier 1)       │    │            │
│  │  │                                              │    │            │
│  │  │  Rules injected:                             │    │            │
│  │  │  • PASS → DO NOT generate finding            │    │            │
│  │  │  • FAIL → Generate with description/remed.   │    │            │
│  │  │  • Not listed → Analyze evidence yourself    │    │            │
│  │  │                                              │    │            │
│  │  │  ┌── Claude CLI ─────┐ ┌── Claude API ────┐  │    │            │
│  │  │  │ analyze_evidence  │ │ analyze_evidence │  │    │            │
│  │  │  │ _chunked() +     │ │ _chunked() +     │  │    │            │
│  │  │  │ retry             │ │ retry            │  │    │            │
│  │  │  └──────────────────┘ └──────────────────┘  │    │            │
│  │  └──────────────────────┬──────────────────────┘    │            │
│  │                         │                            │            │
│  │                         ▼                            │            │
│  │  ┌─────────────────────────────────────────────┐    │            │
│  │  │  TIER 3: RECONCILIATION + NORMALIZATION      │    │            │
│  │  │  base.py + validation/                       │    │            │
│  │  │                                              │    │            │
│  │  │  3a. _reconcile_with_pre_checks()            │    │            │
│  │  │      • Reject AI findings contradicting PASS │    │            │
│  │  │      • Inject findings for missed FAILs      │    │            │
│  │  │                                              │    │            │
│  │  │  3b. findings_normalizer.py                  │    │            │
│  │  │      • Dedup, severity calibration           │    │            │
│  │  │      • Evidence validation (non-pre-checked) │    │            │
│  │  │      • Pre-checked IDs → SKIP validation     │    │            │
│  │  │                                              │    │            │
│  │  │  3c. checklist_coverage.py                   │    │            │
│  │  │      • Missing critical checks detection     │    │            │
│  │  │                                              │    │            │
│  │  │  3d. queue_validator.py                      │    │            │
│  │  │      • Pre-correlation gate                  │    │            │
│  │  └──────────────────────────────────────────────┘    │            │
│  └─────────────────────────────────────────────────┘    │            │
│                                                         │            │
│  Output: SkillFindings → findings/{skill}.json          │            │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  PHASE 2: CORRELATION              correlation/engine.py            │
│  (Solo si ≥2 skills ejecutados)                                     │
│                                                                     │
│  1. Build resource index (O(n), cached)                             │
│  2. Apply patterns from patterns.py                                 │
│     (IAM+Exposure, Network+Vulns, KMS+IAM, CICD+Messaging...)      │
│  3. Generate attack chains                                          │
│  4. Limits: 50/pattern, 200 total, 60s timeout                     │
│                                                                     │
│  Output: CorrelatedFindings + attack chains                         │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  PHASE 3: REPORT GENERATION           reports/generator.py          │
│                                                                     │
│  Post-processors (skill-specific):                                  │
│  ├─ alerting/post_processor.py  → Architecture diagram              │
│  ├─ waf/post_processor.py       → Protection flow                   │
│  └─ network/post_processor.py   → Topology diagram                  │
│                                                                     │
│  Formatters:                                                        │
│  ┌────────────┐ ┌───────────┐ ┌─────────┐ ┌─────────────┐          │
│  │  Markdown   │ │  PCI DSS  │ │ Pentest │ │    JSON     │          │
│  │  (general)  │ │ (control  │ │ (attack │ │ (machine    │          │
│  │  ASCII      │ │  table    │ │  chains │ │  readable)  │          │
│  │  charts     │ │  ✅/❌/⚠️) │ │  paths) │ │             │          │
│  └─────────────┘ └───────────┘ └─────────┘ └─────────────┘          │
│                                                                     │
│  Output: reports/{skill}_report.{md|json}                           │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  PHASE 4: SESSION & METRICS           storage/session.py            │
│                                       logging/metrics_tracker.py    │
│                                                                     │
│  audit-logs/{client}_{timestamp}/                                   │
│  ├── evidence/{skill}/*.json      ← Raw AWS data                   │
│  ├── findings/{skill}.json        ← Normalized findings            │
│  ├── reports/*_report.md          ← Generated reports              │
│  ├── metrics.json                 ← Timing, counts, risk scores    │
│  └── audit.log                    ← Structured log                  │
└─────────────────────────────────────────────────────────────────────┘
```

## 3-Tier Validation Architecture

```
Evidence ─────►  Tier 1 (Pre-checks) ─────►  Tier 2 (AI) ─────►  Tier 3 (Reconcile)
                 DETERMINISTIC                CONSTRAINED          POST-VALIDATE
                 pre_checks.py                agent/client.py      base.py + normalizer

                 69 binary checks             Receives              • Reject PASS
                 PASS / FAIL / SKIP           <pre_computed_facts>    contradictions
                 ~1s, 100% reproducible       as XML in prompt      • Inject missed FAILs
                                              AI focuses on         • Normalize + dedup
                                              complex checks          (skip pre-checked)
```

### Data flow per check ID

```
Check IAM-001 (Root MFA):

  Tier 1: evidence["account-summary"]["AccountMFAEnabled"] == 1?
          → PASS (deterministic)

  Tier 2: <fact id="IAM-001" status="PASS">
            AI instructed: "DO NOT generate finding"

  Tier 3: If AI generates IAM-001 anyway → REJECTED
          normalizer skips IAM-001 evidence validation (already resolved)


Check IAM-008 (Admin policies):

  Tier 1: evidence["policies"] has Action:*/Resource:*?
          → FAIL (deterministic)

  Tier 2: <fact id="IAM-008" status="FAIL">
            AI writes professional description + remediation

  Tier 3: If AI missed IAM-008 → INJECTED from checklist
          normalizer skips IAM-008 evidence validation


Check IAM-005 (Password policy complexity):

  Tier 1: No pre-check registered → not in results

  Tier 2: No <fact> for IAM-005 → AI analyzes evidence itself

  Tier 3: Normal normalizer flow (evidence validation, severity calibration)
```

### Impact metrics

| Metric | Before (AI only) | After (3-Tier) |
|--------|-------------------|-----------------|
| False positives (Tier 1 checks) | ~5-7% | **~0%** |
| Missing criticals (Tier 1) | AI-dependent | **Deterministic injection** |
| Reproducibility (Tier 1) | Variable | **100%** |
| Tokens to AI | 100% evidence analysis | Evidence + pre-computed hints |
| Post-validation for Tier 1 | Full normalizer | **Skipped** (already resolved) |
| Deterministic checks | 0 pre-AI | **69** across 13 skills |

## Skills disponibles (13)

| Skill | AWS Services | Checks | Pre-checks |
|-------|-------------|--------|------------|
| `iam` | IAM users, roles, policies | MFA, access keys, permissions | 8 |
| `exposure` | S3, RDS, ELB, EC2 | Public endpoints, open buckets | 9 |
| `network` | VPC, SGs, NACLs, TGW | Open ports, routing rules | 3 |
| `vulns` | Inspector v2 | Known CVEs, patch status | 3 |
| `alerting` | CloudTrail, CloudWatch, SNS | Event monitoring coverage | 2 |
| `hardening` | Config, Security Hub | CIS/PCI compliance score | 11 |
| `ecr` | ECR | Image scanning, registry config | 4 |
| `secretsmanager` | Secrets Manager | Rotation, encryption | 2 |
| `waf` | WAF, CloudFront, ALB | Rule coverage, protection gaps | 5 |
| `kms` | KMS | Key rotation, policies | 4 |
| `messaging` | SQS, SNS | Encryption, access policies | 4 |
| `cicd` | CodeBuild | Build security, secrets in env | 2 |
| `compute` | ECS, EKS | Container hardening | 5 |

## Arquitectura clave

**Principio:** App orquesta, Agent analiza. Pre-checks resuelven lo determinista.

```
App (Python)                    Agent (Claude)
├─ Wizard + Config              ├─ Recibe evidence JSON
├─ AWS credential mgmt    →    ├─ Recibe <pre_computed_facts>
├─ boto3 data collection        ├─ Respeta PASS/FAIL verdicts
├─ Evidence persistence    →    ├─ Analiza checks complejos
├─ PRE-CHECKS (Tier 1)         ├─ Genera description/remediation
├─ Parse findings          ←    └─ Retorna findings JSON
├─ Reconciliation (Tier 3)
├─ Normalization (skip pre-checked)
├─ Correlation cross-skill
└─ Report generation
```

## Puntos clave para tuning

1. **Pre-checks** (`validation/pre_checks.py`) - Tier 1 determinista, 100% reproducible
2. **Prompts XML** (`prompts/templates/`) - Calidad de findings para checks complejos
3. **Findings normalizer** - Reduce varianza (skips pre-checked IDs)
4. **Checklists** - Determinan qué busca el agente (y qué pre-checks existen)
5. **Correlation patterns** - Attack chains cross-skill

## Key files

| File | Role |
|------|------|
| `validation/pre_checks.py` | Tier 1: 69 deterministic checks, registry, XML formatter |
| `skills/base.py` | Orchestrates 3-tier flow in `analyze()`, reconciliation |
| `agent/client.py` | Tier 2: Injects `<pre_computed_facts>` via SKILL_ADDENDUM |
| `validation/findings_normalizer.py` | Tier 3: Skips pre-checked IDs, handles complex checks |
| `validation/checklist_coverage.py` | Coverage gap detection |
| `validation/queue_validator.py` | Pre-correlation gate |
