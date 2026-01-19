"""AI agent client for security analysis.

Provides multi-provider architecture for AI analysis:
- Claude (Anthropic) - primary
- Gemini, OpenAI (planned)
"""

import json
import os
import subprocess
import shutil
from typing import Any, Dict, Optional

import anthropic

try:
    import google.generativeai as genai
except ImportError:
    genai = None

from drystone.models.findings import SkillFindings


class AgentError(Exception):
    """Agent client error."""

    pass


class AgentClient:
    """AI agent client for AWS security analysis.

    Analyzes collected evidence against security checklists
    and generates findings with recommendations.

    Currently supports Claude (Anthropic).
    Designed for extensibility to Gemini, OpenAI in future.

    Example:
        >>> agent = AgentClient(api_key="sk-ant-...")
        >>> findings = agent.analyze_evidence(
        ...     skill_name="iam",
        ...     evidence={"users": [...]},
        ...     checklist={"items": [...]}
        ... )
        >>> print(findings.summary.overall_risk_score)
        7.5
    """

    def __init__(self, provider_config: Optional[Dict[str, str]] = None):
        """Initialize agent client.

        Args:
            provider_config: Configuration dictionary with:
                {
                    'type': 'claude-api' | 'claude-cli' | 'gemini-api',
                    'api_key': 'sk-ant-...' (optional, required for API-based)
                }

        Raises:
            AgentError: If configuration invalid or backend unavailable
        """
        self.provider_config = provider_config or {}
        self.provider_type = self.provider_config.get('type', 'claude-cli')
        self.api_key = self.provider_config.get('api_key')
        self.client = None
        self.use_cli = False

        # Validate provider type
        valid_types = {"claude-api", "claude-cli", "gemini-api"}
        if self.provider_type not in valid_types:
            raise AgentError(
                f"Provider type '{self.provider_type}' not supported. "
                f"Valid: {valid_types}"
            )

        # Configure Claude
        if self.provider_type.startswith("claude"):
            self._setup_claude()
        # Configure Gemini
        elif self.provider_type.startswith("gemini"):
            self._setup_gemini()

    def _setup_claude(self) -> None:
        """Setup Claude provider (API or CLI)."""
        self.provider_name = "claude"

        if self.provider_type == "claude-cli":
            # Use CLI
            if not self._check_claude_cli_available():
                raise AgentError(
                    "Claude CLI not found in PATH.\n"
                    "Install: npm install -g @anthropic-ai/claude-code\n"
                    "Or select 'Claude API Key' option if you have an API key"
                )
            self.use_cli = True

        elif self.provider_type == "claude-api":
            # Use API
            if not self.api_key:
                raise AgentError("Claude API key required for 'claude-api' provider")

            try:
                self.client = anthropic.Anthropic(api_key=self.api_key)
                self.model = "claude-opus-4-5-20251101"
                self.max_tokens = 16000
                self.temperature = 0.0
            except Exception as e:
                raise AgentError(f"Failed to initialize Anthropic client: {e}")

    def _check_claude_cli_available(self) -> bool:
        """Check if Claude CLI is available in system.

        Returns:
            True if 'claude' command is available, False otherwise
        """
        return shutil.which("claude") is not None

    def _setup_gemini(self) -> None:
        """Setup Gemini API provider."""
        if self.provider_type == "gemini-api":
            # Use Gemini API
            if not self.api_key:
                raise AgentError("Gemini API key required for 'gemini-api' provider")

            if genai is None:
                raise AgentError(
                    "google-generativeai library not installed.\n"
                    "Install: pip install google-generativeai"
                )

            try:
                genai.configure(api_key=self.api_key)
                self.gemini_model = genai.GenerativeModel("gemini-pro")
                self.use_cli = False
                self.provider_name = "gemini"
            except Exception as e:
                raise AgentError(f"Failed to initialize Gemini client: {e}")

    def analyze_evidence(
        self,
        skill_name: str,
        evidence: Dict[str, Any],
        checklist: Dict[str, Any],
    ) -> SkillFindings:
        """Analyze AWS evidence against security checklist.

        Uses Claude CLI (subprocess) if available, otherwise Anthropic API.

        Flow:
        1. Builds analysis prompt with evidence and checklist
        2. Calls Claude (CLI or API)
        3. Parses JSON response
        4. Validates with Pydantic model
        5. Returns structured findings

        Args:
            skill_name: Skill identifier (e.g., "iam")
            evidence: AWS evidence data (from collectors)
            checklist: Security checklist with items

        Returns:
            SkillFindings with structured findings and summary

        Raises:
            AgentError: If call fails or response invalid
        """
        # 1. Build prompt
        analysis_prompt = self._build_analysis_prompt(skill_name, evidence, checklist)
        full_prompt = f"{self._get_system_prompt()}\n\n{analysis_prompt}"

        # 2. Call LLM (CLI or API)
        if self.provider_type.startswith("claude"):
            if self.use_cli:
                response_text = self._call_claude_cli(full_prompt)
            else:
                response_text = self._call_claude_api(full_prompt)
        elif self.provider_type == "gemini-api":
            response_text = self._call_gemini_api(full_prompt)

        # 3. Parse JSON response
        try:
            findings_data = self._parse_json_response(response_text)
        except AgentError:
            raise

        # 4. Validate with Pydantic
        try:
            findings = SkillFindings(**findings_data)
        except Exception as e:
            raise AgentError(f"Response validation failed: {e}")

        return findings

    def _call_claude_cli(self, prompt: str) -> str:
        """Call Claude via CLI subprocess.

        Args:
            prompt: Full prompt (system + user)

        Returns:
            Response text from Claude

        Raises:
            AgentError: If subprocess fails
        """
        try:
            result = subprocess.run(
                ["claude", "-p", prompt],
                input="",  # Empty stdin
                capture_output=True,
                text=True,
                timeout=300,  # 5 minutes - Claude CLI can be slow with large prompts
            )

            if result.returncode != 0:
                raise AgentError(
                    f"Claude CLI error: {result.stderr}\n"
                    f"Make sure Claude Code CLI is installed: npm install -g @anthropic-ai/claude-code"
                )

            return result.stdout

        except subprocess.TimeoutExpired:
            raise AgentError("Claude CLI call timed out (>300s). Prompt may be too large.")
        except Exception as e:
            raise AgentError(f"Claude CLI error: {e}")

    def _call_claude_api(self, prompt: str) -> str:
        """Call Claude via Anthropic API.

        Args:
            prompt: Full prompt (system + user)

        Returns:
            Response text from Claude

        Raises:
            AgentError: If API call fails
        """
        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                messages=[{"role": "user", "content": prompt}],
            )
            return response.content[0].text

        except anthropic.APIError as e:
            raise AgentError(f"API call failed: {e}")
        except (IndexError, AttributeError) as e:
            raise AgentError(f"Invalid API response format: {e}")

    def _call_gemini_api(self, prompt: str) -> str:
        """Call Gemini via Google Generative AI API.

        Args:
            prompt: Full prompt (system + user)

        Returns:
            Response text from Gemini

        Raises:
            AgentError: If API call fails
        """
        try:
            response = self.gemini_model.generate_content(
                prompt,
                generation_config=genai.types.GenerationConfig(
                    temperature=0.0,
                    max_output_tokens=16000,
                ),
            )
            return response.text

        except Exception as e:
            raise AgentError(f"Gemini API call failed: {e}")

    def _get_system_prompt(self) -> str:
        """Get system prompt for Claude - IAM Security Specialist."""
        return """Eres un auditor AWS experto en IAM security con certificación AWS Security Specialty y conocimiento de compliance (PCI DSS v4.0).

Tu rol:
- Analizar configuraciones IAM contra CIS AWS Foundations + AWS Security Best Practices + PCI DSS v4.0
- Identificar 25+ categorías de vulnerabilidades y misconfigurations
- Mapear cada hallazgo a controles PCI DSS relevantes para compliance reporting
- Generar hallazgos accionables con remediaciones específicas
- Aplicar principios de least privilege y defense in depth

CATEGORÍAS DE ANÁLISIS (EXHAUSTIVAS):

🔴 CRÍTICOS (máxima prioridad - resolver en 24h):
1. Root account sin MFA (risk_score: 10)
2. Root account con access keys activas (risk_score: 10)
3. Usuarios admin sin MFA (risk_score: 9.5)
4. Access keys > 90 días sin rotación (risk_score: 9)
5. Políticas *:* (full admin) sin restricción (risk_score: 9)
6. Trust policies con Principal: "*" público (risk_score: 10)

🟠 ALTOS (prioridad media - resolver en 1 semana):
7. Usuarios inactivos > 90 días con credenciales activas (risk_score: 7-8)
8. Access keys nunca usadas pero activas > 30 días (risk_score: 7)
9. Múltiples access keys activas por usuario (risk_score: 6-7)
10. Usuarios con permisos directos (no en grupos) (risk_score: 6)
11. Service accounts como IAM users (no roles) (risk_score: 6)
12. Cross-account roles sin ExternalId (risk_score: 7)
13. Password policy débil (< 14 chars, sin símbolos) (risk_score: 6-7)
14. Password policy sin max-age o reuse prevention (risk_score: 6)

🟡 MEDIOS (mejora recomendada - resolver en 2 semanas):
15. Inline policies (deben migrar a managed) (risk_score: 4-5)
16. Usuarios sin grupo asignado (risk_score: 3-4)
17. Grupos vacíos (sin usuarios) (risk_score: 2-3)
18. Roles sin uso en 90+ días (risk_score: 3-4)
19. Políticas customer-managed duplicadas (risk_score: 3)
20. CloudTrail sin logging de IAM events (risk_score: 4)
21. Access Analyzer deshabilitado (risk_score: 3)
22. Permission boundaries no usadas (delegated admin) (risk_score: 3)
23. Políticas customer-managed sin attachments (dead code) (risk_score: 2)

🔵 BAJOS (best practice - resolver cuando sea posible):
24. Alias de cuenta no configurado (risk_score: 1)
25. Tags faltantes en recursos (risk_score: 1)
26. RequireSymbols no activado (risk_score: 2)

INSTRUCCIONES DE ANÁLISIS:

**Paso 1: Revisa TODA la evidencia**
- users.json: Analiza cada usuario por MFA, access keys, grupos, permisos directos
- roles.json: Busca trust policies con "*", inline policies, permisos excesivos
- policies.json: Detecta "*:*", duplicados, inline policies
- password-policy.json: Valida longitud, símbolos, números, max-age, reuse prevention
- groups.json: Identifica grupos vacíos, usuarios no agrupados
- account-summary.json: Verifica CloudTrail, Access Analyzer

**Paso 2: Genera findings SOLO si encuentras riesgo real**
- No generes false positives
- Incluye evidencia específica (arn, user name, policy details)
- Calcula risk_score 0-10 basado en: severidad + impacto + probabilidad
- Para cada finding: incluir affected_resources con ARNs reales

**Paso 3: Prioriza por severidad**
- Críticos primero (risk_score 8-10)
- Luego altos (6-7.9)
- Luego medios (3-5.9)
- Luego bajos (0-2.9)

**Paso 4: Mapea a controles PCI DSS**
- El checklist.json incluye "pci_dss" array para cada check (control + reason)
- Extrae los controles PCI-DSS del checklist para cada hallazgo
- Incluye en "pci_dss_controls" field: {control: "8.4.1", reason: "..."}
- Usa las razones del checklist, no inventes nuevas

**Paso 5: Incluye referencias específicas**
- users.json#root → Root user
- users.json#UserName='admin-user' → Specific user
- roles.json#RoleName='LambdaExecutionRole'#AssumeRolePolicyDocument → Trust policy
- policies.json#PolicyName → Policy name
- password-policy.json → Password policy settings

Requisitos de respuesta:
- SOLO JSON válido, sin markdown, sin explicaciones adicionales
- Usar schema exacto del user prompt
- Ser exhaustivo: revisar TODOS los 28 checks del checklist
- Campo "cis_reference" debe reflejar CIS control ID
- overall_risk_score = promedio ponderado de todos los findings
- Máximo 50 findings por skill (prioriza críticos y altos)"""

    def _build_analysis_prompt(
        self, skill_name: str, evidence: Dict[str, Any], checklist: Dict[str, Any]
    ) -> str:
        """Build analysis prompt with evidence and checklist.

        Args:
            skill_name: Skill name (e.g., "iam")
            evidence: AWS evidence data
            checklist: Security checklist

        Returns:
            Formatted prompt for Claude
        """
        # Evidence count
        evidence_count = sum(
            len(v) if isinstance(v, list) else 1
            for v in evidence.values()
            if v is not None
        )

        prompt = f"""Analiza la siguiente evidencia AWS {skill_name.upper()} contra el checklist de seguridad.

===== EVIDENCIA AWS =====
{json.dumps(evidence, indent=2, default=str)}

===== CHECKLIST DE SEGURIDAD =====
{json.dumps(checklist, indent=2)}

===== SCHEMA DE RESPUESTA (JSON ESTRICTO) =====
{{
  "skill": "{skill_name}",
  "findings": [
    {{
      "id": "ID-XXX",
      "severity": "Critical|High|Medium|Low",
      "risk_score": 0.0-10.0,
      "title": "Título breve",
      "description": "Descripción detallada del hallazgo",
      "evidence_refs": ["evidence/iam/users.json#path"],
      "affected_resources": ["arn:aws:iam::..."],
      "remediation": "Pasos concretos de remediación",
      "cis_reference": "CIS ID",
      "pci_dss": [
        {{
          "control": "8.4.1",
          "reason": "Razón específica del checklist por qué este hallazgo se relaciona con este control"
        }}
      ]
    }}
  ],
  "summary": {{
    "total_findings": 0,
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "overall_risk_score": 0.0
  }},
  "analyzed_at": "ISO timestamp",
  "evidence_count": {evidence_count},
  "checklist_version": "2.0"
}}

===== INSTRUCCIONES =====
1. Revisa TODA la evidencia contra CADA item del checklist
2. Genera finding solo si encuentras riesgo real o incumplimiento
3. Incluye referencias específicas a evidencia (ej: users.json#root)
4. Calcula risk_score 0-10 basado en: severidad + impacto + probabilidad
5. Incluye affected_resources con ARNs reales de la evidencia
6. Mapea cada finding a controles PCI DSS usando el checklist.json (campo "pci_dss")
7. overall_risk_score = promedio de todos los risk_score
8. Retorna SOLO JSON válido, sin texto adicional, sin markdown"""

        return prompt

    def _parse_json_response(self, text: str) -> dict:
        """Parse JSON response, handle markdown wrapping.

        Args:
            text: Raw response text from Claude

        Returns:
            Parsed JSON dictionary

        Raises:
            AgentError: If JSON invalid or cannot be extracted
        """
        # Remove markdown code blocks if present
        if "```json" in text:
            text = text.split("```json")[1].split("```")[0]
        elif "```" in text:
            text = text.split("```")[1].split("```")[0]

        # Try to parse JSON
        try:
            return json.loads(text.strip())
        except json.JSONDecodeError as e:
            # Log first 500 chars for debugging
            preview = text.strip()[:500]
            raise AgentError(
                f"Invalid JSON response from API: {e}\n"
                f"Response preview: {preview}"
            )
