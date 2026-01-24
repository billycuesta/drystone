"""AI agent client for security analysis.

Provides multi-provider architecture for AI analysis:
- Claude (Anthropic) - primary
- Gemini, OpenAI (planned)
"""

import json
import os
import subprocess
import shutil
import warnings
from typing import Any, Dict, Optional

import anthropic
import botocore.exceptions

# Suppress deprecation warning for google.generativeai
# TODO: Migrate to google.genai when available
try:
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=FutureWarning)
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
        valid_types = {"claude-api", "claude-cli", "gemini-api", "bedrock"}
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
        # Configure Bedrock
        elif self.provider_type == "bedrock":
            self._setup_bedrock()

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

    def _setup_bedrock(self) -> None:
        """Setup AWS Bedrock provider (Amazon Nova Micro).

        Uses Amazon Nova Micro model (amazon.nova-micro-v1:0) - AWS's efficient
        foundation model optimized for speed and cost.
        Uses separate AWS credentials for Bedrock (can be different from audit credentials).
        Region hardcoded to eu-west-1 where Bedrock is enabled.
        """
        self.provider_name = "bedrock"

        # Extract Bedrock AWS credentials from provider_config
        # These are separate credentials for Bedrock (can be from a different AWS account)
        # Priority: bedrock_* fields, fall back to aws_* if bedrock_* not provided
        bedrock_access_key = self.provider_config.get('bedrock_access_key_id')
        bedrock_secret_key = self.provider_config.get('bedrock_secret_access_key')
        bedrock_session_token = self.provider_config.get('bedrock_session_token')

        # Fall back to audit credentials if Bedrock credentials not provided
        if not bedrock_access_key:
            bedrock_access_key = self.provider_config.get('aws_access_key_id')
        if not bedrock_secret_key:
            bedrock_secret_key = self.provider_config.get('aws_secret_access_key')

        if not bedrock_access_key or not bedrock_secret_key:
            raise AgentError(
                "AWS credentials required for Bedrock provider.\n"
                "Provide bedrock_access_key_id and bedrock_secret_access_key, or ensure aws_access_key_id and aws_secret_access_key are configured."
            )

        try:
            import boto3

            # Create Bedrock Runtime client
            # Region: eu-west-1 (hardcoded - where company has Bedrock enabled)
            bedrock_kwargs = {
                'region_name': 'eu-west-1',
                'aws_access_key_id': bedrock_access_key,
                'aws_secret_access_key': bedrock_secret_key,
            }
            # Add session token only if provided (for temporary credentials)
            if bedrock_session_token:
                bedrock_kwargs['aws_session_token'] = bedrock_session_token

            self.bedrock_client = boto3.client('bedrock-runtime', **bedrock_kwargs)

            # Model configuration
            # Using Amazon Nova Micro via Inference Profile (fast, cost-effective)
            # Nova Micro has 5000 token limit (sufficient for typical evidence analysis)
            self.bedrock_model_id = "arn:aws:bedrock:eu-west-1:781978598807:inference-profile/eu.amazon.nova-micro-v1:0"
            self.max_tokens = 5000
            self.temperature = 0.0
            self.use_cli = False

        except ImportError:
            raise AgentError(
                "boto3 library required for Bedrock.\n"
                "Install: pip install boto3"
            )
        except Exception as e:
            raise AgentError(f"Failed to initialize Bedrock client: {e}")

    def get_display_name(self) -> str:
        """Get user-friendly display name for the configured AI provider.

        Returns display name like "AWS Bedrock (Nova Micro)" or "Claude API (Opus 4.5)".
        Defensive: if cannot determine exact model, returns generic provider name.

        Returns:
            Display name string for UI output
        """
        if self.provider_type == "bedrock":
            # Extract model name from ARN or model ID
            # ARN format: arn:aws:bedrock:region:account:inference-profile/eu.amazon.nova-micro-v1:0
            # Model ID format: amazon.nova-micro-v1:0
            model_id = self.bedrock_model_id

            if "nova-micro" in model_id:
                return "AWS Bedrock (Nova Micro)"
            elif "nova-lite" in model_id:
                return "AWS Bedrock (Nova Lite)"
            elif "claude-3-sonnet" in model_id:
                return "AWS Bedrock (Claude 3 Sonnet)"
            else:
                return "AWS Bedrock"

        elif self.provider_type == "claude-api":
            # Use self.model (e.g., "claude-opus-4-5-20251101")
            if hasattr(self, 'model') and 'opus' in self.model:
                return "Claude API (Opus 4.5)"
            elif hasattr(self, 'model') and 'sonnet' in self.model:
                return "Claude API (Sonnet)"
            else:
                return "Claude API"

        elif self.provider_type == "claude-cli":
            return "Claude CLI"

        elif self.provider_type == "gemini-api":
            return "Gemini API"

        else:
            return "AI Provider"  # Fallback

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
        2. Calls Claude (CLI or API) or Bedrock
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
        # 1. Get prompts
        system_prompt = self._get_system_prompt()
        user_prompt = self._build_analysis_prompt(skill_name, evidence, checklist)

        # 2. Call LLM (CLI or API)
        if self.provider_type.startswith("claude"):
            # Claude providers use combined prompt
            full_prompt = f"{system_prompt}\n\n{user_prompt}"
            if self.use_cli:
                response_text = self._call_claude_cli(full_prompt)
            else:
                response_text = self._call_claude_api(full_prompt)
        elif self.provider_type == "gemini-api":
            # Gemini uses combined prompt
            full_prompt = f"{system_prompt}\n\n{user_prompt}"
            response_text = self._call_gemini_api(full_prompt)
        elif self.provider_type == "bedrock":
            # Bedrock (Nova Micro) requires separated prompts
            response_text = self._call_bedrock_api(system_prompt, user_prompt)

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

    def _call_bedrock_api(self, system_prompt: str, user_prompt: str) -> str:
        """Call Amazon Nova Micro via AWS Bedrock Runtime API.

        Nova Micro requires separated system and user prompts in the request body.

        Args:
            system_prompt: System prompt (instructions)
            user_prompt: User prompt (analysis request with evidence)

        Returns:
            Response text from Nova Micro via Bedrock

        Raises:
            AgentError: If Bedrock API call fails
        """
        try:
            # Bedrock request format for Amazon Nova Micro
            # https://docs.aws.amazon.com/bedrock/latest/userguide/model-parameters-nova.html
            request_body = {
                "system": [
                    {
                        "text": system_prompt
                    }
                ],
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {
                                "text": user_prompt
                            }
                        ]
                    }
                ],
                "inferenceConfig": {
                    "maxTokens": self.max_tokens,
                    "temperature": self.temperature
                }
            }

            # Call Bedrock InvokeModel API
            response = self.bedrock_client.invoke_model(
                modelId=self.bedrock_model_id,
                body=json.dumps(request_body),
                contentType="application/json",
                accept="application/json",
            )

            # Parse response
            response_body = json.loads(response['body'].read())

            # Extract text from Nova Micro response format
            # Response structure: {"output": {"message": {"content": [{"text": "..."}]}}}
            if ('output' in response_body and
                'message' in response_body['output'] and
                'content' in response_body['output']['message'] and
                len(response_body['output']['message']['content']) > 0):
                return response_body['output']['message']['content'][0]['text']

            # Defensive error with response keys for debugging
            raise AgentError(
                f"Invalid response structure from Bedrock Nova Micro. "
                f"Got keys: {list(response_body.keys())}"
            )

        except botocore.exceptions.ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            if error_code == "ValidationException":
                raise AgentError(f"Bedrock validation error: {e}")
            elif error_code == "ModelTimeoutException":
                raise AgentError(f"Bedrock model timeout (prompt too large?): {e}")
            elif error_code == "ThrottlingException":
                raise AgentError(f"Bedrock throttling (rate limit exceeded): {e}")
            else:
                raise AgentError(f"Bedrock API call failed: {e}")
        except Exception as e:
            raise AgentError(f"Bedrock API call failed: {e}")

    def _get_system_prompt(self) -> str:
        """Get system prompt for AI agent - SKILL-AGNOSTIC version.

        Generic prompt that works for any security skill (IAM, Exposure, Network, Vulns).
        Emphasizes consistency and anti-variance rules for multi-model deployment.
        """
        return """Eres un auditor AWS experto en seguridad y compliance (PCI DSS v4.0).
Tu rol:
- Analizar evidencia AWS contra checklists de seguridad
- Identificar configuraciones inseguras y vulnerabilidades reales
- Mapear hallazgos a controles PCI DSS relevantes
- Generar recomendaciones accionables y específicas
- Aplicar principios de least privilege y defense in depth
FORMATO DE IDs OBLIGATORIO (UNIVERSAL):
✅ CORRECTO:
  - IAM-001, IAM-007, IAM-028 (formato SKILL-XXX)
  - EXP-005, EXP-012, EXP-020
  - NET-001, NET-003, NET-015
  - VULN-001, VULN-008, VULN-012
❌ PROHIBIDO:
  - IAM-008-001 (sub-IDs prohibidos)
  - IAM-099 (IDs fuera del checklist)
  - RANDOM-123 (IDs inventados)
REGLA ANTI-VARIANZA:
- Usa EXACTAMENTE los IDs del checklist proporcionado
- NO uses sub-IDs como SKILL-XXX-YYY
- NO inventes IDs fuera del checklist
- MÁXIMO 1 finding por item de checklist
SEVERITY CALIBRATION (RANGOS UNIVERSALES):
🔴 CRITICAL (risk_score: 8.5-10.0):
- Pérdida de confidencialidad: datos sensibles expuestos sin autenticación
- Pérdida de integridad: modificación de configs sin autorización
- Pérdida de disponibilidad: eliminación o sabotaje de servicios
- Cumplimiento: violaciones PCI DSS critical (8.4.1, 2.3.1, etc)
🟠 HIGH (risk_score: 6.0-8.4):
- Acceso excesivo: usuarios sin MFA, permisos sin restricción
- Credenciales débiles: rotación >90 días, policies permisivos
- Exposición no intendida: recursos públicos sin justificación
🟡 MEDIUM (risk_score: 3.0-5.9):
- Configuraciones subóptimas: inline policies, password policies débiles
- Mejoras recomendadas: usuarios sin grupos, roles sin uso
- Best practices: logs incompletos, sin segmentación
🔵 LOW (risk_score: 1.0-2.9):
- Mejoras cosmética: alias no configurados, tags faltantes
- Optimización: configuraciones no criticas
⚠️ INSTRUCCIONES ANTI-VARIANZA CRÍTICAS:
1. NUNCA generes findings con texto "DISREGARD THIS FINDING"
2. NUNCA uses sub-IDs (formato SKILL-XXX-YYY está prohibido)
3. NUNCA generes más de 1 finding por checklist item
4. NUNCA inventes severidades fuera de los 4 niveles
5. NUNCA reportes hallazgos ambiguos sin evidencia clara
6. NUNCA violes los límites de findings (min/max dinámicos)
Si encuentras evidencia ambigua:
→ Aplica principio conservador (menor severity o no reportar)
→ Documenta ambigüedad en "description"
→ Usa risk_score MÍNIMO del rango de severidad
INSTRUCCIONES DE ANÁLISIS:
**Paso 1: Revisa TODA la evidencia**
- Lee todos los archivos de evidencia proporcionados
- Valida contra CADA item del checklist
- Nota: evidencia incompleta = sin reporte (no asumas datos)
**Paso 2: Genera findings SOLO si encuentras riesgo real**
- Cada finding debe tener evidencia específica
- Incluye referencias precisas (file#path o arn)
- Calcula risk_score 0-10: severidad × impacto × probabilidad
**Paso 3: Prioriza por severidad**
- Críticos primero (risk_score 8.5-10.0)
- Luego altos (6.0-8.4)
- Luego medios (3.0-5.9)
- Luego bajos (1.0-2.9)
**Paso 4: Mapea a controles PCI DSS**
- Usa el array "pci_dss" del checklist como source of truth
- Solo incluye controles del checklist (no inventes nuevos)
- Copia la "reason" exacta del checklist
**Paso 5: Incluye referencias específicas**
- Formato: file.json#identifier
- Ejemplo: users.json#root, roles.json#RoleName='Lambda'
- Ejemplo ARN: arn:aws:iam::123456789012:user/admin
Requisitos de respuesta:
- SOLO JSON válido, sin markdown, sin explicaciones adicionales
- Usar schema exacto proporcionado
- Revisar TODOS los checks del checklist
- overall_risk_score = promedio ponderado de severity
- Máximo de findings: según rango dinámico (calculado por app)"""

    def _build_analysis_prompt(
        self, skill_name: str, evidence: Dict[str, Any], checklist: Dict[str, Any]
    ) -> str:
        """Build analysis prompt with evidence and checklist (SKILL-AGNOSTIC).

        Includes dynamic anti-variance calibration instructions based on checklist.

        Args:
            skill_name: Skill name (e.g., "iam", "exposure", "network")
            evidence: AWS evidence data
            checklist: Security checklist with items

        Returns:
            Formatted prompt for Claude with anti-variance instructions
        """
        # Evidence count
        evidence_count = sum(
            len(v) if isinstance(v, list) else 1
            for v in evidence.values()
            if v is not None
        )

        # Calculate dynamic findings limits (reduce variance)
        total_checklist_items = len(checklist.get('items', []))
        min_findings = max(8, int(total_checklist_items * 0.6))  # At least 60% of items
        max_findings = int(total_checklist_items * 0.8)  # Max 80% of items

        # Generate severity guide from checklist
        severity_guide = self._generate_severity_guide(checklist)

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
      "evidence_refs": ["evidence/skill/file.json#path"],
      "affected_resources": ["arn:aws:iam::..."],
      "remediation": "Pasos concretos de remediación",
      "cis_reference": "CIS ID",
      "pci_dss": [
        {{
          "control": "8.4.1",
          "reason": "Razón del checklist"
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

===== CALIBRACIÓN ESPECÍFICA DEL SKILL =====
Skill: {skill_name.upper()}
ID format: {skill_name.upper()}-XXX (ej: {skill_name.upper()}-001, {skill_name.upper()}-015)
Checklist items: {total_checklist_items}

RANGO DE FINDINGS A REPORTAR:
- Mínimo: {min_findings} findings (cubriendo Critical y High)
- Máximo: {max_findings} findings (evitar over-reporting)
- Target: Reportar SOLO riesgos reales con evidencia sólida

{severity_guide}

===== INSTRUCCIONES ANTI-VARIANZA =====
1. ✅ Usa IDs del checklist: {skill_name.upper()}-001, {skill_name.upper()}-002, etc
2. ❌ NUNCA uses sub-IDs: {skill_name.upper()}-008-001 está PROHIBIDO
3. ❌ NUNCA inventes IDs fuera del checklist
4. ❌ NUNCA generes "DISREGARD THIS FINDING" text
5. ✅ Máximo 1 finding por checklist item
6. ✅ Severidades del checklist = source of truth
7. ✅ Risk scores dentro del rango de severidad

===== INSTRUCCIONES DE ANÁLISIS =====
1. Revisa TODA la evidencia contra CADA item del checklist
2. Genera finding solo si encuentras riesgo real
3. Incluye referencias específicas a evidencia
4. Calcula risk_score 0-10: severidad × impacto × probabilidad
5. Incluye affected_resources con identifiers reales
6. Mapea cada finding a controles PCI DSS del checklist
7. overall_risk_score = promedio ponderado por severity
8. Retorna SOLO JSON válido, sin markdown, sin explicaciones"""

        return prompt

    def _generate_severity_guide(self, checklist: Dict[str, Any]) -> str:
        """Generate severity calibration guide from checklist.

        Extracts severity examples from checklist items to guide AI model.
        Works for any skill (IAM, Exposure, Network, Vulns).

        Args:
            checklist: Security checklist with items

        Returns:
            Formatted severity guide for prompt
        """
        items = checklist.get('items', [])

        # Group items by severity
        critical_items = []
        high_items = []
        medium_items = []
        low_items = []

        for item in items:
            severity = item.get('severity', 'Medium')
            item_id = item.get('id', '')
            title = item.get('title', '')[:50] + '...' if len(item.get('title', '')) > 50 else item.get('title', '')

            example = f"{item_id}: {title}"

            if severity == 'Critical':
                critical_items.append(example)
            elif severity == 'High':
                high_items.append(example)
            elif severity == 'Medium':
                medium_items.append(example)
            elif severity == 'Low':
                low_items.append(example)

        # Build guide
        guide_lines = ["EJEMPLOS DE SEVERIDADES DEL CHECKLIST:\n"]

        if critical_items:
            guide_lines.append("🔴 CRITICAL (risk_score 8.5-10.0):")
            for item in critical_items[:3]:  # Show first 3
                guide_lines.append(f"    - {item}")
            guide_lines.append("")

        if high_items:
            guide_lines.append("🟠 HIGH (risk_score 6.0-8.4):")
            for item in high_items[:3]:  # Show first 3
                guide_lines.append(f"    - {item}")
            guide_lines.append("")

        if medium_items:
            guide_lines.append("🟡 MEDIUM (risk_score 3.0-5.9):")
            for item in medium_items[:3]:  # Show first 3
                guide_lines.append(f"    - {item}")
            guide_lines.append("")

        if low_items:
            guide_lines.append("🔵 LOW (risk_score 1.0-2.9):")
            for item in low_items[:3]:  # Show first 3
                guide_lines.append(f"    - {item}")
            guide_lines.append("")

        return "\n".join(guide_lines)

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
