# OpenCode Context for Drystone

Este archivo resume el contexto operativo clave extraido de `CLAUDE.md` para trabajar en este repositorio con OpenCode.

## Proyecto

- Nombre: Drystone
- Objetivo: CLI para auditorias de seguridad AWS (compliance/security, no pentesting activo)
- Principio: la app orquesta, el agente analiza evidencia

## Stack tecnico

- Python 3.9+
- Click, Questionary, Rich
- boto3
- Pydantic
- Anthropic SDK

## Skills soportadas

- iam
- exposure
- network
- vulns
- alerting
- hardening
- secretsmanager
- waf
- ecr

## Flujo de ejecucion (alto nivel)

1. `python -m drystone audit`
2. Wizard interactivo (cliente, credenciales, region, skills, formato)
3. Validacion de credenciales AWS (STS)
4. Recoleccion de evidencia por skill (raw JSON)
5. Analisis con Claude por skill
6. Correlacion cross-skill + scoring
7. Generacion de reportes (markdown/html/json)
8. Logging y audit trail

## Arquitectura y convenciones clave

- Separacion estricta app vs agente
  - App: orquestacion, coleccion, validacion, reportes
  - Agente: analisis sobre evidencia + checklist, salida JSON
- Evidencia siempre raw primero, luego analisis
- Modelos con Pydantic + type hints
- Manejo de errores boto3 con mensajes utiles
- Nunca exponer credenciales en logs/UI

## Estado tecnico reciente relevante

- Implementada arquitectura de validacion en 3 capas:
  - Tier 1: pre-checks deterministas
  - Tier 2: analisis AI
  - Tier 3: normalizacion/reconciliacion
- 69 pre-checks deterministas en 13 skills
- Mejoras de resiliencia en chunker (skip metadata + manejo de errores por chunk)
- Normalizer ajustado para evitar errores de validacion en checks precomputados
- Suite de tests amplia en verde (contexto reportado: 426 tests)

## Prioridades actuales (resumen)

- Pendiente: upgrade boto3/botocore para ECR registry scanning
- Pendiente: pruebas manuales wizard (casos definidos)
- Pendiente: verificar compatibilidad `--non-interactive`
- Pendiente: IAM collector e integracion end-to-end

## Reglas operativas para OpenCode en este repo

- Mantener documentacion de arquitectura/planes/inventarios en `drystone-specs/` cuando aplique
- No eliminar `drystone_env/` bajo ninguna circunstancia
- Evitar comandos destructivos de git
- Seguir patrones existentes de skills/checklists/reportes
- Regla documental: ante cambios relevantes, actualizar siempre `opencode.md` y tambien `drystone-specs/drystone-architecture.md` cuando el cambio afecte arquitectura/flujo

## Comandos utiles

- `python -m drystone audit`
- `python -m drystone audit --non-interactive`
- `pytest tests/`
- `ruff check drystone/`
- `black drystone/`
- `mypy drystone/`

## Nota de mantenimiento

OpenCode debe actualizar este archivo cuando se hagan cambios relevantes (arquitectura, flujo, prioridades, skills, validaciones, reportes o decisiones tecnicas) para mantener contexto operativo vigente.

## Cambios recientes (OpenCode)

- Soporte PDF consolidado en pipeline de reportes:
  - formatter: `drystone/reports/formats/pdf.py`
  - template XML: `drystone/reports/templates/pdf_report.xml`
  - render: WeasyPrint desde HTML/XML
- Header PDF iterado para alinearlo con el estilo de la aplicacion:
  - recuadro coral
  - logo DRYSTONE con degradado por caracter (compatible PDF)
  - orden de textos: tagline -> motto -> `v1.0.0`
  - mayor separacion visual con el titulo del analisis
- Titulo del analisis movido fuera de la caja del header, con mas jerarquia visual.
- Reemplazo de seccion `Quick Summary` por `Scope Definition`.
  - formato en bloque unico (sin tarjeta por campo)
  - incluye parametros de alcance reales (client, fecha, skill, report type, account, region, access key usada, provider/model)
  - se removieron del scope campos no estrictamente de alcance (`min severity`, `total findings`, `overall risk score`)
- Resolucion de AWS Account ID robustecida en PDF:
  - usa `session.account_id` cuando existe
  - fallback por extraccion desde ARNs/evidencia si llega `unknown`
- Findings PDF ajustados:
  - orden: descripcion -> affected resources -> evidence -> remediation -> CIS reference
  - se elimina `Evidence References` en PDF; solo queda `Evidence` (raw JSON/snippet)
- Tabla de resumen de findings:
  - renombrada a `Findings Summary`
  - sin limite Top 10 (incluye todos)
- Paginacion en iteracion activa:
  - salto tras `Executive Summary`
  - salto tras cada finding
  - ajustes hibridos para manejar bloques de evidencia extensos
- `pdf` habilitado en configuracion y UX:
  - `WizardConfig.output_formats`
  - CLI `--formats`
  - wizard checkbox de formatos
  - `ReportGenerator.FORMATTERS`
- Pentest ahora soporta salida PDF manteniendo enfoque attack chains:
  - markdown pentest existente (`drystone/reports/formats/pentest.py`) se mantiene sin cambios
  - nuevo formatter PDF pentest (`drystone/reports/formats/pentest_pdf.py`)
  - en `report_type=pentest`, si se selecciona `pdf`, se genera `pentest-technical-report-*.pdf` con contenido orientado a attack chains
- Validacion reproducible en reportes PDF:
  - nueva capa compartida de sugerencias AWS CLI: `drystone/reports/validation_commands.py`
  - cobertura para skills: iam, exposure, network, waf, vulns, alerting, hardening, secretsmanager, ecr, kms, messaging, cicd, compute
  - `skills/base.py` ahora inyecta `validation_commands` en findings persistidos (cuando no vienen del agente)
  - `PDFFormatter` prioriza comandos explicitos del finding y, si faltan, usa sugerencias AWS CLI derivadas de `evidence_refs`
- Seccion de explotacion en findings PDF:
  - nuevo bloque `Exploitation (Theoretical)` por finding en `drystone/reports/formats/pdf.py`
  - usa descripcion de explotacion si existe en finding; si no, aplica narrativa inferida
  - incluye comandos de explotacion/PoC cuando existan y fallback a comandos de validacion
  - estilo visual dedicado en template (`.finding-exploitation`) en `drystone/reports/templates/pdf_report.xml`
- Modulo dedicado para explotacion en modo pentest:
  - `drystone/pentest/exploitation_enricher.py` (nuevo)
  - en `report_type=pentest`, enriquece findings con `exploitation_description` y `exploitation_commands`
  - usa evidencia + `evidence_refs` para construir narrativas mas utiles y comandos reproducibles
  - integracion en `drystone/reports/generator.py` solo para reportes pentest
- Pentest PDF alineado al mismo template visual que reportes generales:
  - `drystone/reports/formats/pentest_pdf.py` ahora reutiliza `PDFFormatter` + `pdf_report.xml`
  - se elimina render preformateado aislado; mismo look&feel (header, scope, tablas, footer)
- Tema oscuro consolidado en template PDF compartido:
  - fondo full-page teal, cards oscuras, texto claro, footer con margenes laterales
  - fixes de paginacion/footer clipping tras pasar a fondo completo
- Seccion de metodologia en PDF pentest:
  - bloque `Methodology` bajo `Scope Definition` (solo `report_type=pentest`)
  - describe fases PTES adaptadas + referencias metodologicas
- Seccion de explotacion en findings:
  - visible solo en pentest
  - orden final: Affected Resources -> Validation Commands -> Evidence -> Exploitation -> Remediation
- Ajuste visual tabla `Findings Summary`:
  - columnas ID, Severity, Risk y Resources centradas
- Nuevo diagrama de metodologia pentest:
  - `drystone-specs/drystone-pentest-methodology.md`
  - documenta flujo end-to-end de `report_type=pentest` y modelado de attack chains
- Pentest report ahora incluye seccion de metodologia descriptiva:
  - `drystone/reports/formats/pentest.py` agrega `Methodology (Our Pentest Approach)`
  - incluye fases PTES adaptadas + diagrama embebido desde `drystone-specs/drystone-pentest-methodology.md`

## Proximas iteraciones sugeridas

- Afinar paginacion para minimizar paginas huerfanas sin fragmentar en exceso bloques criticos.
- Unificar comportamiento de resumen de findings entre markdown y PDF cuando aplique.
- Agregar pruebas de consistencia cross-formato (MD vs PDF) para evitar drift visual/funcional.
