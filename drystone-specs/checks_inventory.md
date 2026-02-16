# Drystone Checks Inventory

Lista exhaustiva de checks/findings que Drystone es capaz de emitir segun los `checklist.json` de cada skill.

Uso: marca/desmarca cada check en la columna `Sel`.

Convenciones:
- `Sel`: usar `[ ]` para pendiente y `[x]` para seleccionado.
- La descripcion esta en espanol y resume el objetivo del check.

---

## IAM

| Sel | ID      | Descripcion (ES)                                                                                                         | PCI DSS                    |
| --- | ------- | ------------------------------------------------------------------------------------------------------------------------ | -------------------------- |
| [x] | IAM-001 | La cuenta root debe tener MFA habilitado para reducir el riesgo de compromiso del mayor privilegio en AWS.               | 8.4.1, 7.2.1               |
| [x] | IAM-002 | Los usuarios IAM (especialmente privilegiados) deben usar MFA para proteger accesos de consola/admin.                    | 8.4.2, 8.5.1               |
| [x] | IAM-003 | Deben eliminarse o rotarse credenciales IAM sin uso durante mas de 90 dias para reducir superficie de ataque.            | 8.2.6                      |
| [x] | IAM-004 | Las access keys deben rotarse al menos cada 90 dias para limitar el impacto de credenciales filtradas.                   | 8.3.9                      |
| [x] | IAM-005 | La politica de contrasenas IAM debe exigir longitud minima de 12+ caracteres para resistir fuerza bruta.                 | 8.3.6                      |
| [x] | IAM-006 | La politica de contrasenas debe impedir reutilizacion (historial), recomendando recordar al menos 4 contrasenas previas. | 8.3.7                      |
| [x] | IAM-007 | Evitar inline policies; usar managed policies para mejorar control de versiones, reutilizacion y auditoria.              | 7.2.2                      |
| [ ] | IAM-008 | Ninguna policy debe permitir permisos administrativos totales (`*:*`); aplicar principio de minimo privilegio.           | 7.2.1, 7.3.3               |
| [x] | IAM-009 | La cuenta root no debe tener access keys activas (acceso programatico ilimitado de maximo riesgo).                       | 2.2.2, 7.2.1               |
| [x] | IAM-010 | Usuarios administrativos deben tener MFA habilitado para reducir el riesgo de escalada/abuso de privilegios.             | 8.4.1                      |
| [ ] | IAM-011 | Trust policies de roles no deben permitir acceso publico (`Principal: "*"`) para evitar asuncion desde cualquier cuenta. | 7.2.1, 1.3.1               |
| [x] | IAM-012 | Usuarios inactivos (sin login en 90+ dias) deben deshabilitarse/eliminarse para reducir cuentas dormidas.                | 8.2.6                      |
| [x] | IAM-013 | Access keys activas pero sin uso (>30 dias) deben revisarse y eliminarse/rotarse (posibles credenciales zombie).         | 7.2.4, 8.2.6               |
| [x] | IAM-014 | Usuarios no deben tener multiples access keys activas salvo durante rotacion (reduce riesgo y complejidad).              | 8.2.1                      |
| [x] | IAM-015 | Evitar permisos directos a usuarios; preferir grupos para gestion centralizada y auditoria.                              | 7.2.1, 7.3.2               |
| [x] | IAM-016 | Cuentas de servicio deben usar roles (STS) en vez de usuarios IAM con keys estaticas.                                    | 7.2.5, 8.6.1               |
| [ ] | IAM-017 | Acceso cross-account debe incluir `ExternalId` para mitigar confused-deputy y endurecer confianza.                       | 8.5.1, 7.2.1               |
| [x] | IAM-018 | La politica de contrasenas debe forzar edad maxima (p.ej. 90 dias) para rotacion periodica.                              | 8.3.9                      |
| [x] | IAM-019 | La politica de contrasenas deberia requerir simbolos para aumentar complejidad/entropia.                                 | 8.3.6                      |
| [x] | IAM-020 | No deberian existir usuarios sin asignacion a grupos (mejora gobernanza y control de permisos).                          | 7.2.1                      |
| [x] | IAM-021 | Grupos vacios deben eliminarse para reducir deuda tecnica y confusion operacional.                                       | 12.5.1                     |
| [x] | IAM-022 | Roles sin uso durante 90+ dias deben revisarse para posible eliminacion (identidades innecesarias).                      | 7.2.4, 8.2.6               |
| [ ] | IAM-023 | CloudTrail debe registrar eventos de API IAM para trazabilidad de cambios y deteccion de actividad sospechosa.           | 10.2.1, 10.2.1.2, 10.2.1.5 |
| [x] | IAM-024 | IAM Access Analyzer debe estar habilitado para detectar comparticion externa y exposiciones por policies.                | 7.2.4                      |
| [ ] | IAM-025 | Policies customer-managed no deberian duplicar AWS managed policies para reducir mantenimiento e inconsistencias.        | 6.5.1                      |
| [ ] | IAM-026 | Usar permission boundaries en administracion delegada para limitar permisos maximos y prevenir escaladas.                | 7.2.1, 7.2.2               |
| [ ] | IAM-027 | Configurar alias de cuenta IAM para mejorar usabilidad y reducir errores/phishing por uso de ID numerico.                | 12.1.3                     |
| [ ] | IAM-028 | Aplicar tags de forma consistente a recursos IAM para organizacion, automatizacion y auditoria.                          | 12.5.1                     |

---

## Exposure

| Sel | ID | Descripcion (ES) | PCI DSS |
|---|---|---|---|
| [ ] | EXP-001 | Detectar buckets S3 publicos con datos sensibles (riesgo directo de exposicion de informacion). | 1.4.4.b, 3.5.1, 7.2.1 |
| [ ] | EXP-002 | Detectar RDS/BD accesibles desde internet (PubliclyAccessible + SG abierto), aumentando riesgo de compromiso. | 1.4.4.b, 2.2.1, 7.2.1 |
| [ ] | EXP-003 | Detectar Security Groups con SSH/RDP abierto a 0.0.0.0/0 (alto riesgo de fuerza bruta/explotacion). | 1.3.1.b, 2.2.7.b, 8.4.1 |
| [ ] | EXP-004 | Detectar EC2 con puertos de gestion/BD expuestos a internet (22/3389/3306/5432, etc.). | 1.3.1.b, 2.2.4.b |
| [ ] | EXP-005 | Detectar Lambda Function URLs sin autenticacion (Auth NONE) con logica sensible expuesta publicamente. | 6.2.4, 7.2.1, 8.1.1 |
| [ ] | EXP-006 | Detectar API Gateway sin autenticacion ni rate limiting (throttling), favoreciendo abuso y bypass de control. | 8.1.1, 7.2.1, 6.4.2 |
| [ ] | EXP-007 | Detectar ALB/NLB internet-facing sin WAF asociado en aplicaciones criticas (gap de proteccion web). | 6.4.2 |
| [ ] | EXP-008 | Detectar secretos/credenciales hardcodeadas en Lambda (env vars/codigo) en texto plano. | 3.6.1.a, 6.2.4, 8.3.1 |
| [ ] | EXP-009 | Detectar CloudFront critico sin Shield Advanced (solo Shield Standard), aumentando riesgo DDoS. | 12.10.6 |
| [ ] | EXP-010 | Detectar ALB con TLS 1.0/1.1 permitido (protocolos obsoletos y debiles). | 4.2.1.b, 2.2.7.d |
| [ ] | EXP-011 | Detectar buckets S3 con permiso de listar objetos publico (`s3:ListBucket`), filtrando metadatos/estructura. | 7.2.1, 1.3.1.b |
| [ ] | EXP-012 | Detectar EC2 que permite IMDSv1 (no fuerza IMDSv2), aumentando riesgo por SSRF y robo de credenciales. | 2.2.1.a, 6.2.4 |

---

## Network

| Sel | ID | Descripcion (ES) | PCI DSS |
|---|---|---|---|
| [ ] | NET-001 | Security Groups con acceso ANY (0.0.0.0/0) a puertos sensibles (SSH/RDP/DB) exponen recursos a ataques de internet. | 1.3.1.b, 2.2.4.b, 7.2.1 |
| [ ] | NET-002 | Security Groups con ALL traffic (protocol -1) desde 0.0.0.0/0 deshabilitan en la practica el firewall. | 1.3.1.b, 7.3.3 |
| [ ] | NET-003 | NACLs con reglas ALLOW ALL sin restricciones reducen efectividad de control de red stateless. | 1.3.1.b, 7.3.3 |
| [ ] | NET-004 | Route tables con 0.0.0.0/0 hacia IGW en subnets sensibles (DB/apps internas) convierten subnets en publicas. | 1.4.4.b, 2.2.1 |
| [ ] | NET-005 | VPC Peering con rutas bidireccionales amplias sin filtrado rompe segmentacion y minimo privilegio. | 1.3.1.b, 7.2.1 |
| [ ] | NET-006 | Referencias cross-account de SG sin validacion introducen fuentes externas no controladas para trafico entrante. | 1.3.1.b, 7.2.1 |
| [ ] | NET-007 | Falta de Network Firewall en VPCs criticas con trafico norte-sur deja trafico sin inspeccion avanzada. | 1.1.4, 6.4.2 |
| [ ] | NET-008 | Recursos criticos desplegados en subnets publicas (RDS/ElastiCache/apps internas) aumentan exposicion. | 1.4.4.b |
| [ ] | NET-009 | SG con rangos muy amplios (>=/16) para puertos no-web amplian superficie de ataque aunque no sea internet. | 1.3.1.b, 7.2.1 |
| [ ] | NET-010 | NACLs default permisivas (allow all) como baseline pueden debilitar controles si no hay NACLs custom. | 1.3.1.b, 7.3.3 |
| [ ] | NET-011 | Reglas criticas de SG sin descripcion dificultan auditoria, justificacion y gestion de cambios. | 1.2.1.a, 12.5.1 |
| [ ] | NET-012 | Transit Gateway sin inspeccion (Network Firewall) en attachments permite trafico inter-segmento sin control. | 1.1.4 |
| [ ] | NET-013 | Falta/No uso de VPC Endpoints provoca trafico a servicios AWS via internet/NAT (coste/exposicion). | 1.3.4 |
| [ ] | NET-014 | Blackhole routes activos pueden romper conectividad y generar comportamientos inesperados o bypasses. | 1.2.1.b |
| [ ] | NET-015 | Reglas duplicadas/redundantes en SG complican auditoria y pueden ocultar permisos excesivos. | 1.2.1.a |
| [ ] | NET-016 | Subnets usando default NACL (sin NACL custom) pierden una capa adicional de filtrado stateless. | 1.3.1.b |
| [ ] | NET-017 | Private subnets con ruta a Internet Gateway comprometen aislamiento y pueden volverse efectivamente publicas. | 1.4.4.b |
| [ ] | NET-018 | VPC Flow Logs no habilitados reducen visibilidad de trafico y dificultan deteccion y respuesta a incidentes. | 10.2.1, 10.6.1 |
| [ ] | NET-019 | SGs con demasiadas reglas (p.ej. >50) son complejos y aumentan riesgo de misconfiguracion. | 1.2.1.a, 12.5.1 |
| [ ] | NET-020 | NACLs con gaps grandes en numeros de regla indican mala higiene/organizacion y riesgo de errores futuros. | 1.2.1.a |
| [ ] | NET-021 | Security Groups huerfanos (sin recursos asociados) generan deuda tecnica y ruido de auditoria. | 12.5.1 |
| [ ] | NET-022 | Route tables con multiples default routes pueden crear routing ambiguo y potencial bypass de controles. | 1.2.1.b |
| [ ] | NET-023 | VPC Peering sin tags de ownership dificulta inventario, gobernanza y auditoria. | 12.5.1 |
| [ ] | NET-024 | Nombres inconsistentes en recursos de red dificultan gestion, automatizacion y auditoria. | 12.5.1 |
| [ ] | NET-025 | Subnets sin tags de clasificacion (public/private/db/app) dificultan entender proposito y postura. | 12.5.1 |
| [ ] | NET-026 | Egress demasiado restrictivo en SG puede bloquear updates/patching y afectar gestion de vulnerabilidades. | 6.3.3.b |
| [ ] | NET-027 | Security Groups sin tags dificultan organizacion, filtrado e IaC/automatizacion. | 12.5.1 |
| [ ] | NET-028 | Reglas "comentadas" o inactivas en NACLs dejan clutter y confunden durante auditorias. | 1.2.1.a |
| [ ] | NET-029 | CIDR blocks superpuestos entre regiones complican conectividad futura y pueden provocar conflictos de rutas. | 1.2.3.a |
| [ ] | NET-030 | Uso de rutas estaticas en vez de propagacion automatica (TGW/DX) aumenta overhead y riesgo de rutas stale. | 1.2.1.a |
| [ ] | NET-031 | DNS resolution/hostnames deshabilitado en VPC puede romper resolucion interna y visibilidad operativa. | 12.5.1 |

---

## Vulns (Inspector)

| Sel | ID | Descripcion (ES) | PCI DSS |
|---|---|---|---|
| [ ] | VULN-001 | Inspector v2 no esta habilitado: no hay escaneo automatico de vulnerabilidades (EC2/ECR/Lambda). | 6.3.1.b, 11.3.1, 12.2.1 |
| [ ] | VULN-002 | Existen vulnerabilidades CRITICAL sin remediar, con alto riesgo de compromiso de sistemas/datos. | 6.3.3.b, 12.5.2 |
| [ ] | VULN-003 | Vulnerabilidades presentes en recursos accesibles publicamente aumentan probabilidad de explotacion inmediata. | 1.3.1.b, 6.4.2 |
| [ ] | VULN-004 | CVEs con exploit conocido/activo (PoC publico, 0-day) requieren respuesta inmediata y mitigacion urgente. | 6.3.3.b, 6.2.4 |
| [ ] | VULN-005 | Vulnerabilidades en recursos de alta criticidad (AD/BD/APIs core) tienen impacto desproporcionado. | 7.2.1, 2.2.1 |
| [ ] | VULN-006 | Scanning deshabilitado para EC2 deja el compute mas comun sin visibilidad de vulnerabilidades. | 11.3.1, 6.3.1.b |
| [ ] | VULN-007 | Scanning deshabilitado para ECR deja imagenes privadas sin auditar dentro del SDLC. | 6.3.2.a, 6.2.1 |
| [ ] | VULN-008 | Vulnerabilidades HIGH sin plan de remediacion definido aumentan exposicion por falta de ownership/timeline. | 6.3.3.b, 12.5.2 |
| [ ] | VULN-009 | Multiples CVEs en el mismo recurso incrementan riesgo acumulado y requieren priorizacion por agregacion. | 6.3.1.b |
| [ ] | VULN-010 | Vulnerabilidades en componentes de servicio critico elevan riesgo de interrupcion y compromiso de negocio. | 7.2.1 |
| [ ] | VULN-011 | ECR scanning deshabilitado (imagenes no auditadas) incrementa riesgo supply-chain y vulnerabilidades embebidas. | 6.3.2.a |
| [ ] | VULN-012 | Lambda scanning deshabilitado deja codigo serverless sin verificacion de vulnerabilidades/config issues. | 6.2.3.a |
| [ ] | VULN-013 | Hallazgos de Inspector sin investigar durante >7 dias reflejan retraso en VM/IR y aumentan riesgo. | 10.6.1, 12.5.2 |
| [ ] | VULN-014 | Vulnerabilidad detectada sin parchear durante >30 dias amplia ventana de exposicion a explotacion. | 6.3.3.a |
| [ ] | VULN-015 | Vulnerabilidades MEDIUM sin timeline de remediacion generan acumulacion de deuda tecnica y riesgo residual. | 6.3.3.a |
| [ ] | VULN-016 | Scanning habilitado pero sin automatizar reportes/dashboards reduce accionabilidad y visibilidad continua. | 10.6.1 |
| [ ] | VULN-017 | No hay notificaciones de nuevos hallazgos Inspector; retraso en awareness y respuesta. | 10.6.1 |
| [ ] | VULN-018 | Recursos excluidos de scanning sin justificacion documentada crean blind spots en coverage. | 12.5.1 |
| [ ] | VULN-019 | Vulnerabilidades LOW/INFORMATIONAL pendientes pueden ser parte de cadenas de ataque o deuda tecnica. | 6.3.3.a |
| [ ] | VULN-020 | Hallazgos duplicados (misma vuln en multiples recursos) indican causa raiz comun a corregir centralizadamente. | 6.3.1.b |
| [ ] | VULN-021 | CVEs con fix en version nueva no disponible requieren plan de upgrade o controles compensatorios. | 6.3.3.b |

---

## Alerting

| Sel | ID | Descripcion (ES) | PCI DSS |
|---|---|---|---|
| [ ] | ALRT-001 | CloudTrail no esta integrado con CloudWatch Logs: no hay streaming centralizado para filtros/alertas. | 10.2.1, 10.5.1, 10.6.1 |
| [ ] | ALRT-002 | CloudTrail no esta integrado con EventBridge: falta automatizacion y alerting event-driven en tiempo real. | 10.6.1 |
| [ ] | ALRT-003 | Metric Filters de seguridad sin alarmas asociadas: se detecta patron pero no se notifica a nadie. | 10.6.1 |
| [ ] | ALRT-004 | Reglas EventBridge sin targets SNS: no hay notificaciones para eventos de seguridad capturados. | 10.6.1 |
| [ ] | ALRT-005 | SNS Topics de seguridad sin subscripciones: el pipeline de alertas es inefectivo. | 10.6.1 |
| [ ] | ALRT-006 | Subscripciones SNS en PendingConfirmation: alertas no se entregan a endpoints no confirmados. | 10.6.1 |
| [ ] | ALRT-007 | Eventos criticos sin alerta configurada (StopLogging/DeleteTrail/CreateUser/ConsoleLogin, etc.). | 10.6.1, 10.2.1.2 |
| [ ] | ALRT-008 | Trail no es multi-region: se pierden eventos en otras regiones y se degrada cobertura de logging. | 10.2.1 |
| [ ] | ALRT-009 | Log Group sin Metric Filters adecuados para eventos de seguridad: baja capacidad de deteccion. | 10.6.1 |
| [ ] | ALRT-010 | Alarmas en estado INSUFFICIENT_DATA: no evaluan correctamente y pueden perder alertas. | 10.6.1 |
| [ ] | ALRT-011 | SNS Topics sin policy restrictiva: riesgo de publish/lectura no autorizada o abuso del canal. | 7.2.1 |
| [ ] | ALRT-012 | No hay alertas para ConsoleLogin/CreateUser/StopLogging: ausencia de cobertura minima de eventos clave. | 10.6.1, 10.2.1.2 |
| [ ] | ALRT-013 | CloudTrail sin Log File Validation: sin garantia criptografica de integridad de logs. | 10.5.5 |
| [ ] | ALRT-014 | CloudTrail sin cifrado KMS: logs potencialmente menos protegidos en reposo. | 3.5.1 |
| [ ] | ALRT-015 | No hay alertas para cambios IAM (policies/roles/MFA, etc.), riesgo de escalada silenciosa. | 10.2.1.5, 10.6.1 |
| [ ] | ALRT-016 | No hay alertas para cambios en Security Groups, perdiendo visibilidad de modificaciones en NSCs. | 1.2.2.a, 10.6.1 |
| [ ] | ALRT-017 | Retencion de CloudWatch Logs muy baja (<90 dias) puede violar requisitos de auditoria/forense. | 10.5.1 |
| [ ] | ALRT-018 | Alarmas sin descripcion clara dificultan triage e investigacion durante incidentes. | 10.6.1 |
| [ ] | ALRT-019 | Nombres no descriptivos en recursos de alerting dificulta inventario y gestion. | 12.5.1 |
| [ ] | ALRT-020 | Tags faltantes en recursos de alerting dificulta organizacion, ownership y automatizacion. | 12.5.1 |
| [ ] | ALRT-021 | SNS sin Dead Letter Queue puede perder alertas criticas si falla la entrega a endpoints. | 10.5.1 |

---

## Hardening

| Sel | ID | Descripcion (ES) | PCI DSS |
|---|---|---|---|
| [ ] | HRD-001 | AWS Config no habilitado en la region auditada: sin monitorizacion continua de configuracion/inventario. | 10.2.1, 10.5.1, 12.5.1 |
| [ ] | HRD-002 | Security Hub no habilitado en la region auditada: sin postura centralizada ni agregacion de findings. | 12.2.1, 6.3.1 |
| [ ] | HRD-003 | No hay standards de compliance habilitados en Security Hub (FSBP/CIS/PCI), sin evaluacion continua. | 12.2.1, 6.3.1 |
| [ ] | HRD-004 | Compliance score global <50% indica brechas graves y generalizadas en controles de seguridad. | 12.2.1 |
| [ ] | HRD-005 | Existen findings CRITICAL sin remediar, con riesgo elevado de brecha/compromiso. | 6.3.3.b, 12.5.2 |
| [ ] | HRD-006 | AWS Config habilitado pero incompleto (no RECORDING/delivery), cobertura parcial de cambios/inventario. | 10.2.1, 12.5.1 |
| [ ] | HRD-007 | Falta standard PCI DSS en Security Hub (si aplica), sin monitorizacion automatica contra PCI DSS. | 12.2.1, 6.3.1 |
| [ ] | HRD-008 | Compliance score 50-70% indica postura deficiente con numerosas brechas y urgencia de remediacion. | 12.2.1 |
| [ ] | HRD-009 | Mas de 10 findings HIGH sin remediar indica backlog significativo de riesgo alto. | 6.3.3.b, 12.5.2 |
| [ ] | HRD-010 | Sin conformance packs en AWS Config: se pierde automatizacion de validacion de compliance. | 12.2.1 |
| [ ] | HRD-011 | Compliance score 70-85%: postura razonable pero con mejoras necesarias para endurecimiento. | 12.2.1 |
| [ ] | HRD-012 | Mas de 20 findings MEDIUM sin remediar: acumulacion de riesgo moderado y deuda tecnica. | 6.3.3.b, 12.5.2 |
| [ ] | HRD-013 | Standards desactualizados en Security Hub: evaluacion contra benchmarks antiguos, brecha de mejores practicas. | 6.3.1.a |
| [ ] | HRD-014 | Security Hub sin integracion con alertas (SNS/EventBridge/on-call): respuesta tardia a eventos de seguridad. | 10.6.1 |
| [ ] | HRD-015 | Compliance score 85-95%: postura fuerte con gaps menores; foco en mejora continua. | 12.2.1 |
| [ ] | HRD-016 | Findings LOW pendientes: deuda tecnica y oportunidades de mejora de proceso. | 6.3.3.b |
| [ ] | HRD-017 | Tags inconsistentes: dificulta inventario, automatizacion, coste y aplicacion de politicas. | 12.5.1 |
| [ ] | HRD-018 | Documentacion faltante/incompleta: politicas/procedimientos/diagramas no adecuados para auditoria y operacion. | 1.1.1, 2.1.1, 3.1.1, 4.1.1, 5.1.1, 6.1.1, 7.1.1 |

---

## Secrets Manager

| Sel | ID | Descripcion (ES) | PCI DSS |
|---|---|---|---|
| [ ] | SM-001 | No permitir acceso publico a secretos via resource policy con principal comodin (`Principal: "*"`). | 7.2.2, 3.5.1 |
| [ ] | SM-002 | Habilitar rotacion automatica de secretos para reducir ventana de compromiso de credenciales. | 8.3.9, 3.6.1.1 |
| [ ] | SM-003 | El intervalo de rotacion no debe exceder 90 dias (recomendado 30-90 dias). | 8.3.9 |
| [ ] | SM-004 | Preferir KMS customer-managed keys para cifrado (mayor control, politicas, auditoria). | 3.5.1, 3.6.1.2 |
| [ ] | SM-005 | Secretos sin rotar >365 dias deben rotarse urgentemente (credenciales obsoletas de alto riesgo). | 8.3.9, 8.2.6 |
| [ ] | SM-006 | Aplicar tags descriptivos a secretos (gobernanza, ownership, coste y ciclo de vida). | 12.3.1 |
| [ ] | SM-007 | Mantener descripciones claras del proposito del secreto (descubribilidad y prevencion de borrado accidental). | 12.3.1 |
| [ ] | SM-008 | Replicar secretos criticos a multiples regiones si se requiere resiliencia/DR. | 12.10.1 |
| [ ] | SM-009 | Secretos de alto acceso deberian rotar con intervalo <30 dias para reducir ventana de compromiso. | 8.3.9 |
| [ ] | SM-010 | Evitar acceso a secretos desde Lambda via internet; usar VPC endpoints para trafico privado. | 4.2.1, 1.3.1 |
| [ ] | SM-011 | Resource policies deberian requerir MFA (`aws:MultiFactorAuthPresent`) para acceso a secretos criticos. | 8.4.2, 8.5.1 |
| [ ] | SM-012 | Fallos de rotacion no deben quedar silenciosos: configurar alerting (EventBridge/CloudWatch/SNS/runbook). | 10.7.2 |

---

## WAF

| Sel | ID | Descripcion (ES) | PCI DSS |
|---|---|---|---|
| [ ] | WAF-001 | ALBs internet-facing deben tener Web ACL de WAF asociado para reducir exposicion a ataques web comunes. | 6.4.2 |
| [ ] | WAF-002 | CloudFront de apps publicas debe estar protegido por WAF (WebACLId asociado en el edge). | 6.4.2 |
| [ ] | WAF-003 | Habilitar logging de Web ACLs WAFv2 para investigacion, tuning y forense. | 10.2.1, 10.4.1 |
| [ ] | WAF-004 | Redactar componentes sensibles en logs WAF (Authorization, cookies, query params) para evitar registrar secretos. | 3.3.1, 10.3.1 |
| [ ] | WAF-005 | Habilitar metricas/visibilidad (CloudWatch metrics + sampled requests) para tuning y respuesta a incidentes. | 10.7.1 |
| [ ] | WAF-006 | Web ACLs deben incluir AWS Managed Rules baseline (OWASP Top 10) para efectividad contra amenazas comunes. | 6.2.4, 6.4.2 |
| [ ] | WAF-007 | Reglas no deben quedarse permanentemente en modo Count-only en produccion (reducen prevencion real). | 6.4.2 |
| [ ] | WAF-008 | Usar rate-based rules para mitigar abuso, credential stuffing y L7 DoS. | 12.10.6 |
| [ ] | WAF-009 | IP sets no deben incluir rangos excesivamente amplios (0.0.0.0/0 o ::/0) por riesgo de allowlist global/bloqueos. | 1.2.5 |
| [ ] | WAF-010 | Migrar WAF Classic a WAFv2 para capacidades modernas y mejor mantenibilidad. | 2.2.1 |
| [ ] | WAF-011 | Web ACLs no asociados deben revisarse (drift y ruido de auditoria). | 12.5.1 |
| [ ] | WAF-012 | Estandarizar reutilizacion de rule groups para protecciones consistentes entre aplicaciones. | 6.5.1 |
| [ ] | WAF-013 | Evidencia WAF incompleta: si fallan APIs/permissions, tratarlo como issue de evidencia (no misconfig confirmada). | 12.11.1 |
| [ ] | WAF-014 | Stages publicos de API Gateway deberian estar protegidos por WAF (REGIONAL) cuando esten en-scope. | 6.4.2 |
| [ ] | WAF-015 | APIs AppSync GraphQL publicas/in-scope deberian tener WAF asociado (REGIONAL) para reducir exposicion. | 6.4.2 |
| [ ] | WAF-016 | Cognito User Pools expuestos publicamente deberian usar WAF/rate-based protections para mitigar abuso. | 6.2.4 |

---

## ECR

| Sel | ID | Descripcion (ES) | PCI DSS |
|---|---|---|---|
| [ ] | ECR-001 | Repositorios no deben permitir acceso publico mediante principals comodin (`Principal: "*"/AWS:"*"`) en policies. | 7.2.2 |
| [ ] | ECR-002 | Las etiquetas (tags) deberian ser inmutables para evitar sobrescrituras y cambios no trazables en imagenes. | 6.4.3 |
| [ ] | ECR-003 | Habilitar escaneo de imagenes al hacer push (scan-on-push) para detectar vulnerabilidades temprano. | 6.3.3 |
| [ ] | ECR-004 | Definir configuracion de scanning a nivel de registry (reglas/tipo) para consistencia y evitar gaps. | 6.3.3 |
| [ ] | ECR-005 | Usar KMS customer-managed keys cuando la sensibilidad lo requiera para mayor gobernanza de cifrado. | 3.5.1 |
| [ ] | ECR-006 | Configurar lifecycle policies para expirar imagenes sin uso/untagged y reducir superficie de ataque. | 2.2.6 |
| [ ] | ECR-007 | Revisar y restringir acceso cross-account en policies de repositorios (principals explicitos + condiciones). | 7.2.2 |
| [ ] | ECR-008 | Evaluar replicacion de registry si se requiere resiliencia multi-region para artefactos criticos. | 12.10.1 |
| [ ] | ECR-009 | Policies deben preferir principals y acciones explicitas (evitar patrones amplios como `ecr:*`). | 7.2.2 |
| [ ] | ECR-010 | Si falta evidencia de ajustes de registry por permisos/errores, tratar checks dependientes como no verificables. | - |
