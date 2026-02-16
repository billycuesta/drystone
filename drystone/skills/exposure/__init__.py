"""Exposure security skill for AWS audit."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List

import boto3
from botocore.exceptions import ClientError

from drystone.cloud.aws.client import AWSClient
from drystone.skills.base import BaseSkill
from drystone.storage.session import AuditSession

if TYPE_CHECKING:
    from drystone.agent.client import AgentClient


class ExposureSkill(BaseSkill):
    """Public exposure audit skill - identifies resources exposed to internet."""

    @property
    def name(self) -> str:
        """Skill identifier."""
        return "exposure"

    def collect(self, aws_client: AWSClient, session: AuditSession):
        """Collect data about publicly exposed AWS resources.

        Collects:
            - S3 buckets (public access blocks, ACLs, policies)
            - RDS instances (public accessibility)
            - Snapshots (public sharing)
            - AMI images (public sharing)
            - Security group rules (0.0.0.0/0 access)
            - VPC endpoints and their configurations
            - CloudFront distributions (origins and settings)

        Args:
            aws_client: Authenticated AWS client
            session: Audit session for evidence storage
        """
        client_kwargs = {
            "aws_access_key_id": aws_client.access_key_id,
            "aws_secret_access_key": aws_client.secret_access_key,
            "region_name": aws_client.region_name,
        }
        if aws_client.session_token:
            client_kwargs["aws_session_token"] = aws_client.session_token

        evidence_path = session.get_evidence_path(self.name)
        region = aws_client.region_name

        # === AUDIT METADATA ===
        audit_metadata: Dict[str, Any] = {
            "_region": region,
            "_timestamp": datetime.now(timezone.utc).isoformat(),
            "_scope": "single-region",
            "_skill": self.name,
            "_account_id": session.account_id,
            "evidence_files": [],
        }

        def _save(filepath: Path, data: Any) -> None:
            self._save_json(filepath, data)
            audit_metadata["evidence_files"].append(filepath.name)

        def _wrap_indexed(items: List[Dict[str, Any]], *, by_key: str) -> Dict[str, Any]:
            by_id: Dict[str, Any] = {}
            for it in items:
                if not isinstance(it, dict):
                    continue
                k = it.get(by_key)
                if isinstance(k, str) and k:
                    by_id[k] = it
            return {
                "_meta": {"_region": region},
                "items": items,
                "by_id": by_id,
            }

        # === S3 BUCKETS ===
        print("  Collecting S3 bucket configurations...")
        try:
            s3_client = boto3.client("s3", **client_kwargs)
            buckets_response = s3_client.list_buckets()
            buckets_list: List[Dict[str, Any]] = []

            for bucket in buckets_response.get("Buckets", []):
                bucket_name = bucket["Name"]
                bucket_detail = {
                    "Name": bucket_name,
                    "CreationDate": bucket.get("CreationDate"),
                }

                try:
                    acl = s3_client.get_bucket_acl(Bucket=bucket_name)
                    bucket_detail["ACL"] = acl.get("Grants", [])
                except Exception:
                    bucket_detail["ACL"] = []

                try:
                    pab = s3_client.get_public_access_block(Bucket=bucket_name)
                    bucket_detail["PublicAccessBlock"] = pab.get(
                        "PublicAccessBlockConfiguration", {}
                    )
                except Exception:
                    bucket_detail["PublicAccessBlock"] = None

                try:
                    policy = s3_client.get_bucket_policy(Bucket=bucket_name)
                    bucket_detail["BucketPolicy"] = json.loads(policy.get("Policy", "{}"))
                except Exception:
                    bucket_detail["BucketPolicy"] = None

                try:
                    versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
                    bucket_detail["Versioning"] = versioning.get("Status")
                except Exception:
                    bucket_detail["Versioning"] = None

                buckets_list.append(bucket_detail)

            # Index by bucket name for stable evidence references.
            s3_doc = {
                "_meta": {"_region": region},
                "items": buckets_list,
                "by_name": {
                    b.get("Name"): b for b in buckets_list if isinstance(b.get("Name"), str)
                },
            }
            _save(evidence_path / "s3-buckets.json", s3_doc)
        except Exception as e:
            print(f"    Warning: Could not collect S3 data: {e}")

        rds_client = None

        # === RDS INSTANCES ===
        print("  Collecting RDS instance configurations...")
        try:
            rds_client = boto3.client("rds", **client_kwargs)
            rds_response = rds_client.describe_db_instances()
            rds_list: List[Dict[str, Any]] = []

            for instance in rds_response.get("DBInstances", []):
                rds_detail = {
                    "DBInstanceIdentifier": instance.get("DBInstanceIdentifier"),
                    "DBInstanceStatus": instance.get("DBInstanceStatus"),
                    "Engine": instance.get("Engine"),
                    "PubliclyAccessible": instance.get("PubliclyAccessible"),
                    "VpcSecurityGroups": instance.get("VpcSecurityGroups", []),
                    "DBSubnetGroup": instance.get("DBSubnetGroup", {}).get("DBSubnetGroupName"),
                }
                rds_list.append(rds_detail)

            _save(
                evidence_path / "rds-instances.json",
                _wrap_indexed(rds_list, by_key="DBInstanceIdentifier"),
            )
        except Exception as e:
            print(f"    Warning: Could not collect RDS data: {e}")

        # === RDS SNAPSHOTS ===
        print("  Collecting RDS snapshot sharing...")
        try:
            if rds_client is None:
                rds_client = boto3.client("rds", **client_kwargs)
            snapshots = rds_client.describe_db_snapshots()
            snapshots_list: List[Dict[str, Any]] = []

            for snapshot in snapshots.get("DBSnapshots", []):
                snapshot_detail = {
                    "DBSnapshotIdentifier": snapshot.get("DBSnapshotIdentifier"),
                    "Engine": snapshot.get("Engine"),
                    "SnapshotCreateTime": snapshot.get("SnapshotCreateTime"),
                }

                try:
                    attributes = rds_client.describe_db_snapshot_attributes(
                        DBSnapshotIdentifier=snapshot.get("DBSnapshotIdentifier")
                    )
                    snapshot_detail["Attributes"] = attributes.get("DBSnapshotAttributesResult", {})
                except Exception:
                    snapshot_detail["Attributes"] = {}

                snapshots_list.append(snapshot_detail)

            _save(
                evidence_path / "rds-snapshots.json",
                _wrap_indexed(snapshots_list, by_key="DBSnapshotIdentifier"),
            )
        except Exception as e:
            print(f"    Warning: Could not collect RDS snapshot data: {e}")

        ec2_client = None

        # === AMI IMAGES ===
        print("  Collecting AMI image sharing...")
        try:
            ec2_client = boto3.client("ec2", **client_kwargs)
            images = ec2_client.describe_images(Owners=["self"])
            images_list: List[Dict[str, Any]] = []

            for image in images.get("Images", []):
                image_detail = {
                    "ImageId": image.get("ImageId"),
                    "Name": image.get("Name"),
                    "Public": image.get("Public"),
                    "CreationDate": image.get("CreationDate"),
                }

                try:
                    launch_perms = ec2_client.describe_image_attribute(
                        ImageId=image.get("ImageId"), Attribute="launchPermission"
                    )
                    image_detail["LaunchPermissions"] = launch_perms.get("LaunchPermissions", [])
                except Exception:
                    image_detail["LaunchPermissions"] = []

                images_list.append(image_detail)

            _save(
                evidence_path / "ami-images.json",
                _wrap_indexed(images_list, by_key="ImageId"),
            )
        except Exception as e:
            print(f"    Warning: Could not collect AMI data: {e}")

        # === SECURITY GROUPS ===
        print("  Collecting security group rules...")
        try:
            if ec2_client is None:
                ec2_client = boto3.client("ec2", **client_kwargs)
            sgs = ec2_client.describe_security_groups()
            sgs_list: List[Dict[str, Any]] = []

            for sg in sgs.get("SecurityGroups", []):
                sg_detail = {
                    "GroupId": sg.get("GroupId"),
                    "GroupName": sg.get("GroupName"),
                    "VpcId": sg.get("VpcId"),
                    "IngressRules": sg.get("IpPermissions", []),
                    "EgressRules": sg.get("IpPermissionsEgress", []),
                }
                sgs_list.append(sg_detail)

            _save(
                evidence_path / "security-groups.json",
                _wrap_indexed(sgs_list, by_key="GroupId"),
            )
        except Exception as e:
            print(f"    Warning: Could not collect security group data: {e}")

        # === CLOUDFRONT DISTRIBUTIONS ===
        print("  Collecting CloudFront distributions...")
        try:
            cf_client = boto3.client("cloudfront", **client_kwargs)
            distributions = cf_client.list_distributions()
            dists_list: List[Dict[str, Any]] = []

            for dist in distributions.get("DistributionList", {}).get("Items", []):
                dist_detail = {
                    "Id": dist.get("Id"),
                    "DomainName": dist.get("DomainName"),
                    "Enabled": dist.get("Enabled"),
                    "Origins": dist.get("Origins", []),
                    "DefaultCacheBehavior": dist.get("DefaultCacheBehavior", {}),
                }
                dists_list.append(dist_detail)

            _save(
                evidence_path / "cloudfront-distributions.json",
                _wrap_indexed(dists_list, by_key="Id"),
            )
        except Exception as e:
            print(f"    Warning: Could not collect CloudFront data: {e}")

        # === LOAD BALANCERS + LISTENERS (ELBv2) ===
        print("  Collecting load balancers and listeners...")
        try:
            elbv2 = boto3.client("elbv2", **client_kwargs)
            lbs: List[Dict[str, Any]] = []
            marker = None
            while True:
                kwargs = {"PageSize": 400}
                if marker:
                    kwargs["Marker"] = marker
                resp = elbv2.describe_load_balancers(**kwargs)
                for lb in resp.get("LoadBalancers", []) or []:
                    lbs.append(
                        {
                            "LoadBalancerArn": lb.get("LoadBalancerArn"),
                            "LoadBalancerName": lb.get("LoadBalancerName"),
                            "DNSName": lb.get("DNSName"),
                            "Scheme": lb.get("Scheme"),
                            "Type": lb.get("Type"),
                            "VpcId": lb.get("VpcId"),
                            "SecurityGroups": lb.get("SecurityGroups", []),
                            "AvailabilityZones": lb.get("AvailabilityZones", []),
                        }
                    )
                marker = resp.get("NextMarker")
                if not marker:
                    break

            _save(
                evidence_path / "load-balancers.json",
                _wrap_indexed(lbs, by_key="LoadBalancerArn"),
            )

            listeners: List[Dict[str, Any]] = []
            for lb in lbs:
                lb_arn = lb.get("LoadBalancerArn")
                if not lb_arn:
                    continue
                try:
                    l_resp = elbv2.describe_listeners(LoadBalancerArn=lb_arn)
                except ClientError:
                    continue
                for li in l_resp.get("Listeners", []) or []:
                    listeners.append(
                        {
                            "LoadBalancerArn": lb_arn,
                            "ListenerArn": li.get("ListenerArn"),
                            "Protocol": li.get("Protocol"),
                            "Port": li.get("Port"),
                            "SslPolicy": li.get("SslPolicy"),
                            "Certificates": li.get("Certificates", []),
                            "DefaultActions": li.get("DefaultActions", []),
                        }
                    )

            _save(
                evidence_path / "load-balancer-listeners.json",
                {
                    "_meta": {"_region": region},
                    "items": listeners,
                },
            )

        except Exception as e:
            print(f"    Warning: Could not collect ELBv2 data: {e}")

        # === WAFv2 (WebACLs + ALB associations) ===
        print("  Collecting WAFv2 WebACL associations...")
        try:
            waf = boto3.client("wafv2", **client_kwargs)
            web_acls: List[Dict[str, Any]] = []
            alb_associations: Dict[str, List[str]] = {}

            for scope in ["REGIONAL"]:
                marker = None
                while True:
                    kwargs = {"Scope": scope, "Limit": 100}
                    if marker:
                        kwargs["NextMarker"] = marker
                    resp = waf.list_web_acls(**kwargs)
                    for wa in resp.get("WebACLs", []) or []:
                        web_acls.append(
                            {
                                "Scope": scope,
                                "Name": wa.get("Name"),
                                "Id": wa.get("Id"),
                                "ARN": wa.get("ARN"),
                                "Description": wa.get("Description"),
                            }
                        )
                    marker = resp.get("NextMarker")
                    if not marker:
                        break

            for wa in web_acls:
                arn = wa.get("ARN")
                if not arn:
                    continue
                try:
                    r = waf.list_resources_for_web_acl(
                        WebACLArn=arn,
                        ResourceType="APPLICATION_LOAD_BALANCER",
                    )
                    resources = r.get("ResourceArns", []) or []
                    for alb_arn in resources:
                        alb_associations.setdefault(alb_arn, []).append(arn)
                except ClientError:
                    continue

            _save(
                evidence_path / "wafv2-web-acls.json",
                {"_meta": {"_region": region}, "items": web_acls},
            )
            _save(
                evidence_path / "wafv2-web-acl-alb-associations.json",
                {"_meta": {"_region": region}, "by_alb_arn": alb_associations},
            )
        except Exception as e:
            print(f"    Warning: Could not collect WAFv2 data: {e}")

        # === LAMBDA FUNCTION URLS ===
        print("  Collecting Lambda function URLs...")
        try:
            lam = boto3.client("lambda", **client_kwargs)
            fn_urls: List[Dict[str, Any]] = []
            paginator = lam.get_paginator("list_functions")
            for page in paginator.paginate():
                for fn in page.get("Functions", []) or []:
                    fn_name = fn.get("FunctionName")
                    if not fn_name:
                        continue
                    try:
                        cfg = lam.get_function_url_config(FunctionName=fn_name)
                    except ClientError:
                        continue
                    fn_urls.append(
                        {
                            "FunctionName": fn_name,
                            "FunctionArn": fn.get("FunctionArn"),
                            "FunctionUrl": cfg.get("FunctionUrl"),
                            "AuthType": cfg.get("AuthType"),
                            "CreationTime": cfg.get("CreationTime"),
                            "IsPublic": cfg.get("AuthType") == "NONE",
                        }
                    )
            _save(evidence_path / "lambda-function-urls.json", {"items": fn_urls})
        except Exception as e:
            print(f"    Warning: Could not collect Lambda function URLs: {e}")

        # === API GATEWAY STAGES ===
        print("  Collecting API Gateway stages...")
        try:
            api_stages: List[Dict[str, Any]] = []
            apigw = boto3.client("apigateway", **client_kwargs)
            apis = apigw.get_rest_apis().get("items", [])
            for api in apis or []:
                api_id = api.get("id")
                if not api_id:
                    continue
                try:
                    stages = apigw.get_stages(restApiId=api_id).get("item", [])
                except ClientError:
                    continue
                for stage in stages or []:
                    stage_name = stage.get("stageName")
                    api_stages.append(
                        {
                            "ApiId": api_id,
                            "ApiName": api.get("name"),
                            "StageName": stage_name,
                            "InvokeUrl": f"https://{api_id}.execute-api.{region}.amazonaws.com/{stage_name}",
                            "DeploymentId": stage.get("deploymentId"),
                            "HasWAF": "webAclArn" in stage,
                        }
                    )

            # HTTP APIs (apigatewayv2)
            try:
                apigw2 = boto3.client("apigatewayv2", **client_kwargs)
                apis2 = apigw2.get_apis().get("Items", [])
                for api in apis2 or []:
                    api_id = api.get("ApiId")
                    if not api_id:
                        continue
                    try:
                        stages2 = apigw2.get_stages(ApiId=api_id).get("Items", [])
                    except ClientError:
                        continue
                    for stage in stages2 or []:
                        stage_name = stage.get("StageName")
                        api_stages.append(
                            {
                                "ApiId": api_id,
                                "ApiName": api.get("Name"),
                                "StageName": stage_name,
                                "InvokeUrl": api.get("ApiEndpoint"),
                                "DeploymentId": stage.get("DeploymentId"),
                                "HasWAF": False,
                            }
                        )
            except Exception:
                pass

            _save(evidence_path / "api-gateway-stages.json", {"items": api_stages})
        except Exception as e:
            print(f"    Warning: Could not collect API Gateway stages: {e}")

        # === ECS/EKS INGRESS ===
        print("  Collecting ECS/EKS ingress exposure...")
        try:
            ingress_items: List[Dict[str, Any]] = []
            ecs = boto3.client("ecs", **client_kwargs)
            eks = boto3.client("eks", **client_kwargs)

            # ECS services + load balancer attachments
            cluster_arns = ecs.list_clusters().get("clusterArns", []) or []
            for cluster_arn in cluster_arns:
                service_arns = ecs.list_services(cluster=cluster_arn).get("serviceArns", []) or []
                if not service_arns:
                    continue
                chunks = [service_arns[i : i + 10] for i in range(0, len(service_arns), 10)]
                for chunk in chunks:
                    desc = ecs.describe_services(cluster=cluster_arn, services=chunk).get(
                        "services", []
                    )
                    for svc in desc or []:
                        ingress_items.append(
                            {
                                "Type": "ECSService",
                                "ClusterArn": cluster_arn,
                                "ServiceArn": svc.get("serviceArn"),
                                "ServiceName": svc.get("serviceName"),
                                "LoadBalancers": svc.get("loadBalancers", []),
                                "NetworkConfiguration": svc.get("networkConfiguration", {}),
                            }
                        )

            # EKS public endpoint exposure
            cluster_names = eks.list_clusters().get("clusters", []) or []
            for cname in cluster_names:
                try:
                    cluster = eks.describe_cluster(name=cname).get("cluster", {})
                except ClientError:
                    continue
                vpc_cfg = cluster.get("resourcesVpcConfig", {}) if isinstance(cluster, dict) else {}
                ingress_items.append(
                    {
                        "Type": "EKSCluster",
                        "ClusterName": cname,
                        "Endpoint": cluster.get("endpoint"),
                        "EndpointPublicAccess": vpc_cfg.get("endpointPublicAccess"),
                        "PublicAccessCidrs": vpc_cfg.get("publicAccessCidrs", []),
                    }
                )

            _save(evidence_path / "ecs-eks-ingress.json", {"items": ingress_items})
        except Exception as e:
            print(f"    Warning: Could not collect ECS/EKS ingress: {e}")

        # === ELASTICSEARCH / OPENSEARCH DOMAINS ===
        print("  Collecting Elasticsearch/OpenSearch domains...")
        try:
            domains_out: List[Dict[str, Any]] = []

            # OpenSearch service (current)
            try:
                os_client = boto3.client("opensearch", **client_kwargs)
                names = os_client.list_domain_names().get("DomainNames", []) or []
                domain_names = [d.get("DomainName") for d in names if isinstance(d, dict)]
                if domain_names:
                    details = os_client.describe_domain(DomainName=domain_names[0]).get(
                        "DomainStatus", {}
                    )
                    domains_out.append(
                        {
                            "Service": "opensearch",
                            "DomainName": details.get("DomainName"),
                            "ARN": details.get("ARN"),
                            "Endpoint": details.get("Endpoint"),
                            "Endpoints": details.get("Endpoints", {}),
                            "AccessPolicies": details.get("AccessPolicies"),
                            "VPCOptions": details.get("VPCOptions", {}),
                        }
                    )
                    for dn in domain_names[1:]:
                        try:
                            d = os_client.describe_domain(DomainName=dn).get("DomainStatus", {})
                            domains_out.append(
                                {
                                    "Service": "opensearch",
                                    "DomainName": d.get("DomainName"),
                                    "ARN": d.get("ARN"),
                                    "Endpoint": d.get("Endpoint"),
                                    "Endpoints": d.get("Endpoints", {}),
                                    "AccessPolicies": d.get("AccessPolicies"),
                                    "VPCOptions": d.get("VPCOptions", {}),
                                }
                            )
                        except Exception:
                            continue
            except Exception:
                pass

            # Legacy Elasticsearch service
            try:
                es_client = boto3.client("es", **client_kwargs)
                names = es_client.list_domain_names().get("DomainNames", []) or []
                domain_names = [d.get("DomainName") for d in names if isinstance(d, dict)]
                if domain_names:
                    resp = es_client.describe_elasticsearch_domains(DomainNames=domain_names)
                    for d in resp.get("DomainStatusList", []) or []:
                        domains_out.append(
                            {
                                "Service": "elasticsearch",
                                "DomainName": d.get("DomainName"),
                                "ARN": d.get("ARN"),
                                "Endpoint": d.get("Endpoint"),
                                "Endpoints": d.get("Endpoints", {}),
                                "AccessPolicies": d.get("AccessPolicies"),
                                "VPCOptions": d.get("VPCOptions", {}),
                            }
                        )
            except Exception:
                pass

            _save(evidence_path / "elasticsearch-domains.json", {"items": domains_out})
        except Exception as e:
            print(f"    Warning: Could not collect Elasticsearch/OpenSearch domains: {e}")

        # Persist audit metadata last so it includes all files.
        _save(evidence_path / "_audit_metadata.json", audit_metadata)

        print("\n✅ Exposure collection complete")

    def _save_json(self, filepath: Path, data):
        """Save data to JSON file with proper datetime serialization."""
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)

    def analyze(self, session: AuditSession, agent_client: "AgentClient") -> Path:
        """Analyze collected exposure evidence using configured AI provider.

        1. Read all evidence files
        2. Read security checklist
        3. Send to Gemini API for analysis
        4. Save findings to findings/exposure.json
        5. Print summary

        Args:
            session: Audit session with collected evidence
            agent_client: Gemini AI client for analysis

        Returns:
            Path to saved findings JSON file

        Raises:
            Exception: If evidence cannot be read or analysis fails
        """
        print("  Reading evidence files...")

        # 1. Read all evidence files
        evidence_path = session.get_evidence_path(self.name)
        evidence = {}

        if not evidence_path.exists():
            raise FileNotFoundError(f"Evidence directory not found: {evidence_path}")

        for json_file in evidence_path.glob("*.json"):
            try:
                with open(json_file) as f:
                    evidence[json_file.stem] = json.load(f)
            except Exception as e:
                print(f"    Warning: Could not read {json_file.name}: {e}")

        print(f"    Loaded {len(evidence)} evidence files")

        # 2. Read checklist
        checklist_path = Path(__file__).parent / "checklist.json"
        if not checklist_path.exists():
            raise FileNotFoundError(f"Checklist not found: {checklist_path}")

        with open(checklist_path) as f:
            checklist = json.load(f)

        print(f"    Loaded {len(checklist['items'])} security checks")

        # 3. Call agent for analysis (chunked for large evidence)
        provider_name = agent_client.get_display_name()
        print(f"  Analyzing with {provider_name}...")
        findings = agent_client.analyze_evidence_chunked(
            skill_name=self.name, evidence=evidence, checklist=checklist
        )

        # 3a. Deterministic findings from evidence (reduce false negatives)
        # Some exposure checks are reliably derivable from evidence and should not
        # depend on model variability.
        try:
            deterministic = self._generate_deterministic_findings(evidence, checklist)
            if deterministic:
                # Deterministic findings should override model-emitted findings for the same ID.
                merged = {}
                for f in findings.findings or []:
                    fid = getattr(f, "id", None)
                    if isinstance(fid, str) and fid:
                        merged[fid] = f
                for df in deterministic:
                    merged[df.id] = df
                findings.findings = list(merged.values())
        except Exception as e:
            print(f"    Warning: deterministic exposure checks failed: {e}")

        # 3b. Normalize findings (reduce variance between models)
        print("  Normalizing findings...")
        findings = self._normalize_findings(findings, checklist, evidence=evidence)

        # Enforce server-side metadata for report generation and QA consistency.
        findings.skill = self.name
        findings.evidence_count = len(evidence)
        findings.checklist_version = str(checklist.get("version") or "1.0")

        # Override analyzed_at with a reliable server-side timestamp.
        findings.analyzed_at = datetime.now(timezone.utc)

        # Patch affected_resources that use ':unknown:' region.
        audit_region = (evidence.get("_audit_metadata") or {}).get("_region")
        if audit_region:
            for f in findings.findings:
                patched = []
                for r in f.affected_resources or []:
                    if isinstance(r, str) and ":unknown:" in r:
                        patched.append(r.replace(":unknown:", f":{audit_region}:"))
                    else:
                        patched.append(r)
                f.affected_resources = patched

        # 4. Save findings
        findings_dir = session.get_findings_path()
        findings_dir.mkdir(parents=True, exist_ok=True)
        findings_path = findings_dir / f"{self.name}.json"

        with open(findings_path, "w") as f:
            json.dump(findings.model_dump(mode="json"), f, indent=2, default=str)

        # 5. Print summary
        print("\n✅ Analysis complete:")
        print(f"   Total findings: {findings.summary.total_findings}")
        print(f"   Critical: {findings.summary.critical}")
        print(f"   High: {findings.summary.high}")
        print(f"   Medium: {findings.summary.medium}")
        print(f"   Low: {findings.summary.low}")
        print(f"   Overall Risk: {findings.summary.overall_risk_score:.1f}/10")

        return findings_path

    def _generate_deterministic_findings(
        self, evidence: Dict[str, Any], checklist: Dict[str, Any]
    ) -> List[Any]:
        """Generate deterministic findings from evidence for high-signal checks."""

        from drystone.models.findings import Finding, PCIDSSControl
        from drystone.validation.findings_normalizer import FindingsNormalizer

        items = checklist.get("items", []) or []
        item_by_id = {i.get("id"): i for i in items if isinstance(i, dict) and i.get("id")}

        meta = evidence.get("_audit_metadata") or {}
        audit_account = meta.get("_account_id") if isinstance(meta, dict) else None
        if isinstance(audit_account, str):
            audit_account = audit_account.strip()

        s3_doc = evidence.get("s3-buckets")
        by_name = {}
        if isinstance(s3_doc, dict) and isinstance(s3_doc.get("by_name"), dict):
            by_name = s3_doc.get("by_name") or {}

        def _mid_score(sev: str) -> float:
            lo, hi = FindingsNormalizer.SEVERITY_RANGES.get(sev, (5.0, 5.0))
            return round((lo + hi) / 2, 1)

        def _pci(fid: str) -> List[PCIDSSControl]:
            it = item_by_id.get(fid) or {}
            out = []
            for c in it.get("pci_dss") or []:
                if isinstance(c, dict) and c.get("control"):
                    out.append(
                        PCIDSSControl(
                            control=str(c.get("control")), reason=str(c.get("reason") or "")
                        )
                    )
            return out

        def _has_securetransport_deny(policy: Any) -> bool:
            if not isinstance(policy, dict):
                return False
            for st in policy.get("Statement", []) or []:
                if not isinstance(st, dict):
                    continue
                if st.get("Effect") != "Deny":
                    continue
                cond = st.get("Condition")
                if not isinstance(cond, dict):
                    continue
                b = cond.get("Bool")
                if isinstance(b, dict) and b.get("aws:SecureTransport") == "false":
                    return True
            return False

        def _is_audit_log_bucket(name: str, bucket: Dict[str, Any]) -> bool:
            n = name.lower()
            if any(k in n for k in ["cloudtrail", "logs", "log", "audit", "backup", "config"]):
                return True
            pol = bucket.get("BucketPolicy")
            if not isinstance(pol, dict):
                return False
            for st in pol.get("Statement", []) or []:
                if not isinstance(st, dict):
                    continue
                principal = st.get("Principal")
                if not isinstance(principal, dict):
                    continue
                svc = principal.get("Service")
                if not isinstance(svc, str):
                    continue
                if svc in {
                    "config.amazonaws.com",
                    "cloudtrail.amazonaws.com",
                    "delivery.logs.amazonaws.com",
                }:
                    return True
                if svc.startswith("logs.") and svc.endswith(".amazonaws.com"):
                    return True
            return False

        findings = []

        # EXP-013: TLS enforcement missing
        exp_013 = item_by_id.get("EXP-013")
        if exp_013 and by_name:
            buckets = []
            for bn, b in by_name.items():
                if not isinstance(bn, str) or not isinstance(b, dict):
                    continue
                if not _is_audit_log_bucket(bn, b):
                    continue
                pol = b.get("BucketPolicy")
                if pol is None:
                    continue
                if not _has_securetransport_deny(pol):
                    buckets.append(bn)

            if buckets:
                findings.append(
                    Finding(
                        id="EXP-013",
                        severity=exp_013.get("severity", "High"),
                        risk_score=_mid_score(exp_013.get("severity", "High")),
                        title=str(exp_013.get("title", "S3 TLS enforcement missing")),
                        description="One or more audit/log S3 buckets are missing an explicit bucket policy Deny for aws:SecureTransport=false, so non-TLS access is not explicitly blocked.",
                        remediation=str(exp_013.get("remediation", "")),
                        evidence_refs=[f"s3-buckets.json#by_name.{bn}" for bn in buckets[:5]],
                        evidence_snippet={"buckets": [{"Name": bn} for bn in buckets[:20]]},
                        affected_resources=[f"arn:aws:s3:::{bn}" for bn in buckets],
                        cis_reference=None,
                        pci_dss=_pci("EXP-013"),
                    )
                )

        # EXP-014: Versioning missing
        exp_014 = item_by_id.get("EXP-014")
        if exp_014 and by_name:
            buckets = []
            for bn, b in by_name.items():
                if not isinstance(bn, str) or not isinstance(b, dict):
                    continue
                if not _is_audit_log_bucket(bn, b):
                    continue
                if (b.get("Versioning") or "") != "Enabled":
                    buckets.append(bn)

            if buckets:
                findings.append(
                    Finding(
                        id="EXP-014",
                        severity=exp_014.get("severity", "High"),
                        risk_score=_mid_score(exp_014.get("severity", "High")),
                        title=str(exp_014.get("title", "S3 versioning missing")),
                        description="One or more audit/log S3 buckets do not have versioning enabled, reducing protection against overwrites/deletions for audit evidence.",
                        remediation=str(exp_014.get("remediation", "")),
                        evidence_refs=[f"s3-buckets.json#by_name.{bn}" for bn in buckets[:5]],
                        evidence_snippet={
                            "audit_log_buckets": [
                                {
                                    "Name": bn,
                                    "Versioning": (by_name.get(bn) or {}).get("Versioning"),
                                }
                                for bn in buckets[:20]
                            ]
                        },
                        affected_resources=[f"arn:aws:s3:::{bn}" for bn in buckets],
                        cis_reference=None,
                        pci_dss=_pci("EXP-014"),
                    )
                )

        # EXP-015: Cross-account bucket policy without conditions
        exp_015 = item_by_id.get("EXP-015")
        if exp_015 and by_name and isinstance(audit_account, str) and audit_account.isdigit():
            buckets = []
            principals: List[str] = []

            def _has_strong_condition(st: Dict[str, Any]) -> bool:
                cond = st.get("Condition")
                if not isinstance(cond, dict):
                    return False
                for block in ["StringEquals", "ArnEquals", "StringLike", "ArnLike"]:
                    b = cond.get(block)
                    if not isinstance(b, dict):
                        continue
                    for k in b.keys():
                        if k in {
                            "aws:SourceAccount",
                            "AWS:SourceAccount",
                            "aws:SourceArn",
                            "AWS:SourceArn",
                        }:
                            return True
                return False

            for bn, b in by_name.items():
                if not isinstance(bn, str) or not isinstance(b, dict):
                    continue
                pol = b.get("BucketPolicy")
                if not isinstance(pol, dict):
                    continue
                for st in pol.get("Statement", []) or []:
                    if not isinstance(st, dict):
                        continue
                    if st.get("Effect") != "Allow":
                        continue
                    principal = st.get("Principal")
                    if not isinstance(principal, dict):
                        continue
                    aws_p = principal.get("AWS")
                    aws_list = [aws_p] if isinstance(aws_p, str) else (aws_p or [])
                    for p in aws_list:
                        if not isinstance(p, str) or not p.startswith("arn:aws:iam::"):
                            continue
                        parts = p.split(":")
                        if len(parts) > 4 and parts[4].isdigit() and parts[4] != audit_account:
                            if not _has_strong_condition(st):
                                buckets.append(bn)
                                principals.append(p)

            if buckets and principals:
                buckets_u = sorted(set(buckets))
                principals_u = sorted(set(principals))
                findings.append(
                    Finding(
                        id="EXP-015",
                        severity=exp_015.get("severity", "High"),
                        risk_score=_mid_score(exp_015.get("severity", "High")),
                        title=str(exp_015.get("title", "S3 cross-account bucket policy")),
                        description=str(exp_015.get("description", "")),
                        remediation=str(exp_015.get("remediation", "")),
                        evidence_refs=[f"s3-buckets.json#by_name.{bn}" for bn in buckets_u[:5]],
                        evidence_snippet={
                            "buckets": buckets_u[:20],
                            "cross_account_principals": principals_u[:20],
                        },
                        affected_resources=[
                            *[f"arn:aws:s3:::{bn}" for bn in buckets_u],
                            *principals_u,
                        ],
                        cis_reference=None,
                        pci_dss=_pci("EXP-015"),
                    )
                )

        return findings


__all__ = ["ExposureSkill"]
