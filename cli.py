import logging
import os
import sys
from pathlib import Path

import click
import yaml
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from scanner.engine import ScanEngine
from scanner.findings import Severity, Finding, ScanResult
from scanner.reporters.json_reporter import JSONReporter
from scanner.reporters.html_reporter import HTMLReporter
from scanner.reporters.elk_shipper import ELKShipper
from scanner.remediation.terraform import get_terraform_fix

console = Console()

SEVERITY_STYLES = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH:     "bold orange1",
    Severity.MEDIUM:   "bold yellow",
    Severity.LOW:      "bold blue",
    Severity.INFO:     "dim white",
}


def load_config(config_path: str) -> dict:
    if os.path.exists(config_path):
        with open(config_path) as fh:
            return yaml.safe_load(fh) or {}
    return {}


@click.group()
@click.option("--config", default="config.yaml", help="Path to config.yaml")
@click.option("--verbose", is_flag=True, help="Enable debug logging")
@click.pass_context
def cli(ctx, config, verbose):
    """GCP Misconfiguration Scanner — detect and remediate security issues in your GCP project."""
    ctx.ensure_object(dict)
    ctx.obj["config"] = load_config(config)
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


@cli.command()
@click.option("--project", "-p", required=True, help="GCP Project ID to scan")
@click.option("--output-dir", "-o", default="output", help="Directory for output files")
@click.option("--sa-key", default=None, help="Path to service account JSON key file")
@click.option("--skip", multiple=True, help="Scanner names to skip (iam, compute, firewall, storage, sql, logging)")
@click.option("--no-html", is_flag=True, help="Skip HTML report generation")
@click.option("--no-json", is_flag=True, help="Skip JSON report generation")
@click.option("--ship-elk", is_flag=True, help="Ship findings to Elasticsearch")
@click.option("--fail-on-critical", is_flag=True, help="Exit with code 1 if any CRITICAL findings found")
@click.pass_context
def scan(ctx, project, output_dir, sa_key, skip, no_html, no_json, ship_elk, fail_on_critical):
    """Run a full security scan against a GCP project."""
    cfg = ctx.obj.get("config", {})
    skip_list = list(skip) + cfg.get("scanner", {}).get("skip_scanners", [])

    console.print(Panel.fit(
        f"[bold cyan]GCP Misconfiguration Scanner[/bold cyan]\n"
        f"[dim]Project:[/dim] [white]{project}[/white]",
        border_style="cyan",
    ))

    try:
        engine = ScanEngine(
            project_id=project,
            skip_scanners=skip_list,
            service_account_file=sa_key,
        )
    except RuntimeError as exc:
        console.print(f"[bold red]Authentication Error:[/bold red] {exc}")
        sys.exit(1)

    with console.status("[cyan]Scanning project...[/cyan]", spinner="dots"):
        result = engine.run()

    _print_summary_table(result)

    Path(output_dir).mkdir(parents=True, exist_ok=True)

    if not no_json:
        path = JSONReporter(output_dir=output_dir).write(result)
        console.print(f"[green]✓[/green] JSON report: [dim]{path}[/dim]")

    if not no_html:
        path = HTMLReporter(output_dir=output_dir).write(result)
        console.print(f"[green]✓[/green] HTML report: [dim]{path}[/dim]")

    elk_cfg = cfg.get("elk", {})
    if ship_elk or elk_cfg.get("enabled", False):
        shipper = ELKShipper(
            host=elk_cfg.get("host", "http://localhost:9200"),
            index=elk_cfg.get("index", "gcp-misconfig-findings"),
            username=elk_cfg.get("username"),
            password=elk_cfg.get("password"),
        )
        shipped = shipper.ship(result)
        console.print(f"[green]✓[/green] Shipped {shipped} findings to ELK")

    if fail_on_critical and result.by_severity(Severity.CRITICAL):
        console.print(
            f"\n[bold red]⛔ {len(result.by_severity(Severity.CRITICAL))} CRITICAL findings — failing build.[/bold red]"
        )
        sys.exit(1)


@cli.command()
@click.option("--project", "-p", required=True, help="GCP Project ID")
@click.option("--sa-key", default=None, help="Path to service account JSON key file")
@click.option("--scanner", default="all", help="Run a single scanner: iam, compute, firewall, storage, sql, logging")
def quick_check(project, sa_key, scanner):
    """Print findings to terminal — no files written."""
    all_scanners = ["iam", "compute", "firewall", "storage", "sql", "logging"]
    skip = [s for s in all_scanners if s != scanner] if scanner != "all" else []

    try:
        engine = ScanEngine(project_id=project, skip_scanners=skip, service_account_file=sa_key)
    except RuntimeError as exc:
        console.print(f"[bold red]Auth Error:[/bold red] {exc}")
        sys.exit(1)

    with console.status("[cyan]Running...[/cyan]"):
        result = engine.run()

    for finding in result.sorted_findings():
        style = SEVERITY_STYLES.get(finding.severity, "white")
        console.print(
            f"[{style}][{finding.severity.value:8}][/{style}]  "
            f"[dim]{finding.rule_id}[/dim]  {finding.title}"
        )

    console.print(f"\n[dim]Total: {len(result.findings)} findings[/dim]")


@cli.command()
@click.option("--output-dir", "-o", default="output", help="Directory for output files")
def demo(output_dir):
    """Generate a sample report with synthetic findings — no GCP credentials needed."""
    console.print(Panel.fit(
        "[bold cyan]GCP Misconfiguration Scanner — Demo Mode[/bold cyan]\n"
        "[dim]Generating synthetic findings (no GCP credentials needed)[/dim]",
        border_style="cyan",
    ))

    result = ScanResult(project_id="demo-production-project")

    demo_findings = [
        Finding(
            rule_id="GCP-FW-001",
            title="SSH port 22 open to 0.0.0.0/0 via rule 'allow-ssh-from-internet'",
            description=(
                "Firewall rule 'allow-ssh-from-internet' on network 'default' allows SSH (port 22/tcp) "
                "from 0.0.0.0/0. SSH exposure is how many crypto mining attacks begin — an attacker "
                "scans for open port 22 and attempts credential stuffing against every reachable VM."
            ),
            severity=Severity.CRITICAL,
            resource_type="VPC Firewall Rule",
            resource_name="allow-ssh-from-internet",
            project_id="demo-production-project",
            remediation_steps=(
                "1. Delete or disable rule 'allow-ssh-from-internet'.\n"
                "2. Enable Identity-Aware Proxy for tunneled SSH access.\n"
                "3. Allow only 35.235.240.0/20 (Google IAP range)."
            ),
            cis_benchmark="CIS GCP Benchmark v2.0 - Control 3.6",
            terraform_fix=get_terraform_fix("GCP-FW-001", {
                "project_id": "demo-production-project",
                "rule_name": "allow-ssh-from-internet",
                "network": "default",
            }),
            evidence={"rule_name": "allow-ssh-from-internet", "port": 22, "source_ranges": ["0.0.0.0/0"]},
        ),
        Finding(
            rule_id="GCP-GCS-001",
            title="GCS bucket 'demo-production-project-uploads' is publicly accessible",
            description=(
                "Bucket 'demo-production-project-uploads' grants 'roles/storage.objectViewer' to 'allUsers'. "
                "Anyone on the internet can read this bucket without authentication. "
                "Any files present — user uploads, application assets, backup data — are fully exposed."
            ),
            severity=Severity.CRITICAL,
            resource_type="Cloud Storage Bucket",
            resource_name="demo-production-project-uploads",
            project_id="demo-production-project",
            remediation_steps=(
                "1. Remove public access:\n"
                "   gsutil iam ch -d allUsers:objectViewer gs://demo-production-project-uploads\n"
                "2. Enable uniform bucket-level access.\n"
                "3. Use signed URLs for any temporary external access."
            ),
            cis_benchmark="CIS GCP Benchmark v2.0 - Control 5.1",
            terraform_fix=get_terraform_fix("GCP-GCS-001", {"bucket_name": "demo-production-project-uploads"}),
            evidence={"bucket": "demo-production-project-uploads", "public_member": "allUsers"},
        ),
        Finding(
            rule_id="GCP-SQL-003",
            title="Cloud SQL instance 'prod-postgres-db' allows connections from 0.0.0.0/0",
            description=(
                "Cloud SQL instance 'prod-postgres-db' has an authorized network of '0.0.0.0/0'. "
                "Any IP address on the internet can attempt to connect directly to the database. "
                "Combined with weak credentials this creates a directly exploitable database endpoint."
            ),
            severity=Severity.CRITICAL,
            resource_type="Cloud SQL Instance",
            resource_name="prod-postgres-db",
            project_id="demo-production-project",
            remediation_steps=(
                "1. Remove the 0.0.0.0/0 authorized network:\n"
                "   gcloud sql instances patch prod-postgres-db --clear-authorized-networks\n"
                "2. Use Cloud SQL Auth Proxy for application connections."
            ),
            cis_benchmark="CIS GCP Benchmark v2.0 - Control 6.3",
            terraform_fix=get_terraform_fix("GCP-SQL-003", {
                "instance_name": "prod-postgres-db",
                "project_id": "demo-production-project",
            }),
            evidence={"authorized_network": "0.0.0.0/0"},
        ),
        Finding(
            rule_id="GCP-FW-004",
            title="MySQL port 3306 exposed to 0.0.0.0/0 via rule 'allow-mysql-external'",
            description=(
                "Firewall rule 'allow-mysql-external' exposes MySQL port 3306 to the entire internet. "
                "Databases should never be directly reachable from the public internet. "
                "This allows direct brute-force attacks and full data exfiltration if credentials are weak."
            ),
            severity=Severity.CRITICAL,
            resource_type="VPC Firewall Rule",
            resource_name="allow-mysql-external",
            project_id="demo-production-project",
            remediation_steps=(
                "1. Delete rule 'allow-mysql-external'.\n"
                "2. Restrict MySQL to internal IP ranges (10.x.x.x) only.\n"
                "3. For Cloud SQL, use Cloud SQL Auth Proxy instead of direct port access."
            ),
            cis_benchmark="CIS GCP Benchmark v2.0 - Control 3.6",
            terraform_fix=get_terraform_fix("GCP-FW-004", {
                "project_id": "demo-production-project",
                "rule_name": "allow-mysql-external",
                "network": "default",
                "port": "3306",
                "label": "MySQL",
            }),
            evidence={"rule_name": "allow-mysql-external", "port": 3306, "db_type": "MySQL"},
        ),
        Finding(
            rule_id="GCP-IAM-001",
            title="Primitive role roles/editor assigned to user account",
            description=(
                "User 'developer@company.com' has the primitive role 'roles/editor' on this project. "
                "Primitive roles grant broad permissions across all GCP services. "
                "An attacker who compromises this account gains near-total control of the project."
            ),
            severity=Severity.HIGH,
            resource_type="IAM Policy Binding",
            resource_name="demo-production-project/roles/editor/user:developer@company.com",
            project_id="demo-production-project",
            remediation_steps=(
                "1. Identify the minimum permissions the developer actually needs.\n"
                "2. Grant a specific predefined role instead.\n"
                "3. Remove the editor binding:\n"
                "   gcloud projects remove-iam-policy-binding demo-production-project \\\n"
                "     --member='user:developer@company.com' --role='roles/editor'"
            ),
            cis_benchmark="CIS GCP Benchmark v2.0 - Control 1.5",
            terraform_fix=get_terraform_fix("GCP-IAM-001", {
                "project_id": "demo-production-project",
                "role": "roles/editor",
                "member": "user:developer@company.com",
                "rule_suffix": "developer_editor",
            }),
            evidence={"role": "roles/editor", "member": "user:developer@company.com"},
        ),
        Finding(
            rule_id="GCP-SQL-001",
            title="Cloud SQL instance 'prod-postgres-db' has a public IP address",
            description=(
                "Cloud SQL instance 'prod-postgres-db' (POSTGRES_14) has a public IP (34.28.100.22). "
                "A database with a public IP can be reached directly from the internet. "
                "Use Private IP and Cloud SQL Auth Proxy for all connections."
            ),
            severity=Severity.HIGH,
            resource_type="Cloud SQL Instance",
            resource_name="prod-postgres-db",
            project_id="demo-production-project",
            remediation_steps=(
                "1. Enable Private IP and disable Public IP in Cloud SQL settings.\n"
                "2. Use Cloud SQL Auth Proxy:\n"
                "   ./cloud-sql-proxy demo-production-project:us-central1:prod-postgres-db\n"
                "3. Update connection strings to use 127.0.0.1."
            ),
            cis_benchmark="CIS GCP Benchmark v2.0 - Control 6.2",
            terraform_fix=get_terraform_fix("GCP-SQL-001", {
                "instance_name": "prod-postgres-db",
                "project_id": "demo-production-project",
                "db_version": "POSTGRES_14",
            }),
            evidence={"public_ip": "34.28.100.22"},
        ),
        Finding(
            rule_id="GCP-COMP-004",
            title="Instance 'web-server-prod-1' uses default compute SA with full cloud-platform scope",
            description=(
                "Instance 'web-server-prod-1' uses the default Compute Engine service account with "
                "the 'cloud-platform' scope. The default service account has the Editor primitive role. "
                "Code running on this VM can read, modify, or delete any resource in the project. "
                "If the VM is compromised via SSRF or RCE, the attacker inherits these permissions."
            ),
            severity=Severity.HIGH,
            resource_type="Compute Instance",
            resource_name="web-server-prod-1",
            project_id="demo-production-project",
            remediation_steps=(
                "1. Create a dedicated service account with only needed permissions.\n"
                "2. Assign it to the instance with specific OAuth scopes:\n"
                "   gcloud compute instances set-service-account web-server-prod-1 \\\n"
                "     --zone=us-central1-a --service-account=DEDICATED_SA_EMAIL"
            ),
            cis_benchmark="CIS GCP Benchmark v2.0 - Control 4.1",
            terraform_fix=None,
            evidence={
                "sa_email": "123456789-compute@developer.gserviceaccount.com",
                "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
            },
        ),
        Finding(
            rule_id="GCP-LOG-001",
            title="Data Access audit logs (DATA_READ, DATA_WRITE) not enabled for all services",
            description=(
                "DATA_READ and DATA_WRITE audit logs are not enabled for this project. "
                "Without DATA_READ logs, there is no record of who accessed sensitive data "
                "in Cloud Storage or Cloud SQL. Without DATA_WRITE, no record of what was modified."
            ),
            severity=Severity.HIGH,
            resource_type="Project Audit Config",
            resource_name="demo-production-project",
            project_id="demo-production-project",
            remediation_steps=(
                "  gcloud projects get-iam-policy demo-production-project > policy.yaml\n"
                "  # Add auditConfigs for DATA_READ and DATA_WRITE under allServices\n"
                "  gcloud projects set-iam-policy demo-production-project policy.yaml"
            ),
            cis_benchmark="CIS GCP Benchmark v2.0 - Control 2.1",
            terraform_fix=get_terraform_fix("GCP-LOG-001", {"project_id": "demo-production-project"}),
            evidence={"missing_log_types": ["DATA_READ", "DATA_WRITE"]},
        ),
        Finding(
            rule_id="GCP-IAM-003",
            title="Service account key is 127 days old (exceeds 90 days)",
            description=(
                "Service account 'app-backend@demo-production-project.iam.gserviceaccount.com' has a "
                "user-managed key created 127 days ago. Keys older than 90 days increase the risk window "
                "if the key is ever compromised or leaked."
            ),
            severity=Severity.MEDIUM,
            resource_type="Service Account Key",
            resource_name="app-backend@demo-production-project.iam.gserviceaccount.com",
            project_id="demo-production-project",
            remediation_steps=(
                "1. Delete the old key:\n"
                "   gcloud iam service-accounts keys delete a1b2c3d4e5f6 \\\n"
                "     --iam-account=app-backend@demo-production-project.iam.gserviceaccount.com\n"
                "2. Create a replacement if still needed.\n"
                "3. Best practice: migrate to Workload Identity Federation."
            ),
            cis_benchmark="CIS GCP Benchmark v2.0 - Control 1.7",
            terraform_fix=get_terraform_fix("GCP-IAM-003", {
                "sa_email": "app-backend@demo-production-project.iam.gserviceaccount.com",
                "key_id": "a1b2c3d4e5f6",
                "project_id": "demo-production-project",
            }),
            evidence={"sa_email": "app-backend@demo-production-project.iam.gserviceaccount.com", "age_days": 127},
        ),
        Finding(
            rule_id="GCP-SQL-002",
            title="Cloud SQL instance 'prod-postgres-db' does not require SSL connections",
            description=(
                "Cloud SQL instance 'prod-postgres-db' allows non-SSL connections. "
                "Without SSL, database credentials and query data travel as plaintext. "
                "On a shared network this allows credential interception."
            ),
            severity=Severity.MEDIUM,
            resource_type="Cloud SQL Instance",
            resource_name="prod-postgres-db",
            project_id="demo-production-project",
            remediation_steps="gcloud sql instances patch prod-postgres-db --require-ssl",
            cis_benchmark="CIS GCP Benchmark v2.0 - Control 6.4",
            terraform_fix=get_terraform_fix("GCP-SQL-002", {"instance_name": "prod-postgres-db"}),
            evidence={"require_ssl": False},
        ),
        Finding(
            rule_id="GCP-LOG-002",
            title="No log sinks configured — audit logs are not being exported",
            description=(
                "This project has no logging sinks configured. Without a sink, logs are retained "
                "for only 30 days in Cloud Logging. An incident discovered after 31 days would have "
                "no forensic evidence. For ELK Stack integration, a Pub/Sub sink feeding into "
                "Logstash is the standard pattern."
            ),
            severity=Severity.MEDIUM,
            resource_type="Project Logging Config",
            resource_name="demo-production-project",
            project_id="demo-production-project",
            remediation_steps=(
                "  gcloud logging sinks create audit-sink \\\n"
                "    storage.googleapis.com/demo-production-project-audit-logs \\\n"
                "    --log-filter='protoPayload.@type=type.googleapis.com/google.cloud.audit.AuditLog'"
            ),
            cis_benchmark="CIS GCP Benchmark v2.0 - Control 2.2",
            terraform_fix=get_terraform_fix("GCP-LOG-002", {"project_id": "demo-production-project"}),
            evidence={"sink_count": 0},
        ),
        Finding(
            rule_id="GCP-GCS-002",
            title="Bucket 'demo-production-project-backups' does not enforce uniform bucket-level access",
            description=(
                "Bucket 'demo-production-project-backups' has uniform bucket-level access disabled. "
                "Individual object ACLs can override bucket-level IAM policies. An object inside "
                "this bucket could be publicly accessible even if the bucket IAM is restrictive."
            ),
            severity=Severity.MEDIUM,
            resource_type="Cloud Storage Bucket",
            resource_name="demo-production-project-backups",
            project_id="demo-production-project",
            remediation_steps=(
                "gsutil uniformbucketlevelaccess set on gs://demo-production-project-backups\n"
                "Verify no services depend on object-level ACLs before enabling."
            ),
            cis_benchmark="CIS GCP Benchmark v2.0 - Control 5.2",
            terraform_fix=get_terraform_fix("GCP-GCS-002", {"bucket_name": "demo-production-project-backups"}),
            evidence={"bucket": "demo-production-project-backups"},
        ),
        Finding(
            rule_id="GCP-GCS-003",
            title="Versioning is disabled on bucket 'demo-production-project-backups'",
            description=(
                "Bucket 'demo-production-project-backups' does not have versioning enabled. "
                "Accidental deletion or overwrite of objects is unrecoverable without versioning."
            ),
            severity=Severity.LOW,
            resource_type="Cloud Storage Bucket",
            resource_name="demo-production-project-backups",
            project_id="demo-production-project",
            remediation_steps="gsutil versioning set on gs://demo-production-project-backups",
            cis_benchmark="CIS GCP Benchmark v2.0 - Control 5.3",
            terraform_fix=get_terraform_fix("GCP-GCS-003", {"bucket_name": "demo-production-project-backups"}),
            evidence={"bucket": "demo-production-project-backups"},
        ),
    ]

    for f in demo_findings:
        result.add_finding(f)
    result.finalize()

    _print_summary_table(result)

    Path(output_dir).mkdir(parents=True, exist_ok=True)

    html_path = HTMLReporter(output_dir=output_dir).write(result, filename="demo_report.html")
    console.print(f"[green]✓[/green] HTML report: [dim]{html_path}[/dim]")

    json_path = JSONReporter(output_dir=output_dir).write(result, filename="demo_findings.json")
    console.print(f"[green]✓[/green] JSON report: [dim]{json_path}[/dim]")

    console.print(
        "\n[dim]Demo mode — no GCP credentials used. "
        "To scan a real project:[/dim] [cyan]gcp-scan scan --project YOUR_PROJECT_ID[/cyan]"
    )


def _print_summary_table(result):
    summary = result.summary()
    table = Table(title="Scan Summary", box=box.ROUNDED, border_style="dim")
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")
    table.add_row("[bold red]CRITICAL[/bold red]", str(summary["critical"]))
    table.add_row("[bold orange1]HIGH[/bold orange1]", str(summary["high"]))
    table.add_row("[bold yellow]MEDIUM[/bold yellow]", str(summary["medium"]))
    table.add_row("[bold blue]LOW[/bold blue]", str(summary["low"]))
    table.add_row("[bold white]TOTAL[/bold white]", str(summary["total_findings"]))
    console.print(table)
    if result.errors:
        console.print(f"\n[yellow]⚠ {len(result.errors)} scanner(s) reported errors (run with --verbose)[/yellow]")


if __name__ == "__main__":
    cli()
