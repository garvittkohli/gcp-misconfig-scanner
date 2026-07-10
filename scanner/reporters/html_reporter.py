import os
from pathlib import Path
from scanner.findings import ScanResult, Severity

SEVERITY_BADGE = {
    Severity.CRITICAL: "background:#dc2626;color:#fff",
    Severity.HIGH:     "background:#ea580c;color:#fff",
    Severity.MEDIUM:   "background:#d97706;color:#fff",
    Severity.LOW:      "background:#2563eb;color:#fff",
    Severity.INFO:     "background:#6b7280;color:#fff",
}

SEVERITY_BORDER = {
    Severity.CRITICAL: "#dc2626",
    Severity.HIGH:     "#ea580c",
    Severity.MEDIUM:   "#d97706",
    Severity.LOW:      "#2563eb",
    Severity.INFO:     "#e7e5e0",
}

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Scan — {project_id}</title>
<style>
  *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','Helvetica Neue',Arial,sans-serif;background:#fafaf8;color:#1c1917;line-height:1.6;font-size:14px}}

  .page-header{{background:#fff;border-bottom:2px solid #1c1917;padding:36px 56px 28px}}
  .header-top{{display:flex;justify-content:space-between;align-items:flex-start}}
  .report-label{{font-size:10px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:#78716c;margin-bottom:6px}}
  .report-title{{font-size:26px;font-weight:800;color:#1c1917;letter-spacing:-0.5px}}
  .report-project{{font-size:15px;color:#57534e;margin-top:4px;font-family:'Courier New',monospace}}
  .header-meta{{text-align:right;font-size:12px;color:#78716c;line-height:1.8}}
  .header-meta strong{{color:#1c1917}}

  .summary-strip{{background:#fff;border-bottom:1px solid #e7e5e0;padding:20px 56px;display:flex}}
  .summary-cell{{flex:1;padding:8px 20px;border-right:1px solid #e7e5e0;text-align:center}}
  .summary-cell:first-child{{padding-left:0;text-align:left}}
  .summary-cell:last-child{{border-right:none}}
  .summary-count{{font-size:28px;font-weight:800;line-height:1;margin-bottom:4px}}
  .summary-label{{font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:1px;color:#78716c}}
  .c-critical{{color:#dc2626}}.c-high{{color:#ea580c}}.c-medium{{color:#d97706}}.c-low{{color:#2563eb}}.c-total{{color:#1c1917}}

  .body{{max-width:960px;margin:0 auto;padding:40px 56px 80px}}

  .section-header{{display:flex;align-items:baseline;gap:10px;margin:40px 0 16px;padding-bottom:8px;border-bottom:1px solid #d5d3ce}}
  .section-header h2{{font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:1.5px;color:#57534e}}
  .section-count{{font-size:12px;color:#a8a29e}}

  .finding{{background:#fff;border:1px solid #e7e5e0;border-left:3px solid transparent;border-radius:4px;margin-bottom:10px;overflow:hidden}}
  .finding-header{{padding:14px 20px;display:flex;align-items:flex-start;gap:12px;cursor:pointer;user-select:none}}
  .finding-header:hover{{background:#faf9f7}}
  .severity-badge{{padding:3px 9px;border-radius:3px;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:0.5px;white-space:nowrap;flex-shrink:0;margin-top:2px}}
  .finding-title{{font-size:14px;font-weight:600;color:#1c1917;flex:1;line-height:1.4}}
  .finding-rule{{font-size:11px;color:#a8a29e;font-family:'Courier New',monospace;flex-shrink:0;margin-top:3px}}
  .chevron{{color:#a8a29e;font-size:10px;flex-shrink:0;margin-top:4px;transition:transform 0.15s}}
  .finding.open .chevron{{transform:rotate(90deg)}}
  .finding-body{{display:none;padding:0 20px 20px;border-top:1px solid #f0efeb}}
  .finding.open .finding-body{{display:block}}

  .meta-row{{display:flex;gap:28px;padding:12px 0 14px;flex-wrap:wrap}}
  .meta-key{{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:0.8px;color:#a8a29e;margin-bottom:3px}}
  .meta-val{{font-size:13px;color:#44403c;font-family:'Courier New',monospace}}
  .cis-pill{{display:inline-block;background:#f5f5f0;border:1px solid #e7e5e0;padding:3px 10px;border-radius:3px;font-size:11px;color:#57534e;margin-bottom:14px}}
  .body-label{{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:#a8a29e;margin-bottom:6px;margin-top:14px}}
  .description{{font-size:13px;color:#44403c;line-height:1.7}}
  .remediation-block{{background:#f5faf5;border:1px solid #bbf7d0;border-left:3px solid #16a34a;border-radius:3px;padding:12px 16px;font-size:12px;color:#14532d;white-space:pre-line;font-family:'Courier New',monospace;line-height:1.65;margin-top:6px}}
  .tf-toggle{{background:none;border:1px solid #d5d3ce;color:#57534e;font-size:11px;padding:5px 12px;border-radius:3px;cursor:pointer;margin-top:14px;display:inline-flex;align-items:center;gap:5px}}
  .tf-toggle:hover{{background:#f5f5f0;border-color:#a8a29e}}
  .tf-section{{display:none;margin-top:10px}}
  .tf-section.open{{display:block}}
  .tf-code{{background:#fafaf8;border:1px solid #e7e5e0;border-radius:3px;padding:16px;font-family:'Courier New',monospace;font-size:12px;color:#292524;white-space:pre;overflow-x:auto;line-height:1.6}}

  .errors-box{{background:#fff8f0;border:1px solid #fed7aa;border-left:3px solid #ea580c;border-radius:4px;padding:16px 20px;margin-top:28px}}
  .errors-label{{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:#c2410c;margin-bottom:10px}}
  .error-line{{font-size:12px;color:#7c2d12;font-family:'Courier New',monospace;margin-bottom:4px}}

  .page-footer{{border-top:1px solid #e7e5e0;padding:20px 56px;display:flex;justify-content:space-between;font-size:11px;color:#a8a29e;margin-top:48px}}

  @media print{{.finding-body{{display:block!important}}.chevron{{display:none}}}}
</style>
</head>
<body>

<div class="page-header">
  <div class="header-top">
    <div>
      <div class="report-label">GCP Security Assessment</div>
      <div class="report-title">Misconfiguration Report</div>
      <div class="report-project">{project_id}</div>
    </div>
    <div class="header-meta">
      <strong>Completed</strong><br>{scan_end}<br><br>
      <strong>Tool</strong><br>gcp-misconfig-scanner<br><br>
      <strong>Framework</strong><br>CIS GCP Foundation Benchmark v2.0
    </div>
  </div>
</div>

<div class="summary-strip">
  <div class="summary-cell"><div class="summary-count c-total">{total}</div><div class="summary-label">Total</div></div>
  <div class="summary-cell"><div class="summary-count c-critical">{critical}</div><div class="summary-label">Critical</div></div>
  <div class="summary-cell"><div class="summary-count c-high">{high}</div><div class="summary-label">High</div></div>
  <div class="summary-cell"><div class="summary-count c-medium">{medium}</div><div class="summary-label">Medium</div></div>
  <div class="summary-cell"><div class="summary-count c-low">{low}</div><div class="summary-label">Low</div></div>
</div>

<div class="body">
{findings_html}
{errors_html}
</div>

<div class="page-footer">
  <span>gcp-misconfig-scanner &nbsp;·&nbsp; Read-only scan &nbsp;·&nbsp; No resources modified</span>
  <span>{scan_end}</span>
</div>

<script>
  document.querySelectorAll('.finding-header').forEach(function(h){{
    h.addEventListener('click',function(){{h.closest('.finding').classList.toggle('open')}});
  }});
  document.querySelectorAll('.tf-toggle').forEach(function(b){{
    b.addEventListener('click',function(e){{
      e.stopPropagation();
      var s=b.nextElementSibling;
      s.classList.toggle('open');
      b.textContent=s.classList.contains('open')?'▾ Hide Terraform fix':'▸ Show Terraform fix';
    }});
  }});
</script>
</body>
</html>"""


class HTMLReporter:
    def __init__(self, output_dir: str = "output"):
        self.output_dir = output_dir
        Path(output_dir).mkdir(parents=True, exist_ok=True)

    def write(self, result: ScanResult, filename: str = "report.html") -> str:
        summary = result.summary()
        html = HTML_TEMPLATE.format(
            project_id=result.project_id,
            scan_end=summary["scan_end"] or "—",
            total=summary["total_findings"],
            critical=summary["critical"],
            high=summary["high"],
            medium=summary["medium"],
            low=summary["low"],
            findings_html=self._build_findings_html(result),
            errors_html=self._build_errors_html(result),
        )
        path = os.path.join(self.output_dir, filename)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html)
        return path

    def _build_findings_html(self, result: ScanResult) -> str:
        if not result.findings:
            return '<p style="color:#a8a29e;padding:32px 0;text-align:center">No findings — project configuration looks clean.</p>'

        groups = [
            ("Critical", Severity.CRITICAL),
            ("High",     Severity.HIGH),
            ("Medium",   Severity.MEDIUM),
            ("Low",      Severity.LOW),
            ("Info",     Severity.INFO),
        ]

        parts = []
        for label, sev in groups:
            group = [f for f in result.sorted_findings() if f.severity == sev]
            if not group:
                continue

            n = len(group)
            parts.append(
                f'<div class="section-header">'
                f'<h2>{label}</h2>'
                f'<span class="section-count">{n} finding{"s" if n != 1 else ""}</span>'
                f'</div>'
            )

            for finding in group:
                badge = SEVERITY_BADGE.get(finding.severity, "background:#6b7280;color:#fff")
                border = SEVERITY_BORDER.get(finding.severity, "#e7e5e0")

                cis_html = (
                    f'<div><span class="cis-pill">{finding.cis_benchmark}</span></div>'
                    if finding.cis_benchmark else ""
                )

                tf_html = ""
                if finding.terraform_fix:
                    escaped = (
                        finding.terraform_fix
                        .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                    )
                    tf_html = (
                        '<button class="tf-toggle">&#9657; Show Terraform fix</button>'
                        f'<div class="tf-section"><pre class="tf-code">{escaped}</pre></div>'
                    )

                desc = (
                    finding.description
                    .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                )

                parts.append(f"""
<div class="finding" style="border-left-color:{border}">
  <div class="finding-header">
    <span class="severity-badge" style="{badge}">{finding.severity.value}</span>
    <span class="finding-title">{finding.title}</span>
    <span class="finding-rule">{finding.rule_id}</span>
    <span class="chevron">&#9658;</span>
  </div>
  <div class="finding-body">
    <div class="meta-row">
      <div><div class="meta-key">Resource Type</div><div class="meta-val">{finding.resource_type}</div></div>
      <div><div class="meta-key">Name</div><div class="meta-val">{finding.resource_name}</div></div>
      <div><div class="meta-key">Timestamp</div><div class="meta-val">{finding.timestamp[:19].replace("T"," ")}</div></div>
    </div>
    {cis_html}
    <div class="body-label">Finding</div>
    <p class="description">{desc}</p>
    <div class="body-label" style="margin-top:16px">Remediation</div>
    <div class="remediation-block">{finding.remediation_steps}</div>
    {tf_html}
  </div>
</div>""")

        return "\n".join(parts)

    def _build_errors_html(self, result: ScanResult) -> str:
        if not result.errors:
            return ""
        lines = "".join(
            f'<div class="error-line">&#8594; {e}</div>' for e in result.errors
        )
        return f"""
<div class="errors-box">
  <div class="errors-label">Scanner errors — check API permissions</div>
  {lines}
</div>"""
