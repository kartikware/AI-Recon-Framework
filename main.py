import argparse
import sys
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich import box

from core.cve_lookup import NVDLookup
from core.scanner import run_scan
from core.parser import parse_nmap_xml
from core.risk_engine import classify_ports
from core.ai_analyzer import MockAIAnalyzer

console = Console()


def calculate_summary(findings):
    severity_count = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
        "UNKNOWN": 0
    }

    for item in findings:
        severity_count[item["severity"]] += 1

    return severity_count


def generate_markdown_report(target, findings, summary):
    filename = f"reports/report_{target.replace('.', '_')}.md"

    with open(filename, "w") as f:
        f.write(f"# Scan Report for {target}\n\n")
        f.write(f"Generated on: {datetime.now()}\n\n")

        f.write("## Summary\n")
        for key, value in summary.items():
            f.write(f"- {key}: {value}\n")

        f.write("\n## Findings\n\n")

        for item in findings:
            f.write(f"### {item['port']}/{item['protocol']} - {item['service']}\n")
            f.write(f"- Version: {item['version']}\n")
            f.write(f"- Severity: {item['severity']}\n")
            f.write(f"- Reason: {item.get('reason', '')}\n\n")

    return filename


def main():
    parser = argparse.ArgumentParser(
        description="AI-Assisted Offensive Recon Tool"
    )

    parser.add_argument("--target", type=str, help="Target domain or IP")
    args = parser.parse_args()

    if not args.target:
        console.print("[red]Error: --target is required[/red]")
        sys.exit(1)

    console.print(f"\n[bold cyan]Starting scan on {args.target}[/bold cyan]\n")

    # Run scan
    xml_output, error = run_scan(args.target)

    if error:
        console.print(f"[red]Scan error: {error}[/red]")
        return

    parsed_data = parse_nmap_xml(xml_output)
    classified = classify_ports(parsed_data)

    nvd = NVDLookup()
    ai = MockAIAnalyzer()

    table = Table(title="Open Port Risk Analysis", box=box.ROUNDED)
    table.add_column("Port")
    table.add_column("Service")
    table.add_column("Version")
    table.add_column("Severity")

    # 🔥 MAIN LOOP
    for item in classified:

        # ---- CVE LOOKUP ----
        vulns = nvd.search(item["service"], item["version"])
        max_cvss = 0

        if vulns:
            console.print("[bold red]Known CVEs (NVD):[/bold red]")

            for v in vulns:
                console.print(f"- {v['id']} | CVSS: {v['cvss']}")

                if v["cvss"] is not None:
                    try:
                        score = float(v["cvss"])
                        if score > max_cvss:
                            max_cvss = score
                    except:
                        pass

            console.print()

        # ---- CVSS ESCALATION ----
        if max_cvss >= 9.0:
            item["severity"] = "CRITICAL"
        elif max_cvss >= 7.0:
            item["severity"] = "HIGH"
        elif max_cvss >= 4.0:
            item["severity"] = "MEDIUM"
        elif max_cvss > 0:
            item["severity"] = "LOW"

        # ---- AI INSIGHT AFTER ESCALATION ----
        ai_explanation = ai.analyze_port(item)
        console.print(f"[dim]AI Insight:[/dim] {ai_explanation}\n")

        # ---- TABLE ROW AFTER ESCALATION ----
        severity_color = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "green",
            "INFO": "cyan",
            "UNKNOWN": "white"
        }.get(item["severity"], "white")

        table.add_row(
            f"{item['port']}/{item['protocol']}",
            item["service"],
            item["version"],
            f"[{severity_color}]{item['severity']}[/{severity_color}]"
        )

    # 🔥 SUMMARY AFTER ESCALATION
    summary = calculate_summary(classified)

    console.print(table)

    console.print("\n[bold]Summary:[/bold]")
    for key, value in summary.items():
        console.print(f"{key}: {value}")

    overall_ai = ai.analyze_overall(classified, summary)
    console.print("\n[bold magenta]AI Overall Assessment:[/bold magenta]")
    console.print(overall_ai)

    report_file = generate_markdown_report(args.target, classified, summary)
    console.print(f"\n[green]Report saved to {report_file}[/green]")


if __name__ == "__main__":
    main()
