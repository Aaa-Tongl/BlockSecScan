from pathlib import Path

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from blocksec.api.public import generate_report, list_rules, scan
from blocksec.models.scan import ScanTarget

app = typer.Typer(
    name="blocksec",
    help="BlockSecScan — Rule-driven blockchain security scanner for Hyperledger Fabric.",
    no_args_is_help=True,
)

scan_app = typer.Typer(no_args_is_help=True, help="Run security scans")
rules_app = typer.Typer(no_args_is_help=True, help="Manage rules")

app.add_typer(scan_app, name="scan")
app.add_typer(rules_app, name="rules")

console = Console()

DISCLAIMER = "[yellow]Only for authorized security testing, educational, and self-owned asset inspection use.[/yellow]"

SEVERITY_COLORS = {
    "CRITICAL": "bright_red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "blue",
    "INFO": "dim",
}


@app.callback()
def callback():
    """BlockSecScan — Rule-driven blockchain security scanner."""


# ── scan fabric-config ──────────────────────────────────────────

@scan_app.command(name="fabric-config")
def scan_fabric_config(
    path: str = typer.Option(..., "--path", "-p", help="Path to Fabric project directory"),
    output: str | None = typer.Option(None, "--output", "-o", help="Output report file path"),
    fmt: str = typer.Option("json", "--format", "-f", help="Report format: json, markdown, html, sarif"),
):
    """Scan Hyperledger Fabric configuration files for security issues."""
    console.print(Panel.fit(DISCLAIMER, border_style="yellow"))
    console.print()

    target_path = Path(path).resolve()
    if not target_path.exists():
        console.print(f"[red]Error:[/red] Path not found: {target_path}")
        raise typer.Exit(code=1)

    target = ScanTarget(target_type="fabric_config", path=str(target_path))

    with console.status(f"[bold green]Scanning {target_path}..."):
        result = scan(target)

    _print_result(result)

    actual_output = output or f"result.{fmt}"
    generate_report(result, fmt=fmt, output_path=actual_output)
    console.print(f"\n[dim]Report saved to {actual_output}[/dim]")


# ── scan fabric-runtime ────────────────────────────────────────

@scan_app.command(name="fabric-runtime")
def scan_fabric_runtime(
    local: bool = typer.Option(True, "--local/--no-local", help="Scan local Docker containers"),
    host: str | None = typer.Option(None, "--host", "-h", help="Remote host to scan"),
    output: str | None = typer.Option(None, "--output", "-o", help="Output report file path"),
    fmt: str = typer.Option("json", "--format", "-f", help="Report format: json, markdown, html, sarif"),
):
    """Scan running Fabric containers and services for security issues."""
    console.print(Panel.fit(DISCLAIMER, border_style="yellow"))
    console.print()

    if not local and not host:
        console.print("[red]Error:[/red] Specify --local or --host")
        raise typer.Exit(code=1)

    options: dict = {}
    if local:
        options["local"] = True
    if host:
        options["host"] = host

    target = ScanTarget(target_type="fabric_runtime", path=host or "local", options=options)

    with console.status("[bold green]Scanning runtime environment..."):
        result = scan(target)

    _print_result(result)

    if result.findings:
        actual_output = output or f"runtime-result.{fmt}"
        generate_report(result, fmt=fmt, output_path=actual_output)
        console.print(f"\n[dim]Report saved to {actual_output}[/dim]")


# ── rules list ──────────────────────────────────────────────────

@rules_app.command(name="list")
def rules_list(category: str | None = typer.Option(None, "--category", "-c", help="Filter by category")):
    """List all available rules."""
    rules = list_rules(category=category)
    if not rules:
        console.print("[dim]No rules found.[/dim]")
        return

    table = Table(title=f"Rules ({len(rules)} total)", box=box.ROUNDED)
    table.add_column("ID", style="cyan")
    table.add_column("Name")
    table.add_column("Severity")
    table.add_column("Category")

    for rule in rules:
        sev_color = SEVERITY_COLORS.get(rule.severity.upper(), "white")
        table.add_row(rule.id, rule.name, f"[{sev_color}]{rule.severity}[/{sev_color}]", rule.category)

    console.print(table)


# ── report ──────────────────────────────────────────────────────

@app.command()
def report(
    input_file: str = typer.Option(..., "--input", "-i", help="Scan result JSON file"),
    fmt: str = typer.Option("markdown", "--format", "-f", help="Output format: json, markdown, html, sarif"),
    output: str | None = typer.Option(None, "--output", "-o", help="Output file path"),
):
    """Generate a report from a scan result JSON file."""
    import json

    from blocksec.models.scan import ScanResult

    input_path = Path(input_file)
    if not input_path.exists():
        console.print(f"[red]Error:[/red] File not found: {input_file}")
        raise typer.Exit(code=1)

    with open(input_path, encoding="utf-8") as f:
        data = json.load(f)

    result = ScanResult.model_validate(data)
    generate_report(result, fmt=fmt, output_path=output)
    console.print(f"[green]Report generated ({fmt})[/green]")


# ── shared helpers ──────────────────────────────────────────────

def _print_result(result) -> None:
    s = result.summary
    duration = result.duration_seconds

    total_text = Text(f"  {s.total} findings  ", style="bold")
    summary_str = (
        f"[bright_red]CRIT:{s.critical}[/bright_red]  "
        f"[red]HIGH:{s.high}[/red]  "
        f"[yellow]MED:{s.medium}[/yellow]  "
        f"[blue]LOW:{s.low}[/blue]  "
        f"[dim]INFO:{s.info}[/dim]"
    )

    console.print()
    console.print(
        Panel.fit(
            f"{total_text}{summary_str}  [dim]({duration:.1f}s)[/dim]",
            title="Scan Complete",
            border_style="green",
        )
    )

    if not result.findings:
        console.print("[green]No security issues found.[/green]")
        return

    table = Table(box=box.ROUNDED)
    table.add_column("Severity")
    table.add_column("Rule ID", style="cyan")
    table.add_column("Title")
    table.add_column("File")
    table.add_column("Evidence", max_width=60)

    for f in sorted(result.findings, key=lambda x: x.severity.value, reverse=True):
        sev_color = SEVERITY_COLORS.get(f.severity.value, "white")
        table.add_row(
            f"[{sev_color}]{f.severity.value}[/{sev_color}]",
            f.rule_id,
            f.title,
            str(Path(f.file_path).name) if f.file_path else "-",
            f.evidence[:80],
        )

    console.print(table)


if __name__ == "__main__":
    app()
