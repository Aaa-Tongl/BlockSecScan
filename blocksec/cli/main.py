"""BlockSecScan CLI entry point."""

from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from typer import Argument, Option, Typer

from blocksec.api import scan_fabric
from blocksec.reports.exporters.json_exporter import JsonExporter

app = Typer(
    name="blocksec",
    help="BlockSecScan - 区块链安全扫描平台 | 仅用于授权安全测试和教学实验",
)
console = Console()


@app.command()
def scan(
    target_type: str = Argument("fabric", help="扫描类型: fabric"),
    path: str = Option(".", "--path", "-p", help="要扫描的目录路径"),
    output: str | None = Option(None, "--output", "-o", help="输出报告文件路径（JSON）"),
):
    """运行安全扫描"""
    if target_type != "fabric":
        console.print(f"[red]不支持的扫描类型: {target_type}[/red]")
        console.print("当前支持: fabric")
        raise SystemExit(1)

    scan_path = Path(path).resolve()
    if not scan_path.exists():
        console.print(f"[red]路径不存在: {scan_path}[/red]")
        raise SystemExit(1)

    with console.status(f"[bold green]正在扫描 Fabric 配置: {scan_path}..."):
        result = scan_fabric(str(scan_path))

    _print_scan_result(result)

    if output:
        exporter = JsonExporter()
        out_path = exporter.export(result, output)
        console.print(f"\n[green]报告已保存: {out_path}[/green]")
    elif result.errors:
        for err in result.errors:
            console.print(f"[yellow]⚠ {err}[/yellow]")


def _print_scan_result(result):
    """美化打印扫描结果。"""
    if result.summary.total == 0 and not result.errors:
        console.print("\n[bold green][PASS] 未发现安全问题！[/bold green]")
        return

    table = Table(title="扫描结果摘要", show_header=True, header_style="bold")
    table.add_column("等级", style="cyan")
    table.add_column("数量", justify="right")

    severity_colors = {
        "CRITICAL": "red",
        "HIGH": "orange1",
        "MEDIUM": "yellow",
        "LOW": "blue",
        "INFO": "dim",
    }

    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = getattr(result.summary, level.lower(), 0)
        color = severity_colors.get(level, "white")
        if count > 0:
            table.add_row(f"[{color}]{level}[/{color}]", f"[{color}]{count}[/{color}]")

    table.add_row("[bold]合计[/bold]", f"[bold]{result.summary.total}[/bold]")
    console.print(table)
    console.print(f"扫描耗时: {result.duration_seconds}s")

    if result.findings:
        console.print("\n[bold]漏洞详情:[/bold]")
        for f in result.findings:
            color = severity_colors.get(f.severity, "white")
            console.print(
                Panel(
                    f"[bold]位置:[/bold] {f.location.file_path}:{f.location.start_line}\n"
                    f"[bold]证据:[/bold] {f.evidence}\n"
                    f"[bold]修复:[/bold] {f.remediation}",
                    title=f"[{color}]{f.severity}[/{color}] {f.title}",
                    border_style=color,
                )
            )


@app.command()
def report():
    """生成扫描报告"""
    console.print("[yellow]请先运行 scan 命令生成扫描结果，使用 --output 参数输出报告。[/yellow]")


@app.command()
def rules():
    """管理规则库"""
    from blocksec.core.rule_parser import RuleParser

    rules_dir = Path(__file__).parent.parent / "rules" / "fabric"
    rp = RuleParser()
    rules = rp.load_rules(str(rules_dir))

    table = Table(title="Fabric 安全规则库", show_header=True)
    table.add_column("规则 ID")
    table.add_column("名称")
    table.add_column("风险等级")

    severity_colors = {
        "CRITICAL": "red",
        "HIGH": "orange1",
        "MEDIUM": "yellow",
        "LOW": "blue",
        "INFO": "dim",
    }

    for rule in rules:
        color = severity_colors.get(rule.severity, "white")
        table.add_row(
            f"[bold]{rule.id}[/bold]",
            rule.name,
            f"[{color}]{rule.severity}[/{color}]",
        )

    console.print(table)


if __name__ == "__main__":
    app()
