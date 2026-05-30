from dataclasses import dataclass
from collections import Counter
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text


console = Console()


@dataclass(frozen=True)
class Finding:

    severity: str
    finding_type: str
    issue: str
    filepath: str
    line: int | None = None


findings = []

seen_findings = set()


SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "green"
}


SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3
}


def add_finding(
    severity,
    finding_type,
    issue,
    filepath,
    line=None
):

    severity = severity.upper()

    finding_key = (
        severity,
        finding_type,
        issue,
        filepath,
        line
    )

    if finding_key in seen_findings:

        return

    finding = Finding(
        severity,
        finding_type,
        issue,
        filepath,
        line
    )

    seen_findings.add(finding_key)

    findings.append(finding)


def get_severity_counts():

    counter = Counter()

    for finding in findings:

        counter[finding.severity] += 1

    return counter


def sort_findings():

    findings.sort(
        key=lambda finding: (
            SEVERITY_ORDER.get(finding.severity, 999),
            finding.filepath,
            finding.line or 0
        )
    )


def show_findings():

    if not findings:

        console.print(
            Panel.fit(
                "[bold green]No security findings detected[/bold green]",
                title="RepoGuard"
            )
        )

        return

    sort_findings()

    table = Table(
        title="RepoGuard Security Findings",
        show_lines=True
    )

    table.add_column(
        "Severity",
        justify="center"
    )

    table.add_column(
        "Type",
        style="cyan"
    )

    table.add_column(
        "Issue",
        style="white"
    )

    table.add_column(
        "File",
        style="green"
    )

    table.add_column(
        "Line",
        justify="center"
    )

    for finding in findings:

        severity_text = Text(
            finding.severity,
            style=SEVERITY_COLORS.get(
                finding.severity,
                "white"
            )
        )

        table.add_row(
            severity_text,
            finding.finding_type,
            finding.issue,
            finding.filepath,
            str(finding.line)
            if finding.line else "-"
        )

    console.print()

    console.print(table)

    severity_counts = get_severity_counts()

    summary = (
        f"[bold red]CRITICAL:[/bold red] "
        f"{severity_counts.get('CRITICAL', 0)}\n"
        f"[red]HIGH:[/red] "
        f"{severity_counts.get('HIGH', 0)}\n"
        f"[yellow]MEDIUM:[/yellow] "
        f"{severity_counts.get('MEDIUM', 0)}\n"
        f"[green]LOW:[/green] "
        f"{severity_counts.get('LOW', 0)}\n\n"
        f"[bold]Total Findings:[/bold] {len(findings)}"
    )

    console.print(
        Panel.fit(
            summary,
            title="Scan Summary"
        )
    )
