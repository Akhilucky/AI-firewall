"""
AI Firewall - Interactive CLI Dashboard
Rich-powered terminal interface for live firewall testing and analysis.
"""

from __future__ import annotations

import time
import logging

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.align import Align
from rich import box

from ai_firewall.models import (
    FirewallAction,
    ThreatLevel,
    FirewallReport,
    RedTeamResult,
)
from ai_firewall.orchestrator import FirewallOrchestrator
from ai_firewall.config import config

console = Console()

# ── Color Scheme ──────────────────────────────────────────────────────────────

COLORS = {
    FirewallAction.ALLOW: "green",
    FirewallAction.BLOCK: "red",
    FirewallAction.SANITIZE: "yellow",
    ThreatLevel.SAFE: "green",
    ThreatLevel.SUSPICIOUS: "yellow",
    ThreatLevel.MALICIOUS: "red",
}

ICONS = {
    FirewallAction.ALLOW: "✅",
    FirewallAction.BLOCK: "🚫",
    FirewallAction.SANITIZE: "⚠️ ",
    ThreatLevel.SAFE: "🟢",
    ThreatLevel.SUSPICIOUS: "🟡",
    ThreatLevel.MALICIOUS: "🔴",
}


# ── Banner ────────────────────────────────────────────────────────────────────

BANNER = r"""
[bold cyan]
    █████╗ ██╗    ███████╗██╗██████╗ ███████╗██╗    ██╗ █████╗ ██╗     ██╗     
   ██╔══██╗██║    ██╔════╝██║██╔══██╗██╔════╝██║    ██║██╔══██╗██║     ██║     
   ███████║██║    █████╗  ██║██████╔╝█████╗  ██║ █╗ ██║███████║██║     ██║     
   ██╔══██║██║    ██╔══╝  ██║██╔══██╗██╔══╝  ██║███╗██║██╔══██║██║     ██║     
   ██║  ██║██║    ██║     ██║██║  ██║███████╗╚███╔███╔╝██║  ██║███████╗███████╗
   ╚═╝  ╚═╝╚═╝    ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚══════╝
[/bold cyan]
[dim]   Agentic AI Firewall — Protecting LLMs from adversarial attacks[/dim]
"""


def print_banner():
    """Print the startup banner."""
    console.print(BANNER)


def print_status_bar(orchestrator: FirewallOrchestrator):
    """Print the system status bar."""
    stats = orchestrator.vector_store.stats
    table = Table(box=box.SIMPLE_HEAVY, show_header=False, padding=(0, 2))
    table.add_column(style="bold")
    table.add_column()

    table.add_row("🛡️  Mode", f"[bold]{config.mode.upper()}[/bold]")
    table.add_row("📊 Vectors", str(stats["total_entries"]))
    table.add_row("🎯 Threshold", f"{config.similarity_threshold}")
    table.add_row("⚡ Status", "[bold green]OPERATIONAL[/bold green]")

    console.print(Panel(table, title="[bold]System Status[/bold]", border_style="cyan"))


def format_report(report: FirewallReport) -> Panel:
    """Format a FirewallReport as a beautiful Rich Panel."""
    action = report.final_action
    threat = report.threat_level
    action_color = COLORS[action]
    threat_color = COLORS[threat]

    # ── Header ────────────────────────────────────────────────────────────
    header = Text()
    header.append(f"\n  {ICONS[action]} Action: ", style="bold")
    header.append(f"{action.value}", style=f"bold {action_color}")
    header.append(f"   {ICONS[threat]} Threat: ", style="bold")
    header.append(f"{threat.value}", style=f"bold {threat_color}")
    header.append("   🎯 Confidence: ", style="bold")
    header.append(f"{report.overall_confidence:.1%}", style="bold white")
    header.append(f"   ⏱️  {report.processing_time_ms:.0f}ms", style="dim")
    header.append("\n")

    # ── Evidence Table ────────────────────────────────────────────────────
    evidence_table = Table(
        title="📡 Retrieval Evidence",
        box=box.ROUNDED,
        show_lines=True,
        title_style="bold blue",
        width=90,
    )
    evidence_table.add_column("Attack Type", style="bold", width=22)
    evidence_table.add_column("Similarity", justify="center", width=12)
    evidence_table.add_column("Pattern", width=50, no_wrap=True)

    for e in report.retrieval.evidence[:5]:
        sim_color = (
            "red"
            if e.similarity_score >= 0.7
            else "yellow"
            if e.similarity_score >= 0.5
            else "green"
        )
        evidence_table.add_row(
            e.attack_type.value,
            f"[{sim_color}]{e.similarity_score:.3f}[/{sim_color}]",
            e.text[:50] + "..." if len(e.text) > 50 else e.text,
        )

    if not report.retrieval.evidence:
        evidence_table.add_row("[dim]No matches found[/dim]", "", "")

    # ── Signals Table ─────────────────────────────────────────────────────
    signals_table = Table(
        title="🔍 Detection Signals",
        box=box.ROUNDED,
        show_lines=True,
        title_style="bold magenta",
        width=90,
    )
    signals_table.add_column("Type", width=15)
    signals_table.add_column("Detail", width=70)

    for kw in report.guard.keyword_matches:
        signals_table.add_row(
            "[red]Keyword[/red]", f"'{kw.keyword}' at position {kw.position}"
        )

    for sig in report.guard.heuristic_signals:
        sev_color = (
            "red"
            if sig.severity >= 0.7
            else "yellow"
            if sig.severity >= 0.4
            else "green"
        )
        signals_table.add_row(
            f"[{sev_color}]Heuristic[/{sev_color}]",
            f"[{sev_color}]{sig.rule_name}[/{sev_color}]: {sig.description}",
        )

    if not report.guard.keyword_matches and not report.guard.heuristic_signals:
        signals_table.add_row("[dim]None[/dim]", "[dim]No signals triggered[/dim]")

    # ── Policy Rules ──────────────────────────────────────────────────────
    policy_text = Text()
    for rule in report.policy.policy_rules_triggered:
        policy_text.append(f"  • {rule}\n", style="bold")

    # ── Compose Panel ─────────────────────────────────────────────────────
    border = (
        "red"
        if action == FirewallAction.BLOCK
        else "yellow"
        if action == FirewallAction.SANITIZE
        else "green"
    )

    content = Text()
    content.append_text(header)

    return (
        Panel(
            Align.left(Text.from_markup(f"{header.plain}\n")),
            title=f"[bold {border}]━━━ Firewall Report [{report.request_id}] ━━━[/bold {border}]",
            border_style=border,
            padding=(0, 1),
        ),
        evidence_table,
        signals_table,
        policy_text,
    )


def print_report(report: FirewallReport):
    """Print a complete firewall report to the console."""
    panel, evidence_table, signals_table, policy_text = format_report(report)

    action = report.final_action
    threat = report.threat_level
    action_color = COLORS[action]
    threat_color = COLORS[threat]
    border = (
        "red"
        if action == FirewallAction.BLOCK
        else "yellow"
        if action == FirewallAction.SANITIZE
        else "green"
    )

    # Prompt preview
    prompt_preview = report.original_prompt
    if len(prompt_preview) > 120:
        prompt_preview = prompt_preview[:120] + "..."

    console.print()
    console.print(
        Panel(
            f"[dim]{prompt_preview}[/dim]",
            title="[bold]📝 Input Prompt[/bold]",
            border_style="dim",
            width=94,
        )
    )

    # Decision banner
    console.print()
    console.print(
        Panel(
            Align.center(
                Text.from_markup(
                    f"\n{ICONS[action]}  [bold {action_color}]{action.value}[/bold {action_color}]"
                    f"  │  {ICONS[threat]}  [bold {threat_color}]{threat.value}[/bold {threat_color}]"
                    f"  │  🎯  [bold]{report.overall_confidence:.1%}[/bold]"
                    f"  │  ⏱️  [dim]{report.processing_time_ms:.0f}ms[/dim]\n"
                )
            ),
            title=f"[bold {border}]━━━ VERDICT [{report.request_id}] ━━━[/bold {border}]",
            border_style=border,
            width=94,
        )
    )

    # Evidence
    console.print()
    console.print(evidence_table)

    # Signals
    console.print()
    console.print(signals_table)

    # Policy rules
    if report.policy.policy_rules_triggered:
        console.print()
        console.print(
            Panel(
                policy_text,
                title="[bold]📋 Policy Rules Triggered[/bold]",
                border_style="cyan",
                width=94,
            )
        )

    # Sanitized output
    if report.policy.sanitized_prompt:
        console.print()
        console.print(
            Panel(
                f"[yellow]{report.policy.sanitized_prompt}[/yellow]",
                title="[bold yellow]✂️  Sanitized Prompt[/bold yellow]",
                border_style="yellow",
                width=94,
            )
        )

    console.print()


def print_redteam_results(results: list[RedTeamResult]):
    """Print red-team test results as a beautiful table."""
    passed = sum(1 for r in results if r.passed)
    total = len(results)
    pass_rate = passed / total if total > 0 else 0

    # Summary header
    rate_color = (
        "green" if pass_rate >= 0.9 else "yellow" if pass_rate >= 0.7 else "red"
    )
    console.print()
    console.print(
        Panel(
            Align.center(
                Text.from_markup(
                    f"\n[bold]Tests: {total}[/bold]  │  "
                    f"[green]Passed: {passed}[/green]  │  "
                    f"[red]Failed: {total - passed}[/red]  │  "
                    f"Pass Rate: [bold {rate_color}]{pass_rate:.0%}[/bold {rate_color}]\n"
                )
            ),
            title="[bold red]⚔️  Red-Team Test Results ⚔️[/bold red]",
            border_style="red",
            width=94,
        )
    )

    # Results table
    table = Table(
        box=box.ROUNDED,
        show_lines=True,
        width=94,
    )
    table.add_column("", width=3, justify="center")
    table.add_column("Attack Type", style="bold", width=20)
    table.add_column("Label", width=8, justify="center")
    table.add_column("Expected", width=10, justify="center")
    table.add_column("Actual", width=10, justify="center")
    table.add_column("Threat", width=12, justify="center")
    table.add_column("Status", width=8, justify="center")

    for r in results:
        status_icon = "✅" if r.passed else "❌"
        label_style = "red bold" if r.label == "ATTACK" else "green bold"
        actual_color = (
            COLORS.get(r.actual_action, "white") if r.actual_action else "white"
        )
        threat_color = (
            COLORS.get(r.actual_threat_level, "white")
            if r.actual_threat_level
            else "white"
        )

        table.add_row(
            status_icon,
            r.attack_type.value,
            f"[{label_style}]{r.label}[/{label_style}]",
            r.expected_action.value,
            f"[{actual_color}]{r.actual_action.value if r.actual_action else 'N/A'}[/{actual_color}]",
            f"[{threat_color}]{r.actual_threat_level.value if r.actual_threat_level else 'N/A'}[/{threat_color}]",
            "[green]PASS[/green]" if r.passed else "[red]FAIL[/red]",
        )

    console.print()
    console.print(table)
    console.print()


def run_interactive():
    """Run the interactive CLI session."""
    # Setup logging
    logging.basicConfig(
        level=getattr(logging, config.log_level),
        format="%(message)s",
        handlers=[logging.NullHandler()],  # suppress logs in interactive mode
    )

    print_banner()

    console.print("[bold cyan]Initializing AI Firewall...[/bold cyan]")
    with console.status(
        "[bold cyan]Loading embedding model & vector database...", spinner="dots"
    ):
        start = time.perf_counter()
        fw = FirewallOrchestrator()
        elapsed = time.perf_counter() - start

    console.print(f"[bold green]✓ Firewall ready in {elapsed:.1f}s[/bold green]")
    console.print()

    print_status_bar(fw)

    console.print()
    console.print(
        Panel(
            "[bold]Commands:[/bold]\n"
            "  • Type any prompt to analyze it\n"
            "  • [bold cyan]redteam[/bold cyan]  — Run adversarial test suite\n"
            "  • [bold cyan]stats[/bold cyan]    — Show system statistics\n"
            "  • [bold cyan]help[/bold cyan]     — Show this help\n"
            "  • [bold cyan]quit[/bold cyan]     — Exit\n",
            title="[bold]🔥 Interactive Mode[/bold]",
            border_style="cyan",
        )
    )

    while True:
        console.print()
        try:
            user_input = console.input(
                "[bold cyan]🛡️  Enter prompt ❯ [/bold cyan]"
            ).strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[bold]Goodbye! 👋[/bold]")
            break

        if not user_input:
            continue

        cmd = user_input.lower()

        if cmd in ("quit", "exit", "q"):
            console.print("[bold]Goodbye! 👋[/bold]")
            break

        elif cmd == "help":
            console.print(
                Panel(
                    "[bold]Commands:[/bold]\n"
                    "  • Type any prompt to analyze it\n"
                    "  • [bold cyan]redteam[/bold cyan]  — Run adversarial test suite\n"
                    "  • [bold cyan]stats[/bold cyan]    — Show system statistics\n"
                    "  • [bold cyan]quit[/bold cyan]     — Exit",
                    border_style="cyan",
                )
            )

        elif cmd == "redteam":
            console.print("[bold red]⚔️  Running Red-Team Test Suite...[/bold red]")
            with console.status("[bold red]Attacking...", spinner="dots"):
                results = fw.run_red_team()
            print_redteam_results(results)

        elif cmd == "stats":
            print_status_bar(fw)
            stats = fw.vector_store.stats
            console.print(
                Panel(
                    "[bold]Entries by type:[/bold]\n"
                    + "\n".join(
                        f"  • {k}: {v}" for k, v in stats["entries_by_type"].items()
                    ),
                    title="[bold]📊 Vector DB Stats[/bold]",
                    border_style="blue",
                )
            )

        else:
            # Analyze the prompt
            with console.status("[bold cyan]Analyzing...", spinner="dots"):
                report = fw.analyze_text(user_input)
            print_report(report)


if __name__ == "__main__":
    run_interactive()
