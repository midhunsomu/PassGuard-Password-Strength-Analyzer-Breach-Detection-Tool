import sys
import argparse
import getpass
import os
from typing import List, Dict, Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.text import Text
from rich.theme import Theme

from passguard.reporter import analyze_password, export_to_csv, export_to_json
from passguard.common import load_common_passwords

# Define custom color theme for security severity
custom_theme = Theme({
    "very_weak": "bold red",
    "weak": "red",
    "moderate": "bold yellow",
    "strong": "green",
    "very_strong": "bold green",
    "breached": "bold red",
    "safe": "bold green",
    "error": "bold red",
    "info": "cyan"
})

console = Console(
    theme=custom_theme,
    width=120 if not sys.stdout.isatty() else None
)

def display_banner():
    banner = """
    [bold info]=======================================================[/bold info]
    [bold info][PASSGUARD] Password Security Analyzer CLI Tool[/bold info]
    [bold info]=======================================================[/bold info]
    """
    console.print(banner)

def get_color_for_score(score: str) -> str:
    mapping = {
        "Very Weak": "very_weak",
        "Weak": "weak",
        "Moderate": "moderate",
        "Strong": "strong",
        "Very Strong": "very_strong"
    }
    return mapping.get(score, "info")

def display_single_result(res: Dict[str, Any]):
    score_color = get_color_for_score(res["score"])
    
    score_text = Text(res["score"], style=score_color)
    entropy_text = Text(f"{res['entropy']} bits", style="info")
    
    # Breach representation
    if res["breach_error"]:
        breach_text = Text(f"Error ({res['breach_error']})", style="error")
    elif res["breach_count"] > 0:
        breach_text = Text(f"BREACHED ({res['breach_count']:,} times in leaks)", style="breached")
    else:
        breach_text = Text("Clean (0 exposures in leaks)", style="safe")

    # Common password warning
    common_text = ""
    if res["common_error"]:
        common_text = f"\n[error]Common DB Error: {res['common_error']}[/error]"
    elif res["is_common"]:
        common_text = "\n[very_weak][!] Found in Top 10,000 Common Passwords![/very_weak]"

    # Weaknesses panel
    weakness_str = ""
    if res["weaknesses"]:
        weakness_str = "\n[bold red]Detected Weaknesses:[/bold red]\n" + "\n".join(f"  * {w}" for w in res["weaknesses"])
    else:
        weakness_str = "\n[safe][OK] No obvious patterns or length vulnerabilities detected.[/safe]"

    # Suggestions panel
    suggestions_str = "\n\n[bold info]Actionable Recommendations:[/bold info]\n" + "\n".join(f"  * {s}" for s in res["suggestions"])

    panel_content = (
        f"[bold]Masked Password:[/bold] {res['masked_password']}\n"
        f"[bold]Strength Score:[/bold] {score_text}\n"
        f"[bold]Entropy:[/bold] {entropy_text}\n"
        f"[bold]Breach Lookup:[/bold] {breach_text}"
        f"{common_text}"
        f"{weakness_str}"
        f"{suggestions_str}"
    )

    console.print(Panel(
        panel_content,
        title="[bold info]Analysis Report[/bold info]",
        border_style=score_color,
        expand=False
    ))

def handle_single_password(check_breach: bool):
    try:
        console.print("[bold]Enter password to analyze (input will be hidden): [/bold]", end="")
        password = getpass.getpass("")
    except (KeyboardInterrupt, SystemExit):
        console.print("\n[info]Analysis cancelled.[/info]")
        sys.exit(0)

    if not password:
        console.print("[error]No password entered.[/error]")
        return

    # Check for common db load/download first
    with console.status("[info]Loading common passwords database...[/info]"):
        _, db_err = load_common_passwords()
        if db_err:
            console.print(f"[bold yellow]Warning:[/bold yellow] {db_err}")

    # Analyze
    with console.status("[info]Analyzing password security & HIBP leaks...[/info]"):
        res = analyze_password(password, check_breach=check_breach)

    display_single_result(res)

def handle_bulk_audit(file_path: str, check_breach: bool, csv_out: str, json_out: str):
    if not os.path.exists(file_path):
        console.print(f"[error]File not found: {file_path}[/error]")
        sys.exit(1)

    passwords = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                # Strip newline characters but keep spaces inside password if present
                # Standard is to strip end-of-line whitespace
                pwd = line.rstrip("\r\n")
                if pwd:
                    passwords.add(pwd) if isinstance(passwords, set) else passwords.append(pwd)
    except Exception as e:
        console.print(f"[error]Failed to read password file: {str(e)}[/error]")
        sys.exit(1)

    if not passwords:
        console.print("[bold yellow]No valid passwords found in the file.[/bold yellow]")
        return

    # De-duplicate passwords in-memory for audit speed if needed, 
    # but let's preserve exact entries so line-by-line maps perfectly.
    total = len(passwords)
    console.print(f"[info]Loaded {total} passwords for bulk audit.[/info]")

    # Download common passwords db if needed
    with console.status("[info]Checking common passwords database cache...[/info]"):
        _, db_err = load_common_passwords()
        if db_err:
            console.print(f"[bold yellow]Warning:[/bold yellow] {db_err}")

    results = []
    
    # Progress bar for analysis
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Auditing passwords...", total=total)
        for pwd in passwords:
            # Check breach based on option
            res = analyze_password(pwd, check_breach=check_breach)
            results.append(res)
            progress.advance(task)

    # Build Summary Table
    table = Table(title="[bold info]Bulk Security Audit Summary[/bold info]", box=box.ASCII)
    table.add_column("No.", justify="right", style="cyan", no_wrap=True)
    table.add_column("Masked Password", justify="left", no_wrap=True)
    table.add_column("Score", justify="center", no_wrap=True)
    table.add_column("Entropy (bits)", justify="right", no_wrap=True)
    table.add_column("Breaches", justify="right", no_wrap=True)
    table.add_column("Patterns Detected?", justify="center", no_wrap=True)

    very_weak_count = 0
    weak_count = 0
    moderate_count = 0
    strong_count = 0
    very_strong_count = 0
    breached_count = 0

    for idx, r in enumerate(results, 1):
        score = r["score"]
        score_color = get_color_for_score(score)
        
        # Stats counting
        if score == "Very Weak": very_weak_count += 1
        elif score == "Weak": weak_count += 1
        elif score == "Moderate": moderate_count += 1
        elif score == "Strong": strong_count += 1
        elif score == "Very Strong": very_strong_count += 1

        if r["breach_count"] > 0:
            breached_count += 1
            breach_cell = Text(f"{r['breach_count']:,}", style="breached")
        else:
            breach_cell = Text("0", style="safe")

        pattern_cell = "Yes" if len(r["weaknesses"]) - (1 if r["is_common"] else 0) - (1 if r["breach_count"] > 0 else 0) > 0 else "No"
        pattern_style = "very_weak" if pattern_cell == "Yes" else "safe"

        table.add_row(
            str(idx),
            r["masked_password"],
            Text(score, style=score_color),
            f"{r['entropy']}",
            breach_cell,
            Text(pattern_cell, style=pattern_style)
        )

    console.print(table)

    # Print overall statistics summary panel
    stats_panel = (
        f"[bold info]Audit Summary Statistics:[/bold info]\n"
        f"  * Total Passwords Audited: [bold]{total}[/bold]\n"
        f"  * Very Strong / Strong: [strong]{very_strong_count + strong_count}[/strong]\n"
        f"  * Moderate: [moderate]{moderate_count}[/moderate]\n"
        f"  * Weak / Very Weak: [very_weak]{weak_count + very_weak_count}[/very_weak]\n"
        f"  * Compromised in Breaches: [breached]{breached_count}[/breached]"
    )
    console.print(Panel(stats_panel, expand=False, border_style="info"))

    # Exports
    if csv_out:
        try:
            export_to_csv(csv_out, results)
            console.print(f"[safe][SUCCESS] Exported results to CSV: {csv_out}[/safe]")
        except Exception as e:
            console.print(f"[error]Failed to export CSV: {str(e)}[/error]")

    if json_out:
        try:
            export_to_json(json_out, results)
            console.print(f"[safe][SUCCESS] Exported results to JSON: {json_out}[/safe]")
        except Exception as e:
            console.print(f"[error]Failed to export JSON: {str(e)}[/error]")

def main():
    display_banner()

    parser = argparse.ArgumentParser(
        description="PassGuard CLI password security analyzer. Evaluates password strength, local dictionary pattern rules, and Have I Been Pwned breaches."
    )
    
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-i", "--interactive",
        action="store_true",
        help="Check a single password interactively (default)."
    )
    group.add_argument(
        "-b", "--bulk",
        type=str,
        help="Path to a text file containing passwords to audit (one per line)."
    )
    
    parser.add_argument(
        "-c", "--csv",
        type=str,
        help="Export bulk audit results to a CSV file (bulk mode only)."
    )
    parser.add_argument(
        "-j", "--json",
        type=str,
        help="Export bulk audit results to a JSON file (bulk mode only)."
    )
    parser.add_argument(
        "--no-breach",
        action="store_true",
        help="Skip the Have I Been Pwned k-Anonymity API breach check."
    )
    parser.add_argument(
        "--force-download",
        action="store_true",
        help="Force download/redownload of the top 10,000 common passwords database."
    )

    args = parser.parse_args()

    # Check for force database download
    if args.force_download:
        with console.status("[info]Downloading top 10k common password database from SecLists...[/info]"):
            success, err = load_common_passwords(force_download=True)
            if success:
                console.print("[safe][SUCCESS] Downloaded and cached common passwords database.[/safe]")
            else:
                console.print(f"[error]Failed to download common passwords: {err}[/error]")
        if not args.bulk and not args.interactive:
            sys.exit(0)

    check_breach = not args.no_breach

    # Determine execution path
    if args.bulk:
        handle_bulk_audit(args.bulk, check_breach, args.csv, args.json)
    else:
        # Default behavior: Interactive mode
        handle_single_password(check_breach)

if __name__ == "__main__":
    main()
