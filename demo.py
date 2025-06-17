"""
PassGuard CLI - Demonstration Script
Runs key security modules and displays outcomes for different types of passwords.
"""
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from passguard.entropy import calculate_entropy, analyze_length, get_base_strength_score
from passguard.patterns import analyze_patterns
from passguard.breach import lookup_breach
from passguard.common import is_common_password
from passguard.reporter import analyze_password

console = Console(width=100)

def demonstrate_password(password: str):
    console.print(f"\n[bold info]Analyzing Password: '{password}'[/bold info]")
    
    # 1. Basic stats
    entropy = calculate_entropy(password)
    length_res = analyze_length(password)
    base_score = get_base_strength_score(entropy, len(password))
    
    # 2. Pattern check
    pattern_res = analyze_patterns(password)
    
    # 3. Common password check
    is_common, _ = is_common_password(password)
    
    # 4. Breach lookup (mocked or live depending on connection)
    breach_count, breach_err = lookup_breach(password)
    
    # 5. Full aggregate report
    full_report = analyze_password(password, check_breach=True)
    
    # Output presentation table
    table = Table(title=f"Security Metrics: {password}", show_header=True)
    table.add_column("Check / Metric", style="cyan")
    table.add_column("Result / Value", style="white")
    
    table.add_row("Length Check", f"{len(password)} chars (Severity: {length_res['severity']})")
    table.add_row("Shannon Entropy", f"{entropy:.2f} bits")
    table.add_row("Base Score", base_score)
    table.add_row("Repeated Patterns", str(pattern_res['repeated_characters']))
    table.add_row("Sequential Patterns", str(pattern_res['sequential_characters']))
    table.add_row("Keyboard Patterns", str(pattern_res['keyboard_patterns']))
    table.add_row("In 10k Common List?", "Yes" if is_common else "No")
    
    if breach_err:
        table.add_row("HIBP Breach Count", f"Error ({breach_err})")
    else:
        table.add_row("HIBP Breach Count", f"{breach_count:,} exposures")
        
    table.add_row("Final Calibrated Score", f"[bold]{full_report['score']}[/bold]")
    
    console.print(table)
    
    # Recommendations
    console.print("[bold yellow]Actionable Recommendations:[/bold yellow]")
    for suggestion in full_report["suggestions"]:
        console.print(f"  * {suggestion}")

def main():
    console.print(Panel.fit(
        "PassGuard CLI - Core Modules Demonstration\n"
        "Testing password strength, character sets, patterns, 10k common lists, and HIBP breach lookups.",
        title="[bold green]DEMO[/bold green]"
    ))
    
    # Test cases:
    # 1. An extremely common password
    demonstrate_password("123456")
    
    # 2. A weak/short password
    demonstrate_password("qwerty")
    
    # 3. A moderate password with keyboard patterns
    demonstrate_password("asdf123456")
    
    # 4. A strong, long password
    demonstrate_password("CorrectHorseBatteryStaple!")

if __name__ == "__main__":
    main()
