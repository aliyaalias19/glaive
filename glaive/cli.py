"""GLAIVE command-line entry point.

This is intentionally minimal on day 1. Subcommands are wired in as
features land. Keeping the CLI surface stable from the start prevents
breaking changes to install.sh and the README quickstart.
"""
from __future__ import annotations

import typer
from rich.console import Console

app = typer.Typer(
    name="glaive",
    help="Graph-Linked Adversarial Investigation & Verification Engine.",
    no_args_is_help=True,
)
console = Console()


@app.command()
def version() -> None:
    """Print GLAIVE version."""
    from glaive import __version__

    console.print(f"glaive {__version__}")


@app.command()
def investigate(
    evidence_dir: str = typer.Argument(..., help="Path to evidence directory."),
    output: str = typer.Option("runs/", help="Output directory for reports + logs."),
) -> None:
    """Run an autonomous investigation against an evidence directory.

    Not yet implemented. Wired in during Week 2.
    """
    console.print(
        f"[yellow]investigate[/] is not yet implemented. "
        f"Would investigate [bold]{evidence_dir}[/] → [bold]{output}[/]"
    )
    raise typer.Exit(code=2)


if __name__ == "__main__":
    app()
