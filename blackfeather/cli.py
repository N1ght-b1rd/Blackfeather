from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel

from .peel.engine import PeelEngine, PeelResult
from .identify.engine import IdentifyEngine
from .report import AnalysisReport, build_suggestion

app = typer.Typer(
    name="blackfeather",
    help="CLI python deserialization & decoding tool.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()


# ASCII art
FEATHER_ASCII = r"""
                                         
            /'^`.        .-----------------                   
           /     \  __  /    ----------                     
          / /     \(  )/    -------                        
         //////   ` \/ `   -----                           
        //// / // :    : ----                             
       // / / /  /`    `--                               
      //         //`||`\\                                 
     //         VV'\||/'VV                         
    /            '//||\\`                                 
                 `'`''`'`                                 
     
                     ~ BLACKFEATHER Deserializer: v0.1.0 ~
                                -by N1ghtb1rd                                           
                                         



"""


def _version_callback(value: bool):
    if value:
        from . import __version__
        console.print(f"blackfeather {__version__}")
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def _main(
    ctx: typer.Context,
    version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True
    ),
):
    
    if ctx.invoked_subcommand is not None:
        return


@app.callback(invoke_without_command=True)
def _root(
    ctx: typer.Context,
    data: Optional[str] = typer.Option(None, "-d", help="Input string"),
    file: Optional[Path] = typer.Option(None, "-f", "--file", help="Input file path"),
    no_peel: bool = typer.Option(False, "--no-peel", help="Skip encoding peel loop"),
    json_out: bool = typer.Option(False, "--json", help="Output as JSON"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Verbose output"),
):
    if ctx.invoked_subcommand is not None:
        return
    _run_detect(data, file, no_peel, json_out, verbose)


@app.command(name="detect", help="Peel encoding layers and identify the underlying format.")
def detect_cmd(
    data: Optional[str] = typer.Option(None, "-d", help="Input string"),
    file: Optional[Path] = typer.Option(None, "-f", "--file", help="Input file path"),
    no_peel: bool = typer.Option(False, "--no-peel", help="Skip encoding peel loop"),
    json_out: bool = typer.Option(False, "--json", help="Output as JSON"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Verbose output"),
):
    _run_detect(data, file, no_peel, json_out, verbose)


def _load_input(
    data: Optional[str],
    file: Optional[Path],
) -> bytes:
    """Resolve a entrada: -d string, -f arquivo ou stdin."""
    if file is not None:
        if not file.exists():
            console.print(f"[red]File not found:[/red] {file}")
            raise typer.Exit(1)
        return file.read_bytes()
    if data is not None:
        return data.encode("utf-8")
    if not sys.stdin.isatty():
        return sys.stdin.buffer.read()
    console.print("[red]No Input.[/red] use -d STRING, -f FILE or pipe via stdin.")
    raise typer.Exit(1)


def _run_detect(
    data: Optional[str],
    file: Optional[Path],
    no_peel: bool,
    json_out: bool,
    verbose: bool,
):
    raw_input = _load_input(data, file)
    input_size = len(raw_input)

    # 1. descasca as camadas
    peel_engine = PeelEngine()
    if no_peel:
        peel_result = PeelResult(raw_data=raw_input, final_size=input_size)
    else:
        peel_result = peel_engine.peel(raw_input)

    # 2. identifica o formato
    identify_engine = IdentifyEngine()
    match_result = identify_engine.identify(peel_result.raw_data)

    # 3. monta a sugestao de generate
    suggestion = build_suggestion(match_result) if match_result else None

    report = AnalysisReport(
        peel_result=peel_result,
        match_result=match_result,
        suggestion=suggestion,
        input_size=input_size,
    )

    if json_out:
        _print_json(report)
    else:
        _print_human(report, verbose, raw_input)


def _print_human(report: AnalysisReport, verbose: bool = False, raw_input: bytes = b"") -> None:
    
    pr = report.peel_result
    m = report.match_result

    console.print()
    art_lines = FEATHER_ASCII.split('\n')
    bird_end = next(i for i, line in enumerate(art_lines) if 'N1ghtb1rd' in line) + 1
    bird = '\n'.join(art_lines[:bird_end])
    title = '\n'.join(art_lines[bird_end:])
    console.print(f"[bold white]{bird}[/bold white]")
    console.print(f"[bold white]\n{'.' * console.width}[/bold white]")
    console.print()

    # Dado original
    if report.input_size <= 160:
        input_preview = repr(raw_input[:160])[2:-1]
    else:
        input_preview = repr(raw_input[:120])[2:-1] + "..."
    console.print(f'[+] Input: {report.input_size} bytes -> "{input_preview}"')

    # Pipeline de decode
    console.print()
    console.print("[+] Encoding pipeline (outer -> inner):")
    if pr.is_raw:
        console.print("  (no encoding layers — raw data)")
    else:
        for i, step in enumerate(pr.pipeline, 1):
            ow = "  [red][one-way, stopped][/red]" if step.is_one_way else ""
            console.print(f"  {i}. [bold white]{step.encoder}[/bold white]  {step.size_before} -> {step.size_after} bytes{ow}")

    if pr.stopped_at_one_way:
        console.print("  [red]! Stopped: cryptographic hash (cannot decode)[/red]")
    elif pr.stopped_at_max_depth:
        console.print("  [red]! Stopped: max peel depth reached[/red]")

    # Resultado decodificado
    peeled_preview = repr(pr.raw_data[:120])[2:-1]
    console.print()
    console.print(f'[+] Peeled string: "{peeled_preview}"')
    console.print(f"[bold white]\n{'.' * console.width}\n[/bold white]")
    
    # Formato encontrado
    console.print()
    if m is None:
        console.print("Format Identification:")
        console.print("  [red]x - No Format Matched[/red]")
    else:
        panel_content = "Format Identified.\n"
        panel_content += f"  [bold white]{m.format_name}[/bold white]\n\n"
        panel_content += f"    Confidence: [bold white]{m.confidence}%[/bold white]\n"
        if m.magic_bytes:
            panel_content += f"    Magic: [bold white]{m.magic_bytes}[/bold white]\n"
        if m.class_names:
            panel_content += f"    Classes: [bold white]{', '.join(m.class_names[:3])}[/bold white]\n"
        if m.library_hints:
            panel_content += "    Libraries:"
            for lib in m.library_hints:
                panel_content += f" [bold white]{lib}[/bold white]\n"
        panel_content = panel_content.rstrip("\n")
        console.print(Panel(panel_content, border_style="white", padding=(0, 1)))

    # Sugestao de exploit
    console.print()
    console.print("[red]Generate Suggestion -- preview, not implemented yet:[/red]")
    if report.suggestion is None:
        if m is None:
            console.print("  [red](no format, no exploit to suggest)[/red]")
        else:
            console.print("  [red](no chain for this format yet)[/red]")
    else:
        s = report.suggestion
        console.print(f"  [bold white]?? {s.command}[/bold white]")
        console.print(f"    {s.rationale}")

    console.print()


def _print_json(report: AnalysisReport) -> None:
    """Relatório como JSON (pra pipe em outras ferramentas)."""
    pr = report.peel_result
    m = report.match_result
    s = report.suggestion

    out = {
        "input_size": report.input_size,
        "peel": {
            "pipeline": [
                {
                    "encoder": step.encoder,
                    "size_before": step.size_before,
                    "size_after": step.size_after,
                    "is_one_way": step.is_one_way,
                }
                for step in pr.pipeline
            ],
            "stopped_at_one_way": pr.stopped_at_one_way,
            "stopped_at_max_depth": pr.stopped_at_max_depth,
            "final_size": pr.final_size,
        },
        "identify": (
            {
                "format": m.format_name,
                "confidence": m.confidence,
                "magic_bytes": m.magic_bytes,
                "class_names": m.class_names,
                "library_hints": m.library_hints,
                "metadata": m.metadata,
            }
            if m else None
        ),
        "suggestion": (
            {
                "format": s.format,
                "chain": s.chain,
                "rationale": s.rationale,
                "command": s.command,
            }
            if s else None
        ),
    }
