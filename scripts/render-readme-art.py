#!/usr/bin/env python3
"""Render the README hero animation as light and dark SVGs.

The numbers come from the v0.6.0 live release gate on an RTX 3060: the
multisource request/launch/kernel graph. Rerun after changing the story:

    scripts/render-readme-art.py docs/assets
"""

import pathlib
import sys
from html import escape

WIDTH, HEIGHT = 960, 540
CYCLE_S = 14.0
FONT = "ui-monospace, SFMono-Regular, Menlo, Consolas, 'Liberation Mono', monospace"
SANS = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif"

THEMES = {
    "light": {
        "bg": "#ffffff",
        "panel": "#f6f8fa",
        "border": "#d0d7de",
        "text": "#1f2328",
        "muted": "#59636e",
        "prompt": "#0969da",
        "cpu": "#8250df",
        "gpu": "#1a7f37",
        "env": "#9a6700",
    },
    "dark": {
        "bg": "#0d1117",
        "panel": "#161b22",
        "border": "#30363d",
        "text": "#e6edf3",
        "muted": "#8d96a0",
        "prompt": "#4493f8",
        "cpu": "#ab7df8",
        "gpu": "#3fb950",
        "env": "#d29922",
    },
}

# (start, end) as fractions of the cycle for each stage.
STAGES = {
    "cmd1": (0.02, 0.10),
    "find1": (0.12, 0.16),
    "find2": (0.16, 0.20),
    "find3": (0.20, 0.24),
    "next": (0.27, 0.31),
    "cmd2": (0.34, 0.42),
    "lanes": (0.44, 0.48),
    "edge1": (0.50, 0.55),
    "edge2": (0.56, 0.61),
    "edge3": (0.62, 0.67),
    "tagline": (0.72, 0.77),
}
HOLD_UNTIL = 0.93


def keyframes(name: str, start: float, end: float, kind: str) -> str:
    """Hidden until start, shown from end to the loop's end.

    The whole scene fades out and back in around the loop boundary, so
    individual elements never need their own exit frames.
    """
    s, e = (round(v * 100, 2) for v in (start, end))
    if kind == "type":
        hidden, shown = "transform: scaleX(1)", "transform: scaleX(0)"
    else:
        hidden = "opacity: 0; transform: translateY(6px)"
        shown = "opacity: 1; transform: translateY(0)"
    return f"@keyframes {name} {{ 0%, {s}% {{ {hidden} }} {e}%, 100% {{ {shown} }} }}"


def scene_keyframes() -> str:
    h = round(HOLD_UNTIL * 100, 2)
    return (
        f"@keyframes scene {{ 0% {{ opacity: 0 }} 1.5%, {h}% {{ opacity: 1 }} "
        f"99%, 100% {{ opacity: 0 }} }}"
    )


def style(theme: dict) -> str:
    rules = [
        f".mono {{ font-family: {FONT}; }}",
        f".sans {{ font-family: {SANS}; }}",
        ".anim { transform-box: fill-box; }",
        scene_keyframes(),
        f".scene {{ animation: scene {CYCLE_S}s linear infinite; }}",
    ]
    for name, (start, end) in STAGES.items():
        kind = "type" if name.startswith("cmd") else "fade"
        rules.append(keyframes(f"k-{name}", start, end, kind))
        rules.append(
            f".{name} {{ animation: k-{name} {CYCLE_S}s ease-out infinite; "
            f"{'transform-origin: right center;' if kind == 'type' else ''} }}"
        )
    rules.append(
        "@media (prefers-reduced-motion: reduce) { * { animation: none !important; } "
        ".cover { display: none; } }"
    )
    return "\n".join(rules)


def text(x, y, content, size, fill, cls="mono", weight="400", anchor="start") -> str:
    return (
        f'<text x="{x}" y="{y}" class="{cls}" font-size="{size}" fill="{fill}" '
        f'font-weight="{weight}" text-anchor="{anchor}">{escape(content)}</text>'
    )


def command(y: int, line: str, stage: str, t: dict) -> str:
    """A typed command: the text is revealed by a cover that shrinks away."""
    width = 22 + len(line) * 8.4
    return (
        f'<g>{text(48, y, "$", 15, t["prompt"], weight="700")}'
        f'{text(66, y, line, 15, t["text"])}'
        f'<rect class="anim cover {stage}" x="64" y="{y - 16}" width="{width:.0f}" '
        f'height="22" fill="{t["panel"]}"/></g>'
    )


def edge_row(y: int, rank: int, name: str, detail: str, value: str,
             color: str, stage: str, t: dict) -> str:
    """One measured edge: its name, how it was paired, and its latency."""
    return (
        f'<g class="anim {stage}">'
        + text(48, y, f"{rank}", 14, t["muted"])
        + text(70, y, name, 14, color, weight="700")
        + text(70, y + 19, detail, 12.5, t["muted"])
        + text(880, y, value, 14, t["text"], weight="700", anchor="end")
        + "</g>"
    )


def timeline(t: dict) -> str:
    lane_x0, lane_x1 = 150, 900
    cpu_y, gpu_y = 362, 440
    req, launch, kstart, kend = 190, 560, 690, 760
    parts = [
        '<g class="anim lanes">',
        text(48, cpu_y + 5, "CPU", 13, t["cpu"], weight="700"),
        text(48, gpu_y + 5, "GPU", 13, t["gpu"], weight="700"),
        f'<line x1="{lane_x0}" y1="{cpu_y}" x2="{lane_x1}" y2="{cpu_y}" stroke="{t["border"]}" stroke-width="2"/>',
        f'<line x1="{lane_x0}" y1="{gpu_y}" x2="{lane_x1}" y2="{gpu_y}" stroke="{t["border"]}" stroke-width="2"/>',
        f'<circle cx="{req}" cy="{cpu_y}" r="6" fill="{t["cpu"]}"/>',
        text(req, cpu_y - 14, "request", 12, t["muted"], anchor="middle"),
        f'<circle cx="{launch}" cy="{cpu_y}" r="6" fill="{t["cpu"]}"/>',
        text(launch, cpu_y - 14, "cudaLaunchKernel returns", 12, t["muted"], anchor="middle"),
        f'<rect x="{kstart}" y="{gpu_y - 9}" width="{kend - kstart}" height="18" rx="4" fill="{t["gpu"]}"/>',
        text((kstart + kend) / 2, gpu_y + 28, "kernel", 12, t["muted"], anchor="middle"),
        "</g>",
        '<g class="anim edge1">',
        f'<path d="M{req + 8} {cpu_y + 2} L{launch - 8} {cpu_y + 2}" stroke="{t["cpu"]}" stroke-width="3"/>',
        text((req + launch) / 2, cpu_y + 22, "request → launch  1.14 ms  (first-after)", 13, t["text"], anchor="middle"),
        "</g>",
        '<g class="anim edge2">',
        f'<path d="M{launch} {cpu_y + 7} C{launch} {gpu_y - 20}, {kstart} {cpu_y + 20}, {kstart} {gpu_y - 10}" '
        f'fill="none" stroke="{t["prompt"]}" stroke-width="3" stroke-dasharray="6 5"/>',
        text(launch - 10, (cpu_y + gpu_y) / 2 + 8, "launch → kernel  99 µs  (exact)", 13, t["text"], anchor="end"),
        "</g>",
        '<g class="anim edge3">',
        text(kend + 12, gpu_y + 5, "kernel  1.2 µs  (exact)", 13, t["text"]),
        "</g>",
    ]
    return "".join(parts)


def render(theme_name: str, animated: bool = True) -> str:
    t = THEMES[theme_name]
    body = [
        f'<rect width="{WIDTH}" height="{HEIGHT}" rx="14" fill="{t["bg"]}"/>',
        f'<rect x="20" y="20" width="{WIDTH - 40}" height="{HEIGHT - 40}" rx="12" '
        f'fill="{t["panel"]}" stroke="{t["border"]}"/>',
        '<circle cx="44" cy="42" r="5" fill="#ff5f57"/><circle cx="62" cy="42" r="5" fill="#febc2e"/>'
        '<circle cx="80" cy="42" r="5" fill="#28c840"/>',
        text(WIDTH / 2, 47, "Where does a request's time go in PID 4242?", 14, t["muted"], cls="sans", anchor="middle"),
        '<g class="scene">',
        command(90, "xprobe measure --pid 4242 --spec request-graph.json", "cmd1", t),
        edge_row(130, 1, "request_to_launch", "first-after · request → cudaLaunchKernel returns", "1.14 ms", t["cpu"], "find1", t),
        edge_row(174, 2, "launch_to_kernel", "exact · same CUPTI correlation ID", "99 µs", t["prompt"], "find2", t),
        edge_row(218, 3, "kernel", "exact · kernel start → end", "1.2 µs", t["gpu"], "find3", t),
        f'<g class="anim next">{text(48, 262, "→ every raw event is kept for your agent to analyze offline", 13, t["prompt"])}</g>',
        command(304, "scripts/analyze_trace.py events.jsonl", "cmd2", t),
        timeline(t),
        f'<g class="anim tagline">'
        f'{text(WIDTH / 2, 494, "Bounded capture. Strict JSON. No daemon. Evidence your agent can analyze.", 15, t["text"], cls="sans", weight="600", anchor="middle")}'
        "</g>",
        "</g>",
    ]
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {WIDTH} {HEIGHT}" '
        f'width="{WIDTH}" height="{HEIGHT}" role="img" '
        'aria-labelledby="title desc">'
        "<title id=\"title\">xprobe: measure a request's latency path from one capture</title>"
        "<desc id=\"desc\">A terminal runs one xprobe measurement graph on a CUDA process. "
        "It reports request to launch 1.14 ms, launch to kernel 99 microseconds, and kernel "
        "duration 1.2 microseconds, shown on CPU and GPU timelines; the raw events are kept "
        "for offline analysis.</desc>"
        + (f"<style>{style(t)}</style>" if animated else
           f"<style>.mono {{ font-family: {FONT}; }} .sans {{ font-family: {SANS}; }} .cover {{ display: none; }}</style>")
        + "".join(body)
        + "</svg>\n"
    )


def social_card() -> str:
    """A 1280x640 repository social preview built from the final frame."""
    t = THEMES["dark"]
    flow = render("dark", animated=False).split(">", 1)[1].rsplit("</svg>", 1)[0]
    flow = flow.replace('<rect width="960" height="540" rx="14"', '<rect width="960" height="540" rx="14" opacity="0"', 1)
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1280 640" width="1280" height="640">'
        f'<rect width="1280" height="640" fill="{t["bg"]}"/>'
        f'<style>.mono {{ font-family: {FONT}; }} .sans {{ font-family: {SANS}; }} .cover {{ display: none; }}</style>'
        + text(64, 96, "xprobe", 56, t["text"], cls="sans", weight="700")
        + text(64, 140, "Bounded latency evidence from CPU, Python, and CUDA processes.", 26, t["muted"], cls="sans")
        + f'<g transform="translate(232 168) scale(0.86)">{flow}</g>'
        + "</svg>\n"
    )


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: render-readme-art.py <output-directory>")
    output = pathlib.Path(sys.argv[1])
    output.mkdir(parents=True, exist_ok=True)
    for theme in THEMES:
        (output / f"xprobe-flow-{theme}.svg").write_text(render(theme))
    (output / "social-preview.svg").write_text(social_card())


if __name__ == "__main__":
    main()
