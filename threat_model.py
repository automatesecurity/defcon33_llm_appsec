#!/usr/bin/env python3
"""
Threat Model + Architecture Report from FAISS vectors (Bedrock + .env, Windows friendly)

Requires:
  pip install python-dotenv langchain-community langchain-aws sentence-transformers faiss-cpu graphviz reportlab

Windows Graphviz:
  Download & install https://graphviz.org/download/
  Add 'C:\\Program Files\\Graphviz\\bin' to PATH, verify: dot -V
"""

import os
import json
import shutil
from pathlib import Path
import datetime as dt
from xml.sax.saxutils import escape

from dotenv import load_dotenv
from langchain_aws import BedrockEmbeddings, ChatBedrock
from langchain_community.vectorstores import FAISS
from graphviz import Source  # requires Graphviz "dot" binary installed
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle, PageBreak
)
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle

# ----------------------------
# .env
# ----------------------------
load_dotenv(dotenv_path=Path(__file__).with_name(".env"))

# ----------------------------
# CONFIG (env-first with defaults)
# ----------------------------
INDEX_DIR = os.getenv("FAISS_INDEX_DIR", "vector database")
BEDROCK_EMBED_MODEL = os.getenv("BEDROCK_EMBED_MODEL", "amazon.titan-embed-text-v2:0")
BEDROCK_CHAT_MODEL_ID = os.getenv("BEDROCK_CHAT_MODEL_ID", "us.anthropic.claude-3-5-haiku-20241022-v1:0")
TOP_K = int(os.getenv("TOP_K", "18"))
CHUNK_JOIN = "\n\n----\n\n"
OUT_DIR = Path(os.getenv("OUTPUT_DIR", "threat_output_bedrock"))
OUT_DIR.mkdir(parents=True, exist_ok=True)

ARCH_DOT_FILE = OUT_DIR / "architecture.dot"
ARCH_IMG_FILE = OUT_DIR / "architecture.png"
THREATS_JSON  = OUT_DIR / "threat_model.json"
PDF_FILE      = OUT_DIR / "Threat_Model_Report.pdf"

CHAT_KWARGS = {
    "temperature": float(os.getenv("CHAT_TEMPERATURE", "0.1")),
    "max_tokens": int(os.getenv("CHAT_MAX_TOKENS", "1800")),
}

# ----------------------------
# Prompts (use <<CONTEXT>> to avoid {.format} issues)
# ----------------------------
SYSTEM_PROMPT = (
    "You are a senior security architect. "
    "Using the provided repository excerpts, infer the system's architecture and data flows. "
    "When asked for a diagram, output STRICTLY a valid Graphviz DOT graph. "
    "When asked for a threat model, output STRICTLY valid JSON."
)

DIAGRAM_USER_PROMPT = """From the following repository excerpts, infer a high-level architecture and data flow.

Include nodes for:
- User/Client, Web/API layer, Services/Workers, Databases/Queues/Caches, External Providers.
Show edges with brief labels (e.g., HTTPS, gRPC, SQL).
If applicable, use trust boundaries as subgraphs.

Output ONLY a Graphviz DOT string for a left-to-right diagram using rankdir=LR.
Rules:
- Start with: digraph G { rankdir=LR;
- Concise node labels.
- Use subgraph cluster_* for trust boundaries (optional).
- No code fences, no explanations—DOT only.

Repository excerpts:
<<CONTEXT>>
"""

THREAT_USER_PROMPT = """Using the same repository excerpts, produce a STRIDE-style threat model.

Output ONLY valid JSON with this structure:
{
  "summary": "one-paragraph overview",
  "findings": [
    {
      "component": "string",
      "stride": ["Spoofing","Tampering","Repudiation","Information Disclosure","Denial of Service","Elevation of Privilege"],
      "risk": "low|medium|high",
      "evidence": "short quote(s) or file hints from context",
      "mitigations": [
        "actionable mitigation 1",
        "actionable mitigation 2"
      ]
    }
  ],
  "overall_risk": "low|medium|high"
}

Prefer evidence strings (file paths, code hints) from the context. If uncertain, say "insufficient evidence".
Return JSON only.

Repository excerpts:
<<CONTEXT>>
"""

# ----------------------------
# Helpers: system
# ----------------------------
def ensure_graphviz_installed() -> bool:
    """Check if 'dot' is on PATH; print Windows hint if missing."""
    if shutil.which("dot"):
        return True
    print(
        "[!] Graphviz 'dot' binary not found on PATH.\n"
        "    Download: https://graphviz.org/download/\n"
        "    Then add to PATH, e.g.: C:\\Program Files\\Graphviz\\bin"
    )
    return False

# ----------------------------
# Helpers: vector store
# ----------------------------
def load_faiss_with_bedrock(index_dir: str) -> FAISS:
    idx = Path(index_dir)
    if not (idx / "index.faiss").exists() or not (idx / "index.pkl").exists():
        raise FileNotFoundError(
            f"FAISS index not found in '{index_dir}'. Expect index.faiss and index.pkl."
        )
    embeddings = BedrockEmbeddings(model_id=BEDROCK_EMBED_MODEL)
    return FAISS.load_local(index_dir, embeddings, allow_dangerous_deserialization=True)

def retrieve_context(vs: FAISS, queries, top_k_each: int) -> str:
    hits_all = []
    for q in queries:
        hits_all.extend(vs.similarity_search(q, k=top_k_each))
    # dedupe by (path, chunk)
    seen, merged = set(), []
    for h in hits_all:
        key = (h.metadata.get("path"), h.metadata.get("chunk"))
        if key in seen:
            continue
        seen.add(key)
        tail = f"  [file: {h.metadata.get('path','?')}, chunk: {h.metadata.get('chunk','?')}]"
        merged.append((h.page_content.strip()[:3000] + "\n" + tail).strip())
    return CHUNK_JOIN.join(merged[:TOP_K])

# ----------------------------
# Helpers: Bedrock LLM
# ----------------------------
def bedrock_chat() -> ChatBedrock:
    """Return a ChatBedrock instance for Anthropic Claude via Bedrock."""
    return ChatBedrock(model_id=BEDROCK_CHAT_MODEL_ID, model_kwargs=CHAT_KWARGS)

def llm_generate(llm: ChatBedrock, system_prompt: str, user_prompt: str) -> str:
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user",   "content": user_prompt},
    ]
    resp = llm.invoke(messages)
    return getattr(resp, "content", str(resp)).strip()

# ----------------------------
# Helpers: DOT sanitize/validate/render
# ----------------------------
def sanitize_dot(dot_text: str) -> str:
    """Strip fences/language tags; slice from first 'digraph'; wrap fallback."""
    s = (dot_text or "").strip().replace("\r", "")
    # remove triple backticks if present
    if s.startswith("```"):
        s = s.strip("`")
    # remove leading language hint line like 'dot' or 'graphviz'
    first_nl = s.find("\n")
    first_line = s if first_nl == -1 else s[:first_nl]
    if first_line.lower().strip() in {"dot", "graphviz"}:
        s = s[first_nl+1:] if first_nl != -1 else ""
    # slice from 'digraph'
    idx = s.find("digraph")
    if idx != -1:
        s = s[idx:].lstrip()
    s = s.strip().strip("`").strip()
    if not s.startswith("digraph"):
        s = f"digraph G {{ rankdir=LR; {s} }}"
    return s

def validate_dot(dot_str: str) -> str:
    """Light checks: ensure startswith digraph, attempt to balance braces."""
    s = dot_str.strip()
    if not s.startswith("digraph"):
        s = f"digraph G {{ rankdir=LR; {s} }}"
    # balance braces
    open_braces = s.count("{")
    close_braces = s.count("}")
    if open_braces > close_braces:
        s += "}" * (open_braces - close_braces)
    elif close_braces > open_braces:
        # humbly attempt to wrap
        s = "digraph G { rankdir=LR; " + s + " }"
    return s

def render_dot_to_png(dot_str: str, png_path: Path, dot_path: Path):
    cleaned = validate_dot(sanitize_dot(dot_str))
    dot_path.write_text(cleaned, encoding="utf-8")
    src = Source(cleaned)
    base = str(png_path.with_suffix(""))
    src.format = "png"
    src.render(base, cleanup=True)
    gen_png = Path(base + ".png")
    if gen_png != png_path:
        gen_png.replace(png_path)

# ----------------------------
# Helpers: PDF build
# ----------------------------
BODY_STYLE = ParagraphStyle("body", fontName="Helvetica", fontSize=11, leading=15)
TITLE_STYLE = ParagraphStyle("title", fontName="Helvetica-Bold", fontSize=18, spaceAfter=12)
META_STYLE  = ParagraphStyle("meta", fontName="Helvetica-Oblique", fontSize=9, textColor=colors.gray, spaceAfter=8)
H2_STYLE    = ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=14, spaceBefore=12, spaceAfter=6)

def ensure_text(x) -> str:
    """Coerce any value to safe string for PDF/table."""
    if x is None:
        return ""
    if isinstance(x, (list, dict)):
        try:
            return json.dumps(x, ensure_ascii=False)
        except Exception:
            return str(x)
    return str(x)

def P(text: str, style=BODY_STYLE) -> Paragraph:
    return Paragraph(escape(text).replace("\n", "<br/>"), style)

def build_pdf(context_excerpt: str, png_path: Path, threats: dict, pdf_path: Path):
    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=LETTER,
        leftMargin=0.8*inch, rightMargin=0.8*inch,
        topMargin=0.8*inch, bottomMargin=0.8*inch
    )
    story = []

    now_utc = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    story.append(P("Threat Model & Architecture Report (Bedrock)", TITLE_STYLE))
    story.append(P(f"Generated: {now_utc}", META_STYLE))
    story.append(P("Source: FAISS vectors + Amazon Bedrock (Claude).", META_STYLE))

    story.append(P("Context Excerpts (vector search)", H2_STYLE))
    story.append(P(context_excerpt[:2000], BODY_STYLE))
    story.append(Spacer(1, 10))

    story.append(P("Architecture Diagram", H2_STYLE))
    if png_path.exists():
        img = Image(str(png_path))
        img._restrictSize(6.5*inch, 7.5*inch)
        story.append(img)
    else:
        story.append(P("Diagram image not available (Graphviz not found or render error).", BODY_STYLE))

    story.append(PageBreak())
    story.append(P("STRIDE Threat Model", H2_STYLE))

    if isinstance(threats, dict):
        summary = ensure_text(threats.get("summary", ""))
        overall = ensure_text(threats.get("overall_risk", "unknown"))
        story.append(P(f"Overall Risk: {overall}", BODY_STYLE))
        if summary:
            story.append(P(summary, BODY_STYLE))
            story.append(Spacer(1, 6))

        # Table header as Paragraphs
        rows = [
            [P("Component"), P("STRIDE"), P("Risk"), P("Evidence"), P("Mitigations")]
        ]
        for f in threats.get("findings", []):
            comp = ensure_text(f.get("component", ""))
            stride = f.get("stride", [])
            stride_txt = ", ".join([ensure_text(s) for s in stride]) if isinstance(stride, list) else ensure_text(stride)
            risk = ensure_text(f.get("risk", ""))

            evidence = f.get("evidence", "")
            if isinstance(evidence, list):
                evidence_txt = "; ".join([ensure_text(e) for e in evidence])
            else:
                evidence_txt = ensure_text(evidence)
            evidence_txt = evidence_txt[:500]

            mitigations = f.get("mitigations", [])
            if isinstance(mitigations, list):
                mitigations_txt = "• " + "\n• ".join([ensure_text(m) for m in mitigations[:6]]) if mitigations else ""
            else:
                mitigations_txt = ensure_text(mitigations)

            rows.append([P(comp), P(stride_txt), P(risk), P(evidence_txt), P(mitigations_txt)])

        tbl = Table(rows, repeatRows=1, colWidths=[1.4*inch, 1.6*inch, 0.8*inch, 2.1*inch, 2.1*inch])
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.black),
            ("TEXTCOLOR", (0,0), (-1,0), colors.white),
            ("FONTNAME",  (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",  (0,0), (-1,0), 10),
            ("ALIGN",     (0,0), (-1,0), "CENTER"),
            ("GRID",      (0,0), (-1,-1), 0.25, colors.grey),
            ("VALIGN",    (0,0), (-1,-1), "TOP"),
        ]))
        story.append(tbl)
    else:
        story.append(P("Threat model JSON parse error.", BODY_STYLE))

    # write file, with fallback if locked
    try:
        doc.build(story)
    except PermissionError:
        ts = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d_%H%M%S")
        alt = pdf_path.with_name(f"{pdf_path.stem}_{ts}{pdf_path.suffix}")
        SimpleDocTemplate(
            str(alt),
            pagesize=LETTER,
            leftMargin=0.8*inch, rightMargin=0.8*inch,
            topMargin=0.8*inch, bottomMargin=0.8*inch
        ).build(story)
        print(f"[warn] '{pdf_path.name}' is locked. Saved as '{alt.name}' instead.")

# ----------------------------
# Main
# ----------------------------
def main():
    has_gv = ensure_graphviz_installed()

    print("[1/5] Loading FAISS index …")
    vs = load_faiss_with_bedrock(INDEX_DIR)

    print("[2/5] Retrieving context …")
    queries = [
        "overall architecture components entrypoints web server api",
        "databases storage cache queues credentials config",
        "authentication authorization session tokens oauth",
        "external integrations services third-party endpoints",
        "message flow request flow data flow diagram",
        "deployment topology environment and trust boundaries"
    ]
    top_k_each = max(3, TOP_K // len(queries))
    context = retrieve_context(vs, queries, top_k_each)

    print("[3/5] Calling Bedrock (Claude) …")
    llm = bedrock_chat()

    print("[4/5] Generating DOT and rendering …")
    diagram_prompt = DIAGRAM_USER_PROMPT.replace("<<CONTEXT>>", context)
    raw_dot = llm_generate(llm, SYSTEM_PROMPT, diagram_prompt)
    try:
        render_dot_to_png(raw_dot, ARCH_IMG_FILE, ARCH_DOT_FILE)
        print(f"    DOT saved -> {ARCH_DOT_FILE}")
        print(f"    PNG saved -> {ARCH_IMG_FILE}")
    except Exception as e:
        # Save raw/sanitized DOT for debugging even if render fails
        safe = validate_dot(sanitize_dot(raw_dot))
        ARCH_DOT_FILE.write_text(safe, encoding="utf-8")
        print(f"[warn] Graphviz render failed: {e}\n       DOT written to {ARCH_DOT_FILE}")

    print("[5/5] Generating STRIDE threat model …")
    threat_prompt = THREAT_USER_PROMPT.replace("<<CONTEXT>>", context)
    threats_raw = llm_generate(llm, SYSTEM_PROMPT, threat_prompt)
    try:
        threats = json.loads(threats_raw)
    except json.JSONDecodeError:
        threats = json.loads(threats_raw.strip("` \n"))
    THREATS_JSON.write_text(json.dumps(threats, indent=2), encoding="utf-8")
    print(f"    Threat JSON saved -> {THREATS_JSON}")

    print("[final] Building PDF report …")
    excerpt = "\n\n".join(context.split(CHUNK_JOIN)[:4])
    build_pdf(excerpt, ARCH_IMG_FILE, threats, PDF_FILE)
    print(f"    PDF saved -> {PDF_FILE}")
    print("Done.")

if __name__ == "__main__":
    main()
