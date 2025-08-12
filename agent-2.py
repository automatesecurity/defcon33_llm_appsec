import os
import git
import asyncio
from dotenv import load_dotenv

# —— Added imports for vectorization ——
from pathlib import Path
from langchain_aws import BedrockEmbeddings
from langchain_community.vectorstores import FAISS
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.schema import Document

# —— Existing imports ——
from langchain_aws import ChatBedrock
from langchain.agents import create_react_agent, AgentExecutor
from langchain_core.prompts import PromptTemplate
from langchain.tools import Tool
from langchain import hub
from call_graph_analyzer import create_call_graph_tool
from sast_analyzer import create_sast_agent_executor


# =========================
# FAISS indexing utilities
# =========================

EXT_ALLOW = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".kt", ".go", ".rb", ".php",
    ".rs", ".c", ".h", ".cpp", ".hpp", ".cs", ".scala", ".swift", ".m", ".mm",
    ".gradle", ".sh", ".bash", ".zsh", ".ps1",
    ".md", ".rst", ".txt", ".json", ".yml", ".yaml", ".toml", ".ini", ".cfg",
    ".conf", ".env.example"
}

SKIP_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", ".venv", "venv", "dist", "build",
    "node_modules", ".next", ".cache", "target", ".idea", ".vscode"
}

def _should_skip_dir(dirname: str) -> bool:
    name = os.path.basename(dirname)
    return name in SKIP_DIRS or name.startswith(".")

def _collect_files(root: Path, max_file_mb: float = 2.5):
    """Yield file Paths under root that match extensions and size limits."""
    for dirpath, dirnames, filenames in os.walk(root):
        # prune directories in-place
        dirnames[:] = [d for d in dirnames if not _should_skip_dir(os.path.join(dirpath, d))]
        for fname in filenames:
            p = Path(dirpath) / fname
            if p.suffix.lower() in EXT_ALLOW:
                try:
                    if p.stat().st_size <= max_file_mb * 1024 * 1024:
                        yield p
                except Exception:
                    continue

def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""

def build_faiss_index_with_bedrock(
    repo_path: str,
    index_dir: str = "vector database",
    chunk_size: int = 1200,
    chunk_overlap: int = 200,
    bedrock_embed_model: str = "amazon.titan-embed-text-v2:0",
):
    """
    Build a FAISS index from source code & docs in repo_path and save to `index_dir`.
    Uses Bedrock Titan embeddings via langchain_aws.BedrockEmbeddings.
    """
    repo_root = Path(repo_path)
    files = list(_collect_files(repo_root))
    if not files:
        print("[FAISS] No eligible files found to index.")
        return

    print(f"[FAISS] Found {len(files)} files to index under {repo_root.resolve()}")

    splitter = RecursiveCharacterTextSplitter(chunk_size=chunk_size, chunk_overlap=chunk_overlap)
    docs = []

    for i, fp in enumerate(files, 1):
        content = _read_text(fp)
        if not content.strip():
            continue
        chunks = splitter.split_text(content)
        for c_idx, chunk in enumerate(chunks):
            docs.append(
                Document(
                    page_content=chunk,
                    metadata={"path": str(fp.resolve()), "file": fp.name, "chunk": c_idx}
                )
            )
        if i % 50 == 0:
            print(f"[FAISS] Processed {i}/{len(files)} files…")

    if not docs:
        print("[FAISS] No text chunks to index.")
        return

    print(f"[FAISS] Initializing Bedrock embeddings: {bedrock_embed_model}")
    embeddings = BedrockEmbeddings(model_id=bedrock_embed_model)

    print("[FAISS] Creating FAISS index…")
    vs = FAISS.from_documents(docs, embeddings)

    out_dir = Path(index_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    vs.save_local(str(out_dir))  # persists index and index.pkl

    print(f"[FAISS] ✓ Saved FAISS index to: {out_dir.resolve()}")
    print(f"[FAISS]   Total chunks indexed: {len(docs)}")


# =========================
# Main workflow
# =========================
async def main():
    # Load environment variables (AWS creds/region for Bedrock, etc.)
    load_dotenv()

    # Clone repository
    repo_url = "https://github.com/digininja/DVWA.git"
    repo_path = "./repo"

    if os.path.isdir(repo_path) and os.path.isdir(os.path.join(repo_path, ".git")):
        print("Directory already contains a git repository.")
    else:
        try:
            repo = git.Repo.clone_from(repo_url, repo_path)
            print(f"Repository cloned into: {repo_path}")
        except Exception as e:
            print(f"An error occurred while cloning the repository: {e}")

    # —— NEW: Build FAISS vector DB for the repo ——
    print("\n[Step 0] Building FAISS vector database from source code…")
    build_faiss_index_with_bedrock(
        repo_path=repo_path,
        index_dir="vector database",                    # as requested
        chunk_size=1200,
        chunk_overlap=200,
        bedrock_embed_model="amazon.titan-embed-text-v2:0"
    )

    # Initialize ChatBedrock (keep your existing model)
    llm = ChatBedrock(
        model_id="us.anthropic.claude-3-5-haiku-20241022-v1:0",
        model_kwargs={"temperature": 0.2, "max_tokens": 4096}
    )

    # Create call graph analysis tool
    call_graph_func = create_call_graph_tool(repo_path)

    # Create SAST agent executor
    sast_agent_executor, sast_analyzer = create_sast_agent_executor(repo_path, llm)

    print("\nAI Agent initialized!")
    print("Starting analysis workflow...")

    # Step 1: Build call graph
    print("\n1. Building call graph...")
    call_graph_result = call_graph_func("build")
    print(f"Call graph result: {call_graph_result}")

    # Step 2: Get call graph JSON for context
    call_graph_json = call_graph_func("json")
    print(f"Call graph generated with {len(call_graph_json)} characters of data")

    # Step 3: Run SAST analysis
    print("\n2. Starting async SAST analysis...")
    sast_summary = await sast_analyzer.run_full_analysis()  # noqa: F841 (kept for side-effects/logs)
    sast_result = {'output': sast_analyzer.get_findings_summary()}

    print("\n3. Analysis complete!")
    print("=" * 50)
    print("SAST ANALYSIS RESULTS:")
    print("=" * 50)
    print(sast_result['output'])

    # Step 4: Get detailed summary
    print("\n" + "=" * 50)
    print("DETAILED FINDINGS SUMMARY:")
    print("=" * 50)
    summary_result = {'output': sast_analyzer.get_findings_summary()}
    print(summary_result['output'])


if __name__ == "__main__":
    asyncio.run(main())
