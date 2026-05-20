# AVAGuard AI — Things to Keep in Mind

> Read this before every work session. These are the non-obvious constraints, architectural decisions, and gotchas discovered during planning. Update it whenever something new is discovered or a decision is made.

---

## Locked decisions (don't re-debate these without a team discussion)

**1. RAG, not pure fine-tuning.**
The AI layer is built on retrieval-augmented generation. Fine-tuning (`ll0fintuning-main`) is not the primary approach. Compliance documents change regularly — retraining is expensive, slow, and bad at retaining precise factual knowledge. RAG lets us update knowledge by editing a text file. Fine-tuning may be revisited only for teaching a specific *output format* (e.g. always return JSON with severity + remediation + citation) — never for injecting compliance knowledge.

**2. CIS content must come from official PDFs, never AI-generated.**
For CIS benchmark corpus files, always use `CIS_automationv2` to extract from official CIS PDFs. Do not generate CIS content with DeepSeek or any LLM. AVAGuard must cite the literal benchmark text. Zero hallucination risk on critical compliance rules is non-negotiable.

**3. DeepSeek for AI-generated corpus, not OpenAI.**
Cost: DeepSeek is ~$1.30–$2.00 for 1,000 files. Use OpenAI only if DeepSeek quality proves insufficient after the 100-file review batch.

**4. FastAPI microservice as the integration layer.**
The RAG pipeline exposes a FastAPI service. All three AVAGuard interfaces (CLI, desktop, web portal) call it via HTTP. This lets the AI layer scale and update independently without touching the scanner core.

**5. Do not build the DeepSeek automation script until Step 0 analysis is done.**
The script location, naming convention, and output directory all depend on what already exists in `rag-train` and `ll0fintuning-main`. Building before analyzing guarantees wasted work.

---

## The two subprojects are related — understand both before using either

`rag-train` is the original pipeline created by the person doing corpus training. `ll0fintuning-main` is a refined version of it. They are not independent projects — one likely has improvements the other is missing. **Antigravity must read both and produce a merge recommendation before any new code is written.** Running two separate pipelines in parallel is a maintenance problem.

**The key questions to answer:**
- Does `ll0fintuning-main` still use corpus-based retrieval, or has it diverged to pure fine-tuning?
- What exactly is "refined" — chunking? embedding? output format? something else?
- Which one becomes the single canonical pipeline?

---

## `CIS_automationv2` — analyze before planning anything around it

Two PDFs have been processed. But before writing any post-processing script or planning the CIS corpus pipeline, Antigravity must know:

- Exactly what format the current output is in
- How the PDF is currently being split (by page? by heading? by control ID?)
- Whether adding `--output-corpus-format` is a small addition or a significant rewrite

Do not assume the current output is close to corpus-ready. It may need substantial post-processing.

---

## Corpus file rules (strict)

- Every file must be **700–1,000 words**. Not 200, not 2,000.
- Every file must be **self-contained and independently answerable**. A file that only makes sense if you've read another file first is useless for retrieval.
- **Naming:** `[domain]_[section-number]_[short-topic].md` — all lowercase, underscores only, max 60 chars. No dashes, no spaces, no special characters.
- **Split large topics** into numbered sub-files. Don't trim content to hit the word limit — the cut information will be missed at retrieval time.
- No marketing language. No filler. Every sentence must be useful to a security engineer.
- All files go in the correct domain subfolder inside `[canonical-pipeline]/corpus/`.
- If `rag-train` already uses a different naming convention, **match it**. Don't introduce a second standard.

---

## Embedding model constraints

- Use `BAAI/bge-small-en` or `sentence-transformers/all-MiniLM-L6-v2` for local/dev. Both run on CPU, no GPU required.
- Do not use OpenAI embeddings in local dev — costs money and requires internet.
- For production: `BAAI/bge-large-en` or `text-embedding-3-small` (OpenAI) are better options.
- **Critical:** The embedding model must match between indexing time and query time. If you ever switch models, you must rebuild the entire index from scratch. Document which model was used to build each index.

---

## Vector database gotchas

- **FAISS:** Local only, no server needed. Simple, fast. Incremental updates require a full rebuild for clean results — for development this is fine.
- **ChromaDB:** Local with optional server mode. Easy to set up for team development.
- **Pinecone:** Cloud-managed, paid. Supports true incremental upserts, scales to millions of vectors. Use for production.
- Always save the index to disk after every build. Never rely on in-memory state between restarts.
- Store the embedding model name alongside the index so you always know which model built it.

---

## LLM for generation (the final step after retrieval)

- **Development:** Local Llama 3.2 (3B or 8B) via Ollama. Free, fully offline.
- **Production:** DeepSeek API (cheap) or OpenAI GPT-4o-mini (more consistent structured output).
- The LLM only does generation — it receives retrieved corpus chunks + the vulnerability description. It does not need to know compliance rules from memory. The corpus provides them.
- Always include the system prompt in every LLM call:
  ```
  You are AVAGuard AI, a security and compliance assistant.
  Answer only based on the provided context documents.
  Always cite which document your recommendations come from.
  If the context does not contain enough information to answer, say so explicitly — do not guess.
  ```

---

## AVAGuard interface integration notes

- `avaguard-core` is the source of truth for vulnerability findings. The RAG layer is downstream — it never modifies scan logic or findings.
- Use `mock_data/` to test the full RAG query-to-response flow before connecting to real scans.
- `avaguard-cli`: The RAG call must fail gracefully. If the endpoint is unavailable, print "AI context unavailable" and continue — don't block the scan output.
- `avaguard-webportal`: The RAG call must be async. Don't make the page wait for LLM generation before rendering.
- `avaguard-desktop`: Same as web portal — async, render in a side panel.

---

## What goes in `.gitignore` (don't commit these)

- Large model checkpoints or LoRA adapter files
- Vector index files (`avaguard_rag_index/`, `*.faiss`, `*.pkl`)
- `.env` files with API keys
- `corpus_generation_log.csv` and `corpus_generation_errors.log` (generated artifacts)
- Any `__pycache__/` or `.venv/` folders

---

## Corpus update cycle

When a compliance standard updates (SOC2 annual changes, new CIS benchmark version, AWS policy changes):
1. Identify which corpus files are affected
2. Regenerate or manually edit those files
3. Re-run the indexing pipeline (or do an incremental upsert if using Pinecone/ChromaDB)
4. No LLM retraining needed — this is the whole point of RAG

Keep a `corpus_changelog.md` inside the corpus folder noting which files were updated, when, and why.

---

## Things still unknown — Antigravity must resolve these in Step 0

| Unknown | How to resolve |
|---|---|
| Whether `ll0fintuning-main` is still RAG-based or diverged to fine-tuning | Read the codebase in 0B |
| What exactly `ll0fintuning-main` refines over `rag-train` | Read and compare both in 0A/0B |
| Which pipeline becomes canonical | Merge recommendation after 0A/0B |
| Current output format of `CIS_automationv2` | Read and run it in 0C |
| Whether `--output-corpus-format` flag is feasible or needs a rewrite | Read `CIS_automationv2` code in 0C |
| Exact fields available from `avaguard-core` at detection time | Read core code in 0D |
| Whether `avaguard-webportal` is React, Next.js, or something else | Check during 0D |
| Final production LLM (DeepSeek vs OpenAI) | Decide after testing generation quality |
| Whether to publish the RAG service as a standalone microservice eventually | Future decision |

- **Corpus Format:** Corpus files are .txt not .md � this is locked, do not change.
- **Corpus Resiliency:** generate_corpus.py uses checkpoint logic via corpus_generation_log.csv � always restart from same directory if interrupted.
- **Cost Projection:** Token cost projection is ~.35 for 10,000 files at current DeepSeek rates.
- **Progress Tool:** corpus_status.py is at ag-train/tools/ � run it anytime to check progress.
