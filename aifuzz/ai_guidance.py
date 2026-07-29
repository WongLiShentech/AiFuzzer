"""AI guidance — generate fuzzing properties and seed inputs from contract source.

This is the project's novelty: instead of purely random transaction generation,
a local LLM (Ollama) — informed by a RAG knowledge base of vulnerability
patterns and best practices (ChromaDB) — proposes (a) Echidna invariants/
properties to check and (b) seed transaction sequences likely to reach
vulnerable states. Goal: beat random fuzzing on coverage and bugs found.

Everything runs locally / air-gapped (no hosted API): reproducible, no API cost,
no contract source leaves the machine. ChromaDB is an EMBEDDED on-disk store
(no server, no cloud) that lives next to the aifuzz process; embeddings come
from a local Ollama model. Both stages are implemented here: retrieval
(KnowledgeBase) and generation (PropertyGenerator).
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from .config import settings

# Chroma / Ollama are optional (the `ai` extra). Import lazily so the tool and
# tests still run without them installed; retrieval degrades to empty.
try:
    import chromadb
    import ollama

    _AI_DEPS = True
except ImportError:  # pragma: no cover - exercised only without the ai extra
    _AI_DEPS = False

_MAX_CHARS = 2500  # a contract fingerprint (pragma + decls + first fns) is enough to
# retrieve similar contracts, and short docs embed far faster than full sources


class KnowledgeBase:
    """RAG store (embedded ChromaDB) over the labelled contract corpus.

    On first use it builds an on-disk vector index from `rag_corpus_dir` (the
    reference split / offline sample) by embedding each contract with a local
    Ollama model. Subsequent runs reuse the persisted index.
    """

    def __init__(self) -> None:
        self.collection_name = settings.chroma_collection
        self.embed_model = settings.embed_model
        self.corpus_dir = Path(settings.rag_corpus_dir)
        self.chroma_path = settings.chroma_path
        self._collection = None
        # Leakage guard: ids that must NEVER be retrieved (the CURRENT held-out test split),
        # even if one ever slipped into the index. Chroma ids are dataset-relative posix paths,
        # so these match exactly. Sourced from labels.csv (split==test) via test_split_ids.json --
        # NOT the old balanced-500 list, which covered only 395/678 and wrongly blocked 105
        # legitimate reference contracts.
        self._exclude = set()
        try:
            import json as _json
            f = Path(self.chroma_path).parent / "eval_out" / "test_split_ids.json"
            if f.exists():
                self._exclude = set(_json.loads(f.read_text(encoding="utf-8")))
        except Exception:
            self._exclude = set()

    def available(self) -> bool:
        return _AI_DEPS

    def _client(self):
        # A generate() call has no library-level timeout by default, so a single stalled Ollama
        # request blocks the whole batch run indefinitely with no recovery (observed: 11+ hours
        # idle on one contract with no error, no retry, nothing in the log). 600s is generous for
        # even the slowest observed generation (~100 min outliers were pre-timeout hangs, not
        # legitimate work) while still turning a stall into a caught exception the retry loop or
        # caller can act on.
        return ollama.Client(host=settings.ollama_host, timeout=600)

    def _embed(self, texts: list[str]) -> list[list[float]]:
        """Embed texts with the local Ollama embedding model."""
        payload = [t[:_MAX_CHARS] for t in texts]
        resp = self._client().embed(model=self.embed_model, input=payload)
        return resp["embeddings"]

    def _ensure_index(self):
        """Open the persistent collection, building it from the corpus if empty."""
        if self._collection is not None:
            return self._collection
        client = chromadb.PersistentClient(path=self.chroma_path)
        col = client.get_or_create_collection(self.collection_name)
        if col.count() == 0:
            self._build(col)
        self._collection = col
        return col

    def _build(self, col) -> None:
        sols = sorted(self.corpus_dir.rglob("*.sol"))
        if not sols:
            return
        docs, ids, metas = [], [], []
        for sol in sols:
            # The RAG corpus is the REFERENCE split ONLY. Skip the dedup _quarantine/
            # holding area (rejected near-dups), and never embed a `test` contract or
            # retrieval would leak the held-out set into the AI's context. Unstamped
            # contracts (the offline fixtures) are kept so a local run still works.
            if "_quarantine" in sol.parts:
                continue
            text = sol.read_text(encoding="utf-8", errors="replace")
            m = re.search(r"DATASET_SPLIT\s*:\s*(\w+)", text)
            if m and m.group(1) == "test":
                continue
            docs.append(text)
            ids.append(sol.relative_to(self.corpus_dir).as_posix())
            parts = sol.relative_to(self.corpus_dir).parts
            metas.append({"path": ids[-1], "type": parts[-2] if len(parts) > 1 else "unknown"})
        # Embed in batches, committing each batch, and skip any the embedder
        # rejects so one bad contract can't sink a multi-thousand-contract build.
        for i in range(0, len(docs), 16):
            try:
                embs = self._embed(docs[i:i + 16])
            except Exception:
                continue
            col.add(ids=ids[i:i + 16], documents=docs[i:i + 16],
                    embeddings=embs, metadatas=metas[i:i + 16])

    def retrieve(self, contract_source: str, k: int = 5) -> list[str]:
        """Return the k most relevant contracts from the corpus for this query."""
        if not _AI_DEPS:
            return []
        col = self._ensure_index()
        if col.count() == 0:
            return []
        q = self._embed([contract_source])
        n = min(k + len(self._exclude) + 5, col.count()) if self._exclude else min(k, col.count())
        res = col.query(query_embeddings=q, n_results=n)
        ids = res.get("ids", [[]])[0]
        docs = res.get("documents", [[]])[0]
        out = []
        for i, d in zip(ids, docs):
            if self._exclude and i in self._exclude:
                continue   # held-out test contract -> never use as a retrieval example
            out.append(d)
            if len(out) >= k:
                break
        return out


_CODE_FENCE = re.compile(r"```(?:solidity|sol)?\s*(.*?)```", re.S)


def _extract_solidity(text: str) -> str:
    """Pull Solidity out of an LLM response (drop markdown fences and any prose)."""
    m = _CODE_FENCE.search(text)
    body = m.group(1) if m else text
    i = body.find("pragma")
    if i == -1:
        i = body.find("contract ")
    return (body[i:] if i != -1 else body).strip()


def _harness_contract_name(src: str) -> str | None:
    """The contract whose OWN body carries the echidna_* properties -- the one Echidna
    targets. Scans each contract's own span (not `.*?echidna_` across the whole file, which
    wrongly returned the FIRST contract whenever ANY later one had echidna_ -> Echidna then
    analysed a helper contract with no tests)."""
    src = re.sub(r"//[^\n]*", "", re.sub(r"/\*.*?\*/", "", src, flags=re.S))  # strip comments first
    best = None
    for m in re.finditer(r"\bcontract\s+(\w+)", src):
        start = m.end()
        nxt = re.search(r"\bcontract\s+\w+", src[start:])
        body = src[start: start + nxt.start()] if nxt else src[start:]
        if "echidna_" in body:
            best = m.group(1)
    if best:
        return best
    names = re.findall(r"\bcontract\s+(\w+)", src)
    return names[-1] if names else None


_MINOR_SOLC = {"0.4": "0.4.26", "0.5": "0.5.17", "0.6": "0.6.12", "0.7": "0.7.6", "0.8": "0.8.25"}


def _solc_for(pragma: str) -> str:
    """Pick an installed solc for a pragma. Must match benchmark_testset.solc_for exactly:
    the compile-check gate and the fuzzer have to agree, or a harness that fuzzes fine gets
    rejected here (or vice-versa). Handles exact pins, upper-bounded ranges, and floors."""
    p = pragma.replace(" ", "")
    if re.fullmatch(r"\d+\.\d+\.\d+", p):
        return p
    m = re.search(r"(?<![<>])=(\d+\.\d+\.\d+)", p)
    if m:
        return m.group(1)
    m = re.search(r"<0\.(\d+)", p)
    if m:
        for minor in range(int(m.group(1)) - 1, 3, -1):
            if f"0.{minor}" in _MINOR_SOLC:
                return _MINOR_SOLC[f"0.{minor}"]
    for minor in ("0.8", "0.7", "0.6", "0.5", "0.4"):
        if minor in p:
            return _MINOR_SOLC[minor]
    return "0.8.25"


def _extract_interface(src: str) -> str:
    """The target's REAL callable API, handed to the model so it stops inventing signatures (the
    #1 cause of non-compiling harnesses). Uses Slither when available for FULL signatures
    (visibility, payable, return type) -- a complete signature hallucinates far less than a bare
    name; falls back to regex names otherwise."""
    try:
        from .synthesize import _slither_contracts, _pragma
        contracts = _slither_contracts(src, _pragma(src))
    except Exception:
        contracts = None
    if contracts:
        lines = []
        names = []
        for c in contracts:
            if str(getattr(c, "contract_kind", "contract")) in ("interface", "library"):
                continue
            names.append(c.name)
            for f in c.functions:
                if f.is_constructor or str(f.visibility) not in ("public", "external") or f.name == "":
                    continue
                params = ", ".join(str(p.type) for p in f.parameters)
                mods = " payable" if f.payable else (" view" if f.view else "")
                rets = f" returns ({', '.join(str(r.type) for r in f.returns)})" if f.returns else ""
                lines.append(f"  {c.name}.{f.name}({params}){mods}{rets}")
        if lines:
            return (f"deployable contracts: {', '.join(names) or '(none)'}\n"
                    f"CALLABLE functions (use ONLY these, exact names):\n" + "\n".join(lines[:40]))
    contracts = re.findall(r"\bcontract\s+(\w+)", src)
    fns = re.findall(r"\bfunction\s+(\w+)\s*\(([^)]*)\)", src)
    sigs = sorted({f"{n}({p.strip()})" for n, p in fns if n})[:30]
    return f"contracts: {', '.join(contracts) or '(none)'}\nfunctions: {'; '.join(sigs) or '(none)'}"


def _default_arg(ptype: str) -> str:
    ptype = ptype.strip()
    if ptype.endswith("[]"):
        return f"new {ptype}(0)"
    if re.match(r"u?int\d*$", ptype):
        return "1"
    if ptype in ("address", "address payable"):
        return "address(this)"
    if ptype == "bool":
        return "false"
    if ptype in ("string", "bytes"):
        return '""'
    if re.match(r"bytes\d+$", ptype):
        return f"{ptype}(0)"
    return "0"


def _ctor_hint(src: str) -> str:
    """For each CONCRETE contract, the exact `new C(...)` call to deploy it, with default args
    -- and an explicit list of contracts NOT to instantiate (abstract/interface). Qwen doing
    `new AbstractContract()` was the single biggest compile-fail cause. Uses Slither for
    concreteness; regex fallback can't tell abstract apart, so it only lists names."""
    try:
        from .synthesize import _slither_contracts, _pragma
        contracts = _slither_contracts(src, _pragma(src))
    except Exception:
        contracts = None
    if contracts:
        hints, abstract = [], []
        for c in contracts:
            if str(getattr(c, "contract_kind", "contract")) in ("interface", "library"):
                abstract.append(c.name); continue
            if not c.is_fully_implemented:
                abstract.append(c.name); continue
            ctor = c.constructor
            if ctor and ctor.parameters:
                args = ", ".join(_default_arg(str(p.type)) for p in ctor.parameters)
                hints.append(f"new {c.name}({args})")
            else:
                hints.append(f"new {c.name}()")
        out = "; ".join(hints[:8]) or "(no directly-deployable contract)"
        if abstract:
            out += f"\n  NEVER `new` these (abstract/interface, won't compile): {', '.join(abstract[:8])}"
        return out
    # regex fallback (comment-stripped) -- can't detect abstract, so just give ctor calls
    src = re.sub(r"//[^\n]*", "", re.sub(r"/\*.*?\*/", "", src, flags=re.S))
    hints = []
    for m in re.finditer(r"\bcontract\s+(\w+)", src):
        cname = m.group(1)
        body = _contract_span(src, cname)
        cm = re.search(r"constructor\s*\(([^)]*)\)", body) or \
            re.search(rf"function\s+{re.escape(cname)}\s*\(([^)]*)\)", body)
        params = cm.group(1).strip() if cm else ""
        if not params:
            hints.append(f"new {cname}()")
        else:
            args = ", ".join(_default_arg(p.replace("memory", "").replace("calldata", "").split()[0])
                             for p in params.split(",") if p.strip())
            hints.append(f"new {cname}({args})")
    return "; ".join(hints[:8])


_SUSPECT = re.compile(
    r"\.call\b|\.call\.value|\{value:|\.send\s*\(|\.transfer\s*\(|delegatecall|selfdestruct|"
    r"suicide\s*\(|tx\.origin|_re_ent|_tod\d|_txorigin|_unchk|onlyOwner|owner\s*=|"
    r"require\s*\(\s*msg\.sender", re.I)


def _split_functions(body: str) -> list[tuple[str, str]]:
    """(name, full_source) for every function in a contract body, via brace matching so the
    WHOLE body is captured (regex head-splitting truncates at the first nested brace)."""
    out = []
    for m in re.finditer(r"\bfunction\b\s*(\w*)\s*\(", body):
        i = body.find("{", m.end())
        if i == -1:
            continue
        depth = 0
        for j in range(i, len(body)):
            if body[j] == "{":
                depth += 1
            elif body[j] == "}":
                depth -= 1
                if depth == 0:
                    out.append((m.group(1) or "constructor", body[m.start():j + 1]))
                    break
    return out


def _focus_source(src: str, max_chars: int = 7000) -> str:
    """A condensed, BUG-INCLUSIVE view of a contract for the model: state variables plus the
    functions that actually do something dangerous (external calls, selfdestruct, tx.origin,
    ownership writes, SolidiFI's injected `_re_ent`/`_tod`/`_txorigin` sites). Head-truncating
    (`src[:3000]`) hides the vulnerable function whenever it sits past the window -- true for
    23/33 of our vulnerable contracts -- so the model was reasoning about code it never saw.
    Extracting the suspicious regions keeps the bug in view regardless of file size."""
    from .synthesize import _strip_comments, _pragma
    clean = _strip_comments(src)
    if len(clean) <= max_chars:
        return clean
    cm = re.search(r"\b(?:contract|library|interface)\s+\w+[^{]*\{", clean)
    header = cm.group(0) if cm else "contract Target {"
    body = clean[cm.end():] if cm else clean
    # State variables: declaration lines before the first function.
    head = body[:body.find("function")] if "function" in body else ""
    statevars = "\n".join(l.strip() for l in head.splitlines() if l.strip())[:1500]
    suspicious = [t for _, t in _split_functions(body) if _SUSPECT.search(t)]
    chunk = f"pragma solidity {_pragma(src)};\n\n{header}\n{statevars}\n\n"
    for fn in suspicious:
        if len(chunk) + len(fn) > max_chars:
            break
        chunk += fn + "\n\n"
    return chunk + "}"


_ECHIDNA_DST = "0x00a329c0648769A73afAc7F9381E08FB43dBEA72"   # Echidna's deployed-contract addr
_ECHIDNA_SRC = "0x0000000000000000000000000000000000010000"   # a default fuzzer sender


def _encode_abi_arg(sol_type: str, value) -> dict | None:
    """One forwarder argument -> Echidna's ABI JSON. Supports the value types the seed path
    uses (uint/int/address/bool); returns None for anything else so that seed transaction is
    skipped rather than emitted malformed (Echidna would reject the whole corpus file)."""
    t = sol_type.replace(" payable", "").strip()
    m = re.match(r"^uint(\d*)$", t)
    if m:
        bits = int(m.group(1) or 256)
        try:
            v = int(value) & ((1 << bits) - 1)
        except Exception:
            v = 0
        return {"tag": "AbiUInt", "contents": [bits, "0x%064x" % v]}
    m = re.match(r"^int(\d*)$", t)
    if m:
        bits = int(m.group(1) or 256)
        try:
            v = int(value) & ((1 << bits) - 1)   # two's-complement wrap
        except Exception:
            v = 0
        return {"tag": "AbiInt", "contents": [bits, "0x%064x" % v]}
    if t == "address":
        s = str(value).lower().replace("0x", "")
        if not re.fullmatch(r"[0-9a-f]{0,40}", s):
            s = "0"
        return {"tag": "AbiAddress", "contents": "0x" + s.rjust(40, "0")}
    if t == "bool":
        return {"tag": "AbiBool", "contents": bool(value) and str(value).lower() not in ("0", "false")}
    return None


def _encode_seed_tx(spec: dict, args: list) -> dict | None:
    """A {spec,args} step -> one Echidna SolCall transaction, or None if any arg can't be
    encoded (that whole step is dropped so the corpus file stays valid)."""
    enc = []
    for t, v in zip(spec["raw_types"], args):
        a = _encode_abi_arg(t, v)
        if a is None:
            return None
        enc.append(a)
    if len(enc) != len(spec["raw_types"]):
        return None
    # A payable forwarder needs ether attached or the deposit credits nothing -> the withdraw
    # it sets up steals nothing and the reentrancy never triggers. Send 1 ether on payable calls.
    value = "0x0de0b6b3a7640000" if spec.get("payable") else "0x0"
    return {"call": {"tag": "SolCall", "contents": [spec["call_name"], enc]},
            "src": _ECHIDNA_SRC, "dst": _ECHIDNA_DST,
            "value": value, "gas": 12500000, "gasprice": "0x0", "delay": ["0x0", "0x0"]}


def write_seed_corpus(corpus_dir: Path, sequences: list[list[dict]]) -> int:
    """Write AI seed sequences as Echidna coverage-corpus files. Returns the count written.
    Echidna replays these on startup, giving the fuzzer a head start into guarded states."""
    cov = Path(corpus_dir) / "coverage"
    cov.mkdir(parents=True, exist_ok=True)
    written = 0
    for i, seq in enumerate(sequences):
        txs = [t for t in (_encode_seed_tx(s["spec"], s["args"]) for s in seq) if t]
        if not txs:
            continue
        (cov / f"ai_seed_{i}.txt").write_text(json.dumps(txs), encoding="utf-8")
        written += 1
    return written


def _shape_hint(src: str) -> str:
    """Slither-detected vuln shape as targeted guidance for the model -- the SAME structural
    analysis the template arm uses. Matches the design where both fuzzing arms parse with
    Slither first; without it the AI generates a generic harness and trails the template."""
    try:
        from .synthesize import (detect_reentrancy_shape, detect_access_control_shape,
                                  detect_ordering_shape)
        r = detect_reentrancy_shape(src)
        if r:
            return (f"SLITHER STRUCTURAL ANALYSIS: `{r['contract']}` is a REENTRANCY pool -- `{r['deposit']}` "
                    f"is payable and `{r['withdraw']}` sends ETH before updating the balance ledger. Build an "
                    f"Attacker that deposits via the harness, calls `{r['withdraw']}`, and RE-ENTERS `{r['withdraw']}` "
                    f"from its receive/fallback to withdraw again before the ledger updates. The echidna_ invariant "
                    f"must assert the attacker never ends up with more ETH than it deposited.")
        a = detect_access_control_shape(src)
        if a:
            setters = ", ".join(s['name'] for s in a['setters'][:4])
            return (f"SLITHER STRUCTURAL ANALYSIS: `{a['contract']}` has a privileged owner `{a['owner_var']}` "
                    f"written by setter(s): {setters}. Your harness should have a NON-owner call the setter(s); the "
                    f"echidna_ invariant must assert `{a['owner_var']}` never becomes the attacker's address.")
        o = detect_ordering_shape(src)
        if o:
            return (f"SLITHER STRUCTURAL ANALYSIS: `{o['contract']}` is a single-pot reward -- funder `{o['funder']}` "
                    f"is payable and `{o['claimer']}` pays the caller. Fund the pot, then have a DIFFERENT account "
                    f"call `{o['claimer']}`; the echidna_ invariant must assert an account that never contributed "
                    f"cannot take the reward.")
    except Exception:
        return ""
    return ""


def _force_header(harness: str, pragma: str, target_import: str) -> str:
    """Force the correct pragma + target import onto the harness. The model routinely omits or
    mangles the import (-> 'identifier not found' compile-fails); we KNOW both, so we strip any
    it wrote and prepend the right ones. Removes the single biggest compile-fail cause."""
    body = re.sub(r"^\s*pragma[^;\n]*;", "", harness, flags=re.M)
    body = re.sub(r"^\s*import[^;\n]*;", "", body, flags=re.M)
    return f'pragma solidity {pragma};\nimport "{target_import}";\n\n{body.strip()}'


def _contract_span(src: str, cname: str) -> str:
    m = re.search(rf"\bcontract\s+{re.escape(cname)}\b", src)
    if not m:
        return src
    rest = src[m.end():]
    nxt = re.search(r"\bcontract\s+\w+", rest)
    return rest[:nxt.start()] if nxt else rest


def _lint_harness(harness: str, cname: str, target_import: str = "",
                  target_contracts: tuple = ()) -> list[str]:
    """Structural checks Echidna needs but solc won't flag -- the reason raw harnesses
    'compile' yet fuzz nothing. Returned problems are fed back to the model like compiler
    errors so the repair loop actually engages (previously it only saw compile errors)."""
    problems = []
    # must test the REAL target: import it, don't redeclare a stub, and actually deploy it
    if target_import and target_import not in harness:
        problems.append(f'Missing `import "{target_import}";`. Test the REAL target, never a stub copy.')
    for tc in target_contracts:
        if re.search(rf"\bcontract\s+{re.escape(tc)}\b", harness):
            problems.append(f"Do NOT redeclare `contract {tc}` -- it is imported from the target.")
    if target_contracts and not any(re.search(rf"\bnew\s+{re.escape(tc)}\b", harness) for tc in target_contracts):
        problems.append(f"Deploy a REAL target contract ({', '.join(target_contracts[:4])}) with `new`, not a stub.")
    props = re.findall(r"function\s+(echidna_\w+)\s*\(([^)]*)\)([^{]*)\{", harness)
    if not props:
        problems.append("No `echidna_` property. Add >=1 `function echidna_x() public returns (bool)`.")
    for name, params, head in props:
        if params.strip():
            problems.append(f"{name} takes arguments -- Echidna properties MUST be zero-argument.")
        if "bool" not in head:
            problems.append(f"{name} must `returns (bool)`.")
    # contrived constant: an echidna_ body that is essentially just `return true/false;`
    for m in re.finditer(r"function\s+echidna_(\w+)\s*\([^)]*\)[^{]*\{(.*?)\n\s*\}", harness, re.S):
        body = m.group(2)
        if re.search(r"return\s+(true|false)\s*;", body) and not re.search(r"[<>=!]=|\.\w+\s*\(|\.balance|return\s+[A-Za-z_]", body):
            problems.append(f"echidna_{m.group(1)} is contrived (returns a constant) -- it must ASSERT a real "
                            "invariant over target state (e.g. `return target.total() <= cap;`).")
    # the harness contract must be funded: its constructor must be payable
    span = _contract_span(harness, cname)
    ctor = re.search(r"constructor\s*\([^)]*\)([^{]*)\{", span) or \
        re.search(rf"function\s+{re.escape(cname)}\s*\([^)]*\)([^{{]*)\{{", span)
    if ctor and "payable" not in ctor.group(1):
        problems.append("The harness constructor must be `payable` (Echidna funds it via balanceContract).")
    return problems


def _compile_check(harness: str, target_src: str, target_import: str, pragma: str) -> tuple[bool, str]:
    """Compile the harness together with its target; return (ok, error-tail). If solcx
    is unavailable, don't block (assume ok)."""
    try:
        import solcx
    except Exception:
        return True, ""
    import os
    import tempfile
    ver = _solc_for(pragma)
    try:
        solcx.install_solc(ver)
    except Exception:
        pass
    with tempfile.TemporaryDirectory(prefix="aifuzz-harness-") as d:
        with open(os.path.join(d, os.path.basename(target_import)), "w", encoding="utf-8") as f:
            f.write(target_src)
        hp = os.path.join(d, "Harness.sol")
        with open(hp, "w", encoding="utf-8") as f:
            f.write(harness)
        try:
            # NB: no base_path -- solc < 0.6.9 rejects it. `./target.sol` is a
            # relative import solc resolves next to the harness; allow_paths lets
            # it read the dir. Works across 0.4.x .. 0.8.x.
            solcx.compile_files([hp], solc_version=ver, allow_paths=d)
            return True, ""
        except Exception as e:
            return False, str(e).replace(d, ".")


def _distill_solc_error(raw: str, max_errors: int = 3) -> str:
    """Pull the actionable `...: Error: ...` lines (plus the offending source + caret) out of
    solcx's verbose command dump. A focused error is fixed far more reliably by the model than
    the whole blob -- and it keeps the repair prompt small so context doesn't blow up."""
    lines = raw.splitlines()
    out = []
    for i, ln in enumerate(lines):
        if re.search(r":\d+:\d+:\s*(Error|TypeError|DeclarationError):", ln):
            block = [ln.strip()]
            for j in (i + 1, i + 2):   # the source line + caret that solc prints under it
                if j < len(lines) and lines[j].strip():
                    block.append(lines[j].rstrip())
            out.append("\n".join(block))
        if len(out) >= max_errors:
            break
    if not out:   # no structured file:line:col error -> fall back to any Error: line
        out = [ln.strip() for ln in lines if "Error" in ln][:max_errors]
    return "\n\n".join(out) or raw[:400]


def _err_fingerprint(err: str) -> str:
    """Stable id for an error with line numbers / temp paths normalised away, so 'same mistake
    on a different line' collapses to one fingerprint -> we can detect a stuck repair loop."""
    norm = re.sub(r"\d+", "#", re.sub(r"/tmp/\S+|[A-Za-z]:[\\/]\S+", "", err or ""))
    return hashlib.sha1(norm.encode()).hexdigest()[:12]


def _whitelist_violations(harness: str, src: str) -> list[str]:
    """Every function the harness calls on another contract must actually EXIST in the target.
    Catches hallucinated signatures (the #1 compile-fail) with a clearer message than solc, and
    feeds them back through the same repair loop."""
    real = set(re.findall(r"\bfunction\s+(\w+)\s*\(", src))
    called = set(re.findall(r"\.\s*(\w+)\s*\(", harness))
    builtins = {"value", "call", "delegatecall", "staticcall", "transfer", "send", "balance",
                "push", "pop", "length", "encode", "encodePacked", "encodeWithSignature", "sender"}
    invented = [c for c in called
                if c not in real and c not in builtins and not c.startswith("echidna_") and c[:1].islower()]
    if not invented:
        return []
    return [f"`{c}(...)` does not exist on the target. Call ONLY these: "
            f"{', '.join(sorted(real))[:300]}" for c in invented[:5]]


class PropertyGenerator:
    """Local LLM (Ollama qwen) + RAG retrieval -> an Echidna harness. This is the M3
    novelty: generate a fuzzable harness for contracts the Tier-2 templates can't
    handle (oracle-manipulation, unrecognised shapes)."""

    def __init__(self, kb: KnowledgeBase | None = None) -> None:
        self.kb = kb or KnowledgeBase()
        self.model = settings.ollama_model

    def available(self) -> bool:
        return _AI_DEPS

    def _client(self):
        # A generate() call has no library-level timeout by default, so a single stalled Ollama
        # request blocks the whole batch run indefinitely with no recovery (observed: 11+ hours
        # idle on one contract with no error, no retry, nothing in the log). 600s is generous for
        # even the slowest observed generation (~100 min outliers were pre-timeout hangs, not
        # legitimate work) while still turning a stall into a caught exception the retry loop or
        # caller can act on.
        return ollama.Client(host=settings.ollama_host, timeout=600)

    @staticmethod
    def _pragma(src: str) -> str:
        m = re.search(r"pragma\s+solidity\s+([^;]+);", src)
        return m.group(1).strip() if m else "^0.8.0"

    def generate_harness(self, contract_source: str, target_import: str,
                         k: int = 3, max_retries: int = 6) -> tuple[str, str] | None:
        """RAG-augmented Echidna harness generation with a ROBUST retry loop: the model reads
        the contract and writes a harness; we compile-check + lint it; on failure we either feed
        the error back (repair) or restart from scratch, and CRUCIALLY we vary the sampling each
        attempt (temperature + seed) so "trying again" actually explores a different harness
        instead of re-emitting the identical one (the old loop pinned temperature=0/seed=0, so
        every retry was a no-op). Returns (harness, name, attempts) once it COMPILES and is a
        valid Echidna test, else None -- an honest gen-fail, never a template fallback."""
        if not _AI_DEPS:
            return None
        examples = self.kb.retrieve(contract_source, k=k)
        interface = _extract_interface(contract_source)
        target_contracts = tuple(re.findall(r"\bcontract\s+(\w+)", contract_source))
        pragma = self._pragma(contract_source)
        base_prompt = self._harness_prompt(contract_source, target_import, examples, interface)
        last = None   # last compiling-but-invalid candidate, kept to repair
        err = ""
        seen_errs: dict[str, int] = {}   # error fingerprint -> times seen (loop-breaker)
        for attempt in range(max_retries + 1):
            # Attempt 0 is the deterministic best guess; later attempts sample with rising
            # temperature and a fresh seed so the model genuinely tries DIFFERENT harnesses.
            temp = 0.0 if attempt == 0 else min(0.3 + 0.15 * attempt, 0.8)
            fp = _err_fingerprint(err) if err else None
            stuck = bool(fp and seen_errs.get(fp, 0) >= 1)   # this exact error already recurred
            if stuck:
                # Escalate: abandon the repair path, restart clean, and name the mistake so the
                # model stops reproducing it -- this is what breaks the infinite-retry loop.
                prompt = base_prompt + (
                    f"\n\nPREVIOUS ATTEMPTS FAILED REPEATEDLY WITH:\n{_distill_solc_error(err)}\n"
                    "Do NOT reproduce this. Write a SIMPLER harness that definitely compiles.")
            elif attempt and last and err and attempt % 2 == 1:
                prompt = self._repair_prompt(last, _distill_solc_error(err), interface, pragma)
            else:
                prompt = base_prompt
            if fp:
                seen_errs[fp] = seen_errs.get(fp, 0) + 1
            try:
                resp = self._client().generate(
                    model=self.model, prompt=prompt,
                    options={"temperature": temp, "seed": attempt, "num_predict": 3000})
            except Exception:
                return None
            cand = _force_header(_extract_solidity(resp.get("response", "")), pragma, target_import)
            if "echidna_" not in cand:
                continue
            cname = _harness_contract_name(cand)
            if not cname:
                continue
            ok, cerr = _compile_check(cand, contract_source, target_import,
                                      self._pragma(cand) or pragma)
            if ok:
                # Structural + whitelist checks: compiles is necessary but not sufficient.
                lint = _lint_harness(cand, cname, target_import, target_contracts)
                lint += _whitelist_violations(cand, contract_source)
                if not lint:
                    return (cand, cname, attempt + 1)   # compiles AND is a valid Echidna test
                err = "The harness COMPILES but is NOT a valid Echidna test. Fix ALL of:\n- " + \
                      "\n- ".join(lint)
            else:
                err = cerr
            last = cand   # keep for the next repair attempt
        return None  # never produced a valid harness after retries -> honest miss

    @staticmethod
    def _ver_syntax(pragma: str) -> dict:
        """Version-correct scaffolding fragments so Qwen emits code the target's compiler
        accepts (the constructor keyword, receive/fallback, and value-call syntax all differ
        across 0.4/0.5/0.6+)."""
        v = _solc_for(pragma).split("."); mj, mn, pt = int(v[0]), int(v[1]), int(v[2])
        ctor = "function Harness() public payable" if (mj, mn, pt) < (0, 4, 22) else \
               ("constructor() payable" if mn >= 7 else "constructor() public payable")
        return {
            "ctor": ctor,
            "value": ".deposit.value(1 ether)()" if mn < 6 else ".deposit{value: 1 ether}()",
            "newfund": "(new Attacker).value(2 ether)(target)" if mn < 6 else "new Attacker{value: 2 ether}(target)",
            "recv": "function () external payable {}" if mn < 6 else "receive() external payable {}",
        }

    def _worked_example(self, pragma: str) -> str:
        s = self._ver_syntax(pragma)
        actor_ctor = "function Attacker(Target _t) public payable" if "function Harness" in s["ctor"] \
            else s["ctor"].replace("Harness()", "Attacker(Target _t)")
        return (
            "// WORKED EXAMPLE -- copy this STRUCTURE only. `Target` stands for YOUR imported target\n"
            "// contract: use its real name from the interface, and do NOT redeclare it.\n"
            "contract Attacker {\n"
            "    Target t;\n"
            f"    {actor_ctor} {{ t = _t; }}\n"
            "    function attack() public { t.withdraw(1 ether); }\n"
            f"    {s['recv']}\n"
            "}\n"
            "contract Harness {\n"
            "    Target target;\n"
            "    Attacker attacker;\n"
            f"    {s['ctor']} {{                       // payable: Echidna funds it via balanceContract\n"
            "        target = new Target();            // deploy the REAL imported target\n"
            f"        attacker = {s['newfund']};        // FUND any helper you deploy\n"
            f"        target{s['value']};\n"
            "    }\n"
            "    function echidna_no_theft() public view returns (bool) {\n"
            "        return address(attacker).balance <= 2 ether;   // real invariant over state; cannot revert\n"
            "    }\n"
            "}"
        )

    def _harness_prompt(self, src: str, target_import: str, examples: list[str],
                        interface: str) -> str:
        pragma = self._pragma(src)
        s = self._ver_syntax(pragma)
        ctx = "\n\n".join(f"// similar contract {i + 1}:\n{e[:700]}"
                          for i, e in enumerate(examples)) or "(none)"
        shape = _shape_hint(src)
        shape_block = f"{shape}\n\n" if shape else ""
        return (
            "You are a security engineer writing an Echidna fuzzing harness for TARGET.\n\n"
            f"TARGET (import \"{target_import}\"):\n{_focus_source(src)}\n\n"
            f"THE TARGET'S REAL INTERFACE -- use ONLY these names:\n{interface}\n\n"
            f"HOW TO DEPLOY EACH CONTRACT (use these exact constructor calls / default args):\n"
            f"{_ctor_hint(src)}\n\n"
            f"{shape_block}"
            "HARD REQUIREMENTS (a harness that breaks any of these is useless):\n"
            f"1. `pragma solidity {pragma};` and `import \"{target_import}\";`\n"
            "2. Deploy the target IN THE CONSTRUCTOR (Echidna never calls setUp()).\n"
            f"3. The harness constructor MUST be payable: `{s['ctor']}` -- so Echidna's balanceContract funds it.\n"
            f"4. If you deploy a helper/attacker contract, FUND it (e.g. `{s['newfund']}`) -- funding the harness "
            "does NOT fund a contract it creates; unfunded value calls revert and fuzz nothing.\n"
            f"5. Value-carrying calls use `{s['value']}` syntax for this compiler.\n"
            "6. Every property: `function echidna_NAME() public view returns (bool)` -- ZERO arguments, returns "
            "bool, reads target STATE, must NOT revert in the initial state, and returns FALSE once the vuln is "
            "exploited. NEVER write `return true;`/`return false;` -- assert a real invariant.\n"
            "7. Use ONLY names from the interface above; do NOT invent functions.\n"
            "8. COVERAGE. Echidna only reaches code your harness exposes, so besides the attack scaffolding "
            "add plain forwarders for up to 8 state-changing functions from the interface, e.g.\n"
            "     function call_transfer(address to, uint256 v) public { target.transfer(to, v); }\n"
            "   (payable forwarder passing msg.value through, when the target function is payable). Prefer "
            "correctness over count: a compiling harness with 3 forwarders beats one that fails to compile.\n\n"
            f"{self._worked_example(pragma)}\n\n"
            f"SIMILAR CONTRACTS (context only):\n{ctx}\n\n"
            "Output ONLY the Solidity code for the harness."
        )

    def _repair_prompt(self, harness: str, err: str, interface: str, pragma: str) -> str:
        return (
            "This Echidna harness is WRONG. Return a corrected version that fixes every problem.\n\n"
            f"HARNESS:\n{harness}\n\n"
            f"PROBLEMS TO FIX:\n{err}\n\n"
            f"THE TARGET'S REAL INTERFACE -- use ONLY these names:\n{interface}\n\n"
            "Remember: payable constructor; deploy+fund in the constructor (not setUp); fund any sub-contract you "
            "create; each `echidna_x()` is a zero-arg `returns (bool)` invariant over state that cannot revert and "
            f"is NOT a constant; match pragma {pragma} syntax. Output ONLY the corrected Solidity code."
        )

    def generate_properties(self, contract_source: str) -> list[str]:
        """Back-compat: expose the generated harness as a single guidance doc."""
        out = self.generate_harness(contract_source, "./target.sol")
        return [out[0]] if out else []

    def seed_sequences(self, contract_source: str, specs: list[dict],
                       max_seqs: int = 6) -> list[list[dict]]:
        """AI-GUIDED INPUT GENERATION (the thesis). Given the contract and the coverage
        harness's forwarder API, ask the model for concrete multi-call transaction sequences
        that drive the contract into deep/guarded states a random fuzzer would rarely compose
        (e.g. deposit -> withdraw -> re-enter; initialize -> setPrice -> exploit). Returns a
        list of sequences, each a list of {"fn","args"} over the forwarder names. These are
        encoded to an Echidna corpus and REPLAYED as fuzzing seeds -- the harness itself is
        identical to the random arm, so seeds are the ONLY variable (a clean controlled test)."""
        if not _AI_DEPS or not specs:
            return []
        by_name = {s["call_name"]: s for s in specs}
        api = "\n".join(f'  {s["call_name"]}({", ".join(s["raw_types"])})'
                        + ("  [payable]" if s["payable"] else "") for s in specs[:28])
        # RAG, as specified for BOTH generation paths: retrieve contracts from the reference
        # split that are structurally similar to this one, so the proposed sequences are grounded
        # in how comparable contracts are actually exploited rather than in the model's priors
        # alone. Excerpts are kept short -- the sequences depend on the ATTACK SHAPE of the
        # neighbours, not on their full text, and a long prompt slows generation sharply.
        examples = self.kb.retrieve(contract_source, k=3)
        ctx = "\n\n".join(f"// similar known-vulnerable contract {i + 1}:\n{e[:500]}"
                          for i, e in enumerate(examples)) or "(none retrieved)"
        prompt = (
            "You are guiding a smart-contract fuzzer. Below is a contract, similar contracts with "
            "known vulnerabilities, and the exact harness functions the fuzzer can call. Produce "
            "transaction SEQUENCES that reach deep or guarded code and set up known attacks "
            "(reentrancy: fund then withdraw; access-control: call privileged setters; ordering: "
            "fund a pot then claim from another account). Use ONLY these function names and pass "
            "concrete integer/address/bool arguments.\n\n"
            f"CONTRACT (state + security-relevant functions):\n{_focus_source(contract_source)}\n\n"
            f"SIMILAR VULNERABLE CONTRACTS (how contracts of this shape get exploited):\n{ctx}\n\n"
            f"CALLABLE HARNESS FUNCTIONS:\n{api}\n\n"
            # Addresses MUST be requested in short form. Left to itself the model writes
            # zero-padded 42-char literals ("0x0000...0000"), and long runs of zeros tokenise
            # very poorly -- a single argument could consume enough of the budget that the
            # reply was cut off before the first sequence closed, yielding no usable seeds at
            # all. Measured on the null cases: replies truncated at 89-189 characters with
            # correct function names and correct JSON shape. _encode_abi_arg pads any short
            # hex to 40 digits, so "0x1" is encoded identically to the long form.
            f"Reply with ONLY a JSON array of at most {max_seqs} sequences. Each sequence is an "
            'array of {"fn": "<call_name>", "args": [<values>]}.\n'
            "Write addresses in SHORT form -- 0x1, 0x2, 0x3 -- never zero-padded. Keep the "
            "reply compact; do not add commentary or markdown fences. Example:\n"
            '[[{"fn":"call_deposit_0","args":[1000000000000000000]},'
            '{"fn":"call_withdraw_0","args":[]}],'
            '[{"fn":"call_setOwner_0","args":["0x1"]}]]\n')
        try:
            resp = self._client().generate(
                model=self.model, prompt=prompt,
                # 1600, not 700: the old budget truncated mid-array on contracts with wide
                # ABIs. Short-form addresses cut the tokens per argument sharply, so this
                # headroom costs far less generation time than raising it alone would have.
                options={"temperature": 0, "seed": 0, "num_predict": 1600})
        except Exception:
            return []
        raw = resp.get("response", "")
        # Take everything from the first '[' rather than requiring a matching ']'. The previous
        # `\[.*\]` search returned None whenever the reply was cut off before any bracket
        # closed, which discarded the response outright -- the single largest cause of empty
        # seed corpora, and one that produced no error because the caller treats [] as
        # "degrade to random".
        start = raw.find("[")
        if start < 0:
            return []
        raw_arr = raw[start:]
        # Large contracts (the SolidiFI files carry ~40 injected functions) can still push the
        # reply past num_predict, so a strict parse would discard a response that was mostly
        # usable. Salvage in two stages: close the array at successively earlier sequence
        # boundaries, then, failing that, truncate at the last complete call object and
        # re-balance the brackets by hand.
        def _candidates(s: str):
            yield s
            for i in range(len(s) - 1, 0, -1):          # close at an earlier ']'
                if s[i] == "]":
                    yield s[:i + 1] + "]"
            for i in range(len(s) - 1, 0, -1):          # close after the last complete '}'
                if s[i] == "}":
                    head = s[:i + 1]
                    yield head + "]" * max(head.count("[") - head.count("]"), 0)

        data = None
        for cand in _candidates(raw_arr):
            try:
                data = json.loads(cand)
                break
            except Exception:
                continue
        if data is None:
            return []
        # The model routinely names the TARGET function ("withdraw") where the harness exposes a
        # forwarder ("call_withdraw_0"). The intent is unambiguous and the mapping is
        # deterministic, so resolve it rather than discarding the sequence -- this was the single
        # largest source of empty seed corpora (whole contracts contributing nothing).
        by_target: dict[str, dict] = {}
        for s in specs:
            by_target.setdefault(s["fn"], s)
            by_target.setdefault(s["fn"].lower(), s)

        def _resolve(name):
            if not isinstance(name, str):
                return None
            return by_name.get(name) or by_target.get(name) or by_target.get(name.lower())

        # The model answers in two shapes: a list OF sequences ([[call, call]]) and -- just as
        # often -- a single flat sequence ([call, call]). Requiring the nested form silently threw
        # away every flat reply, which is why contracts whose function names all resolved still
        # produced zero seeds. Normalise to the nested form.
        if isinstance(data, list) and data and isinstance(data[0], dict):
            data = [data]

        out = []
        for seq in data if isinstance(data, list) else []:
            calls = []
            for step in seq if isinstance(seq, list) else []:
                spec = _resolve(step.get("fn")) if isinstance(step, dict) else None
                if spec is None:
                    continue
                calls.append({"spec": spec, "args": step.get("args", []) or []})
            if calls:
                out.append(calls)
            if len(out) >= max_seqs:
                break
        return out
