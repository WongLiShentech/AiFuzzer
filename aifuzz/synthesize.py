"""Tier-2 harness synthesis (template-based, no AI).

Reads a raw contract, matches its structure to a known vulnerability shape, and
emits an Echidna harness (attacker + oracle). Each detector fires only on its
shape; otherwise the dispatcher defers to M3. Shapes: reentrancy, access-control,
ordering. Oracle-manipulation is recognised only (a market can't be templated).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_PRAGMA = re.compile(r"pragma\s+solidity\s+([^;]+);")
_CONTRACT = re.compile(r"\bcontract\s+(\w+)\s*(?:is\b|\{)")
_SEND = re.compile(r"\.call\.value|\.transfer\s*\(|\.send\s*\(")
_BALANCE_LEDGER = re.compile(r"mapping\s*\(\s*address\s*=>\s*uint")   # reentrancy fingerprint
_PRIV_NAME = re.compile(r"owner|admin|operator|governor|governance|controller|manager|master|root", re.I)
_BUILTIN_MODS = {"public", "external", "internal", "private", "payable", "view",
                 "pure", "constant", "returns", "memory", "storage", "calldata"}


def _strip_comments(src: str) -> str:
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    src = re.sub(r"//[^\n]*", "", src)
    return src


def _pragma(src: str) -> str:
    m = _PRAGMA.search(src)
    return m.group(1).strip() if m else "^0.4.24"


def _functions(src: str) -> list[tuple[str, str, str]]:
    """Split a flat contract into (name, params, tail) per function."""
    fns = []
    for chunk in re.split(r"\bfunction\b", src)[1:]:
        m = re.match(r"\s*(\w+)\s*\(([^)]*)\)(.*)", chunk, re.S)
        if m:
            fns.append((m.group(1), m.group(2), m.group(3)))
    return fns


def _head_body(tail: str) -> tuple[str, str]:
    head = tail.split("{", 1)[0]
    body = tail.split("{", 1)[1] if "{" in tail else ""
    return head, body


def _param_names(params: str) -> str:
    """'uint x, address y' -> 'x, y' (for forwarding)."""
    names = []
    for part in (p.strip() for p in params.split(",")):
        if not part:
            continue
        toks = part.replace("memory", "").replace("calldata", "").replace("storage", "").split()
        if toks:
            names.append(toks[-1])
    return ", ".join(names)


def _contract_body(src: str, contract: str) -> str:
    """Source span of ONE contract -- from `contract NAME` to the next top-level
    contract/library/interface. A cheap slice (not a brace parser), enough to scope
    per-contract lookups so a sibling contract in the same file can't bleed in."""
    m = re.search(rf"\b(?:contract|library|interface)\s+{re.escape(contract)}\b", src)
    if not m:
        return src
    rest = src[m.end():]
    nxt = re.search(r"\b(?:contract|library|interface)\s+\w+", rest)
    return rest[:nxt.start()] if nxt else rest


def _ctor_requires_args(src: str, contract: str) -> bool:
    """True only if THIS contract's OWN constructor takes parameters. Scoped to the
    contract's body so a sibling contract's `constructor(...)` in the same file can't
    trigger a false positive (which was wrongly blocking valid single-contract shapes)."""
    body = _contract_body(_strip_comments(src), contract)
    m = re.search(rf"function\s+{re.escape(contract)}\s*\(([^)]*)\)", body)
    if not m:
        m = re.search(r"constructor\s*\(([^)]*)\)", body)
    return bool(m and m.group(1).strip())


_SCAFFOLD_MINOR = {"0.4": (0, 4, 26), "0.5": (0, 5, 17), "0.6": (0, 6, 12),
                   "0.7": (0, 7, 6), "0.8": (0, 8, 25)}


def _resolve_solc(pragma: str) -> tuple[int, int, int]:
    """(major,minor,patch) of the solc that will actually compile this pragma -- tracks
    benchmark_testset.solc_for so emitted scaffolding matches the compiler, not the text."""
    p = pragma.replace(" ", "")
    m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", p) or re.search(r"(?<![<>])=(\d+)\.(\d+)\.(\d+)", p)
    if m:
        return int(m.group(1)), int(m.group(2)), int(m.group(3))
    cap = re.search(r"<0\.(\d+)", p)
    if cap:
        for minor in range(int(cap.group(1)) - 1, 3, -1):
            if f"0.{minor}" in _SCAFFOLD_MINOR:
                return _SCAFFOLD_MINOR[f"0.{minor}"]
    for minor in ("0.8", "0.7", "0.6", "0.5", "0.4"):
        if minor in p:
            return _SCAFFOLD_MINOR[minor]
    return 0, 8, 25


def _ver_ctor(pragma: str, cname: str, payable: bool = True) -> str:
    """Version-correct constructor header. <0.4.22 has no `constructor` keyword (named fn);
    0.7+ drops visibility on constructors."""
    v = _resolve_solc(pragma); pay = " payable" if payable else ""
    if v < (0, 4, 22):
        return f"function {cname}() public{pay}"
    if v[1] >= 7:
        return f"constructor(){pay}"
    return f"constructor() public{pay}"


def _ver_recv(pragma: str) -> str:
    """Version-correct payable receive. 0.6+ splits it into receive()/fallback()."""
    return "receive() external payable {}\n    fallback() external payable {}" \
        if _resolve_solc(pragma)[1] >= 6 else "function () external payable {}"


def _ver_value(pragma: str, callee: str, val: str, args: str = "") -> str:
    """Version-correct value-carrying external call: 0.6+ uses `{value: x}` not `.value(x)`."""
    return f"{callee}{{value: {val}}}({args})" if _resolve_solc(pragma)[1] >= 6 \
        else f"{callee}.value({val})({args})"


def _is_guarded(head: str, body: str, owner_var: str) -> bool:
    """True if the function looks access-controlled (owner require, or a modifier)."""
    ov = re.escape(owner_var)
    if re.search(rf"require\s*\(\s*msg\.sender\s*==\s*{ov}", body):
        return True
    if re.search(rf"require\s*\(\s*{ov}\s*==\s*msg\.sender", body):
        return True
    if re.search(r"if\s*\(\s*msg\.sender\s*!=", body):
        return True
    head = re.sub(r"returns\s*\([^)]*\)", "", head)
    return any(tok.lower() not in _BUILTIN_MODS for tok in re.findall(r"[A-Za-z_]\w*", head))


# --- Slither semantic parsing (AST/IR); regex is the fallback --------------- #
def _solc_for_pragma_spec(pragma: str) -> str | None:
    """Solc version for Slither, resolved for ANY pragma (0.4..0.8). Previously only 0.4.x
    was handled, so Slither silently failed on 0.5+ contracts and every detector dropped to
    the sloppy regex path (no payability/visibility/abstract info) -- the root cause of the
    template's broken harnesses on 0.5.x contracts."""
    v = _resolve_solc(pragma)
    return f"{v[0]}.{v[1]}.{v[2]}"


_SLITHER_CACHE: dict = {}   # src -> parsed contracts; the 3 detectors share one parse


def _slither_contracts(src: str, pragma: str):
    """Parse `src` with Slither and return its contract objects (understanding the
    code's structure, not its text). Returns None if Slither is unavailable or the
    contract won't compile — the caller then falls back to the regex detector.
    Cached by source so synthesize_all() compiles a contract once, not per detector."""
    key = hash(src)
    if key in _SLITHER_CACHE:
        return _SLITHER_CACHE[key]
    result = None
    try:
        from slither import Slither
        import solcx
        from solcx.install import get_executable
    except Exception:
        _SLITHER_CACHE[key] = None
        return None
    import os
    import tempfile
    ver = _solc_for_pragma_spec(pragma)
    try:
        # Point Slither at the exact solc BINARY (solcx installs on demand). The host has
        # no solc-select, so the old SOLC_VERSION env did nothing for 0.5+ -> Slither always
        # failed there and every detector silently used the sloppy regex path. This is the fix.
        solcx.install_solc(ver)
        binp = str(get_executable(ver))
        with tempfile.TemporaryDirectory(prefix="aifuzz-slither-") as d:
            path = os.path.join(d, "Contract.sol")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(src)
            # Compile from INSIDE the temp dir using a bare filename. Passing the absolute
            # Windows path makes solc split it on the drive-letter colon ("C:\Users\..." ->
            # "Unknown file: Users:\..."), so Slither failed on every contract routed through
            # a temp dir and the caller silently fell back to the regex detector.
            cwd = os.getcwd()
            try:
                os.chdir(d)
                result = list(Slither("Contract.sol", solc=binp).contracts)
            finally:
                os.chdir(cwd)
    except Exception:
        result = None
    _SLITHER_CACHE[key] = result
    return result


def _is_balance_ledger(sv) -> bool:
    """A per-address balance ledger: mapping(address => uint*) OR mapping(address => Struct)
    where the struct has a uint field (e.g. Holder{uint balance;}). The struct case was
    missing, so pool contracts like PENNY_BY_PENNY that store balances in a struct were never
    detected. Nested mappings (allowance) are NOT ledgers."""
    t = sv.type
    if type(t).__name__ != "MappingType":
        return False
    if "address" not in str(getattr(t, "type_from", "")):
        return False
    vt = getattr(t, "type_to", None)
    vs = str(vt)
    if "mapping" in vs:                      # nested mapping (allowance) -> not a ledger
        return False
    if "uint" in vs:                         # mapping(address => uint*)
        return True
    struct = getattr(vt, "type", None)       # mapping(address => Struct) with a uint field
    elems = getattr(struct, "elems_ordered", None) if struct is not None else None
    return bool(elems) and any("uint" in str(getattr(e, "type", "")) for e in elems)


# --- reentrancy ------------------------------------------------------------- #
def detect_reentrancy_shape(src: str) -> dict | None:
    """Deposit/withdraw pool: a balance ledger + a payable deposit + a function
    that sends ETH. Semantic (Slither) when available, else regex (text)."""
    return _detect_reentrancy_slither(src) or _detect_reentrancy_regex(src)

#slither detection 
def _detect_reentrancy_slither(src: str) -> dict | None:
    """Semantic detection: Slither's can_send_eth() recognises an ETH-sending call
    regardless of syntax (catches 0.8 `call{value:}` that the regex misses)."""
    pragma = _pragma(src)
    contracts = _slither_contracts(src, pragma)
    if contracts is None:
        return None
    for c in contracts:
        if not c.is_fully_implemented:
            continue   # abstract/interface -> can't `new C()`
        if not any(_is_balance_ledger(sv) for sv in c.state_variables):
            continue
        deposit = withdraw = None
        deposit_addr = withdraw_amount = False
        for f in c.functions:
            if f.is_constructor or str(f.visibility) not in ("public", "external"):
                continue   # only externally-callable functions can be driven from the harness
            if f.payable and deposit is None:
                deposit = f.name
                deposit_addr = any("address" in str(p.type) for p in f.parameters)
            if f.can_send_eth() and withdraw is None:
                withdraw = f.name
                withdraw_amount = any(str(p.type).startswith(("uint", "int")) for p in f.parameters)
        if deposit and withdraw:
            return {"contract": c.name, "deposit": deposit,
                    "deposit_takes_address": deposit_addr, "withdraw": withdraw,
                    "withdraw_takes_amount": withdraw_amount, "pragma": pragma}
    return None

#regex level detection
def _detect_reentrancy_regex(src: str) -> dict | None:
    """Fallback: text-pattern detection (a balance ledger + payable + external send)."""
    pragma = _pragma(src)
    src = _strip_comments(src)
    cm = _CONTRACT.search(src)
    if not cm or not _BALANCE_LEDGER.search(src):
        return None

    deposit = None
    deposit_addr = False
    withdraw = None
    withdraw_amount = False
    for name, params, tail in _functions(src):
        head, body = _head_body(tail)
        if "payable" in head and deposit is None:
            deposit = name
            deposit_addr = "address" in params
        if _SEND.search(body) and withdraw is None:
            withdraw = name
            withdraw_amount = "uint" in params          # withdraw(amount) vs withdraw-all()
    if not (deposit and withdraw):
        return None
    return {"contract": cm.group(1), "deposit": deposit,
            "deposit_takes_address": deposit_addr, "withdraw": withdraw,
            "withdraw_takes_amount": withdraw_amount, "pragma": pragma}

#generate harness specific to re entrancy
def synthesize_reentrancy_harness(src: str, target_import: str) -> tuple[str, str] | None:
    """Build a reentrancy harness for the deposit/withdraw shape, or None."""
    shape = detect_reentrancy_shape(src)
    if not shape:
        return None
    if _ctor_requires_args(src, shape["contract"]):
        return None   # can't `new C()` with required ctor args -> defer to M3, don't emit a broken harness
    c, dep, wd, pragma = shape["contract"], shape["deposit"], shape["withdraw"], shape["pragma"]
    hname = f"{c}_AutoReentrancyHarness"
    wcall = f"target.{wd}(1 ether)" if shape["withdraw_takes_amount"] else f"target.{wd}()"

    if shape["deposit_takes_address"]:
        # deposit(address): seed a victim address directly (SimpleDAO style).
        seed = (f'        target.{dep}.value(2 ether)(address(0xdead)); // victim funds\n'
                f'        target.{dep}.value(1 ether)(address(this));   // our stake')
    else:
        # deposit(): credit goes to msg.sender, so a Victim contract seeds the pool.
        seed = (f'        victim.fund.value(2 ether)();                 // victim funds\n'
                f'        target.{dep}.value(1 ether)();                // our stake')

    victim_contract = "" if shape["deposit_takes_address"] else f"""
contract {c}_Victim {{
    {c} internal t;
    constructor({c} _t) public {{ t = _t; }}
    function fund() public payable {{ t.{dep}.value(msg.value)(); }}
    function () external payable {{}}
}}
"""
    victim_field = "" if shape["deposit_takes_address"] else f"    {c}_Victim internal victim;\n"
    victim_init = "" if shape["deposit_takes_address"] else f"        victim = new {c}_Victim(target);\n"

    harness = f"""pragma solidity {pragma};

// Auto-generated reentrancy harness. Oracle: never get back more than you put in.
import "{target_import}";
{victim_contract}
contract {hname} {{
    {c} internal target;
{victim_field}    uint256 public ownDeposit;
    uint256 public received;
    bool internal attacking;

    constructor() public payable {{
        target = new {c}();
{victim_init}    }}

    function setup() public {{
        if (ownDeposit == 0 && address(this).balance >= 3 ether) {{
{seed}
            ownDeposit = 1 ether;
        }}
    }}

    function attack() public {{
        if (ownDeposit > 0) {{
            attacking = true;
            {wcall};
            attacking = false;
        }}
    }}

    function () external payable {{
        if (attacking) {{   // count ONLY re-entrant callbacks, not ether Echidna sends us directly
            received += msg.value;
            if (address(target).balance >= 1 ether) {{
                {wcall};   // re-enter before the ledger updates
            }}
        }}
    }}

    function echidna_no_reentrancy_theft() public view returns (bool) {{
        return received <= ownDeposit;
    }}
}}
"""
    return harness, hname


# --- access control --------------------------------------------------------- #
def detect_access_control_shape(src: str) -> dict | None:
    """Privileged owner var + a setter for it. Semantic (Slither) when available,
    else regex. Oracle reads ownership via the public getter, or (private owner)
    probes a guarded twin."""
    return _detect_access_control_slither(src) or _detect_access_control_regex(src)


def _detect_access_control_slither(src: str) -> dict | None:
    """Slither: an `address` owner var, the functions that WRITE it (setters), and
    which are guarded (have a modifier). Probe = a guarded address-setter twin."""
    pragma = _pragma(src)
    contracts = _slither_contracts(src, pragma)
    if contracts is None:
        return None
    for c in contracts:
        if not c.is_fully_implemented:
            continue   # abstract/interface -> can't `new C()`
        owner = None
        owner_public = False
        for sv in c.state_variables:
            if str(sv.type) == "address" and _PRIV_NAME.search(sv.name):
                owner = sv.name
                owner_public = str(sv.visibility) == "public"
                break
        if not owner:
            continue
        setters = []
        probe = None
        for f in c.functions:
            if f.is_constructor or str(f.visibility) not in ("public", "external"):
                continue
            if owner not in [v.name for v in f.state_variables_written]:
                continue
            takes_addr = any("address" in str(p.type) for p in f.parameters)
            setters.append({"name": f.name, "takes_address": takes_addr})
            if probe is None and bool(f.modifiers) and takes_addr:   # guarded twin probe
                probe = f.name
        if not setters or (not owner_public and probe is None):
            continue
        return {"contract": c.name, "pragma": pragma, "owner_var": owner,
                "owner_public": owner_public, "setters": setters, "probe": probe}
    return None


def _detect_access_control_regex(src: str) -> dict | None:
    """Fallback: text-pattern owner var + setter detection."""
    pragma = _pragma(src)
    src = _strip_comments(src)
    cm = _CONTRACT.search(src)
    if not cm:
        return None
    contract = cm.group(1)

    owner_var = None
    owner_public = False
    for m in re.finditer(r"address\s+(public\s+|private\s+|internal\s+)?(\w+)\s*[;=]", src):
        if _PRIV_NAME.search(m.group(2)):
            owner_var = m.group(2)
            owner_public = "public" in (m.group(1) or "")
            break
    if not owner_var:
        return None

    assign_re = re.compile(rf"\b{re.escape(owner_var)}\s*=(?!=)")
    setters = []
    probe = None
    for name, params, tail in _functions(src):
        if name == contract:                        # constructor
            continue
        head, body = _head_body(tail)
        if not assign_re.search(body):
            continue
        takes_addr = "address" in params
        guarded = _is_guarded(head, body, owner_var)
        setters.append({"name": name, "takes_address": takes_addr})
        if probe is None and guarded and takes_addr:
            probe = name
    if not setters:
        return None
    if not owner_public and probe is None:          # ownership not observable
        return None
    return {"contract": contract, "pragma": pragma, "owner_var": owner_var,
            "owner_public": owner_public, "setters": setters, "probe": probe}


def synthesize_access_control_harness(src: str, target_import: str) -> tuple[str, str] | None:
    """Build an access-control harness: a non-owner attacks every owner-setter."""
    shape = detect_access_control_shape(src)
    if not shape:
        return None
    if _ctor_requires_args(src, shape["contract"]):
        return None   # can't `new C()` with required ctor args -> defer to M3
    c, pragma, ov = shape["contract"], shape["pragma"], shape["owner_var"]
    setters, probe = shape["setters"], shape["probe"]
    hname = f"{c}_AutoAccessControlHarness"

    grabs, attacks = [], []
    for i, s in enumerate(setters):
        call = f"t.{s['name']}(address(this));" if s["takes_address"] else f"t.{s['name']}();"
        grabs.append(f"    function grab{i}({c} t) public {{ {call} }}")
        attacks.append(f"    function attack{i}() public {{ attacker.grab{i}(target); }}")
    grabs_src = "\n".join(grabs)
    attacks_src = "\n".join(attacks)

    if shape["owner_public"]:
        owner_field = "    address internal expectedOwner;\n"
        capture = f"        expectedOwner = target.{ov}();\n"
        oracle = f"""    // Oracle: ownership never leaves the deployer.
    function echidna_owner_unchanged() public view returns (bool) {{
        return target.{ov}() == expectedOwner;
    }}"""
    else:
        # Private owner: probe a guarded owner-setter twin with our own address.
        # It succeeds only while we are still the owner; reverts once seized.
        owner_field = ""
        capture = ""
        oracle = f"""    // Oracle: probe the guarded twin; it reverts once ownership is seized.
    function echidna_owner_retained() public returns (bool) {{
        return address(target).call(bytes4(keccak256("{probe}(address)")), address(this));
    }}"""

    harness = f"""pragma solidity {pragma};

// Auto-generated access-control harness. A non-owner calls every owner-setter.
import "{target_import}";

contract {c}_Attacker {{
{grabs_src}
}}

contract {hname} {{
    {c} internal target;
    {c}_Attacker internal attacker;
{owner_field}
    constructor() public payable {{   // payable: balanceContract funding at deploy
        target = new {c}();
        attacker = new {c}_Attacker();
{capture}    }}

{attacks_src}

{oracle}
}}
"""
    return harness, hname


# --- ordering / transaction-order dependence -------------------------------- #
def detect_ordering_shape(src: str) -> dict | None:
    """Single-pot reward game: a zero-arg payable funder + a claim that pays the
    caller. Semantic (Slither) when available, else regex."""
    return _detect_ordering_slither(src) or _detect_ordering_regex(src)


def _detect_ordering_slither(src: str) -> dict | None:
    """Slither: a zero-arg payable funder + a non-payable function that sends ETH
    (the claim). A balance ledger means it's really a pool -> defer to reentrancy."""
    pragma = _pragma(src)
    contracts = _slither_contracts(src, pragma)
    if contracts is None:
        return None
    for c in contracts:
        if not c.is_fully_implemented:
            continue   # abstract/interface -> can't `new C()`
        if any(_is_balance_ledger(sv) for sv in c.state_variables):
            continue
        funder = None
        claimer = None
        claimer_params = ""
        for f in c.functions:
            if f.is_constructor or str(f.visibility) not in ("public", "external"):
                continue
            if f.payable and len(f.parameters) == 0 and funder is None:
                funder = f.name
            if f.can_send_eth() and not f.payable and claimer is None and all(p.name for p in f.parameters):
                claimer = f.name
                claimer_params = ", ".join(f"{p.type} {p.name}" for p in f.parameters)
        if funder and claimer and funder != claimer:
            return {"contract": c.name, "pragma": pragma, "funder": funder,
                    "claimer": claimer, "claimer_params": claimer_params}
    return None


def _detect_ordering_regex(src: str) -> dict | None:
    """Fallback: a zero-arg payable funder + a claim function that pays msg.sender."""
    pragma = _pragma(src)
    src = _strip_comments(src)
    cm = _CONTRACT.search(src)
    if not cm or _BALANCE_LEDGER.search(src):
        return None

    funder = None
    claimer = None
    claimer_params = ""
    for name, params, tail in _functions(src):
        head, body = _head_body(tail)
        if "payable" in head and params.strip() == "" and funder is None:
            funder = name
        if re.search(r"msg\.sender\s*\.\s*(transfer|send|call)", body) and claimer is None:
            claimer = name
            claimer_params = params.strip()
    if not (funder and claimer) or funder == claimer:
        return None
    return {"contract": cm.group(1), "pragma": pragma, "funder": funder,
            "claimer": claimer, "claimer_params": claimer_params}


def synthesize_ordering_harness(src: str, target_import: str) -> tuple[str, str] | None:
    """Build an ordering/TOD harness: owner funds the prize, a non-owner claims it."""
    shape = detect_ordering_shape(src)
    if not shape:
        return None
    if _ctor_requires_args(src, shape["contract"]):
        return None   # can't `new C()` with required ctor args -> defer to M3
    c, pragma = shape["contract"], shape["pragma"]
    funder, claimer, cparams = shape["funder"], shape["claimer"], shape["claimer_params"]
    hname = f"{c}_AutoOrderingHarness"
    decl = cparams
    args = _param_names(cparams)
    steal_sig = f"{c} g" + (", " + decl if decl else "")
    steal_call = f"g.{claimer}({args});" if args else f"g.{claimer}();"
    attack_sig = decl
    steal_args = "game" + (", " + args if args else "")

    harness = f"""pragma solidity {pragma};

// Auto-generated ordering/TOD harness. Oracle: an unearned account holds nothing.
import "{target_import}";

contract {c}_Attacker {{
    function steal({steal_sig}) public {{ {steal_call} }}
    function () external payable {{}}   // empty: fits transfer's 2300-gas stipend
}}

contract {hname} {{
    {c} internal game;
    {c}_Attacker internal attacker;
    uint256 public seeded;

    constructor() public payable {{
        game = new {c}();
        attacker = new {c}_Attacker();
    }}

    function setup() public {{
        if (seeded == 0 && address(this).balance >= 1 ether) {{
            game.{funder}.value(1 ether)();
            seeded = 1 ether;
        }}
    }}

    function attack({attack_sig}) public {{
        if (seeded > 0) {{
            attacker.steal({steal_args});
        }}
    }}

    function () external payable {{}}

    function echidna_reward_not_stolen() public view returns (bool) {{
        return address(attacker).balance == 0;
    }}
}}
"""
    return harness, hname


# --- oracle manipulation (recognition only) --------------------------------- #
def detect_oracle_shape(src: str) -> dict | None:
    """Recognise an oracle-manip surface (settable price + a borrow/value check).
    No harness is built: a market can't be templated from source, that's M3."""
    pragma = _pragma(src)
    clean = _strip_comments(src)
    cm = _CONTRACT.search(clean)
    if not cm:
        return None
    has_price = re.search(r"price|getprice|latestanswer|exchangerate|oracle|getreserves", clean, re.I)
    has_value = re.search(r"borrow|collateral|liquidat|loan|debt|lend|swap|redeem", clean, re.I)
    if has_price and has_value:
        return {"contract": cm.group(1), "pragma": pragma}
    return None


# --- dispatcher ------------------------------------------------------------- #
@dataclass
class Synthesis:
    """Result of trying to synthesize a harness."""
    vuln_type: str | None
    harness_src: str | None
    harness_name: str | None
    note: str

    @property
    def built(self) -> bool:
        return self.harness_src is not None


_VALUE_TYPE = re.compile(r"^(uint\d*|int\d*|address|bool|bytes\d*|string|bytes)(\[\])?$")


def _fwd_type(t: str) -> str | None:
    """Solidity param type Echidna can fuzz AND we can forward, or None to skip the
    function. Value types + string/bytes + 1-D arrays of them. Structs, tuples, enums,
    contract/interface types, mappings, and 2-D arrays are skipped (can't be fuzzed as a
    plain harness param), so a function with one is simply not forwarded -- coverage loss
    on that function, never a compile error."""
    t = t.strip()
    base = t.replace(" payable", "")   # test the base type, but KEEP `address payable` in the
    return t if _VALUE_TYPE.match(base) else None   # decl -- solc won't implicitly widen address->payable


def _concrete_main(src: str, pragma: str):
    """The target contract to fuzz: the concrete (deployable) contract with the largest
    public/external surface. Skips abstract/interface/library. None if Slither can't parse."""
    contracts = _slither_contracts(src, pragma)
    if not contracts:
        return None
    best, best_n = None, -1
    for c in contracts:
        if not c.is_fully_implemented or c.is_interface or c.contract_kind in ("interface", "library"):
            continue
        n = sum(1 for f in c.functions
                if not f.is_constructor and str(f.visibility) in ("public", "external"))
        if n > best_n:
            best, best_n = c, n
    return best


def _default_literal(t: str) -> str | None:
    """A concrete default for a constructor parameter of value type `t`, so a target with a
    non-empty constructor can still be deployed (`new C(defaults...)`). None if the type isn't
    a plain value type / string -> caller defers rather than emit uncompilable code."""
    base = t.strip().replace(" payable", "")
    if re.match(r"^uint\d*$", base) or re.match(r"^int\d*$", base):
        return "1"
    if base == "address":
        return "address(0x1)"
    if base == "bool":
        return "true"
    if base == "string":
        return '"x"'
    if base == "bytes":
        return '""'
    m = re.match(r"^bytes(\d+)$", base)
    if m:
        return f"bytes{m.group(1)}(0)"
    return None


def _ctor_args(c, src: str) -> str | None:
    """Literal argument list for `c`'s constructor: '' if none needed, a string like
    '1, address(0x1)' if all params are value types, or None if any param can't be defaulted
    (array/struct/contract) -> the target isn't template-deployable."""
    if not _ctor_requires_args(src, c.name):
        return ""
    ctor = getattr(c, "constructor", None)
    if ctor is None:
        return None
    lits = []
    for p in ctor.parameters:
        lit = _default_literal(str(p.type))
        if lit is None:
            return None
        lits.append(lit)
    return ", ".join(lits)


def _forwarder_specs(c, pragma: str) -> list[dict]:
    """One record per forwardable public/external function of `c`: the generated forwarder
    name (`call_<fn>_<n>`), the source function name, the declared param types (address widened
    to `address payable` on 0.5+), the raw target param types (for ABI seed encoding), and
    whether it's payable. Shared by the harness builder and the AI seed encoder so the seed
    targets the exact forwarder names Echidna sees."""
    payable_addr = _resolve_solc(pragma)[:2] >= (0, 5)
    seen: dict[str, int] = {}
    specs = []
    for f in c.functions:
        if f.is_constructor or getattr(f, "is_fallback", False) or getattr(f, "is_receive", False):
            continue
        if not f.name or str(f.visibility) not in ("public", "external") or f.view or f.pure:
            continue
        decl_types, raw_types, ok = [], [], True
        for p in f.parameters:
            ft = _fwd_type(str(p.type))
            if ft is None:
                ok = False
                break
            raw_types.append(ft)
            decl_types.append("address payable" if (ft == "address" and payable_addr) else ft)
        if not ok:
            continue
        n = seen.get(f.name, 0)
        seen[f.name] = n + 1
        specs.append({"call_name": f"call_{f.name}_{n}", "fn": f.name,
                      "decl_types": decl_types, "raw_types": raw_types, "payable": bool(f.payable),
                      "param_names": [(p.name or "") for p in f.parameters]})
    return specs


_AUTH_PARAM = re.compile(r"owner|admin|operator|creator|governor|manager|auth", re.I)
_RECIP_PARAM = re.compile(r"recipient|receiver|to|dest|target|payee|beneficiar", re.I)


def _is_unearned_drain(src: str, c, fname: str) -> bool:
    """Is a payout from `fname` THEFT rather than a legitimate claim? Only unearned, unguarded
    drains qualify; measured against clean mainnet contracts, the two false-positive sources are:

    1. ENTITLEMENTS. A payout sized from a `msg.sender`-indexed mapping (`affiliateCommision
       [msg.sender]`, `getProfit(msg.sender)`) is money the protocol OWES the caller. The
       attacker can be credited legitimately -- e.g. named as a referral -- and withdrawing that
       is correct behaviour, not a bug.
    2. DELEGATED AUTHORITY. The harness deploys the target, so it is the owner/author. Its own
       legitimate privileged calls (`setCoAuthor(attacker)`) can grant the attacker rights, after
       which a guarded withdrawal succeeds honestly. Any real guard therefore disqualifies the
       function -- EXCEPT a `tx.origin == <parameter>` check, which is not a guard at all because
       the caller supplies both sides.

    So: attack only functions that are unguarded (or guarded solely by a caller-supplied
    tx.origin comparison) AND whose payout is not per-caller accounted."""
    body = _fn_body(src, fname)
    if body is None:
        return False
    txorigin_param_guard = re.search(r"tx\s*\.\s*origin\s*==|==\s*tx\s*\.\s*origin", body) is not None
    if re.search(r"\[\s*msg\s*\.\s*sender\s*\]", body):
        return False                                   # entitlement, not theft
    if re.search(r"\(\s*msg\s*\.\s*sender\s*[,)]", body) and not txorigin_param_guard:
        return False                                   # per-caller accounting (_burn(msg.sender, n))
    if not txorigin_param_guard:
        # ANY msg.sender comparison is an access check, in either operand order and inside a
        # require or an if (`if (receiver == msg.sender && ...)` guards just as effectively as
        # `require(msg.sender == owner)`). Matching only the canonical form let a guarded
        # withdrawal through as theft.
        if re.search(r"msg\s*\.\s*sender\s*[=!]=|[=!]=\s*msg\s*\.\s*sender", body):
            return False                               # inline access check
        for f in c.functions:                          # modifier-based access check
            if f.name == fname and getattr(f, "modifiers", None):
                return False
        called = set(re.findall(r"\b(\w+)\s*\(", body))
        if called & _guard_fn_names(src):              # guard invoked as an internal call
            return False
    return True


def _fn_body(src: str, fname: str) -> str | None:
    """Source text of `fname`'s body, brace-matched (regex alone stops at the first `}`).
    Abstract/interface declarations (`function f(...) public;`) have no body -- taking the next
    `{` there would silently return a LATER function's body and misjudge it, so a signature whose
    header terminates in `;` is skipped and the search continues to the real definition."""
    for m in re.finditer(rf"function\s+{re.escape(fname)}\s*\(", src):
        i, semi = src.find("{", m.end()), src.find(";", m.end())
        if i < 0 or (0 <= semi < i):
            continue                       # declaration only, not this one
        depth = 0
        for j in range(i, len(src)):
            if src[j] == "{":
                depth += 1
            elif src[j] == "}":
                depth -= 1
                if depth == 0:
                    return src[i:j + 1]
    return None


def _guard_fn_names(src: str) -> set[str]:
    """Internal helpers that ARE access checks (`function _only_owner() { require(msg.sender ==
    owner); }`). A guard invoked as a plain call is invisible to a modifier or inline-require
    scan, so those names are collected once and treated as guards wherever they are called."""
    out = set()
    for m in re.finditer(r"function\s+(\w+)\s*\(", src):
        b = _fn_body(src, m.group(1))
        if b and len(b) < 400 and re.search(r"msg\s*\.\s*sender\s*[=!]=|[=!]=\s*msg\s*\.\s*sender", b):
            out.add(m.group(1))
    return out


def _ownership_setters(src: str, c) -> set[str]:
    """Functions that reassign an owner-like state variable. The harness deploys the target and
    is therefore its owner, so forwarding these lets Echidna legitimately hand ownership to the
    attacker -- after which a properly-guarded withdrawal succeeds and looks like theft. They are
    withheld from the forwarders so authority cannot be delegated mid-run."""
    owners = {v.name for v in getattr(c, "state_variables", [])
              if re.search(r"owner|admin|author|governor|operator", v.name, re.I)}
    out = set()
    for f in getattr(c, "functions", []):
        if f.is_constructor or str(f.visibility) not in ("public", "external"):
            continue
        b = _fn_body(src, f.name)
        if b and any(re.search(rf"\b{re.escape(o)}\b\s*(\[[^\]]*\])?\s*=[^=]", b) for o in owners):
            out.add(f.name)
    return out


def _guarded_eth_senders(src: str, c) -> set[str]:
    """Ether-sending functions behind an access guard. The harness both DEPLOYS the target (so it
    is the owner) and plays the attacker for value accounting -- it cannot be both. Forwarding an
    owner-only withdrawal lets the harness legitimately collect user deposits, which the
    `_got <= _sent` invariant then reads as extraction (measured: exactly this sequence,
    `setup_attack(); call_withdrawEth_0()`, on a clean token-sale contract). Withholding them
    costs no detection, because the attacker cannot call a guarded function anyway."""
    guarded, out = _guard_fn_names(src), set()
    for f in getattr(c, "functions", []):
        if f.is_constructor or str(f.visibility) not in ("public", "external"):
            continue
        try:
            if not f.can_send_eth():
                continue
        except Exception:
            continue
        b = _fn_body(src, f.name)
        if b is None:
            continue
        if re.search(r"tx\s*\.\s*origin\s*==|==\s*tx\s*\.\s*origin", b):
            continue                                   # not a real guard: caller supplies both sides
        if (getattr(f, "modifiers", None)
                or re.search(r"msg\s*\.\s*sender\s*[=!]=|[=!]=\s*msg\s*\.\s*sender", b)
                or (set(re.findall(r"\b(\w+)\s*\(", b)) & guarded)):
            out.add(f.name)
    return out


def _monotone_twin(src: str, var: str) -> str | None:
    """A second accumulator incremented by the SAME expression as `var` but never decremented.
    Where `var` is a live balance that goes up and down (bondsHeld), the twin is the lifetime
    total (bondsEver) -- and a solvency bound must be stated against the lifetime total, since
    the live balance can be drained to zero while the debt it backed remains outstanding."""
    for m in re.finditer(rf"\b{re.escape(var)}\s*\+=\s*(\w+)\s*;", src):
        expr = m.group(1)
        for t in re.finditer(rf"\b(\w+)\s*\+=\s*{re.escape(expr)}\s*;", src):
            cand = t.group(1)
            if cand != var and not re.search(rf"\b{re.escape(cand)}\s*-=", src):
                return cand
    return None


def _detect_price_solvency(src: str, c) -> dict | None:
    """Oracle-manipulation shape: a solvency rule enforced against a price that an arbitrary
    caller can rewrite. The contract declares a trusted reference (`uint constant C = 100`)
    alongside a mutable price seeded to the same value; if any caller can move the price, the
    solvency check it guards is meaningless. The invariant is therefore the contract's own
    solvency rule RE-EVALUATED AT THE TRUSTED CONSTANT -- a standard DeFi fuzzing invariant, and
    the fuzzer must still discover the manipulate-then-borrow sequence itself.

    Two accumulation shapes occur: bounded (`require(debt + x <= coll * price)`) and direct
    (`debt += x * price`). Returns {debt, coll, lit} naming the public getters to compare."""
    cons = re.findall(r"uint\d*\s+(?:public\s+|internal\s+|private\s+)?constant\s+(\w+)\s*=\s*(\d+)", src)
    if not cons:
        return None
    guarded = _guard_fn_names(src)
    for _, lit in cons:
        for m in re.finditer(r"uint\d*\s+public\s+(\w+)\s*=\s*(\d+)\s*;", src):
            price = m.group(1)
            if m.group(2) != lit:
                continue                    # not seeded to the trusted reference value
            if not _has_unguarded_writer(src, c, price, guarded):
                continue
            r1 = re.search(rf"require\s*\(\s*(\w+)\s*\+\s*\w+\s*<=\s*(\w+)\s*\*\s*{re.escape(price)}\b", src)
            if r1:
                return {"debt": r1.group(1), "coll": r1.group(2), "lit": lit}
            r2 = re.search(rf"(\w+)\s*\+=\s*(\w+)\s*\*\s*{re.escape(price)}\b", src)
            if r2:
                rb = re.search(rf"require\s*\(\s*{re.escape(r2.group(2))}\s*<=\s*(\w+)", src)
                if rb:
                    base = _monotone_twin(src, rb.group(1)) or rb.group(1)
                    return {"debt": r2.group(1), "coll": base, "lit": lit}
    return None


def _has_unguarded_writer(src: str, c, var: str, guarded: set[str]) -> bool:
    """Can an arbitrary caller rewrite `var`? True only for a public function that assigns it
    with no modifier, no inline msg.sender check and no guard-helper call."""
    for f in getattr(c, "functions", []):
        if f.is_constructor or str(f.visibility) not in ("public", "external"):
            continue
        b = _fn_body(src, f.name)
        if not b or not re.search(rf"\b{re.escape(var)}\s*=[^=]", b):
            continue
        if getattr(f, "modifiers", None):
            continue
        if re.search(r"msg\s*\.\s*sender\s*[=!]=", b) or (set(re.findall(r"\b(\w+)\s*\(", b)) & guarded):
            continue
        return True
    return False


def _attack_args(spec, v6: bool) -> str | None:
    """Strategic arguments for an attack wrapper, or None if the signature isn't attackable.

    Several real vulnerability patterns take the *authority* as a caller-supplied PARAMETER --
    e.g. `withdrawAll_txorigin(address payable _recipient, address owner)` guarded by
    `require(tx.origin == owner)`. Passing `tx.origin` for the authority parameter satisfies the
    check trivially, and passing `address(this)` for the recipient directs the funds to the
    attacker. A random fuzzer essentially never samples this exact pair, which is why these
    functions are executed but never exploited. Choosing the arguments deterministically turns
    an unreachable branch into a reproducible extraction.
    """
    args = []
    for t, nm in zip(spec["raw_types"], spec["param_names"]):
        base = t.replace(" payable", "")
        if base == "address":
            if _AUTH_PARAM.search(nm or ""):
                args.append("tx.origin")                       # satisfies tx.origin authority checks
            elif t.endswith("payable") or _RECIP_PARAM.search(nm or ""):
                args.append("address(uint160(address(this)))" if not v6 else "payable(address(this))")
            else:
                args.append("address(this)")
        elif re.match(r"uint\d*$", base):
            args.append("1")                                    # small, always-affordable amount
        elif re.match(r"int\d*$", base):
            args.append("1")
        elif base == "bool":
            args.append("true")
        else:
            return None                                         # string/bytes/array -> skip
    return ", ".join(args)


def coverage_forwarder_specs(src: str) -> tuple[str, list[dict]] | None:
    """(harness_contract_name, forwarder specs) for the coverage harness of `src`, or None if
    it can't be built. Lets the AI arm generate seed sequences over the exact forwarder API."""
    pragma = _pragma(src)
    c = _concrete_main(src, pragma)
    if c is None or _ctor_args(c, src) is None:
        return None
    specs = _forwarder_specs(c, pragma)
    if not specs:
        return None
    return f"{c.name}_CoverageHarness", specs


def _selfdestruct_fns(src: str, c) -> list[str]:
    """No-arg public/external functions of `c` that call selfdestruct/suicide AND are UNGUARDED
    (no modifier, no `msg.sender`/`tx.origin ==` authorization check). A non-owner attacker calls
    each; if the contract is destroyed (extcodesize -> 0) the destruct was genuinely unprotected
    -> a real access-control bug. Requiring 'unguarded' is what keeps it FP-safe: a guarded
    destruct (`onlyOwner`, `require(msg.sender==owner)`) is skipped, so we never flag a contract
    whose destruct is protected."""
    clean = _strip_comments(src)
    out = []
    for f in c.functions:
        if f.is_constructor or f.name == "" or str(f.visibility) not in ("public", "external"):
            continue
        if f.parameters:   # no-arg only, so the attacker can call it blindly
            continue
        try:
            calls = " ".join(str(x) for x in f.all_solidity_calls())
        except Exception:
            calls = ""
        if "selfdestruct" not in calls and "suicide" not in calls:
            continue
        if getattr(f, "modifiers", None):   # any modifier -> assume it guards; skip
            continue
        m = re.search(rf"function\s+{re.escape(f.name)}\s*\([^)]*\)[^{{]*\{{(.*?)\n\s*\}}", clean, re.S)
        body = m.group(1) if m else ""
        if re.search(r"(require|assert|if)\s*\([^)]*(msg\.sender|tx\.origin)\s*==", body):
            continue   # inline sender authorization -> guarded; skip
        out.append(f.name)
    return out


def synthesize_coverage_harness(src: str, target_import: str,
                                reentrant: bool = False) -> tuple[str, str] | None:
    """Generic, dynamic, per-CLASS harness (one assembled harness per contract). It always
    forwards the target's public ABI so Echidna explores the whole contract (coverage), then
    attaches the ORACLE that matches each vulnerability shape Slither detects:

      * reentrancy     -> re-entrant fallback + value-extraction invariant (_got <= _sent)
      * access-control -> a NON-owner Attacker calls each ownership setter + `owner unchanged`
      * ordering/theft -> the value-extraction invariant (reward pulled without contributing)

    This is the professor's model: a small set of generic class templates, specialised per
    contract via ABI introspection. Returns (harness_src, name) or None if the target can't be
    parsed/deployed. `reentrant` is retained for callers that force it; the shape is otherwise
    auto-detected."""
    pragma = _pragma(src)
    c = _concrete_main(src, pragma)
    if c is None:
        return None
    cargs = _ctor_args(c, src)
    if cargs is None:
        return None   # ctor needs a non-value arg we can't default -> defer, don't emit broken code
    specs = _forwarder_specs(c, pragma)
    if not specs:
        return None

    v6 = _resolve_solc(pragma)[:2] >= (0, 6)
    reent = detect_reentrancy_shape(src)
    reentrant = reentrant or (reent is not None)
    # Access-control oracle DISABLED. An `owner unchanged` invariant cannot distinguish a
    # protected owner from an address field that is settable BY DESIGN (fee recipient, operator).
    # A re-enable was attempted once the harness could no longer delegate ownership itself
    # (_ownership_setters withholds those setters from the forwarders), on the theory that this
    # was the sole false-positive cause. Measured: it detected 0/4 of the access-control misses
    # and introduced 3 new false positives on 27 clean contracts, so the theory was wrong and the
    # oracle is left off. Access-control recall via generic fuzzing is a stated limitation.
    ac = None
    ac_setters = set()
    # Unprotected-selfdestruct detection (FP-safe): a non-owner attacker calls each destruct
    # function; the oracle checks the target still has code. A guarded destruct reverts for the
    # attacker -> no false positive. These functions are excluded from the normal forwarders so
    # the harness (the deployer) can't legitimately self-destruct the target and trip the oracle.
    sd_fns = _selfdestruct_fns(src, c)
    excluded = ac_setters | set(sd_fns) | _ownership_setters(src, c) | _guarded_eth_senders(src, c)
    # Reentrancy PoC setup: pick the payable no-arg deposit and the ether-sending withdraw(s).
    # A VICTIM deposits first (so the target holds ether the attacker doesn't own), then the
    # attacker deposits a little and drains via re-entry -> it extracts MORE than it deposited
    # (`_got > _sent`). A safe contract zeroes the balance before paying, so re-entry withdraws
    # 0 and the oracle holds -> no false positive.
    send_eth_names = set()
    for f in c.functions:
        try:
            if not f.is_constructor and str(f.visibility) in ("public", "external") and f.can_send_eth():
                send_eth_names.add(f.name)
        except Exception:
            pass
    # Deposit = a payable entry point that credits the caller. Accept BOTH `deposit()` and the
    # very common `donate(address to) payable` / `depositFor(address)` shape -- restricting to
    # no-arg deposits silently skipped contracts like simple_dao, so the pool was never funded
    # and the reentrancy could never be triggered.
    deposit_fn, deposit_arg = None, ""
    if reentrant:
        cands = []
        for s in specs:
            if not s["payable"] or s["fn"] in excluded or s["fn"] in send_eth_names:
                continue
            rt = s["raw_types"]
            if len(rt) == 0:
                cands.append((0, s["fn"], ""))
            elif len(rt) == 1 and rt[0].replace(" payable", "") == "address":
                cands.append((1, s["fn"], "address(this)"))
        if cands:
            cands.sort(key=lambda x: x[0])      # prefer the no-arg deposit when both exist
            _, deposit_fn, deposit_arg = cands[0]
            excluded = excluded | {deposit_fn}

    # Forwarders for coverage. When access-control is active we do NOT forward its ownership
    # setters -- otherwise the harness (which IS the deployer/owner) could change ownership
    # legitimately and trip the invariant -> a false positive. Only the Attacker touches them.
    fwds = []
    for s in specs:
        if s["fn"] in excluded:
            continue
        decls = ", ".join(f"{t}{' memory' if (t.endswith('[]') or t in ('string','bytes')) else ''} a{i}"
                          for i, t in enumerate(s["decl_types"]))
        argn = ", ".join(f"a{i}" for i in range(len(s["decl_types"])))
        pay = " payable" if s["payable"] else ""
        val = "{value: msg.value}" if (s["payable"] and v6) else (".value(msg.value)" if s["payable"] else "")
        track = "_sent += msg.value; " if s["payable"] else ""
        fwds.append(f"    function {s['call_name']}({decls}) public{pay} "
                    f"{{ {track}target.{s['fn']}{val}({argn}); }}")

    hname = f"{c.name}_GenericHarness"
    sub, fields, init, extra, oracles = [], [], [], [], []
    oracles.append("    function echidna_coverage_probe() public pure returns (bool) { return true; }")
    # value-extraction invariant (reentrancy + ether-theft ordering)
    oracles.append("    function echidna_no_value_extraction() public view returns (bool) { return _got <= _sent; }")

    # Force-funder: a contract with no payable entry point can still be given a balance, because
    # `selfdestruct(target)` credits it unconditionally -- a real EVM primitive an attacker can
    # use. Without this, a drain such as `_recipient.transfer(address(this).balance)` moves 0 wei
    # and the theft is unobservable, so the target is force-funded before the attack wrappers run.
    if send_eth_names:
        mmf = _resolve_solc(pragma)[:2]
        fctor = ("constructor(address payable t) public payable" if (0, 5) <= mmf < (0, 7) else
                 "constructor(address payable t) payable" if mmf >= (0, 7) else
                 f"function {c.name}_Forcer(address t) public payable")
        cast = ("address(uint160(address(target)))" if (0, 5) <= mmf < (0, 6)
                else "payable(address(target))" if mmf >= (0, 6) else "address(target)")
        sub.append(f"contract {c.name}_Forcer {{\n    {fctor} {{ selfdestruct(t); }}\n}}")
        newf = (f"(new {c.name}_Forcer).value(2 ether)({cast})" if mmf < (0, 6)
                else f"new {c.name}_Forcer{{value: 2 ether}}({cast})")
        # The force-fed 2 ether comes from the HARNESS, so it counts as `_sent`. Without this the
        # harness could withdraw its own force-fed ether through a perfectly legitimate (even
        # owner-guarded) path and the `_got <= _sent` invariant would read it as extraction.
        extra.append(f"    function force_fund() public {{ if (!_forced && address(this).balance >= 2 ether) "
                     f"{{ _forced = true; _sent += 2 ether; {newf}; }} }}")
        fields.append("    bool internal _forced;")

    # Targeted attack wrappers: call each ether-sending function with STRATEGIC arguments
    # (tx.origin for an authority parameter, the attacker's address for a recipient) instead of
    # the random values Echidna samples. Patterns such as `require(tx.origin == ownerParam)` are
    # satisfied deterministically this way, converting a branch that is merely executed into one
    # that is actually exploited.
    #
    # The payout is received by a DEDICATED attacker contract, not by the harness, for two
    # reasons. (1) Gas: `transfer`/`send` forward only a 2300-gas stipend, so a receive hook that
    # writes storage (`_got += msg.value`) exceeds the stipend and reverts the whole withdrawal --
    # the theft could never be observed. The attacker's payable fallback is empty and fits.
    # (2) Semantics: the attacker never deposits and never sends ether anywhere, so ANY balance it
    # holds is ether extracted from the target, making `balance == 0` an exact theft oracle.
    val_atk = []
    for s in specs:
        if s["fn"] not in send_eth_names or s["fn"] in excluded:
            continue
        if not _is_unearned_drain(src, c, s["fn"]):
            continue
        aa = _attack_args(s, v6)
        if aa is not None:
            val_atk.append((s["fn"], aa))
        if len(val_atk) >= 12:
            break
    if val_atk:
        mmv = _resolve_solc(pragma)[:2]
        v_ctor = (f"constructor({c.name} _t)" if mmv >= (0, 7) else
                  f"constructor({c.name} _t) public" if _resolve_solc(pragma) >= (0, 4, 22)
                  else f"function {c.name}_ValAttacker({c.name} _t) public")
        v_recv = ("    receive() external payable {}\n    fallback() external payable {}"
                  if mmv >= (0, 6) else "    function () external payable {}")
        grabs = "\n".join(f"    function take{i}() public {{ t.{fn}({aa}); }}"
                          for i, (fn, aa) in enumerate(val_atk))
        sub.append(f"contract {c.name}_ValAttacker {{\n    {c.name} t;\n"
                   f"    {v_ctor} {{ t = _t; }}\n{grabs}\n{v_recv}\n}}")
        fields.append(f"    {c.name}_ValAttacker internal _vatk;")
        init.append(f"        _vatk = new {c.name}_ValAttacker(target);")
        # Comment shows the underlying call+args -- without it, expanding the harness in the
        # dashboard shows an opaque `_vatk.take3()` with no indication this is a tx.origin
        # impersonation or which function is being drained (observed directly: a demo run showed
        # exactly this, and the reviewer couldn't tell an access-control bug was being exploited).
        extra.extend(f"    function attack_val_{i}() public {{ _vatk.take{i}(); }}"
                     f"  // drains via target.{fn}({aa})"
                     for i, (fn, aa) in enumerate(val_atk))
        oracles.append("    function echidna_no_theft() public view returns (bool) "
                       "{ return address(_vatk).balance == 0; }")

    # Access-control: a NON-owner attacker calls each setter in its OWN function (so a guarded
    # setter reverting can't roll back a bug found via another setter); invariant = owner intact.
    if ac:
        owner = ac["owner_var"]
        grabs, attacks = [], []
        for i, s in enumerate(ac["setters"]):
            arg = "address(this)" if s["takes_address"] else ""
            grabs.append(f"    function grab{i}() public {{ t.{s['name']}({arg}); }}")
            attacks.append(f"    function attack_ac_{i}() public {{ _acatk.grab{i}(); }}")
        sub.append(f"contract {c.name}_ACAttacker {{\n    {c.name} t;\n"
                   f"    constructor({c.name} _t) public {{ t = _t; }}\n" + "\n".join(grabs) + "\n}")
        fields.append(f"    {c.name}_ACAttacker internal _acatk;")
        fields.append("    address internal _owner0;")
        init.append(f"        _acatk = new {c.name}_ACAttacker(target);")
        init.append(f"        _owner0 = target.{owner}();")
        extra.extend(attacks)
        oracles.append(f"    function echidna_owner_unchanged() public view returns (bool) "
                       f"{{ return target.{owner}() == _owner0; }}")

    # Unprotected selfdestruct: attacker calls each destruct fn; oracle = target still has code.
    if sd_fns:
        mm = _resolve_solc(pragma)[:2]
        sd_ctor = (f"constructor({c.name} _t)" if mm >= (0, 7) else
                   f"constructor({c.name} _t) public" if mm >= (0, 4) and _resolve_solc(pragma) >= (0, 4, 22)
                   else f"function {c.name}_SDAttacker({c.name} _t) public")
        grabs = "\n".join(f"    function kill{i}() public {{ t.{fn}(); }}" for i, fn in enumerate(sd_fns))
        sub.append(f"contract {c.name}_SDAttacker {{\n    {c.name} t;\n"
                   f"    {sd_ctor} {{ t = _t; }}\n{grabs}\n}}")
        fields.append(f"    {c.name}_SDAttacker internal _sdatk;")
        init.append(f"        _sdatk = new {c.name}_SDAttacker(target);")
        extra.extend(f"    function attack_sd_{i}() public {{ _sdatk.kill{i}(); }}" for i in range(len(sd_fns)))
        oracles.append("    function echidna_not_destroyed() public view returns (bool) "
                       "{ uint256 sz; address tt = address(target); assembly { sz := extcodesize(tt) } return sz > 0; }")

    # Oracle manipulation: the target's own solvency rule, re-evaluated at its trusted reference
    # price instead of the caller-writable one. The forwarders already expose the price setter,
    # so Echidna must still find the manipulate-then-borrow sequence on its own.
    solv = _detect_price_solvency(src, c)
    if solv:
        oracles.append(f"    function echidna_price_solvent() public view returns (bool) "
                       f"{{ return target.{solv['debt']}() <= target.{solv['coll']}() * {solv['lit']}; }}")

    # Re-entrant fallback: when the target pays ether back, RE-ENTER the ether-sending withdraw
    # WITH ARGUMENTS (real withdraws take an amount), up to a bounded depth so the attacker drains
    # more than it deposited. Re-entering with `msg.value` (the amount just paid) reproduces the
    # classic drain. Depth is bounded to avoid out-of-gas.
    reentry_encs = []
    for s in specs:
        if s["fn"] not in send_eth_names or s["fn"] in excluded:
            continue
        rt = s["raw_types"]
        if len(rt) == 0:
            enc = f'abi.encodeWithSignature("{s["fn"]}()")'
        elif len(rt) == 1 and re.match(r"uint\d*$", rt[0]):
            enc = f'abi.encodeWithSignature("{s["fn"]}(uint256)", msg.value)'
        elif len(rt) == 1 and rt[0].replace(" payable", "") == "address":
            enc = f'abi.encodeWithSignature("{s["fn"]}(address)", address(this))'
        else:
            continue
        reentry_encs.append(enc)
        if len(reentry_encs) >= 4:
            break
    # Ether-theft detection (reentrancy OR unprotected withdrawal): a VICTIM funds the target so
    # it holds ether the attacker does not own; the attacker (harness, via forwarders + re-entry)
    # tries to extract it. If it gets out MORE than it put in (`_got > _sent`) -> theft. FP-safe:
    # a safe contract only returns your own deposit (got == sent) and guards privileged payouts.
    reentry = ""
    payable_fallback = any((getattr(f, "is_fallback", False) or getattr(f, "is_receive", False)) and f.payable
                           for f in c.functions)
    if send_eth_names and (deposit_fn or payable_fallback):
        mmv = _resolve_solc(pragma)[:2]
        dv = (lambda x: f"{{value: {x}}}" if v6 else f".value({x})")
        vctor = (f"constructor({c.name} _t) public payable" if mmv < (0, 7) else f"constructor({c.name} _t) payable")
        vfall = "receive() external payable {}\n    fallback() external payable {}" if v6 else "function () external payable {}"
        if deposit_fn:   # victim + attacker deposit via the deposit fn (arg = credit recipient)
            fund = f"t.{deposit_fn}{dv('msg.value')}({deposit_arg});"
            atk = f"target.{deposit_fn}{dv('1 ether')}({deposit_arg}); _sent = 1 ether;"
        else:            # no deposit fn: victim sends ether straight to the (payable) target; attacker deposits nothing
            fund = (f'(bool _fs,) = address(t).call{dv("msg.value")}(""); _fs;' if mmv >= (0, 5)
                    else f'address(t).call{dv("msg.value")}();')
            atk = ""
        sub.append(f"contract {c.name}_Victim {{\n    {c.name} t;\n    {vctor} {{ t = _t; }}\n"
                   f"    function fund() public payable {{ {fund} }}\n    {vfall}\n}}")
        fields.append(f"    {c.name}_Victim internal _victim;")
        fields.append("    bool internal _setup;")
        init.append(f"        _victim = new {c.name}_Victim(target);")
        extra.append(f"    function setup_attack() public {{ if (!_setup && address(this).balance >= 3 ether) {{ "
                     f"_setup = true; _victim.fund{dv('2 ether')}(); {atk} }} }}")
        if reentry_encs:
            calls = "".join(f'(bool _r{i},) = address(target).call({enc}); _r{i};\n            '
                            for i, enc in enumerate(reentry_encs))
            reentry = f" if (_reDepth < 6) {{ _reDepth++;\n            {calls}_reDepth--; }}"
            fields.append("    uint256 internal _reDepth;")
    guard = f"if (msg.sender == address(target)) {{ _got += msg.value;{reentry} }}"
    recv_block = (f"    receive() external payable {{ {guard} }}\n    fallback() external payable {{ {guard} }}"
                  if v6 else f"    function () external payable {{ {guard} }}")

    subs = ("\n".join(sub) + "\n\n") if sub else ""
    harness = f"""pragma solidity {pragma};

// Auto-generated GENERIC per-class harness: ABI forwarders (coverage) + the oracle for each
// vulnerability shape Slither detected on this contract.
import "{target_import}";

{subs}contract {hname} {{
    {c.name} internal target;
    uint256 internal _sent;
    uint256 internal _got;
{chr(10).join(fields)}
    constructor() public payable {{
        target = new {c.name}({cargs});
{chr(10).join(init)}
    }}

{chr(10).join(fwds)}
{chr(10).join(extra)}

{chr(10).join(oracles)}

{recv_block}
}}
"""
    return harness, hname


_BUILDERS = (
    ("reentrancy", synthesize_reentrancy_harness),
    ("access-control", synthesize_access_control_harness),
    ("ordering-attacks", synthesize_ordering_harness),
)


def _harness_compiles(harness_src: str, target_src: str, target_import: str) -> bool:
    """Compile-check a synthesised harness with its target (solcx). A detector can still
    mis-pick via the regex fallback (e.g. an abstract contract, which regex can't see is
    abstract in 0.5.x) -- only emit harnesses that actually COMPILE, else defer. The template
    must never hand the fuzzer broken code. If solcx is unavailable, don't block."""
    try:
        from .ai_guidance import _compile_check
    except Exception:
        return True
    try:
        ok, _ = _compile_check(harness_src, target_src, target_import, _pragma(harness_src))
        return ok
    except Exception:
        return True


def synthesize_all(src: str, target_import: str) -> list[Synthesis]:
    """Build a harness for EVERY templated shape the contract matches (0, 1, or
    several) — so one contract can be fuzzed for multiple vuln types. An empty
    list means no buildable shape; callers fall back to synthesize_harness() for
    the honest oracle-recognition / needs-M3 message."""
    builds = []
    for vtype, builder in _BUILDERS:
        out = builder(src, target_import)
        if out:
            harness_src, hname = out
            if _harness_compiles(harness_src, src, target_import):
                builds.append(Synthesis(vtype, harness_src, hname,
                                        f"Tier-2 synthesised a {vtype} harness ({hname})."))
    return builds


def synthesize_harness(src: str, target_import: str) -> Synthesis:
    """Try each shape; return the first harness that builds AND compiles, else recognise the
    oracle surface or defer to M3. Never returns a faked or non-compiling result."""
    for vtype, builder in _BUILDERS:
        built = builder(src, target_import)
        if built:
            harness_src, hname = built
            if _harness_compiles(harness_src, src, target_import):
                return Synthesis(vtype, harness_src, hname,
                                 f"Tier-2 synthesised a {vtype} harness ({hname}).")
    if detect_oracle_shape(src):
        return Synthesis(
            "oracle-manipulation", None, None,
            "Recognised an oracle-manipulation surface, but a faithful market "
            "harness can't be templated from source - that's the M3 AI step.")
    return Synthesis(
        None, None, None,
        "Could not recognise this contract's shape - automatic harness generation "
        "for arbitrary contracts is the M3 AI step.")
