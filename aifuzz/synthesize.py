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


# --- reentrancy ------------------------------------------------------------- #
def detect_reentrancy_shape(src: str) -> dict | None:
    """Deposit/withdraw pool: a balance ledger + payable deposit + external send."""
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


def synthesize_reentrancy_harness(src: str, target_import: str) -> tuple[str, str] | None:
    """Build a reentrancy harness for the deposit/withdraw shape, or None."""
    shape = detect_reentrancy_shape(src)
    if not shape:
        return None
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
    function {c}_Victim({c} _t) public {{ t = _t; }}
    function fund() public payable {{ t.{dep}.value(msg.value)(); }}
    function () public payable {{}}
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

    function {hname}() public payable {{
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

    function () public payable {{
        received += msg.value;
        if (attacking && address(target).balance >= 1 ether) {{
            {wcall};   // re-enter before the ledger updates
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
    """Privileged owner var + a setter for it. Oracle reads ownership via the
    public getter, or (private owner) probes a guarded twin. Else None (M3)."""
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
    function {hname}() public payable {{   // payable: balanceContract funding at deploy
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
    """Single-pot reward game: a zero-arg payable funder + a claim that pays
    msg.sender. A balance ledger means it's a pool, so defer to reentrancy."""
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
    function () public payable {{}}   // empty: fits transfer's 2300-gas stipend
}}

contract {hname} {{
    {c} internal game;
    {c}_Attacker internal attacker;
    uint256 public seeded;

    function {hname}() public payable {{
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

    function () public payable {{}}

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


_BUILDERS = (
    ("reentrancy", synthesize_reentrancy_harness),
    ("access-control", synthesize_access_control_harness),
    ("ordering-attacks", synthesize_ordering_harness),
)


def synthesize_harness(src: str, target_import: str) -> Synthesis:
    """Try each shape; return the first harness built, else recognise the oracle
    surface or defer to M3. Never returns a faked result."""
    for vtype, builder in _BUILDERS:
        built = builder(src, target_import)
        if built:
            harness_src, hname = built
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
