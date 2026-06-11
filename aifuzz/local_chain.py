"""Local blockchain (Anvil) — deploy contracts and run transactions against them.

This is the literal "local blockchain testing environment" (deliverable #2): a
real local Ethereum node you deploy to and query — distinct from Echidna's
internal EVM, which is used only for fuzzing. Used for deploy/interact demos and
proof-of-concept exploits.

Runs inside the Docker image (which has `anvil` from Foundry + `solc`). `web3`
is an optional dependency (`pip install -e ".[chain]"`), imported lazily so the
rest of the package works without it.
"""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass
from urllib.parse import urlparse

from .config import settings


@dataclass
class Deployment:
    address: str
    abi: list


def _compile(contract_path: str, contract_name: str) -> tuple[list, str]:
    """Compile one contract with solc → (abi, 0x-prefixed bytecode)."""
    if shutil.which("solc") is None:
        raise RuntimeError("solc not found — run inside the Docker image.")
    out = subprocess.run(
        ["solc", "--combined-json", "abi,bin", contract_path],
        capture_output=True, text=True,
    )
    if out.returncode != 0:
        raise RuntimeError(f"solc failed:\n{out.stderr.strip()}")
    contracts = json.loads(out.stdout)["contracts"]
    # keys look like "<path>:<ContractName>"
    match = [k for k in contracts if k.rsplit(":", 1)[-1] == contract_name]
    if not match:
        names = ", ".join(sorted(k.rsplit(":", 1)[-1] for k in contracts))
        raise RuntimeError(f"contract {contract_name!r} not found. Available: {names}")
    entry = contracts[match[0]]
    abi = entry["abi"]
    if isinstance(abi, str):
        abi = json.loads(abi)
    bytecode = entry["bin"]
    if not bytecode.startswith("0x"):
        bytecode = "0x" + bytecode
    return abi, bytecode


class LocalChain:
    """Context manager that runs a local Anvil node for deploy/interact."""

    def __init__(self, rpc_url: str | None = None) -> None:
        # No hardcoded chain: read from config/env, default to local Anvil.
        self.rpc_url = rpc_url or settings.rpc_url
        self._proc: subprocess.Popen | None = None
        self._w3 = None

    # -- lifecycle ----------------------------------------------------------

    def __enter__(self) -> "LocalChain":
        self._start_anvil()
        self._connect()
        return self

    def __exit__(self, *exc: object) -> None:
        if self._proc is not None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()

    def _host_port(self) -> tuple[str, int]:
        u = urlparse(self.rpc_url)
        return (u.hostname or "127.0.0.1", u.port or 8545)

    def _start_anvil(self) -> None:
        if shutil.which("anvil") is None:
            raise RuntimeError(
                "anvil not found. The local chain runs inside the Docker image — "
                "use `docker compose run --rm --no-deps aifuzz ...` (see README)."
            )
        host, port = self._host_port()
        self._proc = subprocess.Popen(
            ["anvil", "--host", host, "--port", str(port), "--silent"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        for _ in range(100):  # wait until the RPC port accepts connections
            with socket.socket() as s:
                s.settimeout(0.2)
                if s.connect_ex((host, port)) == 0:
                    return
            time.sleep(0.1)
        raise RuntimeError("anvil did not start in time")

    def _connect(self) -> None:
        from web3 import Web3  # lazy import (optional dep)

        self._w3 = Web3(Web3.HTTPProvider(self.rpc_url))
        for _ in range(50):
            if self._w3.is_connected():
                return
            time.sleep(0.1)
        raise RuntimeError(f"could not connect to anvil at {self.rpc_url}")

    # -- operations ---------------------------------------------------------

    @property
    def chain_id(self) -> int:
        return self._w3.eth.chain_id

    @property
    def block_number(self) -> int:
        return self._w3.eth.block_number

    def deploy(self, contract_path: str, contract_name: str) -> Deployment:
        """Compile and deploy a contract; return its on-chain address + ABI."""
        abi, bytecode = _compile(contract_path, contract_name)
        deployer = self._w3.eth.accounts[0]
        factory = self._w3.eth.contract(abi=abi, bytecode=bytecode)
        tx_hash = factory.constructor().transact({"from": deployer})
        receipt = self._w3.eth.wait_for_transaction_receipt(tx_hash)
        return Deployment(address=receipt.contractAddress, abi=abi)

    def call(self, deployment: Deployment, fn: str, *args):
        """Read a view/pure function on a deployed contract."""
        c = self._w3.eth.contract(address=deployment.address, abi=deployment.abi)
        return getattr(c.functions, fn)(*args).call()

    def send(self, deployment: Deployment, fn: str, *args, sender_index: int = 0):
        """Send a state-changing transaction from one of Anvil's funded accounts."""
        c = self._w3.eth.contract(address=deployment.address, abi=deployment.abi)
        sender = self._w3.eth.accounts[sender_index]
        tx_hash = getattr(c.functions, fn)(*args).transact({"from": sender})
        return self._w3.eth.wait_for_transaction_receipt(tx_hash)
