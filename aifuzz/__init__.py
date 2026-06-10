"""aifuzz — AI-assisted fuzzing tool for smart-contract security analysis.

Give it a Solidity contract; it deploys to a local chain, fuzzes transaction
sequences (random and AI-guided), and reports vulnerabilities.

Public surface:
    aifuzz analyze <contract.sol>     # CLI (see aifuzz.cli)
    from aifuzz.report import Report, Finding, Severity
"""

__version__ = "0.1.0"
