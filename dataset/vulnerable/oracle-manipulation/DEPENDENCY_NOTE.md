These contracts import OpenZeppelin. Do not run Slither on
individual files. Run Slither from the Hardhat project root:
staging/damn-vulnerable-defi/
The pipeline handles this automatically.

---

**Note (verified 2026-06-09):** the upstream Damn Vulnerable DeFi repository has
migrated from Hardhat to Foundry. The Puppet contracts now live under
`staging/damn-vulnerable-defi/src/puppet/` and `src/puppet-v2/` (not `contracts/`),
and the project root is a Foundry project (`foundry.toml`, `src/`, `lib/`). The
dependency principle above is unchanged: these contracts import OpenZeppelin and
must be compiled/analyzed from the project root with its dependencies resolved,
never as standalone files. The pipeline resolves the project root and its
remappings automatically.
