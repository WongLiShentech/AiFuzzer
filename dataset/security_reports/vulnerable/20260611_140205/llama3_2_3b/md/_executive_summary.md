# Executive Summary

Date: 2026-06-12 01:38:34

Model: llama3.2:3b

## Overview

Analyzed 24 vulnerability types across the codebase.

## How to read this executive summary

The tables below group analyzed files by **embedding similarity** between each vulnerability type and the file (cosine similarity). This ordering reflects **retrieval relevance**, not exploit severity and not the severity labels inside per-vulnerability JSON/HTML reports.

**Tiers**: strong (similarity ≥ 0.80), moderate (0.60 ≤ similarity < 0.80), weak (similarity < 0.60). For authoritative finding counts and severities, open the linked vulnerability-type reports.

## Models Used
- Deep model: llama3.2:3b
- Small model: mistral:latest
- Embedding model: nomic-embed-text

## Scan Progress
| Status | Completed vulnerabilities |
|--------|----------------------------|
| Complete | 25/25 |
- Tested vulnerabilities: Authentication Issues, Command Injection, Security Misconfiguration, CORS Misconfiguration, Insecure Cryptographic Usage, Cross-Site Request Forgery, Sensitive Data Exposure, Debug Information Exposure, Insecure Deserialization, Insecure Direct Object Reference, Insufficient Input Validation, JWT Implementation Flaws, Local File Inclusion, Sensitive Data Logging, Path Traversal, Remote Code Execution, Remote File Inclusion, Hardcoded Secrets, Session Management Issues, SQL Injection, Server-Side Request Forgery, File Upload Vulnerabilities, Cross-Site Scripting (XSS), XML External Entity Injection

### Pipeline phases
| Phase | Status | Progress |
|-------|--------|----------|
| Embeddings | complete | 14/14 |
| Discover candidates | complete | 25/25 |
| Structured chunk scan | complete | 1/1 |
| Context expansion | complete | 1/1 |
| Deep analysis | complete | 1/1 |
| Verify structured output | complete | 1/1 |

## Vulnerability Summary
| Vulnerability Type | Files Analyzed |
|-------------------|----------------|
| Authentication Issues | 12 |
| Command Injection | 6 |
| Security Misconfiguration | 12 |
| CORS Misconfiguration | 4 |
| Insecure Cryptographic Usage | 11 |
| Cross-Site Request Forgery | 9 |
| Sensitive Data Exposure | 11 |
| Debug Information Exposure | 7 |
| Insecure Deserialization | 8 |
| Insecure Direct Object Reference | 9 |
| Insufficient Input Validation | 11 |
| JWT Implementation Flaws | 9 |
| Local File Inclusion | 3 |
| Sensitive Data Logging | 8 |
| Path Traversal | 5 |
| Remote Code Execution | 11 |
| Remote File Inclusion | 4 |
| Hardcoded Secrets | 8 |
| Session Management Issues | 9 |
| SQL Injection | 7 |
| Server-Side Request Forgery | 9 |
| File Upload Vulnerabilities | 8 |
| Cross-Site Scripting (XSS) | 3 |
| XML External Entity Injection | 4 |

## Moderate embedding match (0.60 ≤ similarity < 0.80) — 134 matches
| Vulnerability Type | File | Similarity | Report Link |
|-------------------|------|------------|--------------|
| Insecure Direct Object Reference | `/work/project/dataset/vulnerable/oracle-manipulation/PuppetV2Pool.sol` | 0.72 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/insecure_direct_object_reference.json) |
| CORS Misconfiguration | `/work/project/dataset/vulnerable/access-control/mycontract.sol` | 0.71 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/cors_misconfiguration.json) |
| Insecure Deserialization | `/work/project/dataset/vulnerable/reentrancy/simple_dao.sol` | 0.69 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/insecure_deserialization.json) |
| Insecure Deserialization | `/work/project/dataset/vulnerable/oracle-manipulation/PuppetV2Pool.sol` | 0.68 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/insecure_deserialization.json) |
| Sensitive Data Exposure | `/work/project/dataset/vulnerable/oracle-manipulation/PuppetPool.sol` | 0.68 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/sensitive_data_exposure.json) |
| Server-Side Request Forgery | `/work/project/dataset/vulnerable/reentrancy/0xbaf51e761510c1a11bf48dd87c0307ac8a8c8a4f.sol` | 0.68 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/server-side_request_forgery.json) |
| Insecure Direct Object Reference | `/work/project/dataset/vulnerable/access-control/parity_wallet_bug_1.sol` | 0.68 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/insecure_direct_object_reference.json) |
| Server-Side Request Forgery | `/work/project/dataset/vulnerable/reentrancy/simple_dao.sol` | 0.68 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/server-side_request_forgery.json) |
| Insecure Direct Object Reference | `/work/project/dataset/vulnerable/reentrancy/simple_dao.sol` | 0.68 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/insecure_direct_object_reference.json) |
| Security Misconfiguration | `/work/project/dataset/vulnerable/oracle-manipulation/PuppetV2Pool.sol` | 0.68 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/security_misconfiguration.json) |
| Security Misconfiguration | `/work/project/dataset/vulnerable/oracle-manipulation/PuppetPool.sol` | 0.68 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/security_misconfiguration.json) |
| Hardcoded Secrets | `/work/project/dataset/vulnerable/ordering-attacks/FindThisHash.sol` | 0.68 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/hardcoded_secrets.json) |
| Server-Side Request Forgery | `/work/project/dataset/vulnerable/reentrancy/etherstore.sol` | 0.68 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/server-side_request_forgery.json) |
| Hardcoded Secrets | `/work/project/dataset/vulnerable/reentrancy/0xbaf51e761510c1a11bf48dd87c0307ac8a8c8a4f.sol` | 0.68 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/hardcoded_secrets.json) |
| Sensitive Data Exposure | `/work/project/dataset/vulnerable/oracle-manipulation/PuppetV2Pool.sol` | 0.67 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/sensitive_data_exposure.json) |
| JWT Implementation Flaws | `/work/project/dataset/vulnerable/oracle-manipulation/PuppetV2Pool.sol` | 0.67 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/jwt_implementation_flaws.json) |
| Remote Code Execution | `/work/project/dataset/vulnerable/oracle-manipulation/PuppetV2Pool.sol` | 0.67 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/remote_code_execution.json) |
| Insecure Deserialization | `/work/project/dataset/vulnerable/reentrancy/etherstore.sol` | 0.67 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/insecure_deserialization.json) |
| Server-Side Request Forgery | `/work/project/dataset/vulnerable/ordering-attacks/FindThisHash.sol` | 0.67 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/server-side_request_forgery.json) |
| Security Misconfiguration | `/work/project/dataset/vulnerable/ordering-attacks/FindThisHash.sol` | 0.67 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/security_misconfiguration.json) |
| Hardcoded Secrets | `/work/project/dataset/vulnerable/reentrancy/etherstore.sol` | 0.67 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/hardcoded_secrets.json) |
| Security Misconfiguration | `/work/project/dataset/vulnerable/access-control/mycontract.sol` | 0.66 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/security_misconfiguration.json) |
| Insecure Cryptographic Usage | `/work/project/dataset/vulnerable/oracle-manipulation/PuppetV2Pool.sol` | 0.66 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/insecure_cryptographic_usage.json) |
| Insufficient Input Validation | `/work/project/dataset/vulnerable/oracle-manipulation/PuppetV2Pool.sol` | 0.66 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/insufficient_input_validation.json) |
| Insecure Deserialization | `/work/project/dataset/vulnerable/reentrancy/0xbaf51e761510c1a11bf48dd87c0307ac8a8c8a4f.sol` | 0.66 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/insecure_deserialization.json) |
| Security Misconfiguration | `/work/project/dataset/vulnerable/reentrancy/0xbaf51e761510c1a11bf48dd87c0307ac8a8c8a4f.sol` | 0.66 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/security_misconfiguration.json) |
| Hardcoded Secrets | `/work/project/dataset/vulnerable/access-control/mycontract.sol` | 0.66 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/hardcoded_secrets.json) |
| Insecure Direct Object Reference | `/work/project/dataset/vulnerable/access-control/parity_wallet_bug_2.sol` | 0.66 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/insecure_direct_object_reference.json) |
| Session Management Issues | `/work/project/dataset/vulnerable/access-control/parity_wallet_bug_1.sol` | 0.66 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/session_management_issues.json) |
| Cross-Site Request Forgery | `/work/project/dataset/vulnerable/access-control/mycontract.sol` | 0.66 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/cross-site_request_forgery.json) |
| Insufficient Input Validation | `/work/project/dataset/vulnerable/oracle-manipulation/PuppetPool.sol` | 0.66 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/insufficient_input_validation.json) |
| Security Misconfiguration | `/work/project/dataset/vulnerable/reentrancy/etherstore.sol` | 0.66 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/security_misconfiguration.json) |
| Insecure Deserialization | `/work/project/dataset/vulnerable/access-control/parity_wallet_bug_1.sol` | 0.66 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/insecure_deserialization.json) |
| CORS Misconfiguration | `/work/project/dataset/vulnerable/reentrancy/0xbaf51e761510c1a11bf48dd87c0307ac8a8c8a4f.sol` | 0.66 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/cors_misconfiguration.json) |
| Sensitive Data Exposure | `/work/project/dataset/vulnerable/reentrancy/0xbaf51e761510c1a11bf48dd87c0307ac8a8c8a4f.sol` | 0.66 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/sensitive_data_exposure.json) |
| Sensitive Data Exposure | `/work/project/dataset/vulnerable/access-control/mycontract.sol` | 0.65 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/sensitive_data_exposure.json) |
| Sensitive Data Exposure | `/work/project/dataset/vulnerable/reentrancy/etherstore.sol` | 0.65 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/sensitive_data_exposure.json) |
| Insecure Direct Object Reference | `/work/project/dataset/vulnerable/reentrancy/etherstore.sol` | 0.65 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/insecure_direct_object_reference.json) |
| Server-Side Request Forgery | `/work/project/dataset/vulnerable/access-control/mycontract.sol` | 0.65 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/server-side_request_forgery.json) |
| Insecure Cryptographic Usage | `/work/project/dataset/vulnerable/ordering-attacks/FindThisHash.sol` | 0.65 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/insecure_cryptographic_usage.json) |
| Remote Code Execution | `/work/project/dataset/vulnerable/ordering-attacks/ERC20.sol` | 0.65 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/remote_code_execution.json) |
| Cross-Site Scripting (XSS) | `/work/project/dataset/vulnerable/access-control/mycontract.sol` | 0.65 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/cross-site_scripting_(xss).json) |
| Session Management Issues | `/work/project/dataset/vulnerable/access-control/parity_wallet_bug_2.sol` | 0.65 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/session_management_issues.json) |
| Security Misconfiguration | `/work/project/dataset/vulnerable/reentrancy/simple_dao.sol` | 0.65 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/security_misconfiguration.json) |
| Insecure Direct Object Reference | `/work/project/dataset/vulnerable/access-control/mycontract.sol` | 0.65 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/insecure_direct_object_reference.json) |
| Security Misconfiguration | `/work/project/dataset/vulnerable/ordering-attacks/eth_tx_order_dependence_minimal.sol` | 0.65 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/security_misconfiguration.json) |
| Insecure Deserialization | `/work/project/dataset/vulnerable/access-control/parity_wallet_bug_2.sol` | 0.65 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/insecure_deserialization.json) |
| Insecure Direct Object Reference | `/work/project/dataset/vulnerable/reentrancy/0xbaf51e761510c1a11bf48dd87c0307ac8a8c8a4f.sol` | 0.64 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/insecure_direct_object_reference.json) |
| XML External Entity Injection | `/work/project/dataset/vulnerable/reentrancy/etherstore.sol` | 0.64 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/xml_external_entity_injection.json) |
| Security Misconfiguration | `/work/project/dataset/vulnerable/access-control/parity_wallet_bug_1.sol` | 0.64 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/security_misconfiguration.json) |
| Insecure Deserialization | `/work/project/dataset/vulnerable/ordering-attacks/odds_and_evens.sol` | 0.64 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/insecure_deserialization.json) |
| Insecure Cryptographic Usage | `/work/project/dataset/vulnerable/reentrancy/etherstore.sol` | 0.64 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/insecure_cryptographic_usage.json) |
| Sensitive Data Exposure | `/work/project/dataset/vulnerable/ordering-attacks/FindThisHash.sol` | 0.64 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/sensitive_data_exposure.json) |
| Cross-Site Request Forgery | `/work/project/dataset/vulnerable/reentrancy/etherstore.sol` | 0.64 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/cross-site_request_forgery.json) |
| Insecure Cryptographic Usage | `/work/project/dataset/vulnerable/reentrancy/simple_dao.sol` | 0.64 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/insecure_cryptographic_usage.json) |
| Server-Side Request Forgery | `/work/project/dataset/vulnerable/ordering-attacks/odds_and_evens.sol` | 0.64 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/server-side_request_forgery.json) |
| Server-Side Request Forgery | `/work/project/dataset/vulnerable/ordering-attacks/eth_tx_order_dependence_minimal.sol` | 0.64 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/server-side_request_forgery.json) |
| Server-Side Request Forgery | `/work/project/dataset/vulnerable/access-control/parity_wallet_bug_1.sol` | 0.64 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/server-side_request_forgery.json) |
| Insufficient Input Validation | `/work/project/dataset/vulnerable/access-control/parity_wallet_bug_1.sol` | 0.64 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/insufficient_input_validation.json) |
| Cross-Site Scripting (XSS) | `/work/project/dataset/vulnerable/reentrancy/0xbaf51e761510c1a11bf48dd87c0307ac8a8c8a4f.sol` | 0.64 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/cross-site_scripting_(xss).json) |
| Cross-Site Request Forgery | `/work/project/dataset/vulnerable/reentrancy/0xbaf51e761510c1a11bf48dd87c0307ac8a8c8a4f.sol` | 0.64 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/cross-site_request_forgery.json) |
| Remote Code Execution | `/work/project/dataset/vulnerable/reentrancy/simple_dao.sol` | 0.64 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/remote_code_execution.json) |
| CORS Misconfiguration | `/work/project/dataset/vulnerable/reentrancy/etherstore.sol` | 0.64 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/cors_misconfiguration.json) |
| Cross-Site Request Forgery | `/work/project/dataset/vulnerable/reentrancy/simple_dao.sol` | 0.64 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/cross-site_request_forgery.json) |
| SQL Injection | `/work/project/dataset/vulnerable/oracle-manipulation/PuppetV2Pool.sol` | 0.64 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/sql_injection.json) |
| Debug Information Exposure | `/work/project/dataset/vulnerable/reentrancy/simple_dao.sol` | 0.63 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/debug_information_exposure.json) |
| Hardcoded Secrets | `/work/project/dataset/vulnerable/ordering-attacks/eth_tx_order_dependence_minimal.sol` | 0.63 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/hardcoded_secrets.json) |
| Cross-Site Request Forgery | `/work/project/dataset/vulnerable/ordering-attacks/FindThisHash.sol` | 0.63 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/cross-site_request_forgery.json) |
| Sensitive Data Exposure | `/work/project/dataset/vulnerable/reentrancy/simple_dao.sol` | 0.63 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/sensitive_data_exposure.json) |
| Remote Code Execution | `/work/project/dataset/vulnerable/reentrancy/0xbaf51e761510c1a11bf48dd87c0307ac8a8c8a4f.sol` | 0.63 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/remote_code_execution.json) |
| Security Misconfiguration | `/work/project/dataset/vulnerable/access-control/parity_wallet_bug_2.sol` | 0.63 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/security_misconfiguration.json) |
| Cross-Site Scripting (XSS) | `/work/project/dataset/vulnerable/reentrancy/etherstore.sol` | 0.63 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/cross-site_scripting_(xss).json) |
| Insecure Cryptographic Usage | `/work/project/dataset/vulnerable/reentrancy/0xbaf51e761510c1a11bf48dd87c0307ac8a8c8a4f.sol` | 0.63 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/insecure_cryptographic_usage.json) |
| Hardcoded Secrets | `/work/project/dataset/vulnerable/access-control/parity_wallet_bug_1.sol` | 0.63 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/hardcoded_secrets.json) |
| JWT Implementation Flaws | `/work/project/dataset/vulnerable/access-control/parity_wallet_bug_1.sol` | 0.63 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/jwt_implementation_flaws.json) |
| Remote Code Execution | `/work/project/dataset/vulnerable/ordering-attacks/eth_tx_order_dependence_minimal.sol` | 0.63 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/remote_code_execution.json) |
| Remote Code Execution | `/work/project/dataset/vulnerable/access-control/parity_wallet_bug_1.sol` | 0.63 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/remote_code_execution.json) |
| File Upload Vulnerabilities | `/work/project/dataset/vulnerable/reentrancy/etherstore.sol` | 0.63 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/file_upload_vulnerabilities.json) |
| Remote File Inclusion | `/work/project/dataset/vulnerable/reentrancy/0xbaf51e761510c1a11bf48dd87c0307ac8a8c8a4f.sol` | 0.63 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/remote_file_inclusion.json) |
| Insufficient Input Validation | `/work/project/dataset/vulnerable/access-control/parity_wallet_bug_2.sol` | 0.63 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/insufficient_input_validation.json) |
| File Upload Vulnerabilities | `/work/project/dataset/vulnerable/reentrancy/0xbaf51e761510c1a11bf48dd87c0307ac8a8c8a4f.sol` | 0.63 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/file_upload_vulnerabilities.json) |
| Hardcoded Secrets | `/work/project/dataset/vulnerable/ordering-attacks/odds_and_evens.sol` | 0.63 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/hardcoded_secrets.json) |
| JWT Implementation Flaws | `/work/project/dataset/vulnerable/reentrancy/etherstore.sol` | 0.63 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/jwt_implementation_flaws.json) |
| File Upload Vulnerabilities | `/work/project/dataset/vulnerable/reentrancy/simple_dao.sol` | 0.62 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/file_upload_vulnerabilities.json) |
| Local File Inclusion | `/work/project/dataset/vulnerable/reentrancy/etherstore.sol` | 0.62 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/local_file_inclusion.json) |
| XML External Entity Injection | `/work/project/dataset/vulnerable/reentrancy/0xbaf51e761510c1a11bf48dd87c0307ac8a8c8a4f.sol` | 0.62 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/xml_external_entity_injection.json) |
| JWT Implementation Flaws | `/work/project/dataset/vulnerable/reentrancy/0xbaf51e761510c1a11bf48dd87c0307ac8a8c8a4f.sol` | 0.62 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/jwt_implementation_flaws.json) |
| Remote Code Execution | `/work/project/dataset/vulnerable/reentrancy/etherstore.sol` | 0.62 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/remote_code_execution.json) |
| Server-Side Request Forgery | `/work/project/dataset/vulnerable/access-control/parity_wallet_bug_2.sol` | 0.62 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/server-side_request_forgery.json) |
| Authentication Issues | `/work/project/dataset/vulnerable/reentrancy/etherstore.sol` | 0.62 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/authentication_issues.json) |
| Authentication Issues | `/work/project/dataset/vulnerable/oracle-manipulation/PuppetPool.sol` | 0.62 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/authentication_issues.json) |
| Security Misconfiguration | `/work/project/dataset/vulnerable/ordering-attacks/odds_and_evens.sol` | 0.62 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/security_misconfiguration.json) |
| Authentication Issues | `/work/project/dataset/vulnerable/oracle-manipulation/PuppetV2Pool.sol` | 0.62 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/authentication_issues.json) |
| Sensitive Data Exposure | `/work/project/dataset/vulnerable/ordering-attacks/eth_tx_order_dependence_minimal.sol` | 0.62 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/sensitive_data_exposure.json) |
| JWT Implementation Flaws | `/work/project/dataset/vulnerable/access-control/parity_wallet_bug_2.sol` | 0.62 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/jwt_implementation_flaws.json) |
| Local File Inclusion | `/work/project/dataset/vulnerable/reentrancy/0xbaf51e761510c1a11bf48dd87c0307ac8a8c8a4f.sol` | 0.62 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/local_file_inclusion.json) |
| Remote Code Execution | `/work/project/dataset/vulnerable/ordering-attacks/FindThisHash.sol` | 0.62 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/remote_code_execution.json) |
| Hardcoded Secrets | `/work/project/dataset/vulnerable/access-control/parity_wallet_bug_2.sol` | 0.62 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/hardcoded_secrets.json) |
| Cross-Site Request Forgery | `/work/project/dataset/vulnerable/ordering-attacks/eth_tx_order_dependence_minimal.sol` | 0.62 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/cross-site_request_forgery.json) |
| Insecure Cryptographic Usage | `/work/project/dataset/vulnerable/access-control/parity_wallet_bug_1.sol` | 0.62 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/insecure_cryptographic_usage.json) |
| Remote File Inclusion | `/work/project/dataset/vulnerable/reentrancy/etherstore.sol` | 0.62 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/remote_file_inclusion.json) |
| Remote Code Execution | `/work/project/dataset/vulnerable/ordering-attacks/odds_and_evens.sol` | 0.62 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/remote_code_execution.json) |
| Insecure Cryptographic Usage | `/work/project/dataset/vulnerable/ordering-attacks/odds_and_evens.sol` | 0.62 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/insecure_cryptographic_usage.json) |
| JWT Implementation Flaws | `/work/project/dataset/vulnerable/reentrancy/simple_dao.sol` | 0.61 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/jwt_implementation_flaws.json) |
| Cross-Site Request Forgery | `/work/project/dataset/vulnerable/ordering-attacks/odds_and_evens.sol` | 0.61 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/cross-site_request_forgery.json) |
| Debug Information Exposure | `/work/project/dataset/vulnerable/reentrancy/etherstore.sol` | 0.61 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/debug_information_exposure.json) |
| JWT Implementation Flaws | `/work/project/dataset/vulnerable/access-control/mycontract.sol` | 0.61 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/jwt_implementation_flaws.json) |
| Insufficient Input Validation | `/work/project/dataset/vulnerable/reentrancy/etherstore.sol` | 0.61 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/insufficient_input_validation.json) |
| CORS Misconfiguration | `/work/project/dataset/vulnerable/ordering-attacks/odds_and_evens.sol` | 0.61 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/cors_misconfiguration.json) |
| Cross-Site Request Forgery | `/work/project/dataset/vulnerable/access-control/parity_wallet_bug_1.sol` | 0.61 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/cross-site_request_forgery.json) |
| SQL Injection | `/work/project/dataset/vulnerable/ordering-attacks/odds_and_evens.sol` | 0.61 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/sql_injection.json) |
| Authentication Issues | `/work/project/dataset/vulnerable/access-control/parity_wallet_bug_1.sol` | 0.61 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/authentication_issues.json) |
| Remote Code Execution | `/work/project/dataset/vulnerable/access-control/mycontract.sol` | 0.61 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/remote_code_execution.json) |
| Session Management Issues | `/work/project/dataset/vulnerable/reentrancy/etherstore.sol` | 0.61 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/session_management_issues.json) |
| Authentication Issues | `/work/project/dataset/vulnerable/access-control/mycontract.sol` | 0.61 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/authentication_issues.json) |
| Insecure Direct Object Reference | `/work/project/dataset/vulnerable/ordering-attacks/eth_tx_order_dependence_minimal.sol` | 0.61 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/insecure_direct_object_reference.json) |
| Remote Code Execution | `/work/project/dataset/vulnerable/access-control/parity_wallet_bug_2.sol` | 0.61 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/remote_code_execution.json) |
| XML External Entity Injection | `/work/project/dataset/vulnerable/access-control/parity_wallet_bug_1.sol` | 0.61 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/xml_external_entity_injection.json) |
| Path Traversal | `/work/project/dataset/vulnerable/access-control/parity_wallet_bug_1.sol` | 0.61 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/path_traversal.json) |
| SQL Injection | `/work/project/dataset/vulnerable/access-control/parity_wallet_bug_2.sol` | 0.60 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/sql_injection.json) |
| Insufficient Input Validation | `/work/project/dataset/vulnerable/reentrancy/0xbaf51e761510c1a11bf48dd87c0307ac8a8c8a4f.sol` | 0.60 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/insufficient_input_validation.json) |
| Insufficient Input Validation | `/work/project/dataset/vulnerable/reentrancy/simple_dao.sol` | 0.60 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/insufficient_input_validation.json) |
| Insecure Cryptographic Usage | `/work/project/dataset/vulnerable/ordering-attacks/eth_tx_order_dependence_minimal.sol` | 0.60 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/insecure_cryptographic_usage.json) |
| Remote File Inclusion | `/work/project/dataset/vulnerable/access-control/parity_wallet_bug_1.sol` | 0.60 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/remote_file_inclusion.json) |
| Debug Information Exposure | `/work/project/dataset/vulnerable/reentrancy/0xbaf51e761510c1a11bf48dd87c0307ac8a8c8a4f.sol` | 0.60 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/debug_information_exposure.json) |
| Authentication Issues | `/work/project/dataset/vulnerable/reentrancy/simple_dao.sol` | 0.60 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/authentication_issues.json) |
| SQL Injection | `/work/project/dataset/vulnerable/reentrancy/0xbaf51e761510c1a11bf48dd87c0307ac8a8c8a4f.sol` | 0.60 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/sql_injection.json) |
| Insecure Cryptographic Usage | `/work/project/dataset/vulnerable/access-control/parity_wallet_bug_2.sol` | 0.60 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/insecure_cryptographic_usage.json) |
| SQL Injection | `/work/project/dataset/vulnerable/access-control/mycontract.sol` | 0.60 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/sql_injection.json) |
| Authentication Issues | `/work/project/dataset/vulnerable/access-control/parity_wallet_bug_2.sol` | 0.60 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/authentication_issues.json) |
| Insecure Cryptographic Usage | `/work/project/dataset/vulnerable/access-control/mycontract.sol` | 0.60 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/insecure_cryptographic_usage.json) |
| SQL Injection | `/work/project/dataset/vulnerable/reentrancy/simple_dao.sol` | 0.60 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/sql_injection.json) |
| Sensitive Data Logging | `/work/project/dataset/vulnerable/access-control/mycontract.sol` | 0.60 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/sensitive_data_logging.json) |
| Debug Information Exposure | `/work/project/dataset/vulnerable/access-control/parity_wallet_bug_1.sol` | 0.60 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/debug_information_exposure.json) |

## Weak embedding match (similarity < 0.60) — 54 matches
| Vulnerability Type | File | Similarity | Report Link |
|-------------------|------|------------|--------------|
| Command Injection | `/work/project/dataset/vulnerable/reentrancy/simple_dao.sol` | 0.60 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/command_injection.json) |
| Command Injection | `/work/project/dataset/vulnerable/reentrancy/0xbaf51e761510c1a11bf48dd87c0307ac8a8c8a4f.sol` | 0.60 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/command_injection.json) |
| Sensitive Data Exposure | `/work/project/dataset/vulnerable/access-control/parity_wallet_bug_1.sol` | 0.60 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/sensitive_data_exposure.json) |
| Insecure Deserialization | `/work/project/dataset/vulnerable/access-control/mycontract.sol` | 0.60 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/insecure_deserialization.json) |
| Authentication Issues | `/work/project/dataset/vulnerable/reentrancy/0xbaf51e761510c1a11bf48dd87c0307ac8a8c8a4f.sol` | 0.60 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/authentication_issues.json) |
| Sensitive Data Logging | `/work/project/dataset/vulnerable/reentrancy/0xbaf51e761510c1a11bf48dd87c0307ac8a8c8a4f.sol` | 0.60 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/sensitive_data_logging.json) |
| JWT Implementation Flaws | `/work/project/dataset/vulnerable/ordering-attacks/odds_and_evens.sol` | 0.60 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/jwt_implementation_flaws.json) |
| Sensitive Data Logging | `/work/project/dataset/vulnerable/access-control/parity_wallet_bug_1.sol` | 0.60 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/sensitive_data_logging.json) |
| Insufficient Input Validation | `/work/project/dataset/vulnerable/access-control/mycontract.sol` | 0.60 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/insufficient_input_validation.json) |
| File Upload Vulnerabilities | `/work/project/dataset/vulnerable/ordering-attacks/eth_tx_order_dependence_minimal.sol` | 0.60 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/file_upload_vulnerabilities.json) |
| Cross-Site Request Forgery | `/work/project/dataset/vulnerable/access-control/parity_wallet_bug_2.sol` | 0.60 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/cross-site_request_forgery.json) |
| File Upload Vulnerabilities | `/work/project/dataset/vulnerable/access-control/mycontract.sol` | 0.59 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/file_upload_vulnerabilities.json) |
| Command Injection | `/work/project/dataset/vulnerable/access-control/parity_wallet_bug_1.sol` | 0.59 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/command_injection.json) |
| Path Traversal | `/work/project/dataset/vulnerable/reentrancy/etherstore.sol` | 0.59 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/path_traversal.json) |
| Local File Inclusion | `/work/project/dataset/vulnerable/access-control/parity_wallet_bug_2.sol` | 0.59 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/local_file_inclusion.json) |
| File Upload Vulnerabilities | `/work/project/dataset/vulnerable/access-control/parity_wallet_bug_1.sol` | 0.59 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/file_upload_vulnerabilities.json) |
| SQL Injection | `/work/project/dataset/vulnerable/reentrancy/etherstore.sol` | 0.59 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/sql_injection.json) |
| JWT Implementation Flaws | `/work/project/dataset/vulnerable/ordering-attacks/eth_tx_order_dependence_minimal.sol` | 0.59 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/jwt_implementation_flaws.json) |
| Session Management Issues | `/work/project/dataset/vulnerable/reentrancy/simple_dao.sol` | 0.59 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/session_management_issues.json) |
| Command Injection | `/work/project/dataset/vulnerable/reentrancy/etherstore.sol` | 0.59 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/command_injection.json) |
| Sensitive Data Logging | `/work/project/dataset/vulnerable/reentrancy/simple_dao.sol` | 0.59 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/sensitive_data_logging.json) |
| Session Management Issues | `/work/project/dataset/vulnerable/reentrancy/0xbaf51e761510c1a11bf48dd87c0307ac8a8c8a4f.sol` | 0.59 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/session_management_issues.json) |
| Sensitive Data Exposure | `/work/project/dataset/vulnerable/ordering-attacks/odds_and_evens.sol` | 0.59 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/sensitive_data_exposure.json) |
| Debug Information Exposure | `/work/project/dataset/vulnerable/access-control/parity_wallet_bug_2.sol` | 0.59 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/debug_information_exposure.json) |
| Session Management Issues | `/work/project/dataset/vulnerable/access-control/mycontract.sol` | 0.59 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/session_management_issues.json) |
| Sensitive Data Logging | `/work/project/dataset/vulnerable/reentrancy/etherstore.sol` | 0.59 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/sensitive_data_logging.json) |
| XML External Entity Injection | `/work/project/dataset/vulnerable/access-control/parity_wallet_bug_2.sol` | 0.59 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/xml_external_entity_injection.json) |
| Authentication Issues | `/work/project/dataset/vulnerable/ordering-attacks/FindThisHash.sol` | 0.58 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/authentication_issues.json) |
| Insufficient Input Validation | `/work/project/dataset/vulnerable/ordering-attacks/FindThisHash.sol` | 0.58 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/insufficient_input_validation.json) |
| Sensitive Data Exposure | `/work/project/dataset/vulnerable/access-control/parity_wallet_bug_2.sol` | 0.58 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/sensitive_data_exposure.json) |
| Debug Information Exposure | `/work/project/dataset/vulnerable/ordering-attacks/odds_and_evens.sol` | 0.58 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/debug_information_exposure.json) |
| Insecure Direct Object Reference | `/work/project/dataset/vulnerable/ordering-attacks/odds_and_evens.sol` | 0.58 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/insecure_direct_object_reference.json) |
| Session Management Issues | `/work/project/dataset/vulnerable/ordering-attacks/FindThisHash.sol` | 0.58 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/session_management_issues.json) |
| Insecure Cryptographic Usage | `/work/project/dataset/vulnerable/ordering-attacks/ERC20.sol` | 0.58 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/insecure_cryptographic_usage.json) |
| Remote File Inclusion | `/work/project/dataset/vulnerable/access-control/parity_wallet_bug_2.sol` | 0.58 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/remote_file_inclusion.json) |
| Path Traversal | `/work/project/dataset/vulnerable/reentrancy/0xbaf51e761510c1a11bf48dd87c0307ac8a8c8a4f.sol` | 0.58 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/path_traversal.json) |
| Sensitive Data Logging | `/work/project/dataset/vulnerable/access-control/parity_wallet_bug_2.sol` | 0.58 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/sensitive_data_logging.json) |
| File Upload Vulnerabilities | `/work/project/dataset/vulnerable/access-control/parity_wallet_bug_2.sol` | 0.58 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/file_upload_vulnerabilities.json) |
| Path Traversal | `/work/project/dataset/vulnerable/reentrancy/simple_dao.sol` | 0.58 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/path_traversal.json) |
| Security Misconfiguration | `/work/project/dataset/vulnerable/ordering-attacks/ERC20.sol` | 0.58 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/security_misconfiguration.json) |
| Path Traversal | `/work/project/dataset/vulnerable/access-control/parity_wallet_bug_2.sol` | 0.58 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/path_traversal.json) |
| Command Injection | `/work/project/dataset/vulnerable/access-control/parity_wallet_bug_2.sol` | 0.57 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/command_injection.json) |
| Insufficient Input Validation | `/work/project/dataset/vulnerable/ordering-attacks/odds_and_evens.sol` | 0.57 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/insufficient_input_validation.json) |
| Command Injection | `/work/project/dataset/vulnerable/ordering-attacks/odds_and_evens.sol` | 0.57 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/command_injection.json) |
| Session Management Issues | `/work/project/dataset/vulnerable/ordering-attacks/odds_and_evens.sol` | 0.57 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/session_management_issues.json) |
| Authentication Issues | `/work/project/dataset/vulnerable/ordering-attacks/eth_tx_order_dependence_minimal.sol` | 0.57 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/authentication_issues.json) |
| Session Management Issues | `/work/project/dataset/vulnerable/ordering-attacks/eth_tx_order_dependence_minimal.sol` | 0.57 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/session_management_issues.json) |
| Insufficient Input Validation | `/work/project/dataset/vulnerable/ordering-attacks/eth_tx_order_dependence_minimal.sol` | 0.56 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/insufficient_input_validation.json) |
| Debug Information Exposure | `/work/project/dataset/vulnerable/access-control/mycontract.sol` | 0.56 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/debug_information_exposure.json) |
| Sensitive Data Logging | `/work/project/dataset/vulnerable/ordering-attacks/eth_tx_order_dependence_minimal.sol` | 0.56 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/sensitive_data_logging.json) |
| Authentication Issues | `/work/project/dataset/vulnerable/ordering-attacks/ERC20.sol` | 0.56 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/authentication_issues.json) |
| File Upload Vulnerabilities | `/work/project/dataset/vulnerable/ordering-attacks/odds_and_evens.sol` | 0.56 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/file_upload_vulnerabilities.json) |
| Authentication Issues | `/work/project/dataset/vulnerable/ordering-attacks/odds_and_evens.sol` | 0.55 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/authentication_issues.json) |
| Sensitive Data Logging | `/work/project/dataset/vulnerable/ordering-attacks/odds_and_evens.sol` | 0.54 | [Details](/reports/vulnerable/20260611_140205/llama3_2_3b/json/sensitive_data_logging.json) |