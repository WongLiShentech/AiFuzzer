# Executive Summary

Date: 2026-06-11 11:00:32

Model: mistral:latest

## Overview

Analyzed 25 vulnerability types across the codebase.

## How to read this executive summary

The tables below group analyzed files by **embedding similarity** between each vulnerability type and the file (cosine similarity). This ordering reflects **retrieval relevance**, not exploit severity and not the severity labels inside per-vulnerability JSON/HTML reports.

**Tiers**: strong (similarity ≥ 0.80), moderate (0.60 ≤ similarity < 0.80), weak (similarity < 0.60). For authoritative finding counts and severities, open the linked vulnerability-type reports.

## Models Used
- Deep model: mistral:latest
- Small model: llama3.2:3b
- Embedding model: nomic-embed-text

## Scan Progress
| Status | Completed vulnerabilities |
|--------|----------------------------|
| Complete | 25/25 |
- Tested vulnerabilities: Authentication Issues, Command Injection, Security Misconfiguration, CORS Misconfiguration, Insecure Cryptographic Usage, Cross-Site Request Forgery, Sensitive Data Exposure, Debug Information Exposure, Insecure Deserialization, Insecure Direct Object Reference, Insufficient Input Validation, JWT Implementation Flaws, Local File Inclusion, Sensitive Data Logging, Path Traversal, Remote Code Execution, Open Redirect, Remote File Inclusion, Hardcoded Secrets, Session Management Issues, SQL Injection, Server-Side Request Forgery, File Upload Vulnerabilities, Cross-Site Scripting (XSS), XML External Entity Injection

### Pipeline phases
| Phase | Status | Progress |
|-------|--------|----------|
| Embeddings | complete | 3/3 |
| Discover candidates | complete | 25/25 |
| Structured chunk scan | complete | 1/1 |
| Context expansion | complete | 1/1 |
| Deep analysis | complete | 1/1 |
| Verify structured output | complete | 1/1 |

## Vulnerability Summary
| Vulnerability Type | Files Analyzed |
|-------------------|----------------|
| Authentication Issues | 3 |
| Command Injection | 2 |
| Security Misconfiguration | 2 |
| CORS Misconfiguration | 3 |
| Insecure Cryptographic Usage | 2 |
| Cross-Site Request Forgery | 2 |
| Sensitive Data Exposure | 2 |
| Debug Information Exposure | 3 |
| Insecure Deserialization | 3 |
| Insecure Direct Object Reference | 2 |
| Insufficient Input Validation | 2 |
| JWT Implementation Flaws | 3 |
| Local File Inclusion | 1 |
| Sensitive Data Logging | 2 |
| Path Traversal | 1 |
| Remote Code Execution | 2 |
| Open Redirect | 1 |
| Remote File Inclusion | 1 |
| Hardcoded Secrets | 2 |
| Session Management Issues | 2 |
| SQL Injection | 2 |
| Server-Side Request Forgery | 2 |
| File Upload Vulnerabilities | 2 |
| Cross-Site Scripting (XSS) | 3 |
| XML External Entity Injection | 2 |

## Moderate embedding match (0.60 ≤ similarity < 0.80) — 26 matches
| Vulnerability Type | File | Similarity | Report Link |
|-------------------|------|------------|--------------|
| CORS Misconfiguration | `/work/project/dataset/clean/mycontract_fixed.sol` | 0.67 | [Details](/reports/clean_contracts/20260611_092836/mistral_latest/json/cors_misconfiguration.json) |
| JWT Implementation Flaws | `/work/project/dataset/clean/modifier_reentrancy_fixed.sol` | 0.66 | [Details](/reports/clean_contracts/20260611_092836/mistral_latest/json/jwt_implementation_flaws.json) |
| Insecure Deserialization | `/work/project/dataset/clean/simple_dao_fixed.sol` | 0.65 | [Details](/reports/clean_contracts/20260611_092836/mistral_latest/json/insecure_deserialization.json) |
| Insecure Deserialization | `/work/project/dataset/clean/modifier_reentrancy_fixed.sol` | 0.65 | [Details](/reports/clean_contracts/20260611_092836/mistral_latest/json/insecure_deserialization.json) |
| Hardcoded Secrets | `/work/project/dataset/clean/modifier_reentrancy_fixed.sol` | 0.64 | [Details](/reports/clean_contracts/20260611_092836/mistral_latest/json/hardcoded_secrets.json) |
| Insecure Direct Object Reference | `/work/project/dataset/clean/simple_dao_fixed.sol` | 0.64 | [Details](/reports/clean_contracts/20260611_092836/mistral_latest/json/insecure_direct_object_reference.json) |
| Cross-Site Request Forgery | `/work/project/dataset/clean/modifier_reentrancy_fixed.sol` | 0.64 | [Details](/reports/clean_contracts/20260611_092836/mistral_latest/json/cross-site_request_forgery.json) |
| Open Redirect | `/work/project/dataset/clean/simple_dao_fixed.sol` | 0.64 | [Details](/reports/clean_contracts/20260611_092836/mistral_latest/json/open_redirect.json) |
| Server-Side Request Forgery | `/work/project/dataset/clean/simple_dao_fixed.sol` | 0.63 | [Details](/reports/clean_contracts/20260611_092836/mistral_latest/json/server-side_request_forgery.json) |
| Server-Side Request Forgery | `/work/project/dataset/clean/modifier_reentrancy_fixed.sol` | 0.63 | [Details](/reports/clean_contracts/20260611_092836/mistral_latest/json/server-side_request_forgery.json) |
| Security Misconfiguration | `/work/project/dataset/clean/modifier_reentrancy_fixed.sol` | 0.63 | [Details](/reports/clean_contracts/20260611_092836/mistral_latest/json/security_misconfiguration.json) |
| Cross-Site Request Forgery | `/work/project/dataset/clean/simple_dao_fixed.sol` | 0.63 | [Details](/reports/clean_contracts/20260611_092836/mistral_latest/json/cross-site_request_forgery.json) |
| Insecure Cryptographic Usage | `/work/project/dataset/clean/modifier_reentrancy_fixed.sol` | 0.63 | [Details](/reports/clean_contracts/20260611_092836/mistral_latest/json/insecure_cryptographic_usage.json) |
| CORS Misconfiguration | `/work/project/dataset/clean/simple_dao_fixed.sol` | 0.63 | [Details](/reports/clean_contracts/20260611_092836/mistral_latest/json/cors_misconfiguration.json) |
| Hardcoded Secrets | `/work/project/dataset/clean/simple_dao_fixed.sol` | 0.63 | [Details](/reports/clean_contracts/20260611_092836/mistral_latest/json/hardcoded_secrets.json) |
| Insecure Cryptographic Usage | `/work/project/dataset/clean/simple_dao_fixed.sol` | 0.62 | [Details](/reports/clean_contracts/20260611_092836/mistral_latest/json/insecure_cryptographic_usage.json) |
| Cross-Site Scripting (XSS) | `/work/project/dataset/clean/mycontract_fixed.sol` | 0.62 | [Details](/reports/clean_contracts/20260611_092836/mistral_latest/json/cross-site_scripting_(xss).json) |
| CORS Misconfiguration | `/work/project/dataset/clean/modifier_reentrancy_fixed.sol` | 0.62 | [Details](/reports/clean_contracts/20260611_092836/mistral_latest/json/cors_misconfiguration.json) |
| Security Misconfiguration | `/work/project/dataset/clean/simple_dao_fixed.sol` | 0.62 | [Details](/reports/clean_contracts/20260611_092836/mistral_latest/json/security_misconfiguration.json) |
| Insecure Direct Object Reference | `/work/project/dataset/clean/modifier_reentrancy_fixed.sol` | 0.62 | [Details](/reports/clean_contracts/20260611_092836/mistral_latest/json/insecure_direct_object_reference.json) |
| XML External Entity Injection | `/work/project/dataset/clean/modifier_reentrancy_fixed.sol` | 0.62 | [Details](/reports/clean_contracts/20260611_092836/mistral_latest/json/xml_external_entity_injection.json) |
| Remote Code Execution | `/work/project/dataset/clean/modifier_reentrancy_fixed.sol` | 0.61 | [Details](/reports/clean_contracts/20260611_092836/mistral_latest/json/remote_code_execution.json) |
| JWT Implementation Flaws | `/work/project/dataset/clean/simple_dao_fixed.sol` | 0.60 | [Details](/reports/clean_contracts/20260611_092836/mistral_latest/json/jwt_implementation_flaws.json) |
| Cross-Site Scripting (XSS) | `/work/project/dataset/clean/modifier_reentrancy_fixed.sol` | 0.60 | [Details](/reports/clean_contracts/20260611_092836/mistral_latest/json/cross-site_scripting_(xss).json) |
| Insufficient Input Validation | `/work/project/dataset/clean/modifier_reentrancy_fixed.sol` | 0.60 | [Details](/reports/clean_contracts/20260611_092836/mistral_latest/json/insufficient_input_validation.json) |
| Sensitive Data Exposure | `/work/project/dataset/clean/simple_dao_fixed.sol` | 0.60 | [Details](/reports/clean_contracts/20260611_092836/mistral_latest/json/sensitive_data_exposure.json) |

## Weak embedding match (similarity < 0.60) — 26 matches
| Vulnerability Type | File | Similarity | Report Link |
|-------------------|------|------------|--------------|
| Insecure Deserialization | `/work/project/dataset/clean/mycontract_fixed.sol` | 0.60 | [Details](/reports/clean_contracts/20260611_092836/mistral_latest/json/insecure_deserialization.json) |
| JWT Implementation Flaws | `/work/project/dataset/clean/mycontract_fixed.sol` | 0.60 | [Details](/reports/clean_contracts/20260611_092836/mistral_latest/json/jwt_implementation_flaws.json) |
| Remote File Inclusion | `/work/project/dataset/clean/modifier_reentrancy_fixed.sol` | 0.59 | [Details](/reports/clean_contracts/20260611_092836/mistral_latest/json/remote_file_inclusion.json) |
| Remote Code Execution | `/work/project/dataset/clean/simple_dao_fixed.sol` | 0.59 | [Details](/reports/clean_contracts/20260611_092836/mistral_latest/json/remote_code_execution.json) |
| Sensitive Data Exposure | `/work/project/dataset/clean/modifier_reentrancy_fixed.sol` | 0.59 | [Details](/reports/clean_contracts/20260611_092836/mistral_latest/json/sensitive_data_exposure.json) |
| Authentication Issues | `/work/project/dataset/clean/modifier_reentrancy_fixed.sol` | 0.59 | [Details](/reports/clean_contracts/20260611_092836/mistral_latest/json/authentication_issues.json) |
| Session Management Issues | `/work/project/dataset/clean/modifier_reentrancy_fixed.sol` | 0.59 | [Details](/reports/clean_contracts/20260611_092836/mistral_latest/json/session_management_issues.json) |
| Cross-Site Scripting (XSS) | `/work/project/dataset/clean/simple_dao_fixed.sol` | 0.59 | [Details](/reports/clean_contracts/20260611_092836/mistral_latest/json/cross-site_scripting_(xss).json) |
| XML External Entity Injection | `/work/project/dataset/clean/simple_dao_fixed.sol` | 0.58 | [Details](/reports/clean_contracts/20260611_092836/mistral_latest/json/xml_external_entity_injection.json) |
| Insufficient Input Validation | `/work/project/dataset/clean/simple_dao_fixed.sol` | 0.58 | [Details](/reports/clean_contracts/20260611_092836/mistral_latest/json/insufficient_input_validation.json) |
| Debug Information Exposure | `/work/project/dataset/clean/simple_dao_fixed.sol` | 0.58 | [Details](/reports/clean_contracts/20260611_092836/mistral_latest/json/debug_information_exposure.json) |
| Local File Inclusion | `/work/project/dataset/clean/modifier_reentrancy_fixed.sol` | 0.58 | [Details](/reports/clean_contracts/20260611_092836/mistral_latest/json/local_file_inclusion.json) |
| Authentication Issues | `/work/project/dataset/clean/mycontract_fixed.sol` | 0.58 | [Details](/reports/clean_contracts/20260611_092836/mistral_latest/json/authentication_issues.json) |
| Authentication Issues | `/work/project/dataset/clean/simple_dao_fixed.sol` | 0.58 | [Details](/reports/clean_contracts/20260611_092836/mistral_latest/json/authentication_issues.json) |
| File Upload Vulnerabilities | `/work/project/dataset/clean/modifier_reentrancy_fixed.sol` | 0.58 | [Details](/reports/clean_contracts/20260611_092836/mistral_latest/json/file_upload_vulnerabilities.json) |
| SQL Injection | `/work/project/dataset/clean/modifier_reentrancy_fixed.sol` | 0.57 | [Details](/reports/clean_contracts/20260611_092836/mistral_latest/json/sql_injection.json) |
| Sensitive Data Logging | `/work/project/dataset/clean/mycontract_fixed.sol` | 0.57 | [Details](/reports/clean_contracts/20260611_092836/mistral_latest/json/sensitive_data_logging.json) |
| File Upload Vulnerabilities | `/work/project/dataset/clean/simple_dao_fixed.sol` | 0.57 | [Details](/reports/clean_contracts/20260611_092836/mistral_latest/json/file_upload_vulnerabilities.json) |
| Command Injection | `/work/project/dataset/clean/modifier_reentrancy_fixed.sol` | 0.57 | [Details](/reports/clean_contracts/20260611_092836/mistral_latest/json/command_injection.json) |
| Command Injection | `/work/project/dataset/clean/simple_dao_fixed.sol` | 0.56 | [Details](/reports/clean_contracts/20260611_092836/mistral_latest/json/command_injection.json) |
| Sensitive Data Logging | `/work/project/dataset/clean/modifier_reentrancy_fixed.sol` | 0.56 | [Details](/reports/clean_contracts/20260611_092836/mistral_latest/json/sensitive_data_logging.json) |
| SQL Injection | `/work/project/dataset/clean/simple_dao_fixed.sol` | 0.56 | [Details](/reports/clean_contracts/20260611_092836/mistral_latest/json/sql_injection.json) |
| Debug Information Exposure | `/work/project/dataset/clean/modifier_reentrancy_fixed.sol` | 0.56 | [Details](/reports/clean_contracts/20260611_092836/mistral_latest/json/debug_information_exposure.json) |
| Session Management Issues | `/work/project/dataset/clean/simple_dao_fixed.sol` | 0.56 | [Details](/reports/clean_contracts/20260611_092836/mistral_latest/json/session_management_issues.json) |
| Debug Information Exposure | `/work/project/dataset/clean/mycontract_fixed.sol` | 0.55 | [Details](/reports/clean_contracts/20260611_092836/mistral_latest/json/debug_information_exposure.json) |
| Path Traversal | `/work/project/dataset/clean/modifier_reentrancy_fixed.sol` | 0.54 | [Details](/reports/clean_contracts/20260611_092836/mistral_latest/json/path_traversal.json) |