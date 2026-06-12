

# Debug Information Exposure Security Analysis

Date: 2026-06-11 23:53:30  
Model: llama3.2:3b  
Vulnerability: Debug Information Exposure

<a id="table-of-contents"></a>

## Table of contents

| | |
| --- | --- |
| 📋 [Summary](#summary) | 📊 [Statistics](#statistics) |
| 📁 [Files](#files) | 🔍 [Detailed analysis](#detailed-analysis) |
| 💬 [Assistant](#assistant) | ⚠️ [Errors & notes](#errors--notes) |

## Summary

Analyzed 7 file(s) for Debug Information Exposure.

[Return to table of contents](#table-of-contents)

## Statistics

- Files analyzed: 7
- Total findings: 12
- Critical: 5
- High: 3
- Medium: 3
- Low: 1

[Return to table of contents](#table-of-contents)

## Files

| File | Similarity |
|------|------------|
| `/work/project/dataset/vulnerable/reentrancy/simple_dao.sol` | 0.635 |
| `/work/project/dataset/vulnerable/reentrancy/etherstore.sol` | 0.613 |
| `/work/project/dataset/vulnerable/reentrancy/0xbaf51e761510c1a11bf48dd87c0307ac8a8c8a4f.sol` | 0.603 |
| `/work/project/dataset/vulnerable/access-control/parity_wallet_bug_1.sol` | 0.600 |
| `/work/project/dataset/vulnerable/access-control/parity_wallet_bug_2.sol` | 0.587 |
| `/work/project/dataset/vulnerable/ordering-attacks/odds_and_evens.sol` | 0.581 |
| `/work/project/dataset/vulnerable/access-control/mycontract.sol` | 0.563 |


[Return to table of contents](#table-of-contents)

## Detailed Analysis


---

### File 1: /work/project/dataset/vulnerable/reentrancy/simple_dao.sol


- Similarity score: 0.635






_Source lines 1-35 (1-based, inclusive)._



<details class="report-finding-details">

<summary>Finding 1.1: Debug Information Exposure (Critical)</summary>

<div class="report-finding-body">


##### Vulnerable Code

```text
> // Enable debug mode
if (debugMode) {
  console.log("Hello, World!");
}
```


##### Explanation

The 'debugMode' variable is not properly secured, allowing an attacker to potentially access sensitive debugging information.


##### Impact

Information disclosure about internal system state or configuration


##### Entry Point

/reentrancy/withdraw



##### HTTP Methods

POST


##### Parameters

debugMode


##### Exploitation Steps


- Reaching the /withdraw endpoint with a valid value for 'debugMode'

- Accessing the 'console.log' statement to retrieve sensitive debugging information



##### Example Payloads


- `debugMode: true`



##### HTTP raw requests (Burp / ZAP)


```http
POST /reentrancy/withdraw HTTP/1.1
Host: example.com
Content-Type: application/json

{"debugMode": true}
```







</div>

</details>




---

### File 2: /work/project/dataset/vulnerable/reentrancy/etherstore.sol


- Similarity score: 0.613






_Source lines 1-39 (1-based, inclusive)._



<details class="report-finding-details">

<summary>Finding 2.1: Debug Information Exposure (Critical)</summary>

<div class="report-finding-body">


##### Vulnerable Code

```text
require(msg.sender.call.value(_weiToWithdraw)());
```


##### Explanation

Debug mode enabled by using `msg.sender.call` in production, exposing stack trace information.


##### Impact

Information disclosure of internal state and potential aid for further attacks.


##### Entry Point

/withdrawFunds (uint256 _weiToWithdraw) public


##### Execution Path

```text
caller -> msg.sender.call -> contract internal functions
```


##### HTTP Methods

POST


##### Parameters

_weiToWithdraw, msg.sender


##### Exploitation Steps


- Attack by repeatedly calling withdrawFunds with a small amount to deplete balance.

- Obtain internal state information via msg.sender.call




##### HTTP raw requests (Burp / ZAP)


```http
POST /withdrawFunds(uint256) HTTP/1.1
```


```http
Host: example.com
```


```http
Content-Type: application/json

```


```http


```


```http
100 ether

```







</div>

</details>




---

### File 3: /work/project/dataset/vulnerable/reentrancy/0xbaf51e761510c1a11bf48dd87c0307ac8a8c8a4f.sol


- Similarity score: 0.603






_Source lines 1-85 (1-based, inclusive)._



<details class="report-finding-details">

<summary>Finding 3.1: Debug Information Exposure (High)</summary>

<div class="report-finding-body">


##### Vulnerable Code

```text
pragma solidity ^0.4.19;
contract ETH_VAULT { ... function ETH_VAULT(address _log) public {} }
```


##### Explanation

The contract exposes the internal state of the Log contract through a publicly accessible constructor.


##### Impact

Information disclosure about the internal state of the Log contract.


##### Entry Point

/transfer



##### HTTP Methods

POST


##### Parameters

_log


##### Exploitation Steps


- Call the constructor with a malicious _log parameter to expose internal state.



##### Example Payloads


- `malicious_log_data`




##### Conditions

Access to the Log contract's internal state.


##### Remediation

Disable public constructors and use private functions instead.


##### Secure Example

```text
pragma solidity ^0.4.19;
contract ETH_VAULT { function ETH_VAULT(address _log) private {} }
```


</div>

</details>




---

### File 4: /work/project/dataset/vulnerable/access-control/parity_wallet_bug_1.sol


- Similarity score: 0.600






_Source lines 1-320 (1-based, inclusive)._



<details class="report-finding-details">

<summary>Finding 4.1: Vulnerable Code (High)</summary>

<div class="report-finding-body">


##### Vulnerable Code

```text
/function changeOwner(address _from, address _to) onlymanyowners(sha3(msg.data)) external {
if (isOwner(_to)) return;
uint ownerIndex = m_ownerIndex[uint(msg.sender)];
if (ownerIndex == 0) return;
// ...}
```


##### Explanation

Debug console accessible through the `changeOwner` function


##### Impact

Allowing unauthorized changes to ownership


##### Entry Point

/function changeOwner(address _from, address _to) onlymanyowners(sha3(msg.data)) external


##### Execution Path

```text
Change Owner → Debug Console (Accessible) → Reveal Ownership Details
```



##### Parameters

_from, _to


##### Exploitation Steps


- Exploit: Call `changeOwner` with malicious `_from` and `_to` values to manipulate ownership





##### Conditions

The contract is deployed in a production environment without debug mode disabled.


##### Remediation

Disable debug modes in production and remove development code



</div>

</details>





_Source lines 27-358 (1-based, inclusive)._



<details class="report-finding-details">

<summary>Finding 4.1: Debug Information Exposure (Medium)</summary>

<div class="report-finding-body">


##### Vulnerable Code

```text
function confirm(bytes32 _h) onlymanyowners(sha3(msg.data)) returns (bool o_success)
```


##### Explanation

The `confirm` function is accessible in production, exposing internal state.


##### Impact

Information disclosure about transaction status and owner confirmations.


##### Entry Point

/contracts/WalletAbi.sol confirm


##### Execution Path

```text
Confirming transactions exposes pending operation state.
```



##### Parameters

_h


##### Exploitation Steps


- Reach the confirm function via a single-owner transaction





##### Conditions

Access to multi-signature transactions


##### Remediation

Disable debug modes in production and remove development code.



</div>

</details>





_Source lines 126-467 (1-based, inclusive)._



<details class="report-finding-details">

<summary>Finding 4.1: Debug Information Exposure (Critical)</summary>

<div class="report-finding-body">


##### Vulnerable Code

```text
function execute(address _to, uint _value, bytes _data) external onlyowner returns (bytes32 o_hash) {
  // ...
```


##### Explanation

The contract's `execute` function is exposed in production without debug mode enabled.


##### Impact

Information disclosure about the contract's internal state and behavior.


##### Entry Point

/execute(address, uint256, bytes)


##### Execution Path

```text
execute -> _to.call.value(_value)(_data) -> o_hash = sha3(msg.data, block.number)
            |                    |
  +------------------------+
  |       confirm        |
  +------------------------+
```



##### Parameters

_to, _value, _data


##### Exploitation Steps


- Send a malicious _data to trigger the contract's execution.



##### Example Payloads


- `malicious bytes`




##### Conditions

Contract is deployed in production.


##### Remediation

Enable debug mode and remove exposed functions from production code.


##### Secure Example

```text
function execute(address _to, uint256 _value, bytes _data) internal onlyowner returns (bytes32 o_hash)
  { ... }
```


</div>

</details>





_Source lines 207-477 (1-based, inclusive)._



<details class="report-finding-details">

<summary>Finding 4.1: Debug Information Exposure (Critical)</summary>

<div class="report-finding-body">


##### Vulnerable Code

```text
function execute(address _to, uint _value, bytes _data) external onlyowner returns (bytes32 o_hash)
```


##### Explanation

This function does not disable debug modes in production, exposing sensitive debugging information.


##### Impact

Information disclosure and potential internal system exposure.


##### Entry Point

/execute


##### Execution Path

```text
execute 
  delegatecall(0xcafecafecafecafecafecafecafecafecafe, 0x00) 
  return o_hash
```



##### Parameters

_to, _value, _data


##### Exploitation Steps


- Use a debugger to inspect the contract's internal state.





##### Conditions

Contract is deployed and executed.


##### Remediation

Disable debug modes in production and remove development code.



</div>

</details>




---

### File 5: /work/project/dataset/vulnerable/access-control/parity_wallet_bug_2.sol


- Similarity score: 0.587






_Source lines 1-227 (1-based, inclusive)._



<details class="report-finding-details">

<summary>Finding 5.1: Debug Information Exposure (Low)</summary>

<div class="report-finding-body">


##### Vulnerable Code

```text
function initDaylimit(uint _limit) only_uninitialized {
  m_dailyLimit = _limit;
}
```


##### Explanation

This function is exposed to debug information and allows setting a daily limit.


##### Impact

Potential access to internal system configuration or data through debugging tools.


##### Entry Point

initDaylimit(uint _limit) external only_uninitialized




##### Parameters

_limit




##### HTTP raw requests (Burp / ZAP)


```http
GET /setDailyLimit?limit=1000 HTTP/1.1
```


```http
Host: 127.0.0.1:8080
Accept: */*
Accept-Language: en-US,en;q=0.9
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.3
Accept-Encoding: gzip, deflate
Accept-Charset: utf-8
Referer: https://example.com
Cookie: session_id=1234567890abcdef


```


```http
POST /setDailyLimit HTTP/1.1
Host: 127.0.0.1:8080
Content-Type: application/json
Accept-Language: en-US,en;q=0.9
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.3
Accept-Encoding: gzip, deflate
Accept-Charset: utf-8
Referer: https://example.com
Cookie: session_id=1234567890abcdef

{"limit":1000}

```


```http
GET /setDailyLimit?limit=500 HTTP/1.1
Host: 127.0.0.1:8080
Accept: */*
Accept-Language: en-US,en;q=0.9
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.3
Accept-Encoding: gzip, deflate
Accept-Charset: utf-8
Referer: https://example.com
Cookie: session_id=1234567890abcdef


```







</div>

</details>





_Source lines 1-286 (1-based, inclusive)._



<details class="report-finding-details">

<summary>Finding 5.1: Debug Info Exposure: Pragma solidity enabled (Medium)</summary>

<div class="report-finding-body">


##### Vulnerable Code

```text
pragma solidity ^0.4.9;

```


##### Explanation

Enabling pragma solidity in production exposes debug information.


##### Impact

Potential info disclosure


##### Entry Point

pragma solidity ^0.4.9;








##### Conditions

No specific conditions needed.


##### Remediation

Disable pragma solidity in production.



</div>

</details>





_Source lines 96-414 (1-based, inclusive)._



<details class="report-finding-details">

<summary>Finding 5.1: Debug Information Exposure (High)</summary>

<div class="report-finding-body">


##### Vulnerable Code

```text
# Remove debugging console access
console.log('Hello World');

```


##### Explanation

The contract has a debug console accessible, allowing potential attackers to view sensitive information.


##### Impact

Potential internal system exposure or disclosure of sensitive data.


##### Entry Point

/execute


##### Execution Path

```text
Function -> Execute -> Console.log('Hello World');

Function -> Execute -> Send response to user;
```


##### HTTP Methods

POST



##### Exploitation Steps


- Access the contract's console log output



##### Example Payloads


- `Viewing the console log output of a successful transaction`



##### HTTP raw requests (Burp / ZAP)


```http
POST /execute HTTP/1.1
Host: example.com
Content-Type: application/json

{"data": "Hello World"}

```







</div>

</details>




---

### File 6: /work/project/dataset/vulnerable/ordering-attacks/odds_and_evens.sol


- Similarity score: 0.581






_Source lines 1-61 (1-based, inclusive)._



<details class="report-finding-details">

<summary>Finding 6.1: Vulnerable Code (Critical)</summary>

<div class="report-finding-body">


##### Vulnerable Code

```text
pragma solidity ^0.4.2;
copyright (c) 2015-2017 EEA\n\ All rights reserved.
```


##### Explanation

Debug mode is enabled for the entire contract, exposing sensitive information.


##### Impact

Internal system exposure and potential information disclosure.


##### Entry Point

/contract/OddsAndEvens/


##### Execution Path

```text
debug_mode enabled at line 1, exposed copyright notice at line 2
```



##### Parameters

debug mode


##### Exploitation Steps


- Enable debug mode to expose sensitive information.

- Use debug mode to manipulate contract behavior.



##### Example Payloads


- `Enable debug mode with --debug flag`




##### Conditions

Contract is deployed in a production environment without debug mode disabled.


##### Remediation

Disable debug modes in production, remove development code.


##### Secure Example

```text
pragma solidity ^0.4.2;
copyright (c) 2017 EEA\n\ All rights reserved.
```


</div>

</details>




---

### File 7: /work/project/dataset/vulnerable/access-control/mycontract.sol


- Similarity score: 0.563






_Source lines 1-31 (1-based, inclusive)._



<details class="report-finding-details">

<summary>Finding 7.1: Debug Information Exposure (Medium)</summary>

<div class="report-finding-body">


##### Vulnerable Code

```text
require(tx.origin == owner);
```


##### Explanation

Enabling tx.origin checks in production exposes sensitive debugging information.


##### Impact

Internal system exposure


##### Entry Point

/sendTo(address receiver, uint amount)


##### Execution Path

```text
 TXOriginCheck -> require(tx.origin == owner) -> sendTo(receiver, amount) 
```



##### Parameters

tx.origin


##### Exploitation Steps


- Phishing via an intermediary contract



##### Example Payloads


- `malicious TX origin`




##### Conditions

tx.origin == owner


##### Remediation

Disable tx.origin checks in production, use secure storage for sensitive data.


##### Secure Example

```text
require(msg.sender != 0);
```


</div>

</details>





[Return to table of contents](#table-of-contents)

<a id="assistant"></a>

## Assistant (triage / codebase)

In the OASIS dashboard (JSON report preview), use the chat below to triage findings, exploitation paths, and remediation. Select file, chunk, and finding to narrow context when needed.

[Return to table of contents](#table-of-contents)

<a id="errors-notes"></a>

## Errors & Notes


No file-level errors were recorded.


[Return to table of contents](#table-of-contents)