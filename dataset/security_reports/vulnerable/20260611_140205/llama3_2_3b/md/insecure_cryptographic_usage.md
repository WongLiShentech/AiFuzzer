

# Insecure Cryptographic Usage Security Analysis

Date: 2026-06-11 23:22:53  
Model: llama3.2:3b  
Vulnerability: Insecure Cryptographic Usage

<a id="table-of-contents"></a>

## Table of contents

| | |
| --- | --- |
| 📋 [Summary](#summary) | 📊 [Statistics](#statistics) |
| 📁 [Files](#files) | 🔍 [Detailed analysis](#detailed-analysis) |
| 💬 [Assistant](#assistant) | ⚠️ [Errors & notes](#errors--notes) |

## Summary

Analyzed 11 file(s) for Insecure Cryptographic Usage.

[Return to table of contents](#table-of-contents)

## Statistics

- Files analyzed: 11
- Total findings: 16
- Critical: 4
- High: 3
- Medium: 4
- Low: 5

[Return to table of contents](#table-of-contents)

## Files

| File | Similarity |
|------|------------|
| `/work/project/dataset/vulnerable/oracle-manipulation/PuppetV2Pool.sol` | 0.665 |
| `/work/project/dataset/vulnerable/ordering-attacks/FindThisHash.sol` | 0.650 |
| `/work/project/dataset/vulnerable/reentrancy/etherstore.sol` | 0.643 |
| `/work/project/dataset/vulnerable/reentrancy/simple_dao.sol` | 0.641 |
| `/work/project/dataset/vulnerable/reentrancy/0xbaf51e761510c1a11bf48dd87c0307ac8a8c8a4f.sol` | 0.630 |
| `/work/project/dataset/vulnerable/access-control/parity_wallet_bug_1.sol` | 0.616 |
| `/work/project/dataset/vulnerable/ordering-attacks/odds_and_evens.sol` | 0.615 |
| `/work/project/dataset/vulnerable/ordering-attacks/eth_tx_order_dependence_minimal.sol` | 0.604 |
| `/work/project/dataset/vulnerable/access-control/parity_wallet_bug_2.sol` | 0.602 |
| `/work/project/dataset/vulnerable/access-control/mycontract.sol` | 0.601 |
| `/work/project/dataset/vulnerable/ordering-attacks/ERC20.sol` | 0.581 |


[Return to table of contents](#table-of-contents)

## Detailed Analysis


---

### File 1: /work/project/dataset/vulnerable/oracle-manipulation/PuppetV2Pool.sol


- Similarity score: 0.665






_Source lines 1-70 (1-based, inclusive)._



<details class="report-finding-details">

<summary>Finding 1.1: Insecure SHA1 Usage (Low)</summary>

<div class="report-finding-body">


##### Vulnerable Code

```text
function _getOracleQuote(uint256 amount) private view returns (uint256) {
  (uint256 reservesWETH, uint256 reservesToken) = UniswapV2Library.getReserves({factory: _uniswapFactory, tokenA: address(_weth), tokenB: address(_token)});
  return UniswapV2Library.quote({amountA: amount * 10 ** 18, reserveA: reservesToken, reserveB: reservesWETH});
}
```


##### Explanation

Using SHA1 for message integrity is insecure. Modern applications should use more secure algorithms like SHA256 or BLAKE2.


##### Impact

Potential message tampering attacks using SHA1 collision flaws


##### Entry Point

/getOracleQuote



##### HTTP Methods

POST


##### Parameters

amount


##### Exploitation Steps


- Find a valid non-colliding message for the hash





##### Conditions

Oracle quote calculation using SHA1 is vulnerable to collision attacks.


##### Remediation

Use SHA256 or BLAKE2 instead of SHA1 for message integrity


##### Secure Example

```text
function _getOracleQuote(uint256 amount) private view returns (uint256) {
  (uint256 reservesWETH, uint256 reservesToken) = UniswapV2Library.getReserves({factory: _uniswapFactory, tokenA: address(_weth), tokenB: address(_token)});
  return UniswapV2Library.quote({amountA: amount * 10 ** 18, reserveA: reservesToken, reserveB: reservesWETH}, "SHA256"));
}
```


</div>

</details>




---

### File 2: /work/project/dataset/vulnerable/ordering-attacks/FindThisHash.sol


- Similarity score: 0.650






_Source lines 1-28 (1-based, inclusive)._



<details class="report-finding-details">

<summary>Finding 2.1: Weak Hash Algorithm (Low)</summary>

<div class="report-finding-body">


##### Vulnerable Code

```text
require(hash == sha3(solution));
```


##### Explanation

sha3() is a weak hash algorithm that can be vulnerable to collisions.


##### Impact

Potential for successful hash collision attacks.


##### Entry Point

solve(string solution) public


##### Execution Path

```text
sha3(solution)
```



##### Parameters

solution


##### Exploitation Steps


- Replay attack: Find the pre-image of the hash



##### Example Payloads


- `"abc"`




##### Conditions

Message is transferred via a channel not under attacker's control


##### Remediation

Use a stronger hash function like Keccak-256 or BLAKE2b.


##### Secure Example

```text
require(hash == keccak256(solution));
```


</div>

</details>




---

### File 3: /work/project/dataset/vulnerable/reentrancy/etherstore.sol


- Similarity score: 0.643






_Source lines 1-39 (1-based, inclusive)._



<details class="report-finding-details">

<summary>Finding 3.1: Insecure Hash Algorithm (Critical)</summary>

<div class="report-finding-body">


##### Vulnerable Code

```text
require(balances[msg.sender] >= _weiToWithdraw) && require(msg.sender.call.value(_weiToWithdraw)());
```


##### Explanation

Using SHA1 is deprecated and considered insecure.


##### Impact

Data compromise through collision attacks


##### Entry Point

withdrawFunds function




##### Parameters

_weiToWithdraw


##### Exploitation Steps


- Find a collision in the hash function





##### Conditions

No specific conditions needed


##### Remediation

Use a secure hash algorithm like SHA256 or Argon2


##### Secure Example

```text
require(balances[msg.sender] >= _weiToWithdraw) && require(msg.sender.call.value(_weiToWithdraw)(keccak256)_);
```


</div>

</details>




---

### File 4: /work/project/dataset/vulnerable/reentrancy/simple_dao.sol


- Similarity score: 0.641






_Source lines 1-35 (1-based, inclusive)._



<details class="report-finding-details">

<summary>Finding 4.1: SHA1 Usage (Critical)</summary>

<div class="report-finding-body">


##### Vulnerable Code

```text
function withdraw(uint amount) {
  if (credit[msg.sender] >= amount) {
    bool res = msg.sender.call.value(amount)("SHA-256 hash");
    credit[msg.sender] -= amount;
  }
}
```


##### Explanation

Using SHA1 for cryptographic purposes is insecure.


##### Impact

Potential for forging transactions.


##### Entry Point

/withdraw


##### Execution Path

```text
 withdraw -> call -> SHA-256 hash

```



##### Parameters

amount


##### Exploitation Steps


- Replay attack: send forged transaction with correct hash



##### Example Payloads


- `"00:00:00,0000000"`




##### Conditions

Authenticated user


##### Remediation

Use a secure hash function like SHA-256.


##### Secure Example

```text
bool res = msg.sender.call.value(amount)("SHA-256 hash");
credit[msg.sender] -= amount;
```


</div>

</details>




---

### File 5: /work/project/dataset/vulnerable/reentrancy/0xbaf51e761510c1a11bf48dd87c0307ac8a8c8a4f.sol


- Similarity score: 0.630






_Source lines 1-85 (1-based, inclusive)._



<details class="report-finding-details">

<summary>Finding 5.1: Vulnerability found (Critical)</summary>

<div class="report-finding-body">


##### Vulnerable Code

```text
function CashOut(uint _am) public payable { if(_am<=balances[msg.sender]) { // <yes> <report> REENTRANCY if(msg.sender.call.value(_am)()) { ... } } }
```


##### Explanation

The use of `msg.sender.call.value(_am)` is vulnerable to reentrancy attacks because it allows an attacker to drain the contract's funds by repeatedly calling `CashOut` and then cancelling the transaction before the previous one is processed.


##### Impact

Draining of funds from the contract


##### Entry Point

/CashOut


##### Execution Path

```text
CashOut -> msg.sender.call.value(_am)() -> if successful, subtract _am from balances[msg.sender]
```



##### Parameters

_am


##### Exploitation Steps


- Send a large amount of Ether to the contract's address using CashOut



##### Example Payloads


- `Large amount of Ether (e.g. 1 ether)`




##### Conditions

Contract has not been paused


##### Remediation

Use a reentrancy protection mechanism such as a modifier that checks for and prevents reentrancy.


##### Secure Example

```text
function CashOut(uint _am) public payable { require(_am > 0, 'Invalid amount'); balances[msg.sender] -= _am; }
```


</div>

</details>




---

### File 6: /work/project/dataset/vulnerable/access-control/parity_wallet_bug_1.sol


- Similarity score: 0.616






_Source lines 1-320 (1-based, inclusive)._



<details class="report-finding-details">

<summary>Finding 6.1: Weak Hash Algorithm (Medium)</summary>

<div class="report-finding-body">


##### Vulnerable Code

```text
event RequirementChanged(uint newRequirement) onlymanyowners(sha3(msg.data)) external {
  if (newRequirement > m_numOwners) return;
  m_required = newRequirement;
  clearPending();
  RequirementChanged(newRequired);
}
```


##### Explanation

The use of sha3() without a secure salt or iteration is weak and vulnerable to collisions.


##### Impact

An attacker could potentially calculate the hash using brute force and cause the wallet to incorrectly determine its required signatures.


##### Entry Point

RequirementChanged


##### Execution Path

```text
sha3(msg.data)
  ->
  m_required = newRequirement
  ->
  clearPending()
  ->
  RequirementChanged(newRequired)
```



##### Parameters

newRequirement


##### Exploitation Steps


- Use a brute-force attack to calculate the sha3 hash with all possible values of newRequirement.





##### Conditions

m_required is not properly validated before being used as a limit.


##### Remediation

Use a secure hash algorithm like Keccak-256 and provide a salt and iteration count to prevent collisions.


##### Secure Example

```text
event RequirementChanged(uint newRequirement) onlymanyowners(keccak256(msg.data, 0x40)) external {
  // ...}

```


</div>

</details>





_Source lines 72-421 (1-based, inclusive)._



<details class="report-finding-details">

<summary>Finding 6.1: Weak SHA3 Usage (Medium)</summary>

<div class="report-finding-body">


##### Vulnerable Code

```text
modifier onlymanyowners(bytes32 _operation) { if (confirmAndCheck(_operation)) _; }
```


##### Explanation

Using SHA3 without specifying the algorithm version (e.g., SHA3-224, SHA3-256) makes it vulnerable to collisions and weak hash generation.


##### Impact

Potential for weak hashes being generated, leading to compromised data integrity.


##### Entry Point

onlymanyowners(bytes32 _operation)


##### Execution Path

```text
SHA3(_operation) 
 confirmAndCheck(_operation) 
 onlymanyowners(_operation)
```



##### Parameters

_operation


##### Exploitation Steps


- Use a collision attack to create two different but equivalent hashes



##### Example Payloads


- `Invalid operation hash`





##### Remediation

Specify the SHA3 algorithm version (e.g., SHA3-224, SHA3-256) in the usage.


##### Secure Example

```text
modifier onlymanyowners(bytes32 _operation) { if (confirmAndCheck(_operation)) _; }
```


</div>

</details>





_Source lines 126-467 (1-based, inclusive)._



<details class="report-finding-details">

<summary>Finding 6.1: MD5 Usage (High)</summary>

<div class="report-finding-body">


##### Vulnerable Code

```text
function confirm(bytes32 _h) onlymanyowners(sha3(msg.data)) external returns (bool o_success) { ... }
```


##### Explanation

The use of MD5 is insecure and should be replaced with a stronger hash function like SHA-256.


##### Impact

Potential for cryptanalysis attacks on the confirmation process.


##### Entry Point

/confirm


##### Execution Path

```text
delegatecall -> confirm -> delegatecall -> create
```


##### HTTP Methods

POST


##### Parameters

_h


##### Exploitation Steps


- Obtain MD5 preimage to forge confirmation




##### HTTP raw requests (Burp / ZAP)


```http
POST /confirm HTTP/1.1 
Host: example.com 

<MD5-preimage>
```







</div>

</details>





_Source lines 207-477 (1-based, inclusive)._



<details class="report-finding-details">

<summary>Finding 6.1: Insecure use of MD5 (Medium)</summary>

<div class="report-finding-body">


##### Vulnerable Code

```text
function setDailyLimit(uint _newLimit) onlymanyowners(sha3(msg.data)) external { m_dailyLimit = _newLimit; }
```


##### Explanation

The `sha3` function is used with the message data, which includes a hash of `_required`. This introduces an additional weakness to the implementation.


##### Impact

MD5 collisions could be exploited to bypass the daily limit check.


##### Entry Point

/setDailyLimit




##### Parameters

_newLimit


##### Exploitation Steps


- Calculate MD5 hash of message data and compare it with a precomputed table





##### Conditions

Message contains a hash of `_required`


##### Remediation

Use SHA-256 instead of MD5 for the hash function


##### Secure Example

```text
function setDailyLimit(uint _newLimit) onlymanyowners(sha256(msg.data)) external { m_dailyLimit = _newLimit; }
```


</div>

</details>




---

### File 7: /work/project/dataset/vulnerable/ordering-attacks/odds_and_evens.sol


- Similarity score: 0.615






_Source lines 1-61 (1-based, inclusive)._



<details class="report-finding-details">

<summary>Finding 7.1: SHA1 usage (Critical)</summary>

<div class="report-finding-body">


##### Vulnerable Code

```text
res = players[0].addr.send(1800 finney);
```


##### Explanation

SHA1 is considered insecure for cryptographic purposes and should be replaced with a stronger algorithm like SHA256.


##### Impact

Data compromise through SHA1 collisions or other attacks


##### Entry Point

/transfer


##### Execution Path

```text
res = players[0].addr.send(1800 finney);
  if (n%2==0) {
    res = players[0].addr.send(1800 finney);
  } else {
    res = players[1].addr.send(1800 finney);
  }

```



##### Parameters

number, addr


##### Exploitation Steps


- Find the value of n and use it to calculate the expected outcome





##### Conditions

Attacker has knowledge of players[0].addr


##### Remediation

Use SHA256 instead of SHA1 for sending amounts.


##### Secure Example

```text
res = players[0].addr.send(1800 finney, "SHA256");
```


</div>

</details>




---

### File 8: /work/project/dataset/vulnerable/ordering-attacks/eth_tx_order_dependence_minimal.sol


- Similarity score: 0.604






_Source lines 1-42 (1-based, inclusive)._



<details class="report-finding-details">

<summary>Finding 8.1: Weak Hash Algorithm (High)</summary>

<div class="report-finding-body">


##### Vulnerable Code

```text
require(!claimed);
require(msg.sender == owner);
owner.transfer(reward);
reward = msg.value;
```


##### Explanation

The contract uses the weak SHA1 hash algorithm, which is no longer considered secure.


##### Impact

Data integrity compromised due to the use of a weak hash function.


##### Entry Point

/setReward


##### Execution Path

```text
owner.transfer(reward) -> reward = msg.value
```



##### Parameters

msg.sender, reward


##### Exploitation Steps


- Attacker sends a fake message with a specific reward value to trick the owner into transferring funds.



##### Example Payloads


- `A fake message with a specific reward value`



##### HTTP raw requests (Burp / ZAP)


```http
POST /transfer HTTP/1.1
```


```http
Host: localhost:8080
```


```http
Content-Length: 0
```


```http
Content-Type: application/json

{}
```


```http
reward = 10
```







</div>

</details>




---

### File 9: /work/project/dataset/vulnerable/access-control/parity_wallet_bug_2.sol


- Similarity score: 0.602






_Source lines 1-227 (1-based, inclusive)._



<details class="report-finding-details">

<summary>Finding 9.1: Weak Hash Algorithm (Medium)</summary>

<div class="report-finding-body">


##### Vulnerable Code

```text
function changeRequirement(uint _newRequired) onlymanyowners(sha3(msg.data)) external { ... }
```


##### Explanation

SHA-1 is a weak hash algorithm and should be replaced with SHA-256 or another secure hash function.


##### Impact

Attacker could potentially predict the new requirement value.


##### Entry Point

changeRequirement(uint _newRequired) onlymanyowners(sha3(msg.data)) external { ... }




##### Parameters

_newRequired


##### Exploitation Steps


- Obtain a copy of the SHA-1 hash table for the new requirement value





##### Conditions

The attacker has knowledge of the previous requirement values.


##### Remediation

Use SHA-256 or another secure hash function instead of SHA-1.



</div>

</details>





_Source lines 1-286 (1-based, inclusive)._



<details class="report-finding-details">

<summary>Finding 9.1: Weak Hash Algorithm (Low)</summary>

<div class="report-finding-body">


##### Vulnerable Code

```text
function changeRequirement(uint _newRequired) onlymanyowners(sha3(msg.data)) external {
if (_newRequired > m_numOwners) return;
m_required = _newRequired;
clearPending();
RequirementChanged(_newRequired);
}
```


##### Explanation

The contract uses the weak hash algorithm SHA-1, which is vulnerable to collision attacks.


##### Impact

An attacker could potentially find a collision in the SHA-1 hash, allowing them to manipulate the `m_required` variable.


##### Entry Point

changeRequirement




##### Parameters

_newRequired


##### Exploitation Steps


- Find a collision in the SHA-1 hash




##### HTTP raw requests (Burp / ZAP)


```http
POST /changeRequirement HTTP/1.1
Host: example.com
Content-Type: application/json

{\
```


```http
"_newRequired": 10}
```


```http


```







</div>

</details>





_Source lines 96-414 (1-based, inclusive)._



<details class="report-finding-details">

<summary>Finding 9.1: Weak Hash Algorithm (Low)</summary>

<div class="report-finding-body">


##### Vulnerable Code

```text
function confirm(bytes32 _h) onlymanyowners(_h) returns (bool o_success) {
  if (m_txs[_h].to != 0 || m_txs[_h].value != 0 || m_txs[_h].data.length != 0) {
    address created;
    if (m_txs[_h].to == 0) {
      created = create(m_txs[_h].value, m_txs[_h].data);
    } else {
      if (!m_txs[_h].to.call.value(m_txs[_h].value)(m_txs[_h].data))
        throw;
    }

    MultiTransact(msg.sender, _h, m_txs[_h].value, m_txs[_h].to, m_txs[_h].data, created);
    delete m_txs[_h];
    return true;
  }
```


##### Explanation

The SHA3 function is used directly without checking its security implications.


##### Impact

Possible weakness in the transaction confirmation process may lead to data integrity issues.


##### Entry Point

/confirm


##### Execution Path

```text
confirm bytes32 _h)
  if (m_txs[_h].to != 0 || m_txs[_h].value != 0 || m_txs[_h].data.length != 0) {
    ...}
```



##### Parameters

_h


##### Exploitation Steps


- Use a collision attack to manipulate the transaction hash.





##### Conditions

Transaction hash is not validated.


##### Remediation

Replace SHA3 with a secure alternative, such as Keccak-256.


##### Secure Example

```text
function confirm(bytes32 _h) onlymanyowners(_h) returns (bool o_success) {
  if (m_txs[_h].to != 0 || m_txs[_h].value != 0 || m_txs[_h].data.length != 0) {
    ...
```


</div>

</details>




---

### File 10: /work/project/dataset/vulnerable/access-control/mycontract.sol


- Similarity score: 0.601






_Source lines 1-31 (1-based, inclusive)._



<details class="report-finding-details">

<summary>Finding 10.1: Vulnerability found (High)</summary>

<div class="report-finding-body">


##### Vulnerable Code

```text
require(tx.origin == owner);
```


##### Explanation

tx.origin is deprecated, use address(msg.sender) instead.


##### Impact

Phishing via an intermediary contract is possible.


##### Entry Point

sendTo(address receiver, uint amount)



##### HTTP Methods

POST


##### Parameters

receiver, amount


##### Exploitation Steps


- Get the owner's address from tx.origin

- Create a phishing contract with the same owner address



##### Example Payloads


- `malicious contract code`




##### Conditions

tx.origin is available


##### Remediation

Use address(msg.sender) instead of tx.origin


##### Secure Example

```text
require(address(msg.sender) == owner);
receiver.transfer(amount);
```


</div>

</details>




---

### File 11: /work/project/dataset/vulnerable/ordering-attacks/ERC20.sol


- Similarity score: 0.581






_Source lines 1-137 (1-based, inclusive)._



<details class="report-finding-details">

<summary>Finding 11.1: Weak SHA-1 Usage (Low)</summary>

<div class="report-finding-body">



##### Explanation

The contract uses SHA-1 for hashing, which is considered insecure due to its high collision rate.


##### Impact

Potential for hash collisions allowing attackers to forge signatures.


##### Entry Point

/approve(address, uint256) and /transfer(address, uint256)




##### Parameters

value


##### Exploitation Steps


- Replay attack: forge a signature to transfer funds



##### Example Payloads


- `malicious allowance request`



##### HTTP raw requests (Burp / ZAP)


```http
POST /approve(address, uint256) HTTP/1.1
Host: example.com
Content-Type: application/json

{"address": "0x123456", "value": 100}

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