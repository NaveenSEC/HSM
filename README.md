# AUTOSAR HSM, Secure Boot, Bootloader & Application

A reference implementation of an automotive **Hardware Security Module (HSM)** firmware
together with the **AUTOSAR crypto stack** (Csm → CryIf → Crypto Driver), a
**Boot Manager**, a **UDS flash Bootloader**, and an **Application** using
**SecOC**. It is written in MISRA-style C99 and runs on a host PC as a complete ECU
simulation. Test suites cover MAC generation/verification, SHE key provisioning,
secure boot and the chain of trust.

```
make test     # 59 unit/integration tests (5 suites)
make demo     # end-to-end ECU life-cycle simulation incl. attack scenarios
make asan     # tests under AddressSanitizer + UndefinedBehaviorSanitizer
```

> The HSM is simulated in software, and the bundled keys are **demo keys**. To use
> this in production you must port it to real HSM hardware and adapt the
> configuration (see [Limitations](#limitations)).

---

## Architecture

```
 +-------------------------------- Host core ---------------------------------+
 |  Application (App)        Boot Manager            UDS Bootloader            |
 |   SecOC (MAC gen/verify)   chain-of-trust check    0x10 0x11 0x22 0x27 0x31 |
 |        |                   (CMAC+SHA-256+rollback)  0x34 0x36 0x37 0x3E      |
 |        +-----------------------+----------------------+                     |
 |                                v                                            |
 |   Csm  (jobs, queue, sync/async, START/UPDATE/FINISH, key management)        |
 |   CryIf (channel + key mapping)                                              |
 |   Crypto Driver (driver objects, job queues, SHE key elements, HSM IPC)      |
 +--------------------------------|-------------------------------------------+
                                  |  mailbox (Hsm_IpcSubmit / Hsm_MainFunction)
 +--------------------------------v------------- HSM core --------------------+
 |  Command dispatcher (SHE commands + extensions)                             |
 |  Secure boot (SHE BOOT_MAC)   | Key store (SHE slots, flags, counters)       |
 |  SHE memory update M1..M5     | Lifecycle DEVELOPMENT->PRODUCTION->IN_FIELD   |
 |  AES-128 / CMAC / SHA-256 / HMAC / CTR_DRBG | monotonic counters | debug auth |
 +-----------------------------------------------------------------------------+
```

**Chain of trust:**

1. **HSM** boots first and computes `CMAC(BOOT_MAC_KEY, 0^96 ‖ size ‖ BM+BL)`, then compares it with `BOOT_MAC` (SHE secure boot).
   * Match → `BOOT_OK`; boot-protected keys are usable.
   * Mismatch → `BOOT_OK` cleared, boot-protected keys locked, Boot Manager **halts**.
2. The **Boot Manager** checks for a programming request, then verifies the application through the CSM:
   * header CMAC (key `KEY_1`, boot-protected)
   * SHA-256 of the body
   * anti-rollback against the HSM monotonic counter
3. **Application** is started only if every check passed; otherwise the ECU starts the **Bootloader**.

Details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) · Requirements → code → tests:
[docs/REQUIREMENTS_TRACEABILITY.md](docs/REQUIREMENTS_TRACEABILITY.md)

## Repository layout

| Path | Content |
|---|---|
| `common/` | `Std_Types.h`, `Platform_Types.h`, `Compiler.h` |
| `hsm/crypto/` | AES-128 (ECB/CBC), AES-CMAC, SHA-256, HMAC-SHA-256, AES CTR_DRBG |
| `hsm/keystore/` | SHE key slots + extended slots, protection flags, NVM model |
| `hsm/she/` | SHE KDF (Miyaguchi-Preneel), memory update protocol M1–M5, RAM-key export |
| `hsm/core/` | HSM command dispatcher, secure boot, RNG, debug challenge/authorization, IPC mailbox |
| `autosar/Csm`, `autosar/CryIf`, `autosar/Crypto` | AUTOSAR crypto stack (R4.4 style API) incl. HSM driver |
| `autosar/SecOC` | Secure Onboard Communication (truncated freshness + MAC) |
| `autosar/Det` | Default Error Tracer |
| `config/` | Csm / CryIf / Crypto configuration (jobs, keys, channels) |
| `boot/platform/` | Flash driver (NOR model), memory map, boot data, image verification, ECU start-up |
| `boot/bootmanager/` | Boot Manager |
| `boot/bootloader/` | UDS (ISO 14229) flash bootloader |
| `app/` | Application SW-C (SecOC, diagnostic jump to bootloader) |
| `tools/` | OEM back-end (image signing, M1–M5 generation), EOL provisioning, UDS tester, `hsmtool` CLI |
| `sim/` | End-to-end ECU simulation (`make demo`) |
| `tests/` | Test suites |

## HSM key map

| SHE slot | CSM key | Purpose | Flags |
|---|---|---|---|
| `MASTER_ECU_KEY` (0x1) | `CSM_KEY_MASTER_ECU` | authorises key updates, `CMD_GET_ID`, debug auth | – |
| `BOOT_MAC_KEY` (0x2) | `CSM_KEY_BOOT_MAC_KEY` | secure boot CMAC key | – |
| `BOOT_MAC` (0x3) | – | reference MAC of BM+BL (learned at first boot, not in field) | – |
| `KEY_1` (0x4) | `CSM_KEY_FLASH_VERIFY` | application image authenticity | KEY_USAGE, BOOT_PROT, WILDCARD |
| `KEY_2` (0x5) | `CSM_KEY_DIAG_SECACCESS` | UDS 0x27 seed/key (CMAC) | KEY_USAGE, DEBUGGER_PROT |
| `KEY_3` (0x6) | `CSM_KEY_SECOC` | SecOC PDU authentication | KEY_USAGE, BOOT_PROT |
| `KEY_4` (0x7) | `CSM_KEY_APP_CIPHER` | AES-CBC/ECB encryption | BOOT_PROT |
| `RAM_KEY` (0xE) | `CSM_KEY_RAM` | volatile session key | – |
| ext. slot 0x10 | `CSM_KEY_HMAC` | HMAC-SHA-256 (32 byte key) | – |

## CSM services / jobs

| Job | Service | Algorithm | Processing |
|---|---|---|---|
| `CSM_JOB_FLASH_MAC_GENERATE` / `_VERIFY` | MacGenerate / MacVerify | AES-CMAC | sync, single-call + streaming |
| `CSM_JOB_SECACCESS_MAC_GEN` / `_VERIFY` | MacGenerate / MacVerify | AES-CMAC | sync |
| `CSM_JOB_SECOC_MAC_GENERATE` / `_VERIFY` | MacGenerate / MacVerify (truncated) | AES-CMAC | sync |
| `CSM_JOB_MAC_GENERATE_ASYNC` / `_VERIFY_ASYNC` | MacGenerate / MacVerify | AES-CMAC | async + callback, priority queue |
| `CSM_JOB_HASH_SHA256` (`_ASYNC`) | Hash | SHA-256 | sync / async, streaming |
| `CSM_JOB_ENCRYPT/DECRYPT_AES_CBC/ECB` | Encrypt / Decrypt | AES-128 | sync |
| `CSM_JOB_RANDOM_GENERATE` | RandomGenerate | CTR_DRBG | sync |
| `CSM_JOB_HMAC_GENERATE` / `_VERIFY` | MacGenerate / MacVerify | HMAC-SHA-256 | sync |

Key management goes through `Csm_KeyElementSet` / `Csm_KeySetValid` / `Csm_KeyElementGet`. SHE
updates use the vendor key elements `CRYPTO_KE_CUSTOM_SHE_M1M2M3` (write) and
`CRYPTO_KE_CUSTOM_SHE_M4M5` (read the proof).

## Tests

| Suite | What is verified |
|---|---|
| `test_crypto_primitives` | Known-answer tests for FIPS-197 AES, SP 800-38A ECB/CBC, **RFC 4493 CMAC** (all 4 examples), FIPS 180-4 SHA-256 (incl. 1M × 'a'), RFC 4231 HMAC. Also checks streaming = one-shot, truncated MAC verification and tamper detection. |
| `test_hsm_she` | Official **SHE specification test vector** (M1–M5 and KDF). Rejects M3 forgery, replayed/rolled-back counters, wrong UID and unauthorised auth keys. Covers wildcard UID, write-protection, KEY_USAGE, boot/debugger protection, secure boot (learn / verify / tamper / `CMD_BOOT_FAILURE`), no BOOT_MAC learning in field, debug challenge-response, RNG, RAM-key export, monotonic counter, IPC mailbox. |
| `test_csm_crypto_stack` | Csm→CryIf→Crypto→HSM: MAC generate / verify (OK, NOT_OK, wrong key, modified data, truncated bit lengths), START/UPDATE/FINISH streaming, async jobs with callback, priority and cancel, hash, AES, RNG, HMAC, SHE key update via CSM incl. replay, unreadable key material, RAM key, DET reporting, boot-protected key locking. |
| `test_secoc` | Authenticated PDU layout and MAC; detects data or MAC manipulation; rejects replays; reconstructs freshness across 8-bit wrap-around; tolerates lost messages; 64-bit MAC PDU. |
| `test_secure_boot_chain` | Virgin device, EOL provisioning, flashing and booting the app, update via programming request. Rejects: rollback, patched app body/header/digest, forged signing key, tampered bootloader/boot manager (**HALT** + key lock). Also covers recovery after an interrupted download, security-access lockout, UDS negative responses, DIDs, authenticated `GET_ID`. |

Example output of `make demo`:

```
=== 9. Attack: bootloader patched (e.g. to skip the signature check) ===
  HSM SREG=0x29 secure-boot ERC=0x10 | Boot Manager -> HALT (HSM secure boot failed, app=NO_IMAGE)
  [ OK ] HSM secure boot fails -> ECU halted, boot protected keys locked
```

## Reprogramming sequence (UDS)

```
App      : 10 02                  -> sets programming request, reset
Boot Mgr : programming request    -> start Bootloader (programming session)
Tester   : 27 11 / 27 12          -> key = AES-CMAC(KEY_2, seed), verified by HSM (3 attempts)
           31 01 FF00 44 addr size -> erase application area only
           34 00 44 addr size      -> 36 xx data ... -> 37
           31 01 FF01              -> HSM: header CMAC + SHA-256 + roll-back, commit counter
           11 01                   -> Boot Manager verifies again -> Application
```

## hsmtool (back-end CLI)

```
build/hsmtool sign-app   <key> <sw-version> body.bin app.img   # header + CMAC
build/hsmtool verify-app <key> app.img
build/hsmtool keyupdate  <uid15> <keyId> <authId> <authKey> <newKey> <counter> <flags>   # M1..M5
build/hsmtool bootmac    <bootMacKey> bootcode.bin
build/hsmtool cmac       <key> file
build/hsmtool sha256     file
```

## Limitations

- **Host simulation.** The HSM runs as a function call loop instead of on a separate core. Porting to real hardware (Infineon AURIX HSM, Renesas ICU-M, NXP CSEc/HSE, etc.) means:
  - replace `hsm/crypto` with the hardware accelerators;
  - replace the mailbox in `Hsm.c` with the real IPC/interrupt mechanism;
  - replace `Fls.c` and the HSM NVM model with real drivers.
- **AES uses table look-ups**, so it is not constant-time against cache-timing attacks. Hardware AES avoids this.
- **Symmetric only.** The software-update authenticity check uses AES-CMAC (SHE model). Many OEMs require asymmetric signatures (RSA-PSS / ECDSA) for update packages; these would be added as additional CSM `SignatureVerify` jobs.
- Enumeration values in `Crypto_GeneralTypes.h` are project-local; align them with your AUTOSAR release.
- **Demo keys** in `tools/Backend.c`. Never use fixed keys in production.
