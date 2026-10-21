# Architecture

## 1. Layers

| Layer | Modules | Runs on |
|---|---|---|
| Application | `App`, `SecOC` | host core |
| Boot software | `BootManager`, `Bootloader`, `ImageVerify`, `BootData`, `Fls` | host core |
| AUTOSAR crypto stack | `Csm`, `CryIf`, `Crypto` (HSM driver), `Det` | host core |
| HSM firmware | `Hsm` (dispatcher, secure boot, RNG, IPC), `Hsm_KeyStore`, `Hsm_She`, crypto library | HSM core |

The host core can reach key material only through HSM commands. Key values never
leave the HSM; the only exception is the SHE `RAM_KEY`, which can be exported
encrypted as M1–M5 when it was loaded in plain.

## 2. HSM ↔ host interface

`Hsm_RequestType` is the mailbox descriptor (command, key id, up to three
input buffers, two output buffers, scalar value, verify result). The Crypto
Driver posts requests with `Hsm_IpcSubmit()`. The HSM core processes one
request per `Hsm_MainFunction()` call, and the driver collects the result with
`Hsm_IpcRelease()`. In the simulation, the driver's busy-wait steps the HSM core.

### Commands

| SHE standard | Extensions |
|---|---|
| `ENC_ECB/CBC`, `DEC_ECB/CBC` | `MAC_START/UPDATE/FINISH` (streaming CMAC, 8 contexts) |
| `GENERATE_MAC`, `VERIFY_MAC` (bit length) | `HASH_SHA256`, `HASH_START/UPDATE/FINISH` |
| `LOAD_KEY` (M1–M3 → M4, M5) | `HMAC_GENERATE/VERIFY` (extended 32-byte slots) |
| `LOAD_PLAIN_KEY`, `EXPORT_RAM_KEY` | `LOAD_PLAIN_KEY_EXT` (only before `IN_FIELD`) |
| `INIT_RNG`, `EXTEND_SEED`, `RND` | `COUNTER_READ/INCREMENT` (monotonic, anti-rollback) |
| `SECURE_BOOT`, `BOOT_FAILURE`, `BOOT_OK` | `SET_LIFECYCLE`, `KEY_STATUS`, `GET_STATUS` |
| `GET_ID`, `CANCEL`, `DEBUG_CHALLENGE`, `DEBUG_AUTHORIZATION` | |

### Key protection (SHE flags)

| Flag | Effect |
|---|---|
| `WRITE_PROTECTION` | Slot can never be updated again. Debug authorization is refused while any key has this flag. |
| `BOOT_PROTECTION` | Key is unusable unless secure boot succeeded (`BOOT_OK`). |
| `DEBUGGER_PROTECTION` | Key is unusable while a debugger is attached. |
| `KEY_USAGE` | 1 = CMAC only, 0 = encryption/decryption only. |
| `WILDCARD` | Key cannot be updated with the wildcard UID (all zero). |

Every update needs a strictly increasing 28-bit counter, which provides replay protection for key updates.

### Lifecycle

`DEVELOPMENT → PRODUCTION → IN_FIELD` (one way).
In `IN_FIELD`:
- plain key injection into extended slots is refused;
- an empty `BOOT_MAC` is **not** learned automatically, so secure boot fails closed.

## 3. Secure boot

```
reset
  └─ HSM: Hsm_Init()
       ├─ BOOT_MAC_KEY empty            → ERC_NO_SECURE_BOOT (development device)
       ├─ BOOT_MAC empty (not IN_FIELD) → learn BOOT_MAC, BOOT_OK
       ├─ CMAC == BOOT_MAC              → BOOT_OK
       └─ CMAC != BOOT_MAC              → ERC_VERIFY_FAILED, boot-protected keys locked
  └─ host: BSW init (Det, Crypto, CryIf, Csm)
  └─ Boot Manager
       ├─ secure boot failed            → HALT (+ CMD_BOOT_FAILURE)
       ├─ programming request flag      → Bootloader
       ├─ ImageVerify_Application()==OK → Application
       └─ otherwise                     → Bootloader
```

The secure boot CMAC covers both the Boot Manager and the Bootloader
(`SECURE_BOOT_START`..`SECURE_BOOT_SIZE`). Because `KEY_1` (application
verification) is **boot-protected**, a patched boot loader cannot validate
an application: the HSM refuses to use the key.

## 4. Application image

```
APP_START  +0   "APPH" | hdrVer | swVersion | size | entry | reserved
           +32  SHA-256(body)
           +64  AES-CMAC(KEY_1, header[0..63])
           +80  padding
APP_START+0x80  body
```

`ImageVerify_Application()` runs three checks:
1. header CMAC via `Csm_MacVerify` (single call, 128 bits);
2. body SHA-256 via `Csm_Hash` (START/UPDATE in 4 KB chunks/FINISH);
3. `swVersion >= HSM counter 0`.

The Bootloader raises the counter only after a fully verified download.

## 5. Bootloader state machine

| State | Allowed services |
|---|---|
| default session | `10`, `11`, `22`, `3E` |
| programming / extended session, locked | + `27` |
| programming session, unlocked | + `31 FF00` (erase app area only), `34`, `36`, `37`, `31 FF01` |

Security access:
- the seed comes from the HSM DRBG and can be used once;
- key = `AES-CMAC(KEY_2, seed)`, verified by the HSM;
- 3 wrong keys lock the ECU out until the next reset;
- every session request re-locks the ECU.

## 6. SecOC

Secured PDU = `data | FV_trunc | MAC_trunc`. The MAC input is
`DataId(16) | data | FV(32)`. On reception:
- the full freshness value is rebuilt from the truncated one;
- it must be greater than the last accepted value;
- the truncated MAC is checked with `Csm_MacVerify` (length in bits).

## 7. Porting notes

| Simulation | Target |
|---|---|
| `hsm/crypto/*` | HSM AES/CMAC/SHA hardware accelerator driver |
| `Hsm_IpcSubmit` / `Hsm_MainFunction` | shared-RAM mailbox + HSM↔host interrupt |
| `Hsm_KeyStore` NVM struct | HSM-private data flash with power-fail-safe updates |
| `Ecu_GetEntropy` (xorshift) | physical TRNG (+ health tests) |
| `Fls.c` array | Fls/Fee drivers (code & data flash) |
| `Ecu_Reset()` | real reset; Boot Manager jumps to entry points |
