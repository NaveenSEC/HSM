# Requirements traceability

Requirements below are derived from:
- the **SHE Functional Specification v1.1** (HIS/AUTOSAR);
- the AUTOSAR SWS documents for **Crypto Service Manager**, **Crypto Interface**, **Crypto Driver** and **SecOC**;
- **ISO 14229-1** (UDS).

Requirement IDs are project-local. The *Source* column names the specification
and topic.

## HSM firmware

| ID | Requirement | Source | Implementation | Test |
|---|---|---|---|---|
| HSM-01 | AES-128 encryption/decryption ECB & CBC | SHE: CMD_ENC/DEC_ECB/CBC | `hsm/crypto/hsm_aes.c`, `Hsm.c:cmdCipher` | `test_aes128_*`, `test_aes_cbc_ecb_roundtrip` |
| HSM-02 | AES-CMAC generation, output truncation | SHE: CMD_GENERATE_MAC; NIST SP 800-38B | `hsm_cmac.c`, `Hsm.c:cmdGenerateMac` | `test_cmac_rfc4493_examples`, `test_mac_generate_*` |
| HSM-03 | CMAC verification with MAC length in bits | SHE: CMD_VERIFY_MAC | `Hsm_CmacVerify`, `Hsm_CompareBits` | `test_cmac_verify_rejects_tampering_and_truncation`, `test_mac_verify_truncated_bits` |
| HSM-04 | Constant-time comparison of MACs | good practice | `Hsm_ConstTimeEqual`, `Hsm_CompareBits` | (code review) |
| HSM-05 | Key derivation via Miyaguchi-Preneel KDF | SHE: KDF | `Hsm_SheMpCompress`, `Hsm_SheKdf` | `test_she_kdf_and_mp` |
| HSM-06 | Key update with M1–M3 and proof M4/M5 | SHE: memory update protocol | `Hsm_SheLoadKey` | `test_she_memory_update_spec_vector` |
| HSM-07 | Reject update with invalid M3 | SHE: memory update protocol | `Hsm_SheLoadKey` | `test_she_update_rejects_bad_mac_replay_and_wrong_uid` |
| HSM-08 | Counter must strictly increase (anti-replay) | SHE: memory update protocol | `Hsm_SheLoadKey` | same as above, `test_key_update_via_csm_she_protocol` |
| HSM-09 | Authorization matrix (which AuthID may update which key) | SHE: memory update protocol | `isAuthAllowed` | `test_she_update_rejects_bad_mac_replay_and_wrong_uid` |
| HSM-10 | UID check, wildcard only if WILDCARD flag not set | SHE: memory update protocol | `Hsm_SheLoadKey` | `test_she_wildcard_and_write_protection` |
| HSM-11 | Write-protected keys are immutable | SHE: key flags | `Hsm_SheLoadKey`, `cmdLoadPlainKeyExt` | `test_she_wildcard_and_write_protection` |
| HSM-12 | KEY_USAGE separates MAC and cipher keys | SHE: key flags | `Hsm_KeyStoreCheckUsage` | `test_key_usage_flag_enforced` |
| HSM-13 | Boot-protected keys unusable without BOOT_OK | SHE: key flags | `Hsm_KeyStoreCheckUsage` | `test_secure_boot_learn_verify_and_fail`, `test_boot_protected_key_locked_after_boot_failure` |
| HSM-14 | Debugger-protected keys unusable with debugger | SHE: key flags | `Hsm_KeyStoreCheckUsage` | `test_debugger_protection` |
| HSM-15 | Secure boot: BOOT_MAC = CMAC(BOOT_MAC_KEY, 0^96‖size‖code) | SHE: secure boot | `Hsm.c:secureBoot` | `test_secure_boot_learn_verify_and_fail` |
| HSM-16 | First boot learns BOOT_MAC (bootstrap) | SHE: secure boot | `secureBoot` | `test_secure_boot_learn_verify_and_fail` |
| HSM-17 | No BOOT_MAC learning in IN_FIELD lifecycle | project security requirement | `secureBoot` | `test_secure_boot_no_learning_in_field` |
| HSM-18 | CMD_BOOT_FAILURE locks boot-protected keys | SHE: CMD_BOOT_FAILURE | `Hsm_ProcessRequest` | `test_secure_boot_learn_verify_and_fail` |
| HSM-19 | RNG must be initialised before use | SHE: CMD_INIT_RNG / CMD_RND | `rngInit`, `rngGenerate` | `test_rng_and_ram_key_export`, `test_drbg_basic` |
| HSM-20 | Debug unlock through challenge/response, erases keys | SHE: CMD_DEBUG_CHALLENGE / AUTHORIZATION | `cmdDebugChallenge`, `cmdDebugAuthorization` | `test_debug_challenge_authorization` |
| HSM-21 | RAM_KEY is volatile and exportable only when loaded in plain | SHE: LOAD_PLAIN_KEY / EXPORT_RAM_KEY | `cmdLoadPlainKey`, `Hsm_SheExportRamKey` | `test_rng_and_ram_key_export` |
| HSM-22 | GET_ID authenticated with MASTER_ECU_KEY | SHE: CMD_GET_ID | `cmdGetId` | `test_get_id_authenticated_by_master_key` |
| HSM-23 | Monotonic counters for anti-rollback | project | `cmdCounter` | `test_monotonic_counter` |
| HSM-24 | Lifecycle only advances | project | `cmdSetLifecycle` | `test_secure_boot_no_learning_in_field` |
| HSM-25 | SHA-256 and HMAC-SHA-256 | FIPS 180-4, RFC 2104 | `hsm_sha256.c` | `test_sha256_fips180`, `test_hmac_sha256_rfc4231`, `test_hmac_sha256_via_csm` |
| HSM-26 | Sensitive buffers wiped after use | good practice | `Hsm_SecureZero` calls | (code review) |

## AUTOSAR crypto stack

| ID | Requirement | Source | Implementation | Test |
|---|---|---|---|---|
| CSM-01 | Csm_MacGenerate / Csm_MacVerify with job id, mode, MAC length in bits | SWS CSM | `Csm.c` | `test_mac_*` |
| CSM-02 | Operation modes START / UPDATE / FINISH / SINGLECALL | SWS CSM / Crypto Driver | `Crypto.c:execMac/execHash` | `test_mac_streaming_start_update_finish`, `test_hash_sha256` |
| CSM-03 | UPDATE/FINISH without START → E_NOT_OK | SWS Crypto Driver | `Crypto.c:executeJob` | `test_mac_streaming_start_update_finish` |
| CSM-04 | Asynchronous jobs: queue, priority, callback notification | SWS CSM / CryIf / Crypto Driver | `Csm_MainFunction`, `Crypto_MainFunction`, `*_CallbackNotification` | `test_mac_async_with_callback`, `test_async_priority_and_cancel` |
| CSM-05 | Job cancellation reports CRYPTO_E_JOB_CANCELED | SWS CSM | `Csm_CancelJob` | `test_async_priority_and_cancel` |
| CSM-06 | Busy job returns CRYPTO_E_BUSY | SWS CSM | `checkJob`, `executeJob` | `test_mac_async_with_callback` |
| CSM-07 | Hash, Encrypt/Decrypt, RandomGenerate, RandomSeed services | SWS CSM | `Csm.c` | `test_hash_sha256`, `test_aes_cbc_ecb_roundtrip`, `test_random_generate` |
| CSM-08 | Key management via KeyElementSet / KeySetValid / KeyElementGet | SWS CSM / Crypto Driver | `Crypto.c` | `test_key_update_via_csm_she_protocol`, `test_ram_key_plain_load` |
| CSM-09 | Secret key elements cannot be read | SWS Crypto Driver (read access) | `Crypto_KeyElementGet` | `test_key_update_via_csm_she_protocol` |
| CSM-10 | Error codes mapped (KEY_NOT_AVAILABLE, KEY_EMPTY, SMALL_BUFFER, ...) | SWS CSM | `Crypto.c:mapErc` | `test_ram_key_plain_load`, `test_aes_cbc_ecb_roundtrip`, `test_boot_protected_key_locked_after_boot_failure` |
| CSM-11 | Development errors reported to DET | SWS CSM / CryIf / Crypto Driver | `*_DET` macros | `test_det_and_parameter_checks` |
| CSM-12 | CryIf maps channels to driver objects and CryIf keys to crypto keys | SWS CryIf | `CryIf.c`, `CryIf_Cfg.c` | all CSM tests |

## Boot software

| ID | Requirement | Source | Implementation | Test |
|---|---|---|---|---|
| BM-01 | Halt if HSM secure boot of BM+BL failed | project security concept | `BootManager_Run` | `test_tampered_bootloader_halts_and_locks_keys`, `test_tampered_boot_manager_halts` |
| BM-02 | Start bootloader on programming request | project / OEM flash spec | `BootManager_Run`, `BootData` | `test_programming_request_flow` |
| BM-03 | Start application only if CMAC, digest and version are valid | project | `ImageVerify_Application` | `test_tampered_application_in_flash`, `test_flash_and_boot_application` |
| BM-04 | Virgin device without application starts the bootloader | project | `BootManager_Run` | `test_virgin_device_starts_bootloader` |
| BL-01 | UDS session control, ECU reset, TesterPresent, ReadDID | ISO 14229-1 | `Bootloader.c` | `test_bootloader_read_dids`, `test_bootloader_protocol_negative_cases` |
| BL-02 | Security access with HSM-generated seed and CMAC key | ISO 14229-1 0x27 + project | `svcSecurityAccess` | `test_security_access_wrong_key_and_lockout` |
| BL-03 | Attempt counter and lockout | ISO 14229-1 NRC 0x36/0x37 | `svcSecurityAccess` | `test_security_access_wrong_key_and_lockout` |
| BL-04 | Erase/download only inside the application area | project | `inAppArea` | `test_bootloader_protocol_negative_cases` |
| BL-05 | Block sequence counter check, repeated block acknowledged | ISO 14229-1 0x36 | `svcTransferData` | `test_bootloader_protocol_negative_cases` |
| BL-06 | Check programming dependencies verifies the image in the HSM and commits the rollback counter | project | `svcRoutine` | `test_rollback_rejected`, `test_image_signed_with_wrong_key_rejected` |
| BL-07 | Recovery after interrupted programming | project | `BootManager_Run` + `Bootloader` | `test_interrupted_download_recovers` |
| BL-08 | Session (re-)entry re-locks security access | project hardening | `svcSession` | `test_bootloader_protocol_negative_cases`, `test_retry_after_failed_update_without_reset` |

## Application / SecOC

| ID | Requirement | Source | Implementation | Test |
|---|---|---|---|---|
| SEC-01 | Authenticator = MAC(DataId‖data‖FV), truncated | SWS SecOC | `SecOC_Authenticate` | `test_secoc_roundtrip_and_layout` |
| SEC-02 | Freshness reconstruction from truncated FV | SWS SecOC | `SecOC_Verify` | `test_secoc_freshness_wraparound`, `test_secoc_lost_messages_resync` |
| SEC-03 | Reject manipulated PDUs | SWS SecOC | `SecOC_Verify` | `test_secoc_detects_tampering` |
| SEC-04 | Reject replayed PDUs | SWS SecOC | `SecOC_Verify` | `test_secoc_replay_rejected` |
| APP-01 | Diagnostic request 10 02 jumps to the bootloader | OEM flash spec | `App_HandleDiag` | `test_update_via_programming_request` |
