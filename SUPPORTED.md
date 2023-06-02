# Supported features by libcsuit

## Summary
- :green_square: : supported
- :red_square: : **not** supported
### SUIT Manifest
Operation | Metadata | Condition | Directive | Parameter | Text
---|---|---|---|---|---
decode | :green_square::green_square::green_square::green_square::green_square::green_square::green_square::green_square::green_square::green_square: | :green_square::green_square::green_square::green_square::green_square::green_square::green_square: | :green_square::green_square::green_square::green_square::green_square::green_square::green_square::green_square::green_square: | :green_square::green_square::green_square::green_square::green_square::green_square::green_square::green_square::green_square::green_square::green_square::green_square::red_square: | :green_square::green_square::green_square::green_square::green_square::green_square:
encode | :green_square::green_square::green_square::green_square::green_square::green_square::green_square::green_square::green_square::green_square: | :green_square::green_square::green_square::green_square::green_square::green_square::green_square: | :green_square::green_square::green_square::green_square::green_square::green_square::green_square::green_square::green_square: | :green_square::green_square::green_square::green_square::green_square::green_square::green_square::green_square::green_square::green_square::green_square::green_square::red_square: | :green_square::green_square::green_square::green_square::green_square::green_square:
process | :green_square::green_square::green_square::green_square::green_square::green_square::green_square::green_square::green_square::green_square: | :green_square::green_square::green_square::green_square::green_square::green_square::green_square: | :green_square::green_square::green_square::green_square::green_square::green_square::green_square::green_square::green_square: | :green_square::green_square::green_square::green_square::green_square::green_square::green_square::green_square::green_square::green_square::green_square::green_square::red_square: | :green_square::green_square::green_square::green_square::green_square::green_square:
### SUIT Multiple Trust Domains
Operation | Metadata | Condition | Directive | Parameter | Text
---|---|---|---|---|---
decode | :green_square::green_square::green_square: | :green_square::green_square: | :green_square::green_square::green_square: |  | 
encode | :green_square::green_square::green_square: | :green_square::green_square: | :green_square::green_square::green_square: |  | 
process | :green_square::green_square::green_square: | :green_square::green_square: | :green_square::green_square::green_square: |  | 
### SUIT Update Management
Operation | Metadata | Condition | Directive | Parameter | Text
---|---|---|---|---|---
decode | :green_square: | :green_square::green_square::green_square::green_square::green_square: | :red_square::red_square::red_square: | :green_square::green_square::green_square::red_square::red_square: | :green_square:
encode | :green_square: | :green_square::green_square::green_square::green_square::green_square: | :red_square::red_square::red_square: | :green_square::green_square::green_square::red_square::red_square: | :green_square:
process | :green_square: | :green_square::green_square::green_square::green_square::red_square: | :red_square::red_square::red_square: | :green_square::green_square::green_square::red_square::red_square: | :green_square:
### SUIT Encrypted Payload
Operation | Metadata | Condition | Directive | Parameter | Text
---|---|---|---|---|---
decode |  |  |  | :green_square::green_square::green_square::red_square: | 
encode |  |  |  | :green_square::green_square::green_square::red_square: | 
process |  |  |  | :green_square::red_square::red_square::red_square: | 
### SUIT Report
Operation | Metadata | Capabilities
---|---|---
decode | :red_square::red_square::red_square::red_square: | :red_square::red_square::red_square::red_square::red_square::red_square::red_square::red_square::red_square::red_square::red_square:
encode | :red_square::red_square::red_square::red_square: | :red_square::red_square::red_square::red_square::red_square::red_square::red_square::red_square::red_square::red_square::red_square:
process | :red_square::red_square::red_square::red_square: | :red_square::red_square::red_square::red_square::red_square::red_square::red_square::red_square::red_square::red_square::red_square:

## NOTE: How to read the Supported Features Tables
**IN**: which document
Name | Reference
---|---
SUIT Manifest | https://datatracker.ietf.org/doc/html/draft-ietf-suit-manifest
SUIT Multiple Trust Domains | https://datatracker.ietf.org/doc/html/draft-moran-suit-trust-domains
SUIT Update Manegement | https://datatracker.ietf.org/doc/html/draft-ietf-suit-update-management
SUIT Encrypted Payload | https://datatracker.ietf.org/doc/html/draft-ietf-suit-firmware-encryption
SUIT Report | https://datatracker.ietf.org/doc/html/draft-ietf-suit-report

**IS**:
- It is **REQUIRED** to (or **MUST**) implement
- It is **RECOMMENDED** to (or **SHOULD**) implement
- It is **OPTIONAL** to (or **MAY**) implement
- It is Not Mentioned (**N/M**) to implement
Only SUIT Manifest document defines REQUIRED features for minimal implementation, so that other documents may not mention.

**Supported?**: libcsuit has 3 core features: decode (Read), encode (Write) and process (eXecute).  
SUIT features are listed below for each SUIT documents.
- **R**: supported, and **-**: not supported
- **W**: supported, and **-**: not supported
- **X**: supported, and **-**: not supported


## Supported Features Tables
## SUIT Manifest + Extensions
### SUIT Metadata

Name | Label | CDDL Structure | IN | IS | Supported?
---|---|---|---|---|---
Delegation | 1 | suit-delegation | SUIT Multiple Trust Domains | N/M | RWX
Authentication Wrapper | 2 | suit-authentication-wrapper | SUIT Manifest | N/M | RWX
Manifest | 3 | suit-manifest | SUIT Manifest | N/M | RWX
CoSWID (s) | 14 | suit-coswid | SUIT Update Management | RECOMMENDED | RWX
Payload Fetch (s) | 16 | suit-payload-fetch | SUIT Manifest | OPTIONAL | RWX
Payload Installation (s) | 17 | suit-install | SUIT Manifest | OPTIONAL | RWX
Text Description (s) | 23 | suit-text | SUIT Manifest | OPTIONAL | RWX
Uninstall (s) | 24 | suit-uninstall | SUIT Multiple Trust Domains | N/M | RWX

Name | Label | CDDL Structure | IN | IS | Supported?
---|---|---|---|---|---
Encoding Version | 1 | suit-manifest-version | SUIT Manifest | REQUIRED | RWX
Sequence Number | 2 | suit-manifest-sequence-number | SUIT Manifest | REQUIRED | RWX
Common Data | 3 | suit-common | SUIT Manifest | REQUIRED | RWX
Reference URI | 4 | suit-reference-uri | SUIT Manifest | N/M | RWX
Manifest Component ID | 5 | suit-manifest-component-id | SUIT Multiple Trust Domains | N/M | RWX
Image Validation | 7 | suit-validate | SUIT Manifest | REQUIRED | RWX
Image Loading | 8 | suit-load | SUIT Manifest | OPTIONAL | RWX
Image Invocation | 9 | suit-invoke | SUIT Manifest | OPTIONAL | RWX
CoSWID | 14 | suit-coswid | SUIT Update Management | RECOMMENDED | RWX
Dependency Resolution | 15 | suit-dependency-resolution | SUIT Multiple Trust Domains | N/M | RWX
Payload Fetch | 16 | suit-payload-fetch | SUIT Manifest | OPTIONAL | RWX
Payload Installation | 17 | suit-install | SUIT Manifest | OPTIONAL | RWX
Text Description | 23 | suit-text | SUIT Manifest | OPTIONAL | RWX
Uninstall | 24 | suit-uninstall | SUIT Multiple Trust Domains | N/M | RWX

### SUIT Common

Name | Label | CDDL Structure | IN | IS | Supported?
---|---|---|---|---|---
Dependencies | 1 | suit-dependencies | SUIT Multiple Trust Domains | N/M | RWX
Components | 2 | suit-components | SUIT Manifest | REQUIRED | RWX
Shared Sequence | 4 | suit-shared-sequence | SUIT Manifest | RECOMMENDED/REQUIRED | RWX

### SUIT Condition

Name | Label | CDDL Structure | IN | IS | Supported?
---|---|---|---|---|---
Vendor Identifier | 1 | suit-condition-vendor-identifier | SUIT Manifest | REQUIRED | RWX
Class Identifier | 2 | suit-condition-class-identifier | SUIT Manifest | N/M | RWX
Image Match | 3 | suit-condition-image-match | SUIT Manifest | REQUIRED | RWX
Use Before | 4 | suit-condition-use-before | SUIT Update Management | OPTIONAL | RWX
Component Slot | 5 | suit-condition-component-slot | SUIT Manifest | N/M | RWX
Check Content | 6 | suit-condition-check-content | SUIT Manifest | N/M | RWX
Dependency Integrity | 7 | suit-condition-dependency-integrity | SUIT Multiple Trust Domains | N/M | RWX
Is Dependency | 8 | suit-condition-is-dependency | SUIT Multiple Trust Domains | N/M | RWX
Abort | 14 | suit-condition-abort | SUIT Manifest | N/M | RWX
Device Identifier | 24 | suit-condition-device-identifier | SUIT Manifest | OPTIONAL | RWX
Image Not Match | 25 | suit-condition-image-not-match | SUIT Update Management | OPTIONAL | RWX
Minimum Battery | 26 | suit-condition-minimum-battery | SUIT Update Management | OPTIONAL | RWX
Update Authorized | 27 | suit-condition-update-authorized | SUIT Update Management | OPTIONAL | RWX
Version | 28 | suit-condition-version | SUIT Update Management | N/M | RW-
Custom Condition | - | suit-condition-custom | SUIT Manifest | N/M | ---

### SUIT Directive

Name | Label | CDDL Structure | IN | IS | Supported?
---|---|---|---|---|---
Process Dependency | 11 | suit-directive-process-dependency | SUIT Multiple Trust Domains | N/M | RWX
Set Component Index | 12 | suit-directive-set-component-index | SUIT Manifest | REQUIRED | RWX
Try Each | 15 | suit-directive-try-each | SUIT Manifest | OPTIONAL | RWX
Write | 18 | suit-directive-write | SUIT Manifest | N/M | RWX
Set Parameters | 19 | suit-directive-set-parameters | SUIT Multiple Trust Domains | N/M | RWX
Override Parameters | 20 | suit-directive-override-parameters | SUIT Manifest | N/M | RWX
Fetch | 21 | suit-directive-fetch | SUIT Manifest | N/M | RWX
Copy | 22 | suit-directive-copy | SUIT Manifest | N/M | RWX
Invoke | 23 | suit-directive-invoke | SUIT Manifest | REQUIRED for Bootloader | RWX
Wait | 29 | suit-directive-wait | SUIT Update Management | N/M | ---
Swap | 31 | suit-directive-swap | SUIT Manifest | N/M | RWX
Run Sequence | 32 | suit-directive-run-sequence | SUIT Manifest | OPTIONAL | RWX
Unlink | 33 | suit-directive-unlink | SUIT Multiple Trust Domains | N/M | RWX
Override Multiple | ? | suit-directive-override-multiple | SUIT Update Management | N/M | ---
Copy Params | ? | suit-directive-copy-params | SUIT Update Management | N/M | ---

### SUIT Parameters

Name | Label | CDDL Structure | IN | IS | Supported?
---|---|---|---|---|---
Vendor ID | 1 | suit-parameter-vendor-identifier | SUIT Manifest | N/M | RWX
Class ID | 2 | suit-parameter-class-identifier | SUIT Manifest | N/M | RWX
Image Digest | 3 | suit-parameter-image-digest | SUIT Manifest | N/M | RWX
Use Before | 4 | suit-parameter-use-before | SUIT Update Management | N/M | RWX
Component Slot | 5 | suit-parameter-component-slot | SUIT Manifest | N/M | RWX
Strict Order | 12 | suit-parameter-strict-order | SUIT Manifest | N/M | RWX
Soft Failure | 13 | suit-parameter-soft-failure | SUIT Manifest | N/M | RWX
Image Size | 14 | suit-parameter-image-size | SUIT Manifest | N/M | RWX
Content | 18 | suit-parameter-content | SUIT Manifest | N/M | RWX
Encryption Info (AES-KW) | 19 | suit-parameter-encryption-info | SUIT Encrypted Payload | N/M | RWX
Encryption Info (ECDH)   | 19 | suit-parameter-encryption-info | SUIT Encrypted Payload | N/M | RW-
Encryption Info (HPKE)   | 19 | suit-parameter-encryption-info | SUIT Encrypted Payload | N/M | RW-
CEK Verification | 20 | suit-parameter-cek-verification | SUIT Encrypted Payload | N/M | ---
URI | 21 | suit-parameter-uri | SUIT Manifest | N/M | RWX
Source Component | 22 | suit-parameter-source-component | SUIT Manifest | N/M | RWX
Invoke Args | 23 | suit-parameter-invoke-args | SUIT Manifest | N/M | RWX
Device ID | 24 | suit-parameter-device-identifier | SUIT Manifest | N/M | RWX
Minimum Battery | 26 | suit-parameter-minimum-battery | SUIT Update Management | N/M | RWX
Update Priority | 27 | suit-parameter-update-priority | SUIT Update Management | N/M | RWX
Version | 28 | suit-parameter-version | SUIT Update Management | N/M | ---
Wait Info | 29 | suit-parameter-wait-info | SUIT Update Management | N/M | ---
Fetch Arguments | ? | suit-parameter-fetch-arguments | SUIT Manifest | N/M | ---
Custom | - | suit-parameter-custom | SUIT Manifest | N/M | ---

### SUIT Text

NOTE: libcsuit ignores this while processing a SUIT Manifest

Name | Label | CDDL Structure | IN | IS | Supported?
---|---|---|---|---|---
Vendor Name | 1 | suit-text-vendor-name | SUIT Manifest | OPTIONAL | RWX
Model Name | 2 | suit-text-model-name | SUIT Manifest | OPTIONAL | RWX
Vendor Domain | 3 | suit-text-vendor-domain | SUIT Manifest | OPTIONAL | RWX
Model Info | 4 | suit-text-model-info | SUIT Manifest | OPTIONAL | RWX
Component Description | 5 | suit-text-component-description | SUIT Manifest | OPTIONAL | RWX
Component Version | 6 | suit-text-component-version | SUIT Manifest | OPTIONAL | RWX
Version Required | 7 | suit-text-version-required | SUIT Update Management | N/M | RWX

## SUIT Report
### SUIT_Report

Name | Label | CDDL Structure | IN | IS | Supported?
---|---|---|---|---|---
Reference | ? | suit-reference | SUIT Report | N/M | ---
Nonce | ? | suit-report-nonce | SUIT Report | N/M | ---
Result | ? | suit-report-result | SUIT Report | N/M | ---
Extensions | ? | suit-report-extensions | SUIT Report | N/M | ---

### SUIT Capability Reporting

Name | Label | CDDL Structure | IN | IS | Supported?
---|---|---|---|---|---
Component | ? | suit-component-capabilities | SUIT Report | N/M | ---
Command | ? | suit-command-capabilities | SUIT Report | N/M | ---
Parameters | ? | suit-parameters-capabilities | SUIT Report | N/M | ---
Crypt Algo | ? | suit-crypt-algo-capabilities | SUIT Report | N/M | ---
Envelope | ? | suit-envelope-capabilities | SUIT Report | N/M | ---
Manifest | ? | suit-manivest-capabilities | SUIT Report | N/M | ---
Common | ? | suit-common-capabilities | SUIT Report | N/M | ---
Text Component | ? | suit-text-component-capabilities | SUIT Report | N/M | ---
Text | ? | suit-text-capabilities | SUIT Report | N/M | ---
Dependency | ? | suit-dependency-capabilities | SUIT Report | N/M | ---
Extensions | ? | suit-capability-report-extensions | SUIT Report | N/M | ---

