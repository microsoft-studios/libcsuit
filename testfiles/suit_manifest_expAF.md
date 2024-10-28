<!--
 Copyright (c) 2020-2023 SECOM CO., LTD. All Rights reserved.

 SPDX-License-Identifier: BSD-2-Clause
-->

## Example 1: Fetch and Decrypt AES-KW + Encrypted Payload
{: numbered='no'}

### CBOR Diagnostic Notation of SUIT Manifest
{: numbered='no'}

~~~~
/ SUIT_Envelope_Tagged / 107({
  / authentication-wrapper / 2: << [
    << [
      / digest-algorithm-id: / -16 / SHA256 /,
      / digest-bytes: / h'8814BC46089ACA6A863A7BA8393F9747589940EFA40641335EF86155598F06C3'
    ] >>,
    << / COSE_Mac0_Tagged / 17([
      / protected: / << {
        / algorithm-id / 1: 5 / HMAC256 /
      } >>,
      / unprotected: / {},
      / payload: / null,
      / tag: / h'B68572F6F0494FEAF390CE44B462F2A7BDF73EF5DFE9FB8E12585A12F8F641AD'
    ]) >>
  ] >>,
  / manifest / 3: << {
    / manifest-version / 1: 1,
    / manifest-sequence-number / 2: 1,
    / common / 3: << {
      / components / 2: [
        ['plaintext-firmware'],
        ['encrypted-firmware']
      ]
    } >>,
    / install / 20: << [
      / fetch encrypted firmware /
      / directive-set-component-index / 12, 1 / ['encrypted-firmware'] /,
      / directive-override-parameters / 20, {
        / parameter-image-size / 14: 46,
        / parameter-uri / 21: "https://example.com/encrypted-firmware"
      },
      / directive-fetch / 21, 15,

      / decrypt encrypted firmware /
      / directive-set-component-index / 12, 0 / ['plaintext-firmware'] /,
      / directive-override-parameters / 20, {
        / parameter-encryption-info / 19: << 96([
          / protected: / << {
            / alg / 1: 1 / A128GCM /
          } >>,
          / unprotected: / {
            / IV / 5: h'F14AAB9D81D51F7AD943FE87'
          },
          / payload: / null / detached ciphertext /,
          / recipients: / [
            [
              / protected: / h'',
              / unprotected: / {
                / alg / 1: -3 / A128KW /,
                / kid / 4: 'kid-1'
              },
              / payload: / h'75603FFC9518D794713C8CA8A115A7FB32565A6D59534D62' / CEK encrypted with KEK /
            ]
          ]
        ]) >>,
        / parameter-source-component / 22: 1 / ['encrypted-firmware'] /
      },
      / directive-copy / 22, 15 / consumes the SUIT_Encryption_Info above /
    ] >>
  } >>
})
~~~~


### CBOR Binary in Hex
{: numbered='no'}

~~~~
D86BA2025853825824822F58208814BC46089ACA6A863A7BA8393F974758
9940EFA40641335EF86155598F06C3582AD18443A10105A0F65820B68572
F6F0494FEAF390CE44B462F2A7BDF73EF5DFE9FB8E12585A12F8F641AD03
58B2A40101020103582BA102828152706C61696E746578742D6669726D77
6172658152656E637279707465642D6669726D7761726514587C8C0C0114
A20E182E15782668747470733A2F2F6578616D706C652E636F6D2F656E63
7279707465642D6669726D77617265150F0C0014A213583ED8608443A101
01A1054CF14AAB9D81D51F7AD943FE87F6818340A2012204456B69642D31
581875603FFC9518D794713C8CA8A115A7FB32565A6D59534D621601160F
~~~~
