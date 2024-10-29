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
      / digest-bytes: / h'A6D2C13A0DEFD57A09FA65C24206A9A8747261E6EA017532B3DAB0419C42A2FC'
    ] >>,
    << / COSE_Mac0_Tagged / 17([
      / protected: / << {
        / algorithm-id / 1: 5 / HMAC256 /
      } >>,
      / unprotected: / {},
      / payload: / null,
      / tag: / h'DB350AC9603B0BBA3895B850196993633F314A9066634B31BF62E596FD870434'
    ]) >>
  ] >>,
  / manifest / 3: << {
    / manifest-version / 1: 1,
    / manifest-sequence-number / 2: 1,
    / common / 3: << {
      / components / 2: [
        [h'00'],
        [h'01']
      ]
    } >>,
    / install / 20: << [
      / fetch encrypted firmware /
      / directive-set-component-index / 12, 1 / [h'01'] /,
      / directive-override-parameters / 20, {
        / parameter-image-size / 14: 46,
        / parameter-uri / 21: "https://example.com/encrypted-firmware"
      },
      / directive-fetch / 21, 15,

      / decrypt encrypted firmware /
      / directive-set-component-index / 12, 0 / ['00'] /,
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
        / parameter-source-component / 22: 1 / [h'01'] /
      },
      / directive-copy / 22, 15
        / consumes the SUIT_Encryption_Info above /
    ] >>
  } >>
})
~~~~


### CBOR Binary in Hex
{: numbered='no'}

~~~~
D86BA2025853825824822F5820A6D2C13A0DEFD57A09FA65C24206A9A874
7261E6EA017532B3DAB0419C42A2FC582AD18443A10105A0F65820DB350A
C9603B0BBA3895B850196993633F314A9066634B31BF62E596FD87043403
588FA4010102010349A1028281410081410114587C8C0C0114A20E182E15
782668747470733A2F2F6578616D706C652E636F6D2F656E637279707465
642D6669726D77617265150F0C0014A213583ED8608443A10101A1054CF1
4AAB9D81D51F7AD943FE87F6818340A2012204456B69642D31581875603F
FC9518D794713C8CA8A115A7FB32565A6D59534D621601160F
~~~~
