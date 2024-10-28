<!--
 Copyright (c) 2020-2023 SECOM CO., LTD. All Rights reserved.

 SPDX-License-Identifier: BSD-2-Clause
-->

## Example 0: Write and Decrypt AES-KW + Encrypted Payload
{: numbered='no'}

### CBOR Diagnostic Notation of SUIT Manifest
{: numbered='no'}

~~~~
/ SUIT_Envelope_Tagged / 107({
  / authentication-wrapper / 2: << [
    << [
      / digest-algorithm-id: / -16 / SHA256 /,
      / digest-bytes: / h'037A5C325CE14078A0AADF007428EAC659361AD9402A732410BDA542FAE94E2C'
    ] >>,
    << / COSE_Mac0_Tagged / 17([
      / protected: / << {
        / algorithm-id / 1: 5 / HMAC256 /
      } >>,
      / unprotected: / {},
      / payload: / null,
      / tag: / h'8D92599011C451A4C5FB69709FA6CA6C0F846D692BDBB3F624EC91F82F9F620A'
    ]) >>
  ] >>,
  / manifest / 3: << {
    / manifest-version / 1: 1,
    / manifest-sequence-number / 2: 1,
    / common / 3: << {
      / components / 2: [
        ['plaintext-firmware']
      ]
    } >>,
    / install / 20: << [
      / fetch encrypted firmware /
      / directive-override-parameters / 20, {
        / parameter-content / 18: h'758C4B7BBAE2C4C1D462423E0F0DC3164FFA7B85BB94D4BD6D7ED26AB32FEB063385D4D3465927EC82CB5E198A59',
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
        ]) >>
      },

      / decrypt encrypted firmware /
      / directive-write / 18, 15
        / consumes the SUIT_Encryption_Info above /
    ] >>
  } >>
})
~~~~


### CBOR Binary in Hex
{: numbered='no'}

~~~~
D86BA2025853825824822F5820037A5C325CE14078A0AADF007428EAC659
361AD9402A732410BDA542FAE94E2C582AD18443A10105A0F658208D9259
9011C451A4C5FB69709FA6CA6C0F846D692BDBB3F624EC91F82F9F620A03
5898A4010102010357A102818152706C61696E746578742D6669726D7761
72651458778414A212582E758C4B7BBAE2C4C1D462423E0F0DC3164FFA7B
85BB94D4BD6D7ED26AB32FEB063385D4D3465927EC82CB5E198A5913583E
D8608443A10101A1054CF14AAB9D81D51F7AD943FE87F6818340A2012204
456B69642D31581875603FFC9518D794713C8CA8A115A7FB32565A6D5953
4D62120F
~~~~
