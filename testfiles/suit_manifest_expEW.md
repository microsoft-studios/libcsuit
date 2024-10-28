<!--
 Copyright (c) 2020-2023 SECOM CO., LTD. All Rights reserved.

 SPDX-License-Identifier: BSD-2-Clause
-->

## Example 2: Write and Decrypt ES-ECDH + AES-KW + Encrypted Payload
{: numbered='no'}

### CBOR Diagnostic Notation of SUIT Manifest
{: numbered='no'}

~~~~
/ SUIT_Envelope_Tagged / 107({
  / authentication-wrapper / 2: << [
    << [
      / digest-algorithm-id: / -16 / SHA256 /,
      / digest-bytes: / h'1DB69EF1477E9942815F29F78E09957B26B4ADD03902BDB3D1EDF3DA2075F593'
    ] >>,
    << / COSE_Sign1_Tagged / 18([
      / protected: / << {
        / algorithm-id / 1: -7 / ES256 /
      } >>,
      / unprotected: / {},
      / payload: / null,
      / signature: / h'CB4EADA6BEC17EEB22EB836FB2BF9136A6EF733C11DAC955F543BBDCAA373B859321BC77969917E4C70F049527607F4C32752D53E01346E96BFF4880B437DF64'
    ]) >>
  ] >>,
  / manifest / 3: << {
    / manifest-version / 1: 1,
    / manifest-sequence-number / 2: 1,
    / common / 3: << {
      / components / 2: [
        ['decrypted-firmware']
      ]
    } >>,
    / install / 20: << [
      / directive-set-component-index / 12, 0 / ['plaintext-firmware'] /,
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
              / protected: / << {
                / alg / 1: -29 / ECDH-ES + A128KW /
              } >>,
              / unprotected: / {
                / ephemeral key / -1: {
                  / kty / 1: 2 / EC2 /,
                  / crv / -1: 1 / P-256 /,
                  / x / -2: h'73024F415AA51529A66CCEFD88F3F62A734492FF45F6AD37FD2888E73EAF19DA',
                  / y / -3: h'4005B48A6FD091AA6ABFE3CFBEEDE88B347E521D43405FDBD7D2CFF0EBC21B26'
                },
                / kid / 4: 'kid-2'
              },
              / payload: / h'A06B8E6550F308712B1DF044B21B7D11D9B22792F1DE0997'
                / CEK encrypted with KEK /
            ]
          ]
        ]) >>
      },
      / directive-write / 18, 15 / consumes the SUIT_Encryption_Info above /
    ] >>
  } >>
})
~~~~


### CBOR Binary in Hex
{: numbered='no'}

~~~~
D86BA2025873825824822F58201DB69EF1477E9942815F29F78E09957B26
B4ADD03902BDB3D1EDF3DA2075F593584AD28443A10126A0F65840CB4EAD
A6BEC17EEB22EB836FB2BF9136A6EF733C11DAC955F543BBDCAA373B8593
21BC77969917E4C70F049527607F4C32752D53E01346E96BFF4880B437DF
640358E8A4010102010357A1028181526465637279707465642D6669726D
776172651458C7860C0014A212582E758C4B7BBAE2C4C1D462423E0F0DC3
164FFA7B85BB94D4BD6D7ED26AB32FEB063385D4D3465927EC82CB5E198A
5913588CD8608443A10101A1054CF14AAB9D81D51F7AD943FE87F6818344
A101381CA220A40102200121582073024F415AA51529A66CCEFD88F3F62A
734492FF45F6AD37FD2888E73EAF19DA2258204005B48A6FD091AA6ABFE3
CFBEEDE88B347E521D43405FDBD7D2CFF0EBC21B2604456B69642D325818
A06B8E6550F308712B1DF044B21B7D11D9B22792F1DE0997120F
~~~~
