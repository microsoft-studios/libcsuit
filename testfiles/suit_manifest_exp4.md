<!--
 Copyright (c) 2020-2023 SECOM CO., LTD. All Rights reserved.

 SPDX-License-Identifier: BSD-2-Clause
-->

## B.5. Example 4: Load from External Storage

https://tools.ietf.org/html/draft-ietf-suit-manifest-27#appendix-B.5

{: numbered='no'}

### CBOR Diagnostic Notation of SUIT Manifest
{: numbered='no'}

~~~~
/ SUIT_Envelope = / 107({
  / authentication-wrapper / 2: << [
    << [
      / digest-algorithm-id: / -16 / SHA256 /,
      / digest-bytes: / h'5B5F6586B1E6CDF19EE479A5ADABF206581000BD584B0832A9BDAF4F72CDBDD6'
    ] >>,
    << / COSE_Sign1_Tagged / 18([
      / protected: / << {
        / algorithm-id / 1: -7 / ES256 /
      } >>,
      / unprotected: / {},
      / payload: / null,
      / signature: / h'EE5913F4D6DCF4CA278E363084C02378B6340138C3FB403C9A8A1F4B8C226FD247AE9D7D005BDF193F21DBACD8EDD908E7D80594AE1A657F97E14A02DEFBD5EE'
    ]) >>
  ] >>,
  / manifest / 3: << {
    / manifest-version / 1: 1,
    / manifest-sequence-number / 2: 4,
    / common / 3: << {
      / components / 2: [
        [h'00'],
        [h'02'],
        [h'01']
      ],
      / shared-sequence / 4: << [
        / directive-set-component-index / 12, 0,
        / directive-override-parameters / 20, {
          / vendor-id / 1: h'fa6b4a53d5ad5fdfbe9de663e4d41ffe' / fa6b4a53-d5ad-5fdf-be9d-e663e4d41ffe /,
          / class-id / 2: h'1492af1425695e48bf429b2d51f2ab45' / 1492af14-2569-5e48-bf42-9b2d51f2ab45 /,
          / image-digest / 3: << [
            / algorithm-id: / -16 / SHA-256 /,
            / digest-bytes: / h'00112233445566778899aabbccddeeff0123456789abcdeffedcba9876543210'
          ] >>,
          / image-size / 14: 34768
        },
        / condition-vendor-identifier / 1, 15,
        / condition-class-identifier / 2, 15
      ] >>
    } >>,
    / validate / 7: << [
      / directive-set-component-index / 12, 0,
      / condition-image-match / 3, 15
    ] >>,
    / load / 8: << [
      / directive-set-component-index / 12, 2,
      / directive-override-parameters / 20, {
        / image-digest / 3: << [
          / algorithm-id: / -16 / SHA-256 /,
          / digest-bytes: / h'0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff'
        ] >>,
        / image-size / 14: 76834,
        / source-component / 22: 0
      },
      / directive-copy / 22, 2,
      / condition-image-match / 3, 15
    ] >>,
    / invoke / 9: << [
      / directive-set-component-index / 12, 2,
      / directive-invoke / 23, 2
    ] >>,
    / payload-fetch / 16: << [
      / directive-set-component-index / 12, 1,
      / directive-override-parameters / 20, {
        / image-digest / 3: << [
          / algorithm-id: / -16 / SHA-256 /,
          / digest-bytes: / h'00112233445566778899aabbccddeeff0123456789abcdeffedcba9876543210'
        ] >>,
        / uri / 21: "http://example.com/file.bin"
      },
      / directive-fetch / 21, 2,
      / condition-image-match / 3, 15
    ] >>,
    / install / 20: << [
      / directive-set-component-index / 12, 0,
      / directive-override-parameters / 20, {
        / source-component / 22: 1
      },
      / directive-copy / 22, 2,
      / condition-image-match / 3, 15
    ] >>
  } >>
})
~~~~


### CBOR Binary in Hex
{: numbered='no'}

~~~~
D86BA2025873825824822F58205B5F6586B1E6CDF19EE479A5ADABF20658
1000BD584B0832A9BDAF4F72CDBDD6584AD28443A10126A0F65840EE5913
F4D6DCF4CA278E363084C02378B6340138C3FB403C9A8A1F4B8C226FD247
AE9D7D005BDF193F21DBACD8EDD908E7D80594AE1A657F97E14A02DEFBD5
EE03590116A801010204035867A20283814100814102814101045858880C
0014A40150FA6B4A53D5AD5FDFBE9DE663E4D41FFE02501492AF1425695E
48BF429B2D51F2AB45035824822F582000112233445566778899AABBCCDD
EEFF0123456789ABCDEFFEDCBA98765432100E1987D0010F020F0745840C
00030F085838880C0214A3035824822F58200123456789ABCDEFFEDCBA98
7654321000112233445566778899AABBCCDDEEFF0E1A00012C2216001602
030F0945840C02170210584E880C0114A2035824822F5820001122334455
66778899AABBCCDDEEFF0123456789ABCDEFFEDCBA987654321015781B68
7474703A2F2F6578616D706C652E636F6D2F66696C652E62696E1502030F
144B880C0014A116011602030F
~~~~
