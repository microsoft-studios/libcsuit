<!--
 Copyright (c) 2020-2023 SECOM CO., LTD. All Rights reserved.

 SPDX-License-Identifier: BSD-2-Clause
-->

## B.4. Example 3: A/B images
https://tools.ietf.org/html/draft-ietf-suit-manifest-27#appendix-B.4

{: numbered='no'}

### CBOR Diagnostic Notation of SUIT Manifest
{: numbered='no'}

~~~~
/ SUIT_Envelope = / 107({
  / authentication-wrapper / 2: << [
    << [
      / digest-algorithm-id: / -16 / SHA256 /,
      / digest-bytes: / h'F6D44A62EC906B392500C242E78E908E9CC5057F3F04104A06A8566200DA2EE0'
    ] >>,
    << / COSE_Sign1_Tagged / 18([
      / protected: / << {
        / algorithm-id / 1: -7 / ES256 /
      } >>,
      / unprotected: / {},
      / payload: / null,
      / signature: / h'1B5E052F3E8B2AAD1330B1B1D9055B1EF2BBB8AEA0841034D3CD7906AABB723A91A218E7E23C96F8973DDC88D0A31C25FC18D52BA1F2712198E618CECDD30718'
    ]) >>
  ] >>,
  / manifest / 3: << {
    / manifest-version / 1: 1,
    / manifest-sequence-number / 2: 3,
    / common / 3: << {
      / components / 2: [
        [h'00']
      ],
      / shared-sequence / 4: << [
        / directive-override-parameters / 20, {
          / vendor-id / 1: h'fa6b4a53d5ad5fdfbe9de663e4d41ffe' / fa6b4a53-d5ad-5fdf-be9d-e663e4d41ffe /,
          / class-id / 2: h'1492af1425695e48bf429b2d51f2ab45' / 1492af14-2569-5e48-bf42-9b2d51f2ab45 /
        },
        / directive-try-each / 15, [
          << [
            / directive-override-parameters / 20, {
              / component-slot / 5: 0
            },
            / condition-component-slot / 5, 5,
            / directive-override-parameters / 20, {
              / image-digest / 3: << [
                / algorithm-id: / -16 / SHA-256 /,
                / digest-bytes: / h'00112233445566778899aabbccddeeff0123456789abcdeffedcba9876543210'
              ] >>,
              / image-size / 14: 34768
            }
          ] >>,
          << [
            / directive-override-parameters / 20, {
              / component-slot / 5: 1
            },
            / condition-component-slot / 5, 5,
            / directive-override-parameters / 20, {
              / image-digest / 3: << [
                / algorithm-id: / -16 / SHA-256 /,
                / digest-bytes: / h'0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff'
              ] >>,
              / image-size / 14: 76834
            }
          ] >>
        ],
        / condition-vendor-identifier / 1, 15,
        / condition-class-identifier / 2, 15
      ] >>
    } >>,
    / validate / 7: << [
      / condition-image-match / 3, 15
    ] >>,
    / install / 20: << [
      / directive-try-each / 15, [
        << [
          / directive-override-parameters / 20, {
            / component-slot / 5: 0
          },
          / condition-component-slot / 5, 5,
          / directive-override-parameters / 20, {
            / uri / 21: "http://example.com/file1.bin"
          }
        ] >>,
        << [
          / directive-override-parameters / 20, {
            / component-slot / 5: 1
          },
          / condition-component-slot / 5, 5,
          / directive-override-parameters / 20, {
            / uri / 21: "http://example.com/file2.bin"
          }
        ] >>
      ],
      / directive-fetch / 21, 2,
      / condition-image-match / 3, 15
    ] >>
  } >>
})
~~~~


### CBOR Binary in Hex
{: numbered='no'}

~~~~
D86BA2025873825824822F5820F6D44A62EC906B392500C242E78E908E9C
C5057F3F04104A06A8566200DA2EE0584AD28443A10126A0F658401B5E05
2F3E8B2AAD1330B1B1D9055B1EF2BBB8AEA0841034D3CD7906AABB723A91
A218E7E23C96F8973DDC88D0A31C25FC18D52BA1F2712198E618CECDD307
180359010FA5010102030358A4A2028181410004589B8814A20150FA6B4A
53D5AD5FDFBE9DE663E4D41FFE02501492AF1425695E48BF429B2D51F2AB
450F8258348614A10500050514A2035824822F5820001122334455667788
99AABBCCDDEEFF0123456789ABCDEFFEDCBA98765432100E1987D0583686
14A10501050514A2035824822F58200123456789ABCDEFFEDCBA98765432
1000112233445566778899AABBCCDDEEFF0E1A00012C22010F020F074382
030F14585B860F8258288614A10500050514A115781C687474703A2F2F65
78616D706C652E636F6D2F66696C65312E62696E58288614A10501050514
A115781C687474703A2F2F6578616D706C652E636F6D2F66696C65322E62
696E1502030F
~~~~
