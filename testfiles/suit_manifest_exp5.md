<!--
 Copyright (c) 2020-2023 SECOM CO., LTD. All Rights reserved.

 SPDX-License-Identifier: BSD-2-Clause
-->

## B.6. Example 5: Two Images

https://tools.ietf.org/html/draft-ietf-suit-manifest-27#appendix-B.6

{: numbered='no'}

### CBOR Diagnostic Notation of SUIT Manifest
{: numbered='no'}

~~~~
/ SUIT_Envelope = / 107({
  / authentication-wrapper / 2: << [
    << [
      / digest-algorithm-id: / -16 / SHA256 /,
      / digest-bytes: / h'15CE60F77657E4531DC329155F8B0ED78F94BDC6D165B2665473693DCC34F470'
    ] >>,
    << / COSE_Sign1_Tagged / 18([
      / protected: / << {
        / algorithm-id / 1: -7 / ES256 /
      } >>,
      / unprotected: / {},
      / payload: / null,
      / signature: / h'F3B3EFCC47C797508E2316A5FBEBBE3D462C30240CD5349BD781E17C0FEEE58BBC3C8066704C93761A5B5931AAE1BA08632D14880E7FCF6481661045D1399233'
    ]) >>
  ] >>,
  / manifest / 3: << {
    / manifest-version / 1: 1,
    / manifest-sequence-number / 2: 5,
    / common / 3: << {
      / components / 2: [
        [h'00'],
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
        / condition-class-identifier / 2, 15,
        / directive-set-component-index / 12, 1,
        / directive-override-parameters / 20, {
          / image-digest / 3: << [
            / algorithm-id: / -16 / SHA-256 /,
            / digest-bytes: / h'0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff'
          ] >>,
          / image-size / 14: 76834
        }
      ] >>
    } >>,
    / validate / 7: << [
      / directive-set-component-index / 12, 0,
      / condition-image-match / 3, 15,
      / directive-set-component-index / 12, 1,
      / condition-image-match / 3, 15
    ] >>,
    / invoke / 9: << [
      / directive-set-component-index / 12, 0,
      / directive-invoke / 23, 2
    ] >>,
    / install / 20: << [
      / directive-set-component-index / 12, 0,
      / directive-override-parameters / 20, {
        / uri / 21: "http://example.com/file1.bin"
      },
      / directive-fetch / 21, 2,
      / condition-image-match / 3, 15,
      / directive-set-component-index / 12, 1,
      / directive-override-parameters / 20, {
        / uri / 21: "http://example.com/file2.bin"
      },
      / directive-fetch / 21, 2,
      / condition-image-match / 3, 15
    ] >>
  } >>
})
~~~~


### CBOR Binary in Hex
{: numbered='no'}

~~~~
D86BA2025873825824822F582015CE60F77657E4531DC329155F8B0ED78F
94BDC6D165B2665473693DCC34F470584AD28443A10126A0F65840F3B3EF
CC47C797508E2316A5FBEBBE3D462C30240CD5349BD781E17C0FEEE58BBC
3C8066704C93761A5B5931AAE1BA08632D14880E7FCF6481661045D13992
3303590101A601010205035895A202828141008141010458898C0C0014A4
0150FA6B4A53D5AD5FDFBE9DE663E4D41FFE02501492AF1425695E48BF42
9B2D51F2AB45035824822F582000112233445566778899AABBCCDDEEFF01
23456789ABCDEFFEDCBA98765432100E1987D0010F020F0C0114A2035824
822F58200123456789ABCDEFFEDCBA987654321000112233445566778899
AABBCCDDEEFF0E1A00012C220749880C00030F0C01030F0945840C001702
14584F900C0014A115781C687474703A2F2F6578616D706C652E636F6D2F
66696C65312E62696E1502030F0C0114A115781C687474703A2F2F657861
6D706C652E636F6D2F66696C65322E62696E1502030F
~~~~
