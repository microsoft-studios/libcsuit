<!--
 Copyright (c) 2020-2023 SECOM CO., LTD. All Rights reserved.

 SPDX-License-Identifier: BSD-2-Clause
-->

## B.1. Example 0: Secure Boot
https://tools.ietf.org/html/draft-ietf-suit-manifest-27#appendix-B.1

{: numbered='no'}

### CBOR Diagnostic Notation of SUIT Manifest
{: numbered='no'}

~~~~
/ SUIT_Envelope = / 107({
  / authentication-wrapper / 2: << [
    << [
      / digest-algorithm-id: / -16 / SHA256 /,
      / digest-bytes: / h'6658EA560262696DD1F13B782239A064DA7C6C5CBAF52FDED428A6FC83C7E5AF'
    ] >>,
    << / COSE_Sign1_Tagged / 18([
      / protected: / << {
        / algorithm-id / 1: -7 / ES256 /
      } >>,
      / unprotected: / {},
      / payload: / null,
      / signature: / h'6C56F1463DE7D83C945B88BCEB0797958938942A71B2B4A7DFFE2B4E8F07B91DD4EE3C6C48F869E668F6CE9113C32DE6B2B17DBCABDCAD5588102D486C3884DF'
    ]) >>
  ] >>,
  / manifest / 3: << {
    / manifest-version / 1: 1,
    / manifest-sequence-number / 2: 0,
    / common / 3: << {
      / components / 2: [
        [h'00']
      ],
      / shared-sequence / 4: << [
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
      / condition-image-match / 3, 15
    ] >>,
    / invoke / 9: << [
      / directive-invoke / 23, 2
    ] >>
  } >>
})~~~~


### CBOR Binary in Hex
{: numbered='no'}

~~~~
D86BA2025873825824822F58206658EA560262696DD1F13B782239A064DA
7C6C5CBAF52FDED428A6FC83C7E5AF584AD28443A10126A0F658406C56F1
463DE7D83C945B88BCEB0797958938942A71B2B4A7DFFE2B4E8F07B91DD4
EE3C6C48F869E668F6CE9113C32DE6B2B17DBCABDCAD5588102D486C3884
DF035871A50101020003585FA202818141000458568614A40150FA6B4A53
D5AD5FDFBE9DE663E4D41FFE02501492AF1425695E48BF429B2D51F2AB45
035824822F582000112233445566778899AABBCCDDEEFF0123456789ABCD
EFFEDCBA98765432100E1987D0010F020F074382030F0943821702
~~~~
