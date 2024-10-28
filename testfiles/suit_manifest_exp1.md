<!--
 Copyright (c) 2020-2023 SECOM CO., LTD. All Rights reserved.

 SPDX-License-Identifier: BSD-2-Clause
-->

## B.2. Example 1: Simultaneous Download and Installation of Payload
https://tools.ietf.org/html/draft-ietf-suit-manifest-27#appendix-B.2

{: numbered='no'}

### CBOR Diagnostic Notation of SUIT Manifest
{: numbered='no'}

~~~~
/ SUIT_Envelope = / 107({
  / authentication-wrapper / 2: << [
    << [
      / digest-algorithm-id: / -16 / SHA256 /,
      / digest-bytes: / h'1F2E7ACCA0DC2786F2FE4EB947F50873A6A3CFAA98866C5B02E621F42074DAF2'
    ] >>,
    << / COSE_Sign1_Tagged / 18([
      / protected: / << {
        / algorithm-id / 1: -7 / ES256 /
      } >>,
      / unprotected: / {},
      / payload: / null,
      / signature: / h'0D4AFA637ECA6D7B4970DC85926001B42B8E1B96D512CA065E8BD0028B67E04561A2993414C9F2649ED78B37E6F2DD02D147D14BBCBBE25C5982265B5B812062'
    ]) >>
  ] >>,
  / manifest / 3: << {
    / manifest-version / 1: 1,
    / manifest-sequence-number / 2: 1,
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
    / install / 20: << [
      / directive-override-parameters / 20, {
        / uri / 21: "http://example.com/file.bin"
      },
      / directive-fetch / 21, 2,
      / condition-image-match / 3, 15
    ] >>
  } >>
})~~~~


### CBOR Binary in Hex
{: numbered='no'}

~~~~
D86BA2025873825824822F58201F2E7ACCA0DC2786F2FE4EB947F50873A6
A3CFAA98866C5B02E621F42074DAF2584AD28443A10126A0F658400D4AFA
637ECA6D7B4970DC85926001B42B8E1B96D512CA065E8BD0028B67E04561
A2993414C9F2649ED78B37E6F2DD02D147D14BBCBBE25C5982265B5B8120
62035894A50101020103585FA202818141000458568614A40150FA6B4A53
D5AD5FDFBE9DE663E4D41FFE02501492AF1425695E48BF429B2D51F2AB45
035824822F582000112233445566778899AABBCCDDEEFF0123456789ABCD
EFFEDCBA98765432100E1987D0010F020F074382030F1458258614A11578
1B687474703A2F2F6578616D706C652E636F6D2F66696C652E62696E1502
030F
~~~~
