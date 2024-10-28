<!--
 Copyright (c) 2020-2023 SECOM CO., LTD. All Rights reserved.

 SPDX-License-Identifier: BSD-2-Clause
-->

## Example 2: Basic Dependency Example
{: numbered='no'}

### CBOR Diagnostic Notation of SUIT Manifest
{: numbered='no'}

~~~~
/ SUIT_Envelope_Tagged / 107({
  / authentication-wrapper / 2: << [
    << [
      / digest-algorithm-id: / -16 / SHA256 /,
      / digest-bytes: / h'A2FFB59E9F1A29D20BF655BC1DE909CB7EDD972A6C09D50FC42983778670715E'
    ] >>,
    << / COSE_Sign1_Tagged / 18([
      / protected: / << {
        / algorithm-id / 1: -7 / ES256 /
      } >>,
      / unprotected: / {},
      / payload: / null,
      / signature: / h'A506F1647E3A9E0F54A07F303443F33E3CFA28520BE1E93C467CD8B14954E460C604A7623F146D833B6F0A2454095855573C48B18570066FA7472077313E80CE'
    ]) >>
  ] >>,
  / manifest / 3: << {
    / manifest-version / 1: 1,
    / manifest-sequence-number / 2: 0,
    / common / 3: << {
      / dependencies / 1: {
        / component-index / 1: {
          / dependency-prefix / 1: [
            'dependent.suit'
          ]
        }
      },
      / components / 2: [
        ['10']
      ]
    } >>,
    / manifest-component-id / 5: [
      'depending.suit'
    ],
    / invoke / 9: << [
      / directive-set-component-index / 12, 0,
      / directive-override-parameters / 20, {
        / parameter-invoke-args / 23: 'cat 00 10'
      },
      / directive-invoke / 23, 15
    ] >>,
    / dependency-resolution / 15: << [
      / directive-set-component-index / 12, 1,
      / directive-override-parameters / 20, {
        / parameter-image-digest / 3: << [
          / digest-algorithm-id: / -16 / SHA256 /,
          / digest-bytes: / h'2EEEC4ACEC877EE13D8B52DB16C4390C93E5D84FD9F25AEAE0717B861BE0C4A2'
        ] >>,
        / parameter-image-size / 14: 190,
        / parameter-uri / 21: "http://example.com/dependent.suit"
      },
      / directive-fetch / 21, 2,
      / condition-image-match / 3, 15
    ] >>,
    / install / 20: << [
      / directive-set-component-index / 12, 1,
      / directive-override-parameters / 20, {
        / parameter-image-digest / 3: << [
          / digest-algorithm-id: / -16 / SHA256 /,
          / digest-bytes: / h'0F02CAF6D3E61920D36BF3CEA7F862A13BB8FB1F09C3F4C29B121FEAB78EF3D8'
        ] >>
      },
      / condition-dependency-integrity / 7, 15,
      / directive-process-dependency / 11, 0,

      / directive-set-component-index / 12, 0,
      / directive-override-parameters / 20, {
        / parameter-content / 18: ' in multiple trust domains'
      },
      / directive-write / 18, 15
    ] >>
  } >>
})
~~~~


### CBOR Binary in Hex
{: numbered='no'}

~~~~
D86BA2025873825824822F5820A2FFB59E9F1A29D20BF655BC1DE909CB7E
DD972A6C09D50FC42983778670715E584AD28443A10126A0F65840A506F1
647E3A9E0F54A07F303443F33E3CFA28520BE1E93C467CD8B14954E460C6
04A7623F146D833B6F0A2454095855573C48B18570066FA7472077313E80
CE0358F9A70101020003581CA201A101A101814E646570656E64656E742E
7375697402818142313005814E646570656E64696E672E73756974095286
0C0014A11749636174203030203130170F0F5857880C0114A3035824822F
58202EEEC4ACEC877EE13D8B52DB16C4390C93E5D84FD9F25AEAE0717B86
1BE0C4A20E18BE157821687474703A2F2F6578616D706C652E636F6D2F64
6570656E64656E742E737569741502030F1458538E0C0114A1035824822F
58200F02CAF6D3E61920D36BF3CEA7F862A13BB8FB1F09C3F4C29B121FEA
B78EF3D8070F0B000C0014A112581A20696E206D756C7469706C65207472
75737420646F6D61696E73120F
~~~~
