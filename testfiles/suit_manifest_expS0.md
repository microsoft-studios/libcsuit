<!--
 Copyright (c) 2020-2023 SECOM CO., LTD. All Rights reserved.

 SPDX-License-Identifier: BSD-2-Clause
-->

## Example 0: Basic Content+Write Example
{: numbered='no'}

### CBOR Diagnostic Notation of SUIT Manifest
{: numbered='no'}

~~~~
/ SUIT_Envelope_Tagged / 107({
  / authentication-wrapper / 2: << [
    << [
      / digest-algorithm-id: / -16 / SHA256 /,
      / digest-bytes: / h'0F02CAF6D3E61920D36BF3CEA7F862A13BB8FB1F09C3F4C29B121FEAB78EF3D8'
    ] >>,
    << / COSE_Sign1_Tagged / 18([
      / protected: / << {
        / algorithm-id / 1: -7 / ES256 /
      } >>,
      / unprotected: / {},
      / payload: / null,
      / signature: / h'D0703EA193E12381A66FFADEF2F0949711CFE05ED2322818D73D19F2BBD91BE5C52F1604B45C405E96B0642F3D49B2D7C6E3B2C0B40030BDDFBD27AF930B1F8B'
    ]) >>
  ] >>,
  / manifest / 3: << {
    / manifest-version / 1: 1,
    / manifest-sequence-number / 2: 0,
    / common / 3: << {
      / components / 2: [
        ['00']
      ]
    } >>,
    / manifest-component-id / 5: [
      'dependent.suit'
    ],
    / invoke / 9: << [
      / directive-override-parameters / 20, {
        / parameter-invoke-args / 23: 'cat 00'
      },
      / directive-invoke / 23, 15
    ] >>,
    / install / 20: << [
      / directive-override-parameters / 20, {
        / parameter-content / 18: 'hello world'
      },
      / directive-write / 18, 15
    ] >>
  } >>
})
~~~~


### CBOR Binary in Hex
{: numbered='no'}

~~~~
D86BA2025873825824822F58200F02CAF6D3E61920D36BF3CEA7F862A13B
B8FB1F09C3F4C29B121FEAB78EF3D8584AD28443A10126A0F65840D0703E
A193E12381A66FFADEF2F0949711CFE05ED2322818D73D19F2BBD91BE5C5
2F1604B45C405E96B0642F3D49B2D7C6E3B2C0B40030BDDFBD27AF930B1F
8B035842A6010102000347A102818142303005814E646570656E64656E74
2E73756974094D8414A11746636174203030170F14528414A1124B68656C
6C6F20776F726C64120F
~~~~
