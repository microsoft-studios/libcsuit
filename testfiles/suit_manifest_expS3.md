<!--
 Copyright (c) 2020-2023 SECOM CO., LTD. All Rights reserved.

 SPDX-License-Identifier: BSD-2-Clause
-->

## Example 3: Integrated Dependency Example
{: numbered='no'}

### CBOR Diagnostic Notation of SUIT Manifest
{: numbered='no'}

~~~~
/ SUIT_Envelope_Tagged / 107({
  / authentication-wrapper / 2: << [
    << [
      / digest-algorithm-id: / -16 / SHA256 /,
      / digest-bytes: / h'6391CBC36495B9C87AC3EC841DB124DABD8D3C9FE2DEEFE16569AFC349E7DDB2'
    ] >>,
    << / COSE_Sign1_Tagged / 18([
      / protected: / << {
        / algorithm-id / 1: -7 / ES256 /
      } >>,
      / unprotected: / {},
      / payload: / null,
      / signature: / h'517250281E6567FF9DF519CF9D76A440D86DFEB65B505D180D7D794FEC67823FA0E98EBC526FBC985777EAB4E2FFE813A44F205C015AEB3FA842F33E37B52716'
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
        / parameter-uri / 21: "#dependent.suit"
      },
      / directive-fetch / 21, 2,
      / condition-image-match / 3, 15
    ] >>,
    / install / 20: << [
      / directive-set-component-index / 12, 1,
      / directive-process-dependency / 11, 0,

      / directive-set-component-index / 12, 0,
      / directive-override-parameters / 20, {
        / parameter-content / 18: ' in multiple trust domains'
      },
      / directive-write / 18, 15
    ] >>
  } >>,
  "#dependent.suit": h'D86BA2025873825824822F58200F02CAF6D3E61920D36BF3CEA7F862A13BB8FB1F09C3F4C29B121FEAB78EF3D8584AD28443A10126A0F65840D0703EA193E12381A66FFADEF2F0949711CFE05ED2322818D73D19F2BBD91BE5C52F1604B45C405E96B0642F3D49B2D7C6E3B2C0B40030BDDFBD27AF930B1F8B035842A6010102000347A102818142303005814E646570656E64656E742E73756974094D8414A11746636174203030170F14528414A1124B68656C6C6F20776F726C64120F'
})
~~~~


### CBOR Binary in Hex
{: numbered='no'}

~~~~
D86BA3025873825824822F58206391CBC36495B9C87AC3EC841DB124DABD
8D3C9FE2DEEFE16569AFC349E7DDB2584AD28443A10126A0F65840517250
281E6567FF9DF519CF9D76A440D86DFEB65B505D180D7D794FEC67823FA0
E98EBC526FBC985777EAB4E2FFE813A44F205C015AEB3FA842F33E37B527
160358BBA70101020003581CA201A101A101814E646570656E64656E742E
7375697402818142313005814E646570656E64696E672E73756974095286
0C0014A11749636174203030203130170F0F5844880C0114A3035824822F
58202EEEC4ACEC877EE13D8B52DB16C4390C93E5D84FD9F25AEAE0717B86
1BE0C4A20E18BE156F23646570656E64656E742E737569741502030F1458
288A0C010B000C0014A112581A20696E206D756C7469706C652074727573
7420646F6D61696E73120F6F23646570656E64656E742E7375697458BED8
6BA2025873825824822F58200F02CAF6D3E61920D36BF3CEA7F862A13BB8
FB1F09C3F4C29B121FEAB78EF3D8584AD28443A10126A0F65840D0703EA1
93E12381A66FFADEF2F0949711CFE05ED2322818D73D19F2BBD91BE5C52F
1604B45C405E96B0642F3D49B2D7C6E3B2C0B40030BDDFBD27AF930B1F8B
035842A6010102000347A102818142303005814E646570656E64656E742E
73756974094D8414A11746636174203030170F14528414A1124B68656C6C
6F20776F726C64120F
~~~~
