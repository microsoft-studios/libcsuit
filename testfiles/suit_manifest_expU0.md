<!--
 Copyright (c) 2020-2023 SECOM CO., LTD. All Rights reserved.

 SPDX-License-Identifier: BSD-2-Clause
-->

## Example 0: Copy Params Example
{: numbered='no'}

### CBOR Diagnostic Notation of SUIT Manifest
{: numbered='no'}

~~~~
/ SUIT_Envelope_Tagged / 107({
  / authentication-wrapper / 2: << [
    << [
      / digest-algorithm-id: / -16 / SHA256 /,
      / digest-bytes: / h'3E4334BE58525756989101480CA8642B13536E4E5BEBB488527744475B41F5FD'
    ] >>,
    << / COSE_Sign1_Tagged / 18([
      / protected: / << {
        / algorithm-id / 1: -7 / ES256 /
      } >>,
      / unprotected: / {},
      / payload: / null,
      / signature: / h'E3D6E28AADDB5E84EF5B55A0B95AD3ACB90BE4C9E3DCBE9026C2586243BA806053C9369B52D8308AED9447A2EB12E47C0646FD8DFA3C24934C20D53785983885'
    ]) >>
  ] >>,
  / manifest / 3: << {
    / manifest-version / 1: 1,
    / manifest-sequence-number / 2: 0,
    / common / 3: << {
      / components / 2: [
        [h'00'],
        [h'01']
      ]
    } >>,
    / install / 20: << [
      / directive-set-component-index / 12, 0,
      / directive-override-parameters / 20, {
        / parameter-use-before / 4: 1696291200 / Tue 03 Oct 2023 12:00:00AM /,
        / parameter-minimum-battery / 26: 10 / 10% /,
        / parameter-update-priority / 27: -1 / 'critical' /,
        / parameter-version / 28: [
          / comparison-type: / 4 / lesser-equal /,
          / comparison-value: / [ 1, 0 ]
        ]
      },

      / directive-set-component-index / 12, 1,
      / directive-copy-params / 35, {
        / src-index / 0: [ 4, 26, 27 ] / use-before, minimum-battery, update-priority /
      },
      / directive-override-parameters / 20, {
        / parameter-version / 28: [
          / comparison-type: / 5 / lesser /,
          / comparison-value: / [ 1, 0, 2 ]
        ]
      },

      / directive-set-component-index / 12, true,
      / directive-run-sequence / 32, << [
        / condition-use-before / 4, 15,
        / condition-minimum-battery / 26, 15,
        / condition-version / 28, 15,
        / condition-update-authorized / 27, 15
      ] >>
    ] >>
  } >>
})
~~~~


### CBOR Binary in Hex
{: numbered='no'}

~~~~
D86BA2025873825824822F58203E4334BE58525756989101480CA8642B13
536E4E5BEBB488527744475B41F5FD584AD28443A10126A0F65840E3D6E2
8AADDB5E84EF5B55A0B95AD3ACB90BE4C9E3DCBE9026C2586243BA806053
C9369B52D8308AED9447A2EB12E47C0646FD8DFA3C24934C20D537859838
85035852A4010102000349A1028281410081410114583F8E0C0014A4041A
651B5980181A0A181B20181C82048201000C011823A1008304181A181B14
A1181C8205830100020CF518204C88040F181A0F181C0F181B0F
~~~~
