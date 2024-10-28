<!--
 Copyright (c) 2020-2023 SECOM CO., LTD. All Rights reserved.

 SPDX-License-Identifier: BSD-2-Clause
-->

## Example 2: SUIT Manifest including the Trusted Component Binary {#suit-integrated}

~~~~
/ SUIT_Envelope / {
  / authentication-wrapper / 2: << [
    << [
      / digest-algorithm-id: / -16 / SHA256 /,
      / digest-bytes: / h'CEDB0457952F7DD0A33FA4692F73BC833A6A6E2300B16F6605993F0192E3F219'
    ] >>,
    << / COSE_Sign1_Tagged / 18([
      / protected: / << {
        / algorithm-id / 1: -7 / ES256 /
      } >>,
      / unprotected: / {},
      / payload: / null,
      / signature: / h'71E3869E4E134A78C95D7ED81F5911FEA4F189EC33C0F6474C866569ED3DF7FB4E0D8871367BA3C73612A26C9E3984A4E22CAA4BFBCE84DCAC0539AE87BE9D3D'
    ]) >>
  ] >>,
  / manifest / 3: << {
    / manifest-version / 1: 1,
    / manifest-sequence-number / 2: 3,
    / common / 3: << {
      / components / 2: [
        [
           'TEEP-Device',
           'SecureFS',
          h'8D82573A926D4754935332DC29997F74', / tc-uuid /
           'ta'
        ]
      ],
      / shared-sequence / 4: << [
        / directive-override-parameters / 20, {
          / parameter-vendor-identifier / 1: h'C0DDD5F15243566087DB4F5B0AA26C2F',
          / parameter-class-identifier / 2: h'DB42F7093D8C55BAA8C5265FC5820F4E',
          / parameter-image-digest / 3: << [
            / digest-algorithm-id: / -16 / SHA256 /,
            / digest-bytes: / h'8CF71AC86AF31BE184EC7A05A411A8C3A14FD9B77A30D046397481469468ECE8'
          ] >>,
          / parameter-image-size / 14: 20
        },
        / condition-vendor-identifier / 1, 15,
        / condition-class-identifier / 2, 15
      ] >>
    } >>,
    / manifest-component-id / 5: [
       'TEEP-Device',
       'SecureFS',
      h'8D82573A926D4754935332DC29997F74',  / tc-uuid /
       'suit'
    ],
    / install / 20: << [
      / directive-override-parameters / 20, {
        / uri / 21: "#tc"
      },
      / directive-fetch / 21, 15,
      / condition-image-match / 3, 15
    ] >>,
    / uninstall / 24: << [
      / directive-unlink / 33, 15
    ] >>
  } >>,
  "#tc" : 'Hello, Secure World!'
}
~~~~


### CBOR Binary in Hex
{: numbered='no'}

~~~~
A3025873825824822F5820CEDB0457952F7DD0A33FA4692F73BC833A6A6E
2300B16F6605993F0192E3F219584AD28443A10126A0F6584071E3869E4E
134A78C95D7ED81F5911FEA4F189EC33C0F6474C866569ED3DF7FB4E0D88
71367BA3C73612A26C9E3984A4E22CAA4BFBCE84DCAC0539AE87BE9D3D03
58CEA601010203035884A20281844B544545502D44657669636548536563
7572654653508D82573A926D4754935332DC29997F744274610458548614
A40150C0DDD5F15243566087DB4F5B0AA26C2F0250DB42F7093D8C55BAA8
C5265FC5820F4E035824822F58208CF71AC86AF31BE184EC7A05A411A8C3
A14FD9B77A30D046397481469468ECE80E14010F020F05844B544545502D
446576696365485365637572654653508D82573A926D4754935332DC2999
7F744473756974144C8614A11563237463150F030F1818448218210F6323
74635448656C6C6F2C2053656375726520576F726C6421
~~~~
