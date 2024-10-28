<!--
 Copyright (c) 2020-2023 SECOM CO., LTD. All Rights reserved.

 SPDX-License-Identifier: BSD-2-Clause
-->

## Example 3: Supplying Personalization Data for Trusted Component Binary {#suit-personalization}

~~~~
/ SUIT_Envelope / {
  / authentication-wrapper / 2: << [
    << [
      / digest-algorithm-id: / -16 / SHA256 /,
      / digest-bytes: / h'C6E33791C3EA4235D3069E849CCF00390769E0118342161184B293F8893DF010'
    ] >>,
    << / COSE_Sign1_Tagged / 18([
      / protected: / << {
        / algorithm-id / 1: -7 / ES256 /
      } >>,
      / unprotected: / {},
      / payload: / null,
      / signature: / h'E2F02EB95698DF7D3C9B3B5B0A64AF58B363AD0B3E12AF77C279EBD7B503C9BE4858C36614919C110E5C294FFB1538EE234CAED278939B7260A4BB63E1970146'
    ]) >>
  ] >>,
  / manifest / 3: << {
    / manifest-version / 1: 1,
    / manifest-sequence-number / 2: 3,
    / common / 3: << {
      / dependencies / 1: {
        / component-index / 1: {
          / dependency-prefix / 1: [
             'TEEP-Device',
             'SecureFS',
            h'8D82573A926D4754935332DC29997F74', / tc-uuid /
             'suit'
          ]
        }
      },
      / components / 2: [
        [
          'TEEP-Device',
          'SecureFS',
          'config.json'
        ]
      ],
      / shared-sequence / 4: << [
        / directive-set-component-index / 12, 0,
        / directive-override-parameters / 20, {
          / parameter-vendor-identifier / 1: h'C0DDD5F15243566087DB4F5B0AA26C2F',
          / parameter-class-identifier / 2: h'DB42F7093D8C55BAA8C5265FC5820F4E'
        },
        / condition-vendor-identifier / 1, 15,
        / condition-class-identifier / 2, 15
      ] >>
    } >>,
    / manifest-component-id / 5: [
      'TEEP-Device',
      'SecureFS',
      'config.suit'
    ],
    / validate / 7: << [
      / directive-set-component-index / 12, 0,
      / directive-override-parameters / 20, {
        / NOTE: image-digest and image-size of plaintext config.json /
        / parameter-image-digest / 3: << [
          / digest-algorithm-id: / -16 / SHA256 /,
          / digest-bytes: / h'8273468FB64BD84BB04825F8371744D952B751C73A60F455AF681E167726F116'
        ] >>,
        / image-size / 14: 61
      },
      / condition-image-match / 3, 15
    ] >>,
    / dependency-resolution / 15: << [
      / directive-set-component-index / 12, 1,
      / directive-override-parameters / 20, {
        / parameter-image-digest / 3: << [
          / algorithm-id / -16 / SHA256 /,
          / digest-bytes / h'B39B52B0B747EA79588C190F567BFC2C8437BA8A73F7EA983182E79F0148D59B'
        ] >>,
        / parameter-image-size / 14: 389,
        / parameter-uri / 21: "https://example.org/8d82573a-926d-4754-9353-32dc29997f74.suit"
      },
      / directive-fetch / 21, 2
    ] >>,
    / install / 20: << [
      / directive-set-component-index / 12, 1,
      / directive-process-dependency / 11, 0,

      / NOTE: fetch encrypted firmware /
      / directive-set-component-index / 12, 0,
      / directive-override-parameters / 20, {
        / NOTE: encrypted payload and encryption-info /
        / parameter-content / 18: h'C43E94F3B51A5DBB76ECFAD44CA7DEFE71D26A36E10054723DDF0A93CD9B68D9F4B61FCC31CD0CBE30D3FFDF6AB7541BFF1980968A836E17D3BBDE7332',
        / parameter-encryption-info / 19: << 96([
          / protected: / h'',
          / unprotected: / {
            / alg / 1: -65534 / A128CTR /,
            / IV / 5: h'F8FC5E335366171540C1B416ABFDC9A7'
          },
          / payload: / null / detached ciphertext /,
          / recipients: / [
            [
              / protected: / << {
                / alg / 1: -29 / ECDH-ES + A128KW /
              } >>,
              / unprotected: / {
                / ephemeral key / -1: {
                  / kty / 1: 2 / EC2 /,
                  / crv / -1: 1 / P-256 /,
                  / x / -2: h'7AAF18EC7FAB5071B267FA3B8D8FF248A78DAAD9D9B8318EAE8925089F3C9431',
                  / y / -3: h'84BADF92D62F3804E8DE964ABB21EC6A732B46B2B02DCD2908E6A666C6D4871B'
                }
              },
              / payload: / h'F003092CB552689003EB0ACDD081595E6499FF028745DADF'
            ]
          ]
        ]) >>
      },

      / decrypt encrypted firmware /
      / directive-write / 18, 15 / consumes the SUIT_Encryption_Info above /
      / NOTE: decrypted payload would be ``{"name":"FOO Bar","secret":"0123456789abfcdef0123456789abcd"}'' /
    ] >>,
    / uninstall / 24: << [
      / directive-set-component-index / 12, 1,
      / directive-process-dependency / 11, 0,
      / directive-set-component-index / 12, 0,
      / directive-unlink / 33, 15
    ] >>
  } >>
}
~~~~


### CBOR Binary in Hex
{: numbered='no'}

~~~~
A2025873825824822F582037522D96C0F9A6B887A21F4B21CDF02767799C
C3A66EAFD5979250CCE11377E2584AD28443A10126A0F6584084A5B76482
0B927C580BF128CC2CA21AE2656F27A6BCE6D63228915CCCCC32DB23C93A
8518A7DB565BD0348F17978474ED7473C4FDED4A2752EEA93B90BE1FF103
590242A801010203035886A301A101A101844B544545502D446576696365
485365637572654653508D82573A926D4754935332DC29997F7444737569
740281834B544545502D4465766963654853656375726546534B636F6E66
69672E6A736F6E04582D880C0014A20150C0DDD5F15243566087DB4F5B0A
A26C2F0250DB42F7093D8C55BAA8C5265FC5820F4E010F020F05834B5445
45502D4465766963654853656375726546534B636F6E6669672E73756974
075831860C0014A2035824822F58208273468FB64BD84BB04825F8371744
D952B751C73A60F455AF681E167726F1160E183D030F0F5872860C0114A3
035824822F5820B39B52B0B747EA79588C190F567BFC2C8437BA8A73F7EA
983182E79F0148D59B0E19018515783D68747470733A2F2F6578616D706C
652E6F72672F38643832353733612D393236642D343735342D393335332D
3332646332393939376637342E7375697415021458D88A0C010B000C0014
A212583DF137C0755EA5642248EC04F3D24BEF771B5CCD72C56F33F254F4
0A2381DC7C122C5708A99FE87A702A11053EF1BA86CF9A12B7E81AF80147
5959864E6313588AD8608440A20139FFFD0550A0DB218209E3C43E871A81
CF1BEBC9F9F6818344A101381CA120A401022001215820A1A58EA321C7E3
28FE7DE66283DFC3B4081FE5FA7EF90C570FC88693F857EFB6225820AE96
AC0E18D691D5A8066BF95913252F57566F5A07EEF8643822ADD9510ADBBD
58183C09CFE4A33D69F0ADDB73EA728E942791139BA864A9369E120F1818
4A880C010B000C0018210F
~~~~
