<!--
 Copyright (c) 2020-2023 SECOM CO., LTD. All Rights reserved.

 SPDX-License-Identifier: BSD-2-Clause
-->

## Example 1: Override Multiple Example
{: numbered='no'}

### CBOR Diagnostic Notation of SUIT Manifest
{: numbered='no'}

~~~~
/ SUIT_Envelope_Tagged / 107({
  / authentication-wrapper / 2: << [
    << [
      / digest-algorithm-id: / -16 / SHA256 /,
      / digest-bytes: / h'3063438CC2DCEFB2AA25D893AE16C5C6B4A7ECD87B3A578EEFDA2F760A724F06'
    ] >>,
    << / COSE_Sign1_Tagged / 18([
      / protected: / << {
        / algorithm-id / 1: -7 / ES256 /
      } >>,
      / unprotected: / {},
      / payload: / null,
      / signature: / h'BC6620A01A8526C4DB8FEC103F13FA3D2D91F6B6E14C6FA40919A65D704BD41822F886C06378C0CF54EC38B18A8953A67400665373254E3C8CF74AB0F9AA92B6'
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
      / directive-override-multiple / 34, {
        / index / 0: {
          / parameter-wait-info / 29: << {
            / authorization / 1: -1 / 'critical' /,
            / power / 2: 10 / >= 10% /
          } >>
        },
        / index / 1: {
          / parameter-wait-info / 29: << {
            / time-of-day / 6: 82800 / 23:00:00 /
          } >>
        }
      },

      / directive-set-component-index / 12, true,
      / directive-wait / 29, 15
    ] >>
  } >>
})
~~~~


### CBOR Binary in Hex
{: numbered='no'}

~~~~
D86BA2025873825824822F58203063438CC2DCEFB2AA25D893AE16C5C6B4
A7ECD87B3A578EEFDA2F760A724F06584AD28443A10126A0F65840BC6620
A01A8526C4DB8FEC103F13FA3D2D91F6B6E14C6FA40919A65D704BD41822
F886C06378C0CF54EC38B18A8953A67400665373254E3C8CF74AB0F9AA92
B6035832A4010102000349A1028281410081410114581F861822A200A118
1D45A20120020A01A1181D47A1061A000143700CF5181D0F
~~~~
