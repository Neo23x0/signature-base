/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2018-01-24
   Identifier: Lotus Blossom Elise Malware
   Reference: https://community.rsa.com/community/products/netwitness/blog/2018/01/30/apt32-continues-asean-targeting
*/

import "pe"

/* Rule Set ----------------------------------------------------------------- */

rule Elise_Jan18_1 {
   meta:
      description = "Detects Elise malware samples - fake Norton Security NavShExt.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/blu3_team/status/955971742329135105"
      date = "2018-01-24"
      hash1 = "6dc2a49d58dc568944fef8285ad7a03b772b9bdf1fe4bddff3f1ade3862eae79"
      id = "8e4f4ec8-5d31-5990-8c14-861423571a79"
   strings:
      $s1 = "NavShExt.dll" fullword wide
      $s2 = "Norton Security" fullword wide

      $a1 = "donotbotherme" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 250KB and (
        pe.imphash() == "e9478ee4ebf085d1f14f64ba96ef082f" or
        ( 1 of ($s*) and $a1 )
      )
}