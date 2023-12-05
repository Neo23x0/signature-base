/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-08-15
   Identifier: ShadowPad
   Reference: https://securelist.com/shadowpad-in-corporate-networks/81432/
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule ShadowPad_nssock2 {
   meta:
      description = "Detects malicious nssock2.dll from ShadowPad incident - file nssock2.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://securelist.com/shadowpad-in-corporate-networks/81432/"
      date = "2017-08-15"
      hash1 = "462a02a8094e833fd456baf0a6d4e18bb7dab1a9f74d5f163a8334921a4ffde8"
      hash2 = "c45116a22cf5695b618fcdf1002619e8544ba015d06b2e1dbf47982600c7545f"
      hash3 = "696be784c67896b9239a8af0a167add72b1becd3ef98d03e99207a3d5734f6eb"
      hash4 = "515d3110498d7b4fdb451ed60bb11cd6835fcff4780cb2b982ffd2740e1347a0"
      hash5 = "536d7e3bd1c9e1c2fd8438ab75d6c29c921974560b47c71686714d12fb8e9882"
      hash6 = "637fa40cf7dd0252c87140f7895768f42a370551c87c37a3a77aac00eb17d72e"
      id = "47ecc7f8-065a-558b-9bba-300fd28f4eab"
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 500KB and
        (
           pe.imphash() == "c67de089f2009b21715744762fc484e8" or
           pe.imphash() == "11522f7d4b2fc05acba8f534ca1b828a"
        )
      )
}
