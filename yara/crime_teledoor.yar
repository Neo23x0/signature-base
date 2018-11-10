/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-07-05
   Identifier: Telebots Backdoor MEDocs
   Reference: https://goo.gl/CpfJQQ
*/

/* Rule Set ----------------------------------------------------------------- */

rule TeleDoor_Backdoor {
   meta:
      description = "Detects the TeleDoor Backdoor as used in Petya Attack in June 2017"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/CpfJQQ"
      date = "2017-07-05"
      hash1 = "d462966166450416d6addd3bfdf48590f8440dd80fc571a389023b7c860ca3ac"
      hash2 = "f9d6fe8bd8aca6528dec7eaa9f1aafbecde15fd61668182f2ba8a7fc2b9a6740"
      hash3 = "2fd2863d711a1f18eeee5c7c82f2349c5d4e00465de9789da837fcdca4d00277"
   strings:
      /* Payload\x00AutoPayload */
      $c1 = { 50 61 79 6C 6F 61 64 00 41 75 74 6F 50 61 79 6C 6F 61 64 }
      /* RunCmd\x00DumpData */
      $c2 = { 52 75 6E 43 6D 64 00 44 75 6D 70 44 61 74 61 }
      /* ZvitWebClientExt\x00MinInfo */
      $c3 = { 00 5A 76 69 74 57 65 62 43 6C 69 65 6E 74 45 78 74 00 4D 69 6E 49 6E 66 6F }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 15000KB and 2 of them )
}