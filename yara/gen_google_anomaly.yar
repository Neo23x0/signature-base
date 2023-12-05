import "pe"

rule SUSP_Unsigned_GoogleUpdate {
   meta:
      description = "Detects suspicious unsigned GoogleUpdate.exe"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2019-08-05"
      score = 60
      hash1 = "5aa84aa5c90ec34b7f7d75eb350349ae3aa5060f3ad6dd0520e851626e9f8354"
      id = "2575b882-3526-5c42-9d50-83fb0b7df3f5"
   strings:
      /* OriginalName GoogleUpdate.exe */
      $ac1 = { 00 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C
               00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65
               00 00 00 47 00 6F 00 6F 00 67 00 6C 00 65 00 55
               00 70 00 64 00 61 00 74 00 65 00 2E 00 65 00 78
               00 65 }
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and $ac1
      and pe.number_of_signatures < 1
}
