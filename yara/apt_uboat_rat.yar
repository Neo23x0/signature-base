/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-11-28
   Identifier: UBoatRAT
   Reference: https://researchcenter.paloaltonetworks.com/2017/11/unit42-uboatrat-navigates-east-asia/
*/

rule UBoatRAT {
   meta:
      description = "Detects UBoat RAT Samples"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://researchcenter.paloaltonetworks.com/2017/11/unit42-uboatrat-navigates-east-asia/"
      date = "2017-11-29"
      hash1 = "04873dbd63279228a0a4bb1184933b64adb880e874bd3d14078161d06e232c9b"
      hash2 = "7b32f401e2ad577e8398b2975ecb5c5ce68c5b07717b1e0d762f90a6fbd8add1"
      hash3 = "42d8a84cd49ff3afacf3d549fbab1fa80d5eda0c8625938b6d32e18004b0edac"
      hash4 = "6bea49e4260f083ed6b73e100550ecd22300806071f4a6326e0544272a84526c"
      hash5 = "cf832f32b8d27cf9911031910621c21bd3c20e71cc062716923304dacf4dadb7"
      hash6 = "bf7c6e911f14a1f8679c9b0c2b183d74d5accd559e17297adcd173d76755e271"
      id = "f7f745c2-648d-5937-8d06-f5d1b6ed7e11"
   strings:
      $s1 = "URLDownloadToFileA" ascii
      $s2 = "GetModuleFileNameW" ascii
      $s4 = "WININET.dll" ascii
      $s5 = "urlmon.dll" ascii
      $s6 = "WTSAPI32.dll" ascii
      $s7 = "IPHLPAPI.DLL" ascii

      $op1 = { 0E 1F BA 0E 00 B4 09 CD 21 B8 01 4C CD 21 54 68
               69 73 20 70 72 6F 67 72 61 6D 20 63 61 6E 6E 6F
               74 20 62 65 20 72 75 6E 20 69 6E 20 44 4F 53 20
               6D 6F 64 65 2E 0D 0D 0A 24 00 00 00 00 00 00 00 }

      $vprotect = { 2E 76 6D 70 30 }
   condition:
      /* MZ and PE */
      uint16(0) == 0x5a4d and uint32(uint32(0x3c)) == 0x4550 and
      /* Expected file size */
      filesize < 1400KB and filesize > 800KB and (
         /* Imports */
         all of ($s*) and
         /* Specific header - possibly Yoda protector*/
         $op1 at 64 and
         uint16(uint32(0x3c) + 11) == 0x59 and
         /* Vprotect */
         $vprotect in (600..700)
      )
}

rule UBoatRAT_Dropper {
   meta:
      description = "Detects UBoatRAT Dropper"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://researchcenter.paloaltonetworks.com/2017/11/unit42-uboatrat-navigates-east-asia/"
      date = "2017-11-29"
      hash1 = "f4c659238ffab95e87894d2c556f887774dce2431e8cb87f881df4e4d26253a3"
      id = "f3d4e333-1282-5f6e-9294-628a8230d2a5"
   strings:
      $s1 = "GetCurrenvackageId" fullword ascii
      $s2 = "fghijklmnopq" fullword ascii
      $s3 = "23456789:;<=>?@ABCDEFGHIJKLMNOPQ" fullword ascii
      $s4 = "PMM/dd/y" fullword ascii
      $s5 = "bad all" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}
