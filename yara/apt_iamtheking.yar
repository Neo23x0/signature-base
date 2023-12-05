
rule APT_MAL_SLOTHFULMEDIA_Oct20_1 {
   meta:
      description = "Detects SLOTHFULMEDIA malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://us-cert.cisa.gov/ncas/analysis-reports/ar20-275a"
      date = "2020-10-01"
      hash1 = "64d78eec46c9ddd4b9a366de62ba0f2813267dc4393bc79e4c9a51a9bb7e6273"
      hash2 = "927d945476191a3523884f4c0784fb71c16b7738bd7f2abd1e3a198af403f0ae"
      hash3 = "f0503f0131040b805e106eafe64a65d9404a0e279f052237b868e456c34d36e6"
      hash4 = "ed5258306c06d6fac9b13c99c7c8accc7f7fa0de4cf4de4f7d9eccad916555f5"
      hash5 = "04ca010f4c8997a023fabacae230698290e3ff918a86703c5e0a2a6983b039eb"
      hash6 = "cb2adcaaa25bb6b8a9f1c685c219f8d6d78aa5cfd65c633f4d255ff81da2c517"
      id = "cc413225-f084-5859-bc27-04eb018d8894"
   strings:
      $xc1 = { 25 73 26 69 3D 25 64 00 48 54 54 50 2F 31 2E 31
               00 00 00 00 50 4F 53 54 00 00 00 00 43 6F 6E 74
               65 6E 74 2D 4C 65 6E 67 74 68 3A 20 25 64 00 00
               5C 00 53 00 65 00 74 00 75 00 70 00 55 00 69 00
               00 00 00 00 25 00 73 00 25 00 73 00 5F 00 25 00
               64 00 2E 00 64 00 61 00 74 }
      $xc2 = { 2F 76 3F 6D 3D 00 00 00 35 30 31 00 32 30 30 00
               2A 00 2E 00 2A 00 00 00 25 00 73 00 00 00 00 00
               53 00 65 00 44 00 65 00 62 00 75 00 67 00 50 00
               72 00 69 00 76 00 69 00 6C 00 65 00 67 00 65 }
      $xc3 = { 00 25 00 73 00 7C 00 25 00 73 00 7C 00 25 00 73
               00 7C 00 25 00 73 00 00 00 5C 00 46 00 69 00 6C
               00 74 00 65 00 72 00 33 00 2E 00 6A 00 70 00 67 }

      $sc1 = { 25 74 65 6D 70 25 00 00 25 73 5C 25 73 2E 65 78
               65 00 00 00 25 74 65 6D 70 25 00 00 25 73 5C 25
               73 2E 65 78 65 }
      $sc2 = { 61 70 70 6C 69 63 61 74 69 6F 6E 2F 6F 63 74 65
               74 2D 73 74 72 65 61 6D 2C 61 70 70 6C 69 63 61
               74 69 6F 6E 2F 78 68 74 6D 6C 00 00 25 73 26 69
               3D 25 64 00 48 54 54 50 2F 31 2E 31 00 00 00 00
               50 4F 53 54 }
      $s1 = "%s%s_%d.dat" wide fullword
      $s2 = "Local Security Process" wide fullword
      $s3 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.75" ascii fullword
      $s4 = "Global%s%d" wide fullword
      $s5 = "ExtKeyloggerStart" ascii fullword
      $s6 = "GetExtendedTcpTable" ascii fullword
   condition:
      uint16(0) == 0x5a4d and
      filesize < 400KB and
      ( 1 of ($x*) or 3 of them ) or 4 of them
}
