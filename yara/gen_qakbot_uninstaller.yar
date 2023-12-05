
rule SUSP_Qakbot_Uninstaller_ShellCode_Aug23 {
   meta:
      description = "Detects Qakbot Uninstaller files used by the FBI and Dutch National Police in a disruption operation against the Qakbot in August 2023"
      author = "Florian Roth"
      reference = "https://www.justice.gov/usao-cdca/divisions/national-security-division/qakbot-resources"
      date = "2023-08-30"
      score = 60
      id = "860796ab-689f-5c5f-bc40-3e2ef7fd1d5d"
   strings:
      $xc1 = { E8 00 00 00 00 58 55 89 E5 89 C2 68 03 00 00 00 68 00 2C 00 00 05 20 0A 00 00 50 E8 05 00 00 00 83 C4 04 C9 C3 81 EC 08 01 00 00 53 55 56 57 6A 6B 58 6A 65 5B 6A 72 66 89 84 24 D4 00 00 00 33 }
   condition:
      $xc1
}

rule SUSP_QakBot_Uninstaller_FBI_Aug23 {
   meta:
      description = "Detects Qakbot uninstaller used by the FBI / Dutch Police"
      author = "Florian Roth"
      reference = "https://www.justice.gov/usao-cdca/divisions/national-security-division/qakbot-resources"
      date = "2023-08-31"
      score = 60
      hash1 = "559cae635f0d870652b9482ef436b31d4bb1a5a0f51750836f328d749291d0b6"
      hash2 = "855eb5481f77dde5ad8fa6e9d953d4aebc280dddf9461144b16ed62817cc5071"
      hash3 = "fab408536aa37c4abc8be97ab9c1f86cb33b63923d423fdc2859eb9d63fa8ea0"
      id = "499bff56-ff49-53df-9922-227b816c0a36"
   strings:
      $op1 = { 69 c1 65 89 07 6c 03 c2 89 84 95 24 f6 ff ff 8b 55 e4 42 89 55 e4 81 fa 70 02 00 00 7c d4 }
      $op2 = { 42 89 55 e4 81 fa 70 02 00 00 7c d4 f2 0f 10 0d a0 31 00 10 33 f6 f2 0f 10 15 a8 31 00 10 66 90 }
      $op5 = { 68 48 31 00 10 6a 28 57 e8 e4 fd ff ff 8b 4d fc 83 c4 4c 33 cd 33 c0 }
      $op6 = { 33 c0 66 39 06 74 0f 0f 1f 80 00 00 00 00 40 66 83 3c 46 00 75 f8 8d 3c 00 }
   condition:
      all of them
}
