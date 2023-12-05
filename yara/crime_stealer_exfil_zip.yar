
rule SUSP_MAL_EXFIL_Stealer_Output_Characteristics_Sep22_1 {
   meta:
      description = "Detects typical stealer output files as created by RedLine or Racoon stealer"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/cglyer/status/1570965878480719873"
      date = "2022-09-17"
      score = 70
      hash1 = "8ce14c6b720281f43c75ce52e23ec13d08e7b2be1c5fbc2d704238f1fdd1a07f"
      hash2 = "011c19d18fa446a2619b3a2512dacb2694e1da99a2c2ea7828769f1373ecd8fe"
      hash3 = "418530bc7210f74ada8e7f16b41ea2033054e99f0c4423ce1d3ebf973c89e3a3"
      hash4 = "aa6e2c8447f66527f9b6f4d54f57edc6cabe56095df94dc0656dca02e11356ab"
      hash5 = "bbfb608061931565debac405ffebe3c4bb5dac8042443fe4e80aa03395955bd2"
      hash6 = "c15107beecf3301fb12d140690034717e16bd5312a746e7ff43a7925e5533260"
      id = "c1cab3c3-c4f3-5a19-9ea3-9e4242238359"
   strings:
      $sa1 = "passwords.txt" ascii
      $sa2 = "autofills/" ascii
      $sa3 = "browsers/cookies/" ascii
      $sa4 = "wallets/" ascii
      
      $sb1 = "Passwords.txt" ascii
      $sb2 = "Autofills/" ascii
      $sb3 = "Browsers/Cookies/" ascii
      $sb4 = "Wallets/" ascii
   condition:
      uint16(0) == 0x4b50 and
      filesize < 5000KB and
      ( 2 of ($sa*) or 2 of ($sb*) )
}
