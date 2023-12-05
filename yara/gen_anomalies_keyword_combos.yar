
rule SUSP_NullSoftInst_Combo_Oct20_1 {
   meta:
      description = "Detects suspicious NullSoft Installer combination with common Copyright strings"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/malwrhunterteam/status/1313023627177193472"
      date = "2020-10-06"
      score = 65
      hash1 = "686b5240e5e503528cc5ac8d764883413a260716dd290f114a60af873ee6a65f"
      hash2 = "93951379e57e4f159bb62fd7dd563d1ac2f3f23c80ba89f2da2e395b8a647dcf"
      hash3 = "a9ca1d6a981ccc8d8b144f337c259891a67eb6b85ee41b03699baacf4aae9a78"
      id = "380f30a6-df6b-50c6-bb2d-b8785564bbac"
   strings:
      $a1 = "NullsoftInst" ascii 

      $b1 = "Microsoft Corporation" wide fullword
      $b2 = "Apache Software Foundation" ascii wide fullword
      $b3 = "Simon Tatham" wide fullword

      $fp1 = "nsisinstall" fullword ascii
      $fp2 = "\\REGISTRY\\MACHINE\\Software\\" wide
      $fp3 = "Apache Tomcat" wide fullword
      $fp4 = "Bot Framework Emulator" wide fullword
      $fp5 = "Firefox Helper" wide fullword
      $fp6 = "Paint.NET Setup" wide fullword
      $fp7 = "Microsoft .NET Services Installation Utility" wide fullword
      $fp8 = "License: MPL 2" wide
   condition:
      uint16(0) == 0x5a4d and
      filesize < 2000KB and
      $a1 and 1 of ($b*) and 
      not 1 of ($fp*)
}
