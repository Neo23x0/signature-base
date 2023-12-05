
rule HKTL_Venom_LIB_Dec22 {
   meta:
      description = "Detects Venom - a library that meant to perform evasive communication using stolen browser socket"
      author = "Ido Veltzman, Florian Roth"
      reference = "https://github.com/Idov31/Venom"
      date = "2022-12-17"
      score = 75
      id = "b13b8a9c-52a4-53ac-817e-9f729fbf17c2"
   strings:
      $x1 = "[ + ] Created detached hidden msedge process: " fullword ascii
      
      $ss1 = "WS2_32.dll" fullword ascii
      $ss2 = "WSASocketW" fullword ascii
      $ss3 = "WSADuplicateSocketW" fullword ascii
      $ss5 = "\\Device\\Afd" wide fullword
      
      $sx1 = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe --no-startup-window" fullword wide
      $sx2 = "[ + ] Data sent!" fullword ascii
      $sx3 = "[ + ] Socket obtained!" fullword ascii
      
      $op1 = { 4c 8b f0 48 3b c1 48 b8 ff ff ff ff ff ff ff 7f }
      $op2 = { 48 8b cf e8 1c 34 00 00 48 8b 5c 24 30 48 8b c7 }
      $op3 = { 48 8b da 48 8b f9 45 33 f6 48 85 c9 0f 84 34 01 }
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and (
         ( 3 of ($ss*) and all of ($op*) )
         or 2 of ($sx*)
      ) or $x1 or all of ($sx*)
}
