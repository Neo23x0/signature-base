rule SUSP_AppDomainInjection_Keyword_May26 {
   meta:
      description = "Detects link files, archives and binaries that contain keywords related to AppDomain hijacking/injection a technique used by malware to sideload payloads."
      author = "Jonathan Peters (Nextron Systems)"
      date = "2026-05-27"
      reference = "https://attack.mitre.org/techniques/T1574/014/"
      hash = "eee657ffdb2af8ed6412221e7d5fbf4f5742f2ac2c88f43f12db46af0697de71"
      score = 70
      id = "27e98663-c32e-4a7c-b473-7e30dfa97187"
   strings:
      $x1 = "AppDomainInjection" ascii wide fullword
      $x2 = "AppDomainHijack" ascii wide fullword
   condition:
      (
         uint16(0) == 0x5a4d  // PE
         or uint16(0) == 0x4b50  // ZIP
         or uint32(0x8000) == 0x30444301  // ISO
         or uint16(0) == 0x004c and uint32(4) == 0x00021401  // LNK
      )
      and 1 of ($x*)
}

rule SUSP_PE_Contains_Encrypted_Executable_May26 {
   meta:
      description = "Detects executables containing an encrypted embedded payload using parameters commonly observed in malware, suggesting obfuscation or staged execution."
      author = "Jonathan Peters (Nextron Systems)"
      date = "2026-05-20"
      reference = "https://www.nextron-systems.com/2026/06/01/detecting-nimbus-manticore-and-their-sideloading-infection-chains/"
      hash = "eee657ffdb2af8ed6412221e7d5fbf4f5742f2ac2c88f43f12db46af0697de71"
      score = 70
      id = "b0430178-01ac-446f-9df3-553cb0f496dc"
   strings:
      // MZ header AES encrypted with key: 1234567890123456 and IV: abcdefghijklmnop
      $op = { ae b6 8d 86 71 f0 a9 c8 90 66 53 31 ef 7f 1f d2 b4 a8 21 bc 39 77 c2 c2 60 db 24 4a 12 32 f9 69 09 09 46 22 a6 d1 0a 5e a7 dc 62 fa 96 56 ad dd }
   condition:
      uint16(0) == 0x5a4d
      and 1 of them
}
