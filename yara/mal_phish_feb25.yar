rule MAL_PHISH_ShellCode_Enc_Payload_Feb25 {
   meta:
      author = "X__Junior"
      description = "Detects unknown of phishing-delivered malware"
      reference = "https://x.com/dtcert/status/1890384162818802135"
      hash = "247e6a648bb22d35095ba02ef4af8cfe0a4cdfa25271117414ff2e3a21021886"
      date = "2025-02-14"
      score = 80
      id = "8459c5ba-37ec-59bd-8d4a-5ab7b6bb4553"
   strings:
     $op1 = { 48 89 EA FF D0 48 89 E9 4C 8D 4C 24 ?? 41 B8 ?? ?? ?? ?? 48 89 C7 48 89 C3 48 89 EA F3 A4 48 89 C1 41 FF D4 31 C9 FF D3}
   condition:
      uint16(0) == 0x5a4d and $op1
}

rule MAL_PHISH_Final_Payload_Feb25 {
   meta:
      author = "X__Junior"
      description = "Detects possible final payload of phishing-delivered malware, where embedded shellcode is used to decrypt and execute the payload after user-supplied password input."
      reference = "https://x.com/dtcert/status/1890384162818802135"
      hash = "de384aba6b0c6800095eb530954aa718d4ed96cccfc0b1e5e4d01404f3518a77"
      date = "2025-02-14"
      score = 80
      id = "9014e1f2-09c2-5ba0-8b7c-6ae8c069d1f7"
   strings:
      $s1 = "%lu: %s %s" wide
      $s2 = "(Direct Inbound)" wide
      $s3 = "(Primary Domain)" wide
      $s4 = "(Forest Tree Root" wide
      $s5 = "(Native Mode)" wide
      $s6 = "(In Forest)" wide
      $s7 = "(None)" wide
   condition:
      all of them
}

rule SUSP_Sysinternals_Desktops_Anomaly_Feb25 {
   meta:
      description = "Detects anomalies in Sysinternals Desktops binaries"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2025-02-14"
      score = 70
      hash = "5b8f64e090c7c9012e656c222682dfae7910669c7b7afaca35829cd1cc2eac17"
      hash = "d0f7f3f58e0dfcfd81235379bb5a236f40be490207d3bf45f190a264879090db"
      hash = "a83dc4d69a3de72aed4d1933db2ca120657f06adc6683346afbd267b8b7d27d0"
      hash = "9ebfe694914d337304edded8b6406bd3fbff1d4ee110ef3a8bf95c3fb5de7c38"
      hash = "9a5b9d89686de129a7b1970d5804f0f174156143ccfcd2cf669451c1ad4ab97e"
      hash = "ff82c4c679c5486aed2d66a802682245a1e9cd7d6ceb65fa0e7b222f902998e8"
      hash = "1da91d2570329f9e214f51bc633283f10bd55a145b7b3d254e03175fd86292d9"
      id = "5a586222-9263-5079-be48-9cfa464440d4"
   strings:
      $s1 = "Software\\Sysinternals\\Desktops" wide fullword
      $s2 = "Sysinternals Desktops" wide fullword
      $s3 = "http://www.sysinternals.com" wide fullword
   condition:
      uint16(0) == 0x5a4d
      and filesize > 350KB
      and all of them
}

rule SUSP_PE_Compromised_Certificate_Feb25 {
   meta:
      description = "Detects suspicious PE files signed with a certificate used in a widespread phishing attack in February 2025"
      author = "Jonathan Peters"
      reference = "https://x.com/DTCERT/status/1890384162818802135"
      date = "2025-02-14"
      score = 60
      hash = "5b8f64e090c7c9012e656c222682dfae7910669c7b7afaca35829cd1cc2eac17"
      hash = "d0f7f3f58e0dfcfd81235379bb5a236f40be490207d3bf45f190a264879090db"
      hash = "a83dc4d69a3de72aed4d1933db2ca120657f06adc6683346afbd267b8b7d27d0"
      hash = "9ebfe694914d337304edded8b6406bd3fbff1d4ee110ef3a8bf95c3fb5de7c38"
      hash = "9a5b9d89686de129a7b1970d5804f0f174156143ccfcd2cf669451c1ad4ab97e"
      hash = "ff82c4c679c5486aed2d66a802682245a1e9cd7d6ceb65fa0e7b222f902998e8"
      hash = "1da91d2570329f9e214f51bc633283f10bd55a145b7b3d254e03175fd86292d9"
      id = "2e6ad630-b24e-53b2-8ffe-622c51914568"
   strings:
      $sb1 = { 44 B8 66 73 57 BB 95 65 1D 61 D0 61 } // compromised certificate serial
      $sb2 = { 4F 23 43 D9 61 54 B9 41 DB 0A 26 B2 } // compromised certificate serial
      $sb3 = { 40 A3 62 E3 50 68 91 19 F5 2E C3 4C } // compromised certificate serial
   condition:
      uint16(0) == 0x5a4d
      and filesize < 20MB
      and 1 of them
}
