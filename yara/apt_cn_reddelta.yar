
rule APT_CN_MAL_RedDelta_Shellcode_Loader_Oct20_1 {
   meta:
      description = "Detects Red Delta samples"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/JAMESWT_MHT/status/1316387482708119556"
      date = "2020-10-14"
      hash1 = "30b2bbce0ca4cb066721c94a64e2c37b7825dd72fc19c20eb0ab156bea0f8efc"
      hash2 = "42ed73b1d5cc49e09136ec05befabe0860002c97eb94e9bad145e4ea5b8be2e2"
      hash3 = "480a8c883006232361c5812af85de9799b1182f1b52145ccfced4fa21b6daafa"
      hash4 = "7ea7c6406c5a80d3c15511c4d97ec1e45813e9c58431f386710d0486c4898b98"
      id = "47417488-e843-5346-9baa-fcce30b884d1"
   strings:
      $x1 = "InjectShellCode" ascii fullword

      $s1 = "DotNetLoader.exe" wide ascii fullword
      $s2 = "clipboardinject" ascii fullword
      $s3 = "download.php?raw=1" wide
      $s4 = "Windows NT\\CurrentVersion\\AppCompatFlags\\TelemetryController\\Levint" wide
      $s5 = "FlashUpdate.exe" wide
      $s6 = "raw_cc_url" ascii fullword

      $op1 = { 48 8b 4c 24 78 48 89 01 e9 1a ff ff ff 48 8b 44 }
      $op2 = { ff ff 00 00 77 2a 8b 44 24 38 8b 8c 24 98 }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 200KB and
      $x1 or 3 of them
}

rule APT_CN_MAL_RedDelta_Shellcode_Loader_Oct20_2 {
   meta:
      description = "Detects Red Delta samples"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/JAMESWT_MHT/status/1316387482708119556"
      date = "2020-10-14"
      hash1 = "260ebbf392498d00d767a5c5ba695e1a124057c1c01fff2ae76db7853fe4255b"
      hash2 = "9ccb4ed133be5c9c554027347ad8b722f0b4c3f14bfd947edfe75a015bf085e5"
      hash3 = "b3fd750484fca838813e814db7d6491fea36abe889787fb7cf3fb29d9d9f5429"
      id = "acb1024a-64af-51ac-84c8-7fe9a5bd4538"
   strings:
      $x1 = "\\CLRLoader.exe" wide fullword
      $x2 = "/callback.php?token=%s&computername=%s&username=%s" ascii fullword

      $s1 = "DotNetLoader.Program" wide fullword
      $s2 = "/download.php?api=40" ascii fullword
      $s3 = "get %d URLDir" ascii fullword
      $s4 = "Read code failed" ascii fullword
      $s5 = "OpenFile fail!" wide fullword
      $s6 = "Writefile success" wide fullword

      $op1 = { 4c 8d 45 e0 49 8b cc 41 8d 51 c3 e8 34 77 02 00 }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 3000KB and
      1 of ($x*) or 4 of them
}

rule APT_CN_MAL_RedDelta_Shellcode_Loader_Oct20_3 {
   meta:
      description = "Detects Red Delta samples"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/JAMESWT_MHT/status/1316387482708119556"
      date = "2020-10-14"
      modified = "2022-12-21"
      hash1 = "740992d40b84b10aa9640214a4a490e989ea7b869cea27dbbdef544bb33b1048"
      id = "b52836bb-cdef-5416-a8e1-72d0b2298546"
   strings:
      $s1 = "Taskschd.dll" ascii fullword
      $s2 = "AddTaskPlanDllVerson.dll" ascii fullword
      $s3 = "\\FlashUpdate.exe" ascii
      $s4 = "D:\\Project\\FBIRedTeam" ascii fullword
      $s5 = "Error %s:%d, ErrorCode: %x" ascii fullword
   condition:
      uint16(0) == 0x5a4d and
      filesize < 400KB and
      4 of them
}
