
rule APT_UNC2447_MAL_SOMBRAT_May21_1 {
   meta:
      description = "Detects SombRAT samples from UNC2447 campaign"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.fireeye.com/blog/threat-research/2021/04/unc2447-sombrat-and-fivehands-ransomware-sophisticated-financial-threat.html"
      date = "2021-05-01"
      modified = "2023-01-07"
      hash1 = "61e286c62e556ac79b01c17357176e58efb67d86c5d17407e128094c3151f7f9"
      hash2 = "99baffcd7a6b939b72c99af7c1e88523a50053ab966a079d9bf268aff884426e"
      id = "78b46bed-4fd4-596f-bba7-12243f467af3"
   strings:
      $x1 = "~arungvc" ascii fullword

      $s1 = "plugin64_" ascii
      $s2 = "0xUnknown" ascii fullword
      $s3 = "b%x.%s" ascii fullword
      $s4 = "/news" ascii

      $sc1 = { 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 73
               00 2E 00 65 00 78 00 65 00 00 00 00 00 00 00 00
               00 49 73 57 6F 77 36 34 50 72 6F 63 65 73 73 00
               00 6B 00 65 00 72 00 6E 00 65 00 6C 00 33 00 32
               00 00 00 00 00 00 00 00 00 47 00 6C 00 6F 00 62
               00 61 00 6C 00 5C 00 25 00 73 }

      $op1 = { 66 90 0f b6 45 80 32 44 0d 81 34 de 88 44 0d 81 48 ff c1 48 83 f9 19 72 e9 }
      $op2 = { 48 8b d0 66 0f 6f 05 ?1 ?? 0? 00 f3 0f 7f 44 24 68 66 89 7c 24 58 41 b8 10 00 00 00 4c 39 40 10 4c 0f 42 40 10 48 83 78 18 08 }
      $op3 = { 49 f7 b0 a0 00 00 00 42 0f b6 04 0a 41 30 44 33 fe 48 83 79 18 10 72 03 48 8b 09 33 d2 b8 05 00 00 00 }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 3000KB and (
         ( 1 of ($x*) and 1 of ($s*) ) or
         3 of them
      ) or 5 of them
}

rule APT_UNC2447_MAL_RANSOM_HelloKitty_May21_1 {
   meta:
      description = "Detects HelloKitty Ransomware samples from UNC2447 campaign"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.fireeye.com/blog/threat-research/2021/04/unc2447-sombrat-and-fivehands-ransomware-sophisticated-financial-threat.html"
      date = "2021-05-01"
      hash1 = "02a08b994265901a649f1bcf6772bc06df2eb51eb09906af9fd0f4a8103e9851"
      hash2 = "0e5f7737704c8f25b2b8157561be54a463057cd4d79c7e016c30a1cf6590a85c"
      hash3 = "52dace403e8f9b4f7ea20c0c3565fa11b6953b404a7d49d63af237a57b36fd2a"
      hash4 = "7be901c5f7ffeb8f99e4f5813c259d0227335680380ed06df03fb836a041cb06"
      hash5 = "947e357bfdfe411be6c97af6559fd1cdc5c9d6f5cea122bf174d124ee03d2de8"
      hash6 = "9a7daafc56300bd94ceef23eac56a0735b63ec6b9a7a409fb5a9b63efe1aa0b0"
      hash7 = "a147945635d5bd0fa832c9b55bc3ebcea7a7787e8f89b98a44279f8eddda2a77"
      hash8 = "bade05a30aba181ffbe4325c1ba6c76ef9e02cbe41a4190bd3671152c51c4a7b"
      hash9 = "c2498845ed4b287fd0f95528926c8ee620ef0cbb5b27865b2007d6379ffe4323"
      hash10 = "dc007e71085297883ca68a919e37687427b7e6db0c24ca014c148f226d8dd98f"
      hash11 = "ef614b456ca4eaa8156a895f450577600ad41bd553b4512ae6abf3fb8b5eb04e"
      id = "c84b2430-dcf1-5a80-96a0-02d292ea386b"
   strings:
      $xop1 = { 8b 45 08 8b 75 f4 fe 85 f7 fd ff ff 0f 11 44 05 b4 83 c0 10 89 45 08 83 f8 30 7c 82 }
      $xop2 = { 81 c3 dc a9 b0 5c c1 c9 0b 33 c8 89 55 a0 8b c7 8b 7d e0 c1 c8 06 33 f7 }

      $s1 = "select * from Win32_ShadowCopy" wide fullword
      $s2 = "bootfont.bin" wide fullword
      $s3 = "DECRYPT_NOTE.txt" wide fullword
      $s4 = ".onion" wide
      
      $sop1 = { 8b f9 0f 57 c0 68 18 01 00 00 6a 00 0f 11 45 dc 8d 5f 20 53 0f 11 45 ec }
      $sop2 = { 56 57 8b f9 0f 57 c0 68 18 01 00 00 6a 00 0f 11 45 dc 8d 5f 20 }
      $sop3 = { 57 8b f9 0f 57 c0 68 18 01 00 00 6a 00 0f 11 45 dc 8d 5f 20 53 }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 800KB and
      1 of ($x*) or 3 of them
}

rule APT_UNC2447_MAL_RANSOM_HelloKitty_May21_2 {
   meta:
      description = "Detects HelloKitty Ransomware samples from UNC2447 campaign"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.fireeye.com/blog/threat-research/2021/04/unc2447-sombrat-and-fivehands-ransomware-sophisticated-financial-threat.html"
      date = "2021-05-01"
      hash1 = "10887d13dba1f83ef34e047455a04416d25a83079a7f3798ce3483e0526e3768"
      hash2 = "3ae7bedf236d4e53a33f3a3e1e80eae2d93e91b1988da2f7fcb8fde5dcc3a0e9"
      hash3 = "501487b025f25ddf1ca32deb57a2b4db43ccf6635c1edc74b9cff54ce0e5bcfe"
      hash4 = "9a7daafc56300bd94ceef23eac56a0735b63ec6b9a7a409fb5a9b63efe1aa0b0"
      id = "82aaabc6-102a-512e-8c2a-4d6fda864c68"
   strings:
      $xop1 = { 50 8d 45 f8 50 ff 75 fc ff 15 ?? ?? 42 00 3d ea 00 00 00 75 18 83 7d f8 00 }

      $s1 = "HelloKittyMutex" wide
      $s2 = "%s\\read_me_lkd.txt" wide fullword
      $s3 = "/C ping 127.0.0.1 & del %s" wide fullword
      $s4 = "(%d) [%d] %s: STOP DOUBLE PROCESS RUN" ascii fullword
      
      $sop1 = { 6a 00 6a 01 ff 75 fc ff 15 ?? ?? 42 00 85 c0 0f 94 c3 ff 75 fc ff 15 ?? ?? 42 00 }
      $sop2 = { 74 12 6a 00 6a 01 ff 75 fc ff 15 ?? ?? 42 00 85 c0 0f 94 c3 ff 75 fc }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 600KB and
      1 of ($x*) or 2 of them
}

rule APT_UNC2447_PS1_WARPRISM_May21_1 {
   meta:
      description = "Detects WARPRISM PowerShell samples from UNC2447 campaign"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.fireeye.com/blog/threat-research/2021/04/unc2447-sombrat-and-fivehands-ransomware-sophisticated-financial-threat.html"
      date = "2021-05-01"
      hash1 = "3090bff3d16b0b150444c3bfb196229ba0ab0b6b826fa306803de0192beddb80"
      hash2 = "63ba6db8c81c60dd9f1a0c7c4a4c51e2e56883f063509ed7b543ad7651fd8806"
      hash3 = "b41a303a4caa71fa260dd601a796033d8bfebcaa6bd9dfd7ad956fac5229a735"
      id = "fa389a45-3b31-5a84-9882-49fd6ee8cac5"
   strings:
      $x1 = "if ($MyInvocation.MyCommand.Path -match '\\S') {" ascii fullword

      $s1 = "[DllImport(\"kernel32.dll\")]public static extern IntPtr VirtualAlloc(IntPtr " ascii wide
      $s2 = "[Runtime.InteropServices.Marshal]::Copy($" ascii wide
      $s3 = "[System.Diagnostics.Process]::Start((-join(" ascii wide
   condition:
      filesize < 5000KB and 1 of ($x*) or 2 of them
}

rule APT_UNC2447_BAT_Runner_May21_1 {
   meta:
      description = "Detects Batch script runners from UNC2447 campaign"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.fireeye.com/blog/threat-research/2021/04/unc2447-sombrat-and-fivehands-ransomware-sophisticated-financial-threat.html"
      date = "2021-05-01"
      modified = "2023-01-07"
      hash1 = "ccacf4658ae778d02e4e55cd161b5a0772eb8b8eee62fed34e2d8f11db2cc4bc"
      id = "0bacd4f7-421a-570f-9f74-5a19ab806dd0"
   strings:
      $x1 = "powershell.exe -c \"[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String([IO.File]::" ascii
      $x2 = "wwansvc.txt')))\" | powershell.exe -" ascii
   condition:
      filesize < 5000KB and 1 of them
}
