rule SUSP_LNX_Sindoor_ELF_Obfuscation_Aug25 {
   meta:
      description = "Detects ELF obfuscation technique used by Sindoor dropper related to APT 36"
      author = "Pezier Pierre-Henri"
      date = "2025-08-29"
      score = 70
      reference = "Internal Research"
      hash = "6879a2b730e391964afe4dbbc29667844ba0c29239be5503b7c86e59e7052443"
   strings:
      $s1 = "UPX!"
   condition:
      filesize < 10MB
      and uint16(0) == 0
      and uint16(4) > 0
      and $s1 in (0xc0..0x100)
}

rule SUSP_LNX_Sindoor_DesktopFile_Aug25 {
   meta:
      description = "Detects ELF obfuscation technique used by Sindoor dropper related to APT 36"
      author = "Pezier Pierre-Henri"
      date = "2025-08-29"
      score = 70
      reference = "Internal Research"
      hash = "9943bdf1b2a37434054b14a1a56a8e67aaa6a8b733ca785017d3ed8c1173ac59"
   strings:
      $hdr = "[Desktop Entry]"
      $s1 = "printf '\\\\x7FELF' | dd of"
      $s2 = "Future_Note_Warfare_OpSindoor.pdf"
   condition:
      filesize < 100KB
      and $hdr
      and any of ($s*)
}

rule MAL_Sindoor_Decryptor_Aug25 {
   meta:
      description = "Detects AES decryptor used by Sindoor dropper related to APT 36"
      author = "Pezier Pierre-Henri"
      date = "2025-08-29"
      score = 80
      reference = "Internal Research"
      hash = "9a1adb50bb08f5a28160802c8f315749b15c9009f25aa6718c7752471db3bb4b"
   strings:
      $s1 = "Go build"
      $s2 = "main.rc4EncryptDecrypt"
      $s3 = "main.processFile"
      $s4 = "main.deriveKeyAES"
      $s5 = "use RC4 instead of AES"
   condition:
      filesize < 100MB
      and (
         uint16(0) == 0x5a4d // Windows
         or uint32be(0) == 0x7f454c46  // Linux
         or (uint32be(0) == 0xcafebabe and uint32be(4) < 0x20)  // Universal mach-O App with dont-match-java-class-file hack
         or uint32(0) == 0xfeedface  // 32-bit mach-O
         or uint32(0) == 0xfeedfacf  // 64-bit mach-O
      )
      and all of them
}

rule MAL_Sindoor_Downloader_Aug25 {
   meta:
      description = "Detects Sindoor downloader related to APT 36"
      author = "Pezier Pierre-Henri"
      date = "2025-08-29"
      score = 80
      reference = "Internal Research"
      hash = "38b6b93a536cbab5c289fe542656d8817d7c1217ad75c7f367b15c65d96a21d4"
   strings:
      $s1 = "Go build"
      $s2 = "main.downloadFile.deferwrap"
      $s3 = "main.decrypt"
      $s4 = "main.HiddenHome"
      $s5 = "main.RealCheck"
   condition:
      filesize < 100MB
      and (
         uint16(0) == 0x5a4d // Windows
         or uint32be(0) == 0x7f454c46  // Linux
         or (uint32be(0) == 0xcafebabe and uint32be(4) < 0x20)  // Universal mach-O App with dont-match-java-class-file hack
         or uint32(0) == 0xfeedface  // 32-bit mach-O
         or uint32(0) == 0xfeedfacf  // 64-bit mach-O
      )
      and all of them
}

