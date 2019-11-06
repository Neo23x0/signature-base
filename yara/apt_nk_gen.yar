
rule APT_NK_MAL_Keylogger_Unknown_Nov19_1 {
   meta:
      description = "Detects unknown keylogger reported by CNMF in November 2019"
      author = "Florian Roth"
      reference = "https://twitter.com/CNMF_VirusAlert/status/1192131508007505921"
      date = "2019-11-06"
      hash1 = "04d70bb249206a006f83db39bbe49ff6e520ea329e5fbb9c758d426b1c8dec30"
      hash2 = "618a67048d0a9217317c1d1790ad5f6b044eaa58a433bd46ec2fb9f9ff563dc6"
   strings:
      $x1 = "CKeyLogDlg::Keylogger_WriteFile" ascii
      $x2 = "Keylog file is saved >>>>>> %s" fullword ascii
      $x3 = "MicCap file is saved >>>>>> %s" fullword ascii
      $xc1 = { 73 74 61 74 75 73 00 00 5C 4B 65 79 6C 6F 67 }
      $xc2 = { 5B 43 4D 69 63 43 61 70 44 6C 67 5D 2E 00 00 00
               25 30 34 64 25 30 32 64 25 30 32 64 25 30 32 64
               25 30 32 64 2E 77 61 76 }

      $s1 = "%s\\cmd.exe /c %s" fullword ascii
      $s2 = "File upload error occured in [CFSDlg::ProcessResultMessage]." fullword ascii
      $s3 = "\\SAM\\Domains\\Account\\Users\\Names" fullword ascii
      $s4 = "SELECT * FROM moz_logins;" fullword ascii
      $s5 = "%s_hist%d:%d:%s:%s:::" fullword ascii
      $s6 = "CARAT_Ws2_32.dll" fullword ascii
      $s7 = " Process : " fullword ascii
      $s8 = "%s\\Mozilla\\Firefox\\profiles.ini" fullword ascii
      $s9 = "PID [%s], open process failed." fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize <= 40000KB and ( 1 of ($x*) or 4 of them )
}
