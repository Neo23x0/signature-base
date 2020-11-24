
rule MAL_ME_RawDisk_Agent_Jan20_1 {
   meta:
      description = "Detects suspicious malware using ElRawDisk"
      author = "Florian Roth"
      reference = "Saudi National Cybersecurity Authority - Destructive Attack DUSTMAN"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      date = "2020-01-02"
      hash1 = "44100c73c6e2529c591a10cd3668691d92dc0241152ec82a72c6e63da299d3a2"
   strings:
      $x1 = "\\drv\\agent.plain.pdb" fullword ascii
      $x2 = " ************** Down With Saudi Kingdom, Down With Bin Salman ************** " fullword ascii

      $s1 = ".?AVERDError@@" fullword ascii
      $s2 = "b4b615c28ccd059cf8ed1abf1c71fe03c0354522990af63adf3c911e2287a4b906d47d" fullword wide
      $s3 = "\\\\?\\ElRawDisk" fullword wide
      $s4 = "\\??\\c:" fullword wide

      $op1 = { e9 3d ff ff ff 33 c0 48 89 05 0d ff 00 00 48 8b }
      $op2 = { 0f b6 0c 01 88 48 34 48 8b 8d a8 }
   condition:
      uint16(0) == 0x5a4d and filesize <= 2000KB and ( 1 of ($x*) or 4 of them )
}

rule MAL_ME_RawDisk_Agent_Jan20_2 {
   meta:
      description = "Detects suspicious malware using ElRawDisk"
      author = "Florian Roth"
      reference = "https://twitter.com/jfslowik/status/1212501454549741568?s=09"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      date = "2020-01-02"
      hash1 = "44100c73c6e2529c591a10cd3668691d92dc0241152ec82a72c6e63da299d3a2"
   strings:
      $x1 = "\\Release\\Dustman.pdb" fullword ascii
      $x2 = "/c agent.exe A" fullword ascii

      $s1 = "C:\\windows\\system32\\cmd.exe" fullword ascii
      $s2 = "The Magic Word!" fullword ascii
      $s3 = "Software\\Oracle\\VirtualBox" fullword wide
      $s4 = "\\assistant.sys" fullword wide
      $s5 = "Down With Bin Salman" fullword wide

      $sc1 = { 00 5C 00 5C 00 2E 00 5C 00 25 00 73 }

      $op1 = { 49 81 c6 ff ff ff 7f 4c 89 b4 24 98 }
   condition:
      uint16(0) == 0x5a4d and filesize <= 3000KB and ( 1 of ($x*) or 3 of them )
}
