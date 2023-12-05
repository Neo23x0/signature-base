
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-06-22
   Identifier: CN Group Tools
   Reference: Internal Research
*/

rule BTC_Miner_lsass1_chrome_2 {
   meta:
      description = "Detects a Bitcoin Miner"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research - CN Actor"
      date = "2017-06-22"
      super_rule = 1
      score = 60
      hash1 = "048e9146387d6ff2ac055eb9ddfbfb9a7f70e95c7db9692e2214fa4bec3d5b2e"
      hash2 = "c8db8469287d47ffdc74fe86ce0e9d6e51de67ba1df318573c9398742116a6e8"
      id = "7960d96a-7bd3-5135-867d-e39a02274c45"
   strings:
      $x1 = "-t, --threads=N       number of miner threads (default: number of processors)" fullword ascii
      $x2 = "-O, --userpass=U:P    username:password pair for mining server" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and 1 of them )
}

rule CN_Actor_RA_Tool_Ammyy_mscorsvw {
   meta:
      description = "Detects Ammyy remote access tool"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research - CN Actor"
      date = "2017-06-22"
      hash1 = "1831806fc27d496f0f9dcfd8402724189deaeb5f8bcf0118f3d6484d0bdee9ed"
      hash2 = "d9ec0a1be7cd218042c54bfbc12000662b85349a6b78731a09ed336e5d3cf0b4"
      id = "71a0c5a9-b4dc-508d-a6b7-4b85b75bc34b"
   strings:
      $s1 = "Please enter password for accessing remote computer" fullword ascii
      $s2 = "Die Zugriffsanforderung wurde vom Remotecomputer abgelehnt" fullword ascii
      $s3 = "It will automatically be run the next time this computer is restart or you can start it manually" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and 3 of them )
}

rule CN_Actor_AmmyyAdmin {
   meta:
      description = "Detects Ammyy Admin Downloader"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research - CN Actor"
      date = "2017-06-22"
      score = 60
      hash1 = "1831806fc27d496f0f9dcfd8402724189deaeb5f8bcf0118f3d6484d0bdee9ed"
      id = "08ffb61a-e2de-538e-9d9f-040276324af9"
   strings:
      $x2 = "\\Ammyy\\sources\\main\\Downloader.cpp" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and all of them )
}
