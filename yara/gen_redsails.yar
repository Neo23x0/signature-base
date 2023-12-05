/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-10-02
   Identifier: Red Sails
   Reference: https://github.com/BeetleChunks/redsails
*/

/* Rule Set ----------------------------------------------------------------- */

rule redSails_EXE {
   meta:
      description = "Detects Red Sails Hacktool by WinDivert references"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/BeetleChunks/redsails"
      date = "2017-10-02"
      hash1 = "7a7861d25b0c038d77838ecbd5ea5674650ad4f5faf7432a6f3cfeb427433fac"
      id = "e7ebbebf-e2d6-5cd3-b859-b804d39d1641"
   strings:
      $s1 = "bWinDivert64.dll" fullword ascii
      $s2 = "bWinDivert32.dll" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and all of them )
}

rule redSails_PY {
   meta:
      description = "Detects Red Sails Hacktool - Python"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/BeetleChunks/redsails"
      date = "2017-10-02"
      hash1 = "6ebedff41992b9536fe9b1b704a29c8c1d1550b00e14055e3c6376f75e462661"
      hash2 = "5ec20cb99030f48ba512cbc7998b943bebe49396b20cf578c26debbf14176e5e"
      id = "59d5e784-70ff-5061-9867-54c905ecfd8c"
   strings:
      $x1 = "Gained command shell on host" fullword ascii
      $x2 = "[!] Received an ERROR in shell()" fullword ascii
      $x3 = "Target IP address with backdoor installed" fullword ascii
      $x4 = "Open backdoor port on target machine" fullword ascii
      $x5 = "Backdoor port to open on victim machine" fullword ascii
   condition:
      1 of them
}
