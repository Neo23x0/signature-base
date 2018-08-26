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
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/BeetleChunks/redsails"
      date = "2017-10-02"
      hash1 = "7a7861d25b0c038d77838ecbd5ea5674650ad4f5faf7432a6f3cfeb427433fac"
   strings:
      $s1 = "bWinDivert64.dll" fullword ascii
      $s2 = "bWinDivert32.dll" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and all of them )
}

rule redSails_PY {
   meta:
      description = "Detects Red Sails Hacktool - Python"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/BeetleChunks/redsails"
      date = "2017-10-02"
      hash1 = "6ebedff41992b9536fe9b1b704a29c8c1d1550b00e14055e3c6376f75e462661"
      hash2 = "5ec20cb99030f48ba512cbc7998b943bebe49396b20cf578c26debbf14176e5e"
   strings:
      $x1 = "Gained command shell on host" fullword ascii
      $x2 = "[!] Received an ERROR in shell()" fullword ascii
      $x3 = "Target IP address with backdoor installed" fullword ascii
      $x4 = "Open backdoor port on target machine" fullword ascii
      $x5 = "Backdoor port to open on victim machine" fullword ascii
   condition:
      1 of them
}
