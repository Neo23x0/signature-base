import "pe"

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-11-01
   Identifier: Silence
   Reference: https://securelist.com/the-silence/83009/
*/

/* Rule Set ----------------------------------------------------------------- */

rule Silence_malware_1 {
   meta:
      description = "Detects malware sample mentioned in the Silence report on Securelist"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://securelist.com/the-silence/83009/"
      date = "2017-11-01"
      hash1 = "f24b160e9e9d02b8e31524b8a0b30e7cdc66dd085e24e4c58240e4c4b6ec0ac2"
   strings:
      $x1 = "adobeudp.exe" fullword wide
      $x2 = "%s\\adobeudp.exeZone.Identifier" fullword ascii
      $x3 = "%s\\igfxpers_%08x.exe" fullword ascii
      $x4 = "%s\\adobeudp.exe" fullword ascii

      $s1 = "SoftWare\\MicroSoft\\Windows\\CurrentVersion\\Run" fullword ascii
      $s2 = "Copyright (C)  1999 - 2017" fullword wide
      $s3 = "%sget.php?name=%x" fullword ascii
      $s4 = "VNASSRUNXYC" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and (
        pe.imphash() == "e03edb9bd7cbe200dc59f361db847f8a" or
        1 of ($x*) or
        3 of them
      )
}

rule Silence_malware_2 {
   meta:
      description = "Detects malware sample mentioned in the Silence report on Securelist"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://securelist.com/the-silence/83009/"
      date = "2017-11-01"
      hash1 = "75b8f534b2f56f183465ba2b63cfc80b7d7d1d155697af141447ec7144c2ba27"
   strings:
      $x1 = "\\ScreenMonitorService\\Release\\smmsrv.pdb" ascii
      $x2 = "\\\\.\\pipe\\{73F7975A-A4A2-4AB6-9121-AECAE68AABBB}" fullword ascii

      $s1 = "My Sample Service: ServiceMain: SetServiceStatus returned error" fullword ascii
      $s2 = "\\mss.exe" fullword ascii
      $s3 = "\\out.dat" fullword ascii
      $s4 = "\\mss.txt" fullword ascii
      $s5 = "Default monitor" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and (
            pe.imphash() == "69f3ec173efb6fd3ab5f79e0f8051335" or
            ( 1 of ($x*) or 3 of them )
         )
      ) or ( 5 of them )
}
