
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-12-11
   Identifier: Patchwork
   Reference: https://goo.gl/Pg3P4W
*/

/* Rule Set ----------------------------------------------------------------- */

rule xRAT_1 {
   meta:
      description = "Detects Patchwork malware"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/Pg3P4W"
      date = "2017-12-11"
      hash1 = "92be93ec4cbe76182404af0b180871fbbfa3c7b34e4df6745dbcde480b8b4b3b"
      hash2 = "f1a45adcf907e660ec848c6086e28c9863b7b70d0d38417dd05a4261973c955a"
   strings:
      $x1 = "\" -CHECK & PING -n 2 127.0.0.1 & EXIT" fullword wide
      $x2 = "xClient.Core.Elevation" fullword ascii
      $x3 = ">> Welcome to MAX-Shell :Session created" fullword wide
      $x4 = "xClient.Properties.Resources.resources" fullword ascii
      $x5 = "<description>My UAC Compatible application</description>" fullword ascii

      $s1 = "ping -n 20 localhost > nul" fullword wide
      $s2 = "DownloadAndExecute" fullword ascii
      $s3 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.114 Safari/537.36" fullword wide
      $s4 = "Client.exe" fullword ascii
      $s5 = "Microsoft -Defender" fullword wide
      $s6 = "Microsoft- Defender" fullword wide
      $s7 = "set_RunHidden" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and (
         1 of ($x*) or
         3 of them
      )
}