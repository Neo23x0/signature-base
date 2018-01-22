/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2018-01-21
   Identifier: Envrial
   Reference: https://twitter.com/malwrhunterteam/status/953313514629853184
*/

/* Rule Set ----------------------------------------------------------------- */

rule MAL_Envrial_Jan18_1 {
   meta:
      description = "Detects Encrial credential stealer malware"
      author = "Florian Roth"
      reference = "https://twitter.com/malwrhunterteam/status/953313514629853184"
      date = "2018-01-21"
      hash1 = "9ae3aa2c61f7895ba6b1a3f85fbe36c8697287dc7477c5a03d32cf994fdbce85"
      hash2 = "9edd8f0e22340ecc45c5f09e449aa85d196f3f506ff3f44275367df924b95c5d"
   strings:
      $x1 = "/Evrial/master/domen" wide

      $a1 = "\\Opera Software\\Opera Stable\\Login Data" fullword wide
      $a2 = "\\Comodo\\Dragon\\User Data\\Default\\Login Data" fullword wide
      $a3 = "\\Google\\Chrome\\User Data\\Default\\Login Data" fullword wide
      $a4 = "\\Orbitum\\User Data\\Default\\Login Data" fullword wide
      $a5 = "\\Kometa\\User Data\\Default\\Login Data" fullword wide

      $s1 = "dlhosta.exe" fullword wide
      $s2 = "\\passwords.log" fullword wide
      $s3 = "{{ <>h__TransparentIdentifier1 = {0}, Password = {1} }}" fullword wide
      $s4 = "files/upload.php?user={0}&hwid={1}" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and (
        1 of ($x*) or
        3 of them or
        2 of ($s*)
      )
}