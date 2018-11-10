
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-09-08
   Identifier:
   Reference: http://blog.fortinet.com/2017/04/05/in-depth-look-at-new-variant-of-monsoon-apt-backdoor-part-2
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule Monsoon_APT_Malware_1 {
   meta:
      description = "Detects malware from Monsoon APT"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "http://blog.fortinet.com/2017/04/05/in-depth-look-at-new-variant-of-monsoon-apt-backdoor-part-2"
      date = "2017-09-08"
      hash1 = "c9642f44d33e4c990066ce6fa0b0956ff5ace6534b64160004df31b9b690c9cd"
   strings:
      $s1 = "cmd.exe /c start " fullword ascii
      $s2 = "\\Microsoft\\Templates\\" fullword ascii
      $s3 = "\\Microsoft\\Windows\\" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 300KB and
        (
           pe.imphash() == "a0c824244f1d36ea1dd2759cf7599cd1" or
           all of them
        )
      )
}

rule Monsoon_APT_Malware_2 {
   meta:
      description = "Detects malware from Monsoon APT"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "http://blog.fortinet.com/2017/04/05/in-depth-look-at-new-variant-of-monsoon-apt-backdoor-part-2"
      date = "2017-09-08"
      hash1 = "17c3d0fe08e1184c9737144fa065f4530def30d6591e5414a36463609f9aa53a"
      hash2 = "8e0574ebf3dc640ac82987ab6ee2a02fc3dd5eaf4f6b5275272ba887acd15ac0"
      hash3 = "bf93ca5f497fc7f38533d37fd4c083523ececc34aa2d3660d81014c0d9091ae3"
   strings:
      $x1 = "\\Microsoft\\Windows\\coco.exe" fullword ascii
      $x2 = ":\\System Volume Information\\config" fullword ascii
      $x3 = " cscript.[BACKSPA[PAGE DO[CAPS LO[PAGE UPTPX498.dTPX499.d" fullword wide

      $s1 = "\\Microsoft\\Templates\\msvcrt.dll" fullword ascii
      $s2 = "%04d/%02d/%02d %02d:%02d:%02d - {%s}" fullword wide
      $s3 = "wininet.dll    " fullword ascii
      $s4 = "DMCZ0001.dat" fullword ascii
      $s5 = "TZ0000001.dat" fullword ascii
      $s6 = "\\MUT.dat" fullword ascii
      $s7 = "ouemm/emm!!!!!!!!!!!!!" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 400KB and ( 1 of ($x*) or 3 of them )
      )
}
