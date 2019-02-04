
import "pe"

rule MAL_ExileRAT_Feb19_1 {
   meta:
      description = "Detects Exile RAT"
      author = "Florian Roth"
      reference = "https://blog.talosintelligence.com/2019/02/exilerat-shares-c2-with-luckycat.html"
      date = "2019-02-04"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3eb026d8b778716231a07b3dbbdc99e2d3a635b1956de8a1e6efc659330e52de"
   strings:
      $x1 = "Content-Disposition:form-data;name=\"x.bin\"" fullword ascii

      $s1 = "syshost.dll" fullword ascii
      $s2 = "\\scout\\Release\\scout.pdb" ascii
      $s3 = "C:\\data.ini" fullword ascii
      $s4 = "my-ip\" value=\"" fullword ascii
      $s5 = "ver:%d.%d.%d" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and (
         pe.imphash() == "da8475fc7c3c90c0604ce6a0b56b5f21" or
         3 of them
      )
}
