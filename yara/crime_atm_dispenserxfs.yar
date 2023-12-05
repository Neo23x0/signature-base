
import "pe"

rule ATM_Malware_DispenserXFS {
   meta:
      description = "Detects ATM Malware DispenserXFS"
      author = "@Xylit0l @r3c0nst / Modified by Florian Roth"
      reference = "https://twitter.com/r3c0nst/status/1100775857306652673"
      date = "2019/02/27"
      modified = "2023-01-06"
      score = 80
      id = "7c06102c-93d3-52f4-8c25-430f6f7a601f"
   strings:
      $xc1 = { 68 FF FF 00 00 68 60 EA 00 00 6A 10 }
      $s1 = "\\dispenserXFS.pdb" ascii
      $s3 = "C:\\xfsasdf.txt" fullword ascii
      $s4 = "Injected mxsfs killer into %d." fullword ascii
      $s5 = "Waiting for freeze msxfs processes..." fullword ascii
   condition:
      uint16(0) == 0x5A4D and (
         1 of them or
         pe.imphash() == "617e037ae26d1931818db0790fb44bfe"
      )
}
