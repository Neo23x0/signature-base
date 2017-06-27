/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-06-27
   Identifier: Petya
   Reference: https://goo.gl/h6iaGj
*/

/* Rule Set ----------------------------------------------------------------- */

rule Petya_Ransomware_Jun17 {
   meta:
      description = "Detects new Petya Ransomware variant from June 2017"
      author = "Florian Roth"
      reference = "https://goo.gl/h6iaGj"
      date = "2017-06-27"
      hash1 = "027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745"
   strings:
      $x1 = "Ooops, your important files are encrypted." fullword wide
      $x2 = "process call create \"C:\\Windows\\System32\\rundll32.exe \\\"C:\\Windows\\%s\\\" #1 " fullword wide
      $x3 = "-d C:\\Windows\\System32\\rundll32.exe \"C:\\Windows\\%s\",#1 " fullword wide
      $x4 = "Send your Bitcoin wallet ID and personal installation key to e-mail " fullword wide
      $x5 = "fsutil usn deletejournal /D %c:" fullword wide
      $x6 = "wevtutil cl Setup & wevtutil cl System" ascii

      $s1 = "%s /node:\"%ws\" /user:\"%ws\" /password:\"%ws\" " fullword wide
      $s4 = "\\\\.\\pipe\\%ws" fullword wide
      $s5 = "schtasks %ws/Create /SC once /TN \"\" /TR \"%ws\" /ST %02d:%02d" fullword wide
      $s6 = "u%s \\\\%s -accepteula -s " fullword wide
      $s7 = "dllhost.dat" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and ( 1 of ($x*) or 3 of them )
}
