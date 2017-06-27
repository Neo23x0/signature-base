/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-06-27
   Identifier: NoPetya
   Reference: https://goo.gl/h6iaGj
              https://gist.github.com/vulnersCom/65fe44d27d29d7a5de4c176baba45759
*/

/* Rule Set ----------------------------------------------------------------- */

rule NoPetya_Ransomware_Jun17 {
   meta:
      description = "Detects new NoPetya Ransomware variant from June 2017"
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

rule NoPetya_Rel_Malware {
   meta:
      description = "Detects NoPetya related malware - karo.exe"
      author = "Florian Roth"
      reference = "https://gist.github.com/vulnersCom/65fe44d27d29d7a5de4c176baba45759"
      date = "2017-06-27"
      hash1 = "e5c643f1d8ecc0fd739d0bbe4a1c6c7de2601d86ab0fff74fd89c40908654be5"
      hash2 = "7f081859ae2b9b59f014669233473921f1cac755f6c6bbd5dcdd3fafbe710000"
      hash3 = "3e896599851231d11c06ee3f5f9677436850d3e7d745530f0a46f712e37ce082"
   strings:
      $s1 = "PublicKeyToken=3e56350693f7355e" fullword wide
      $s2 = "karo.exe" fullword wide
      $s3 = "IWshShell3" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and all of them )
}

rule NoPetya_Rel_Malware_3 {
   meta:
      description = "Detects NoPetya related malware - iosi.exe"
      author = "Florian Roth"
      reference = "https://gist.github.com/vulnersCom/65fe44d27d29d7a5de4c176baba45759"
      date = "2017-06-27"
      hash1 = "2ddf8df2ee880dae54a7f52e4bf56f896bb3f873fb6b8fdb60cae4a3de16ff49"
   strings:
      $s1 = "PublicKeyToken=3e56350693f7355e" fullword wide
      $s2 = "iosi.exe" fullword wide
      $s3 = "WshExecStatus" fullword ascii
      $s4 = "IsX64Process" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and all of them )
}
