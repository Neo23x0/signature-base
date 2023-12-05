/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-10-25
   Identifier: BadRabbit
   Reference: https://pastebin.com/Y7pJv3tK
*/

/* Rule Set ----------------------------------------------------------------- */

rule BadRabbit_Gen {
   meta:
      description = "Detects BadRabbit Ransomware"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://pastebin.com/Y7pJv3tK"
      date = "2017-10-25"
      hash1 = "8ebc97e05c8e1073bda2efb6f4d00ad7e789260afa2c276f0c72740b838a0a93"
      hash2 = "579fd8a0385482fb4c789561a30b09f25671e86422f40ef5cca2036b28f99648"
      hash3 = "630325cac09ac3fab908f903e3b00d0dadd5fdaa0875ed8496fcbb97a558d0da"
      id = "272e50f8-5aef-52ec-a5d0-01e8504d6c55"
   strings:
      $x1 = "schtasks /Create /SC ONCE /TN viserion_%u /RU SYSTEM /TR \"%ws\" /ST" fullword wide
      $x2 = "schtasks /Create /RU SYSTEM /SC ONSTART /TN rhaegal /TR \"%ws /C Start \\\"\\\" \\\"%wsdispci.exe\\\"" fullword wide
      $x3 = "C:\\Windows\\infpub.dat" fullword wide
      $x4 = "C:\\Windows\\cscc.dat" fullword wide

      $s1 = "need to do is submit the payment and get the decryption password." fullword ascii
      $s2 = "\\\\.\\GLOBALROOT\\ArcName\\multi(0)disk(0)rdisk(0)partition(1)" fullword wide
      $s3 = "\\\\.\\pipe\\%ws" fullword wide
      $s4 = "fsutil usn deletejournal /D %c:" fullword wide
      $s5 = "Run DECRYPT app at your desktop after system boot" fullword ascii
      $s6 = "Files decryption completed" fullword wide
      $s7 = "Disable your anti-virus and anti-malware programs" fullword wide
      $s8 = "SYSTEM\\CurrentControlSet\\services\\%ws" fullword wide
      $s9 = "process call create \"C:\\Windows\\System32\\rundll32.exe" fullword wide
      $s10 = "%ws C:\\Windows\\%ws,#1 %ws" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and ( 1 of ($x*) or 2 of them )
}

rule BadRabbit_Mimikatz_Comp {
   meta:
      description = "Auto-generated rule"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://pastebin.com/Y7pJv3tK"
      date = "2017-10-25"
      hash1 = "2f8c54f9fa8e47596a3beff0031f85360e56840c77f71c6a573ace6f46412035"
      id = "52affd3f-6bf9-55f6-92a5-69314a2e76e0"
   strings:
      $s1 = "%lS%lS%lS:%lS" fullword wide
      $s2 = "lsasrv" fullword wide
      $s3 = "CredentialKeys" ascii
      /* Primary\x00m\x00s\x00v */
      $s4 = { 50 72 69 6D 61 72 79 00 6D 00 73 00 76 00 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 3 of them )
}
