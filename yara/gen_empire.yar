/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2016-11-05
   Identifier: Empire
*/

/* Rule Set ----------------------------------------------------------------- */

rule Empire_OutMiniDump {
   meta:
      description = "Detects Out-MiniDump from PowerShell Empire"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire/blob/master/data/module_source/collection/Out-Minidump.ps1"
      date = "2016-11-05"
      hash1 = "4672a9e95745d0df94ab98992dd479285bc72a34b655f372a45dd58b32c2ffa6"
   strings:
      $x1 = "Get-Process | Out-Minidump -DumpFilePath C:\\temp" fullword ascii
      $x2 = "Get-Process lsass | Out-Minidump -DumpFilePath C:\\windows\\system" fullword ascii
      $x3 = "Out-Minidump -Process (Get-Process -Id 4293)" fullword ascii
      $s4 = "$FileStream = New-Object IO.FileStream($ProcessDumpPath, [IO.FileMode]::Create)" fullword ascii
      $s5 = "This is similar to running procdump.exe with the '-ma' switch." fullword ascii
      $s6 = "Generate a minidump for process ID 4293." fullword ascii
      $s7 = "C:\\ProgramData\\system\\cmd32.exe" fullword wide
      $s8 = "C:\\ProgramData\\system\\cmd64.exe" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and 1 of ($x*) ) or ( 3 of them )
}
