/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-03-27
   Identifier: Osiris
*/

/* Rule Set ----------------------------------------------------------------- */

rule Invoke_OSiRis {
   meta:
      description = "Osiris Device Guard Bypass - file Invoke-OSiRis.ps1"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-03-27"
      modified = "2025-03-21"
      score = 70
      hash1 = "19e4a8b07f85c3d4c396d0c4e839495c9fba9405c06a631d57af588032d2416e"
   strings:
      $x1 = "$null = Iwmi Win32_Process -EnableA -Impers 3 -AuthenPacketprivacy -Name Create -Arg $ObfusK -Computer $Target" ascii wide
      $x3 = "-Arg@{Name=$VarName;VariableValue=$OSiRis;UserName=$env:Username}" ascii wide
      $x4 = "Device Guard Bypass Command Execution" ascii wide
   condition:
      filesize < 8MB
      and 1 of them
}
