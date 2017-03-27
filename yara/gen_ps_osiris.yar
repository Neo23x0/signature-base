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
      hash1 = "19e4a8b07f85c3d4c396d0c4e839495c9fba9405c06a631d57af588032d2416e"
   strings:
      $x1 = "$null = Iwmi Win32_Process -EnableA -Impers 3 -AuthenPacketprivacy -Name Create -Arg $ObfusK -Computer $Target" fullword ascii
      $x2 = "Invoke-OSiRis" ascii
      $x3 = "-Arg@{Name=$VarName;VariableValue=$OSiRis;UserName=$env:Username}" fullword ascii
      $x4 = "Device Guard Bypass Command Execution" fullword ascii
      $x5 = "-Put Payload in Win32_OSRecoveryConfiguration DebugFilePath" fullword ascii
      $x6 = "$null = Iwmi Win32_Process -EnableA -Impers 3 -AuthenPacketprivacy -Name Create" fullword ascii
   condition:
      1 of them
}
