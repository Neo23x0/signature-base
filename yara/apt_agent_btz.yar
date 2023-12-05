/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-08-07
   Identifier: Agent BTZ
   Reference: http://www.intezer.com/new-variants-of-agent-btz-comrat-found/
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule Agent_BTZ_Proxy_DLL_1 {
   meta:
      description = "Detects Agent-BTZ Proxy DLL - activeds.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "http://www.intezer.com/new-variants-of-agent-btz-comrat-found/"
      date = "2017-08-07"
      hash1 = "9c163c3f2bd5c5181147c6f4cf2571160197de98f496d16b38c7dc46b5dc1426"
      hash2 = "628d316a983383ed716e3f827720915683a8876b54677878a7d2db376d117a24"
      id = "f8032616-2a54-5107-b330-65fcc84b866e"
   strings:
      $s1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Modules" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and all of them and pe.exports("Entry") )
}

rule Agent_BTZ_Proxy_DLL_2 {
   meta:
      description = "Detects Agent-BTZ Proxy DLL - activeds.dll"
      author = "Florian Roth (Nextron Systems)"
      reference = "http://www.intezer.com/new-variants-of-agent-btz-comrat-found/"
      date = "2017-08-07"
      hash1 = "73db4295c5b29958c5d93c20be9482c1efffc89fc4e5c8ba59ac9425a4657a88"
      hash2 = "380b0353ba8cd33da8c5e5b95e3e032e83193019e73c71875b58ec1ed389bdac"
      hash3 = "f27e9bba6a2635731845b4334b807c0e4f57d3b790cecdc77d8fef50629f51a2"
      id = "2777443d-6f63-5948-855a-e064a6e0310f"
   strings:
      $s1 = { 38 21 38 2C 38 37 38 42 38 4D 38 58 38 63 38 6E
               38 79 38 84 38 8F 38 9A 38 A5 38 B0 38 BB 38 C6
               38 D1 38 DC 38 E7 38 F2 38 FD 38 08 39 13 39 1E
               39 29 39 34 39 3F 39 4A 39 55 39 60 39 6B 39 76
               39 81 39 8C 39 97 39 A2 39 AD 39 B8 39 C3 39 CE
               39 D9 39 E4 39 EF 39 FA 39 05 3A 10 3A 1B 3A 26
               3A 31 3A 3C 3A 47 3A 52 3A 5D 3A 68 3A 73 3A 7E
               3A 89 3A 94 3A 9F 3A AA 3A B5 3A C0 3A CB 3A D6
               3A E1 3A EC 3A F7 3A }
      $s2 = "activeds.dll" ascii fullword
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and all of them and pe.imphash() == "09b7c73fbe5529e6de7137e3e8268b7b"
}

rule Agent_BTZ_Aug17 {
   meta:
      description = "Detects Agent.BTZ"
      author = "Florian Roth (Nextron Systems)"
      reference = "http://www.intezer.com/new-variants-of-agent-btz-comrat-found/"
      date = "2017-08-07"
      hash1 = "6ad78f069c3619d0d18eef8281219679f538cfe0c1b6d40b244beb359762cf96"
      hash2 = "49c5c798689d4a54e5b7099b647b0596fb96b996a437bb8241b5dd76e974c24e"
      hash3 = "e88970fa4892150441c1616028982fe63c875f149cd490c3c910a1c091d3ad49"
      id = "31804208-3edb-554b-8820-e682db647435"
   strings:
      $s1 = "stdole2.tlb" fullword ascii
      $s2 = "UnInstallW" fullword ascii
   condition:
      (
         uint16(0) == 0x5a4d and filesize < 900KB and
         all of them and
         pe.exports("Entry") and pe.exports("InstallW") and pe.exports("UnInstallW")
      )
}

rule APT_Turla_Agent_BTZ_Gen_1 {
   meta:
      description = "Detects Turla Agent.BTZ"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2018-06-16"
      score = 80
      hash1 = "c905f2dec79ccab115ad32578384008696ebab02276f49f12465dcd026c1a615"
      id = "d5e1dd3d-4f03-5f79-898b-e612d2758b60"
   strings:
      $x1 = "1dM3uu4j7Fw4sjnbcwlDqet4F7JyuUi4m5Imnxl1pzxI6as80cbLnmz54cs5Ldn4ri3do5L6gs923HL34x2f5cvd0fk6c1a0s" fullword ascii

      $s1 = "release mutex - %u (%u)(%u)" fullword ascii
      $s2 = "\\system32\\win.com" ascii
      $s3 = "Command Id:%u%010u(%02d:%02d:%02d %02d/%02d/%04d)" fullword ascii
      $s4 = "MakeFile Error(%d) copy file to temp file %s" fullword ascii
      $s5 = "%s%%s08x.tmp" fullword ascii
      $s6 = "Run instruction: %d ID:%u%010u(%02d:%02d:%02d %02d/%02d/%04d)" fullword ascii
      $s7 = "Mutex_Log" fullword ascii
      $s8 = "%s\\system32\\winview.ocx" fullword ascii
      $s9 = "Microsoft(R) Windows (R) Operating System" fullword wide
      $s10 = "Error: pos(%d) > CmdSize(%d)" fullword ascii
      $s11 = "\\win.com" ascii
      $s12 = "Error(%d) run %s " fullword ascii
      $s13 = "%02d.%02d.%04d Log begin:" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and (
         pe.imphash() == "9d0d6daa47d6e6f2d80eb05405944f87" or
         ( pe.exports("Entry") and pe.exports("InstallM") and pe.exports("InstallS") ) or
         $x1 or 3 of them
      ) or ( 5 of them )
}
