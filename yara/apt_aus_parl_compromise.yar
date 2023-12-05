/*
   YARA Rule Set
   Author: Florian Roth
   Date: 2019-02-18
   Identifier: Compromise of the Australian Parliament House network
   Reference: https://cyber.gov.au/government/news/parliament-house-network-compromise/
              https://twitter.com/cyb3rops/status/1097423665472376832
*/

/* Rule Set ----------------------------------------------------------------- */

rule APT_WebShell_Tiny_1 {
   meta:
      description = "Detetcs a tiny webshell involved in the Australian Parliament House network compromise"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
      date = "2019-02-18"
      id = "e65a8920-0684-5aae-a2b8-079c2beae08a"
   strings:
      $x1 = "eval(" ascii wide
   condition:
      ( uint16(0) == 0x3f3c or uint16(0) == 0x253c ) and filesize < 40 and $x1
}

rule APT_WebShell_AUS_Tiny_2 {
   meta:
      description = "Detetcs a tiny webshell involved in the Australian Parliament House network compromise"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
      date = "2019-02-18"
      hash1 = "0d6209d86f77a0a69451b0f27b476580c14e0cda15fa6a5003aab57a93e7e5a5"
      id = "4746d4ce-628a-59b0-9032-7e0759d96ad3"
   strings:
      $x1 = "Request.Item[System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(\"[password]\"))];" ascii
      $x2 = "eval(arguments,System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(\"" ascii
   condition:
      ( uint16(0) == 0x3f3c or uint16(0) == 0x253c ) and filesize < 1KB and 1 of them
}

rule APT_WebShell_AUS_JScript_3 {
   meta:
      description = "Detetcs a webshell involved in the Australian Parliament House network compromise"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
      date = "2019-02-18"
      hash1 = "7ac6f973f7fccf8c3d58d766dec4ab7eb6867a487aa71bc11d5f05da9322582d"
      id = "ff7e780b-ccf9-53b6-b741-f04a8cbaf580"
   strings:
      $s1 = "<%@ Page Language=\"Jscript\" validateRequest=\"false\"%><%try{eval(System.Text.Encoding.UTF8.GetString(Convert.FromBase64String" ascii
      $s2 = ".Item[\"[password]\"])),\"unsafe\");}" ascii
   condition:
      uint16(0) == 0x6568 and filesize < 1KB and all of them
}


rule APT_WebShell_AUS_4 {
   meta:
      description = "Detetcs a webshell involved in the Australian Parliament House network compromise"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
      date = "2019-02-18"
      hash1 = "83321c02339bb51735fbcd9a80c056bd3b89655f3dc41e5fef07ca46af09bb71"
      id = "bb5b10d1-3528-5361-92fc-8440c65dcda4"
   strings:
      $s1 = "wProxy.Credentials = new System.Net.NetworkCredential(pusr, ppwd);" fullword ascii
      $s2 = "{return System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(" ascii
      $s3 = ".Equals('User-Agent', StringComparison.OrdinalIgnoreCase))" ascii
      $s4 = "gen.Emit(System.Reflection.Emit.OpCodes.Ret);" fullword ascii
   condition:
      uint16(0) == 0x7566 and filesize < 10KB and 3 of them
}

rule APT_Script_AUS_4 {
   meta:
      description = "Detetcs a script involved in the Australian Parliament House network compromise"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
      date = "2019-02-18"
      hash1 = "fdf15f388a511a63fbad223e6edb259abdd4009ec81fcc87ce84f0f2024c8057"
      id = "5cbf2476-5ce8-540d-b87b-e400daf49b43"
   strings:
      $x1 = "myMutex = CreateMutex(0, 1, \"teX23stNew\")" fullword ascii
      $x2 = "mmpath = Environ(appdataPath) & \"\\\" & \"Microsoft\" & \"\\\" & \"mm.accdb\"" fullword ascii
      $x3 = "Dim mmpath As String, newmmpath  As String, appdataPath As String" fullword ascii
      $x4 = "'MsgBox \"myMutex Created\" Do noting" fullword ascii
      $x5 = "appdataPath = \"app\" & \"DatA\"" fullword ascii
      $x6 = ".DoCmd.Close , , acSaveYes" fullword ascii
   condition:
      filesize < 7KB and 1 of them
}

rule APT_WebShell_AUS_5 {
   meta:
      description = "Detetcs a webshell involved in the Australian Parliament House network compromise"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
      date = "2019-02-18"
      hash1 = "54a17fb257db2d09d61af510753fd5aa00537638a81d0a8762a5645b4ef977e4"
      id = "59b3f6aa-2d3b-54b4-b543-57bd9d981e87"
   strings:
      $a1 = "function DEC(d){return System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(d));}" fullword ascii
      $a2 = "function ENC(d){return Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(d));}" fullword ascii

      $s1 = "var hash=DEC(Request.Item['" ascii
      $s2 = "Response.Write(ENC(SET_ASS_SUCCESS));" fullword ascii
      $s3 = "hashtable[hash] = assCode;" fullword ascii
      $s4 = "Response.Write(ss);" fullword ascii
      $s5 = "var hashtable = Application[CachePtr];" fullword ascii
   condition:
      uint16(0) == 0x7566 and filesize < 2KB and 4 of them
}

rule HKTL_LazyCat_LogEraser {
   meta:
      description = "Detetcs a tool used in the Australian Parliament House network compromise"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
      date = "2019-02-18"
      hash1 = "1c113dce265e4d744245a7c55dadc80199ae972a9e0ecbd0c5ced57067cf755b"
      hash2 = "510375f8142b3651df67d42c3eff8d2d880987c0e057fc75a5583f36de34bf0e"
      id = "a3d74657-a389-5482-ab26-966e790afd50"
   strings:
      $x1 = "LazyCat.dll" ascii wide fullword
      $x2 = ".local_privilege_escalation.rotten_potato" ascii wide
      $x3 = "LazyCat.Extension" ascii wide
      $x4 = " MEOWof" ascii wide
      $x5 = "VirtualSite: {0}, Address: {1:X16}, Name: {2}, Handle: {3:X16}, LogPath: {4}" fullword wide

      $s1 = "LazyCat" fullword ascii wide
      $s2 = "$e3ff37f2-85d7-4b24-a385-7eeb1f5a9562"
      $s3 = "local -> remote {0} bytes"
      $s4 = "remote -> local {0} bytes"
   condition:
      3 of them
}

rule HKTL_PowerKatz_Feb19_1 {
   meta:
      description = "Detetcs a tool used in the Australian Parliament House network compromise"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
      date = "2019-02-18"
      id = "294d6f6c-dbc8-5431-87a0-64abe582c4ea"
   strings:
      $x1 = "Powerkatz32" ascii wide fullword
      $x2 = "Powerkatz64" ascii wide

      $s1 = "GetData: not found taskName" fullword ascii wide
      $s2 = "GetRes Ex:" fullword ascii wide
   condition:
      1 of ($x*) and 1 of ($s*)
}

rule HKTL_Unknown_Feb19_1 {
   meta:
      description = "Detetcs a tool used in the Australian Parliament House network compromise"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
      date = "2019-02-18"
      id = "bdcadc4b-8881-5dc7-b203-4e79cbc850ed"
   strings:
      $x1 = "not a valid timeout format!" ascii wide fullword
      $x2 = "host can not be empty!" ascii wide fullword
      $x3 = "not a valid port format!" ascii wide fullword
      $x4 = "{0} - {1} TTL={2} time={3}" ascii wide fullword
      $x5 = "ping count is not a correct format!" ascii wide fullword

      $s1 = "The result is too large,program store to '{0}'.Please download it manully." fullword ascii wide
      $s2 = "C:\\Windows\\temp\\" ascii wide
   condition:
      1 of ($x*) or 2 of them
}
