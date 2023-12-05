
rule APT_Equation_Group_Op_Triangulation_TriangleDB_Implant_Jun23_1 {
   meta:
      description = "Detects TriangleDB implant found being used in Operation Triangulation on iOS devices (maybe also used on macOS systems)"
      author = "Florian Roth"
      reference = "https://securelist.com/triangledb-triangulation-implant/110050/"
      date = "2023-06-21"
      score = 80
      id = "d81a5103-41c8-5dba-a560-8fb5514f6c0a"
   strings:
      $s1 = "unmungeHexString" ascii fullword
      $s2 = "CRPwrInfo" ascii fullword
      $s3 = "CRConfig" ascii fullword
      $s4 = "CRXConfigureDBServer" ascii fullword
   condition:
      ( uint16(0) == 0xfacf and filesize < 30MB and $s1 and 2 of them ) 
      or all of them
}
