/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2018-02-14
   Identifier: LokiBot Dropper
   Reference: https://app.any.run/tasks/401df4d9-098b-4fd0-86e0-7a52ce6ddbf5
*/

/* Rule Set ----------------------------------------------------------------- */

rule LokiBot_Dropper_ScanCopyPDF_Feb18 {
   meta:
      description = "Auto-generated rule - file Scan Copy.pdf.com"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://app.any.run/tasks/401df4d9-098b-4fd0-86e0-7a52ce6ddbf5"
      date = "2018-02-14"
      hash1 = "6f8ff26a5daf47effdea5795cdadfff9265c93a0ebca0ce5a4144712f8cab5be"
      id = "64c45d91-4e18-5fd1-8d93-b5db4df7da29"
   strings:
      $x1 = "Win32           Scan Copy.pdf   " fullword wide

      $a1 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB" fullword ascii

      $s1 = "Compiling2.exe" fullword wide
      $s2 = "Unstalled2" fullword ascii
      $s3 = "Compiling.exe" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and $x1 or
      ( $a1 and 1 of ($s*) )
}

rule LokiBot_Dropper_Packed_R11_Feb18 {
   meta:
      description = "Auto-generated rule - file scan copy.pdf.r11"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://app.any.run/tasks/401df4d9-098b-4fd0-86e0-7a52ce6ddbf5"
      date = "2018-02-14"
      hash1 = "3b248d40fd7acb839cc592def1ed7652734e0e5ef93368be3c36c042883a3029"
      id = "83cd6225-eb6d-5d17-a751-51f20db9c7eb"
   strings:
      $s1 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB" fullword ascii
   condition:
      uint16(0) == 0x0000 and filesize < 2000KB and 1 of them
}
