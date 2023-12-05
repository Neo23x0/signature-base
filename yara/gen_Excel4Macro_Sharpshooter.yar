rule MAL_Sharpshooter_Excel4 {
   meta:
      description = "Detects Excel documents weaponized with Sharpshooter"
      author = "John Lambert, Florian Roth"
      reference = "https://github.com/mdsecactivebreach/SharpShooter"
      reference2="https://outflank.nl/blog/2018/10/06/old-school-evil-excel-4-0-macros-xlm/"
      reference3 = "https://gist.github.com/JohnLaTwC/efab89650d6fcbb37a4221e4c282614c"
      reference4 = "https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/00b5dd7d-51ca-4938-b7b7-483fe0e5933b"
      date = "2020-03-27"
      score = 70
      hash="ccef64586d25ffcb2b28affc1f64319b936175c4911e7841a0e28ee6d6d4a02d"
      id = "a79e3afe-e8f9-5e56-a131-bb1b346df471"
   strings:
      $header_docf = { D0 CF 11 E0 }
      $s1 = "Excel 4.0 Macros"
      $f1 = "CreateThread" ascii fullword
      $f2 = "WriteProcessMemory" ascii fullword
      $f3 = "Kernel32" ascii fullword
      $concat = { 00 41 6f 00 08 1e ?? 00 41 6f 00 08 1e ?? 00 41 6f 00 08}
   condition:
      filesize < 1000KB
      and $header_docf at 0
      and #concat > 10
      and $s1 and 2 of ($f*)
}

rule SUSP_Excel4Macro_AutoOpen
{
    meta:
        description = "Detects Excel4 macro use with auto open / close"
        author = "John Lambert @JohnLaTwC"
        date = "2020-03-26"
        score = 50
        hash="2fb198f6ad33d0f26fb94a1aa159fef7296e0421da68887b8f2548bbd227e58f"
        id = "cfed97fe-b330-5528-8402-08c6ba6af04a"
    strings:
        $header_docf = { D0 CF 11 E0 }
        $s1 = "Excel" fullword

        // 2fb198f6ad33d0f26fb94a1aa159fef7296e0421da68887b8f2548bbd227e58f
        // ' 0018     23 LABEL : Cell Value, String Constant - build-in-name 1 Auto_Open
        // 00002d80:
        // 20 00 00 01 07 00 00 00 00 00 00 00 00 00 00 01 3a 01 00 16 00 07 00

        // f4c01e26eb88b72d38be3d6331fafe03b1ae53fdbff57d610173ed797fa26e73
        // 00003460: 00 00 18 00 17 00 20 00 00 01 07 00 00 00 00 00  ...... .........
        // 00003470: 00 00 00 00 00 01 3a 00 00 3f 02 8d 00 c1 01 08  ......:..?......

        // ccef64586d25ffcb2b28affc1f64319b936175c4911e7841a0e28ee6d6d4a02d
        // ' 0018     23 LABEL : Cell Value, String Constant - build-in-name 1 Auto_Open
        // 00003560: 00 00 00 00 00 18 00 17 00 aa 03 00 01 07 00 00  ................
        // 00003570: 00 00 00 00 00 00 00 00 01 3a 00 00 04 00 65 00  .........:....e.

        $Auto_Open  = {18 00 17 00 20 00 00 01 07 00 00 00 00 00 00 00 00 00 00 01 3a }
        $Auto_Close = {18 00 17 00 20 00 00 01 07 00 00 00 00 00 00 00 00 00 00 02 3a }
        $Auto_Open1 = {18 00 17 00 aa 03 00 01 07 00 00 00 00 00 00 00 00 00 00 01 3a }
        $Auto_Close1= {18 00 17 00 aa 03 00 01 07 00 00 00 00 00 00 00 00 00 00 02 3a }

        // some Excel4 files don't have auto_open names e.g.:
        // b8b80e9458ff0276c9a37f5b46646936a08b83ce050a14efb93350f47aa7d269
        // 079be05edcd5793e1e3596cdb5f511324d0bcaf50eb47119236d3cb8defdfa4c


    condition:
        filesize < 3000KB
        and $header_docf at 0
        and $s1
        and any of ($Auto_*)
}
