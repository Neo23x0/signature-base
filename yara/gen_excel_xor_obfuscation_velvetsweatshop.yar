/* Slightly modified by Florian Roth */

rule gen_excel_xor_obfuscation_velvetsweatshop {
    meta:
        description = "Detects XOR encryption (c. 2003) in Excel file formats"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "@BouncyHat"
        contributed_by = "@JohnLaTwc"
        date = "2020-10-09"
        reference = "https://twitter.com/JohnLaTwC/status/1314602421977452544"
        reference0 = "https://twitter.com/BouncyHat/status/1308896366782042113"
        hash1 = "da1999c23ee2dae02a169fd2208b9766cb8f046a895f5f52bed45615eea94da0"
        hash2 = "14a32b8a504db3775e793be59d7bd5b584ea732c3ca060b2398137efbfd18d5a"
        hash3 = "dd3e89e7bde993f6f1b280f2bf933a5cc2797f4e8736aed4010aaf46e9854f23"
        hash4 = "4e40253b382b20e273edf82362f1c89e916f7ab8d3c518818a76cb6127d4e7c2"
        id = "8a16105c-4f43-5a35-941c-6ee9593b039c"
    strings:
        $olemarker = { D0 CF 11 E0 A1 B1 1A E1 00 00 00 }
        $FilePass_XOR_Obfuscation_VelvetSweatshop = { 2F 00 06 00 00 00 59 B3 0A 9A }
    condition:
        uint32(0) == 0xe011cfd0 and 
        filesize < 400KB and 
        $olemarker at 0 and
        $FilePass_XOR_Obfuscation_VelvetSweatshop
}
