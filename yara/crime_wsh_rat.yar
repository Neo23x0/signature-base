rule MAL_WshRAT_Dotnet_Packer_Feb21 {
    meta:
        description = "Yara Rule for WSH rat .NET packer of February 2021 "
        author = "Yoroi Malware ZLab"
        date = "2021-03-09"
        reference = "https://yoroi.company/research/threatening-within-budget-how-wsh-rat-is-abused-by-cyber-crooks/"
        id = "62e043fc-7d13-5b91-9fdd-e71d91194da2"
    strings:
        $a1 = { BE DD 60 8C 34 49 9A 54 D2 40 }
        $a2 = { 1D D7 24 22 47 A6 B1 A5 }
        $a3 = { 13 30 03 00 07 00 00 00 01 } 
        $a4 = { 11 02 03 7D 78 00 00 04 2A }
        $a5 = { A8 8A F4 C8 61 2B CA 07 }
        $a6 = { 15 AE 5E AB 5A 20 FE B5 56 B4 61 2B BB 06 2A}
    condition:
        uint16(0) == 0x5A4D and 3 of them
}