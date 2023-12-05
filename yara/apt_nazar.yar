rule APT_Nazar_Svchost_Commands {
    meta:
        description = "Detects Nazar's svchost based on supported commands"
        author = "Itay Cohen"
        date = "2020-04-26"
        reference = "https://www.epicturla.com/blog/the-lost-nazar"
        hash1 = "2fe9b76496a9480273357b6d35c012809bfa3ae8976813a7f5f4959402e3fbb6"
        hash2 = "be624acab7dfe6282bbb32b41b10a98b6189ab3a8d9520e7447214a7e5c27728"
        id = "3e02381d-de03-50c8-8bde-2974ee96b7c1"
    strings:
        $str1 = { 33 31 34 00 36 36 36 00 33 31 33 00 }
        $str2 = { 33 31 32 00 33 31 35 00 35 35 35 00 }
        $str3 = { 39 39 39 00 35 39 39 00 34 39 39 00 }
        $str4 = { 32 30 39 00 32 30 31 00 32 30 30 00 }
        $str5 = { 31 39 39 00 31 31 39 00 31 38 39 00 31 33 39 00 33 31 31 00 }
    condition:
        4 of them
}

rule APT_Nazar_Component_Guids {
    meta:
        description = "Detects Nazar Components by COM Objects' GUID"
        author = "Itay Cohen"
        date = "2020-04-27"
        reference = "https://www.epicturla.com/blog/the-lost-nazar"
        hash1 = "1110c3e34b6bbaadc5082fabbdd69f492f3b1480724b879a3df0035ff487fd6f"
        hash2 = "1afe00b54856628d760b711534779da16c69f542ddc1bb835816aa92ed556390"
        hash3 = "2caedd0b2ea45761332a530327f74ca5b1a71301270d1e2e670b7fa34b6f338e"
        hash4 = "2fe9b76496a9480273357b6d35c012809bfa3ae8976813a7f5f4959402e3fbb6"
        hash5 = "460eba344823766fe7c8f13b647b4d5d979ce4041dd5cb4a6d538783d96b2ef8"
        hash6 = "4d0ab3951df93589a874192569cac88f7107f595600e274f52e2b75f68593bca"
        hash7 = "75e4d73252c753cd8e177820eb261cd72fecd7360cc8ec3feeab7bd129c01ff6"
        hash8 = "8fb9a22b20a338d90c7ceb9424d079a61ca7ccb7f78ffb7d74d2f403ae9fbeec"
        hash9 = "967ac245e8429e3b725463a5c4c42fbdf98385ee6f25254e48b9492df21f2d0b"
        hash10 = "be624acab7dfe6282bbb32b41b10a98b6189ab3a8d9520e7447214a7e5c27728"
        hash11 = "d34a996826ea5a028f5b4713c797247913f036ca0063cc4c18d8b04736fa0b65"
        hash12 = "d9801b4da1dbc5264e83029abb93e800d3c9971c650ecc2df5f85bcc10c7bd61"
        hash13 = "eb705459c2b37fba5747c73ce4870497aa1d4de22c97aaea4af38cdc899b51d3"
        id = "1bdc0b54-4903-559d-9037-450470fc7ef7"
    strings:
        $guid1_godown = { 98 B3 E5 F6 DF E3 6B 49 A2 AD C2 0F EA 30 DB FE } // Godown.dll IID
        $guid2_godown = { 31 4B CB DB B8 21 0F 4A BC 69 0C 3C E3 B6 6D 00 } // Godown.dll CLSID
        $guid3_godown = { AF 94 4E B6 6B D5 B4 48 B1 78 AF 07 23 E7 2A B5 } // probably Godown
        $guid4_filesystem = { 79 27 AB 37 34 F2 9D 4D B3 FB 59 A3 FA CB 8D 60 } // Filesystem.dll CLSID
        $guid6_filesystem = { 2D A1 2B 77 62 8A D3 4D B3 E8 92 DA 70 2E 6F 3D } // Filesystem.dll TypeLib IID
        $guid5_filesystem = { AB D3 13 CF 1C 6A E8 4A A3 74 DE D5 15 5D 6A 88 } // Filesystem.dll 
    condition:
        any of them
}
