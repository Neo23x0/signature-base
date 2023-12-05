
/*
https://twitter.com/VK_Intel/status/1247058432223477760
*/

import "pe"

rule crime_win32_dridex_socks5_mod {
    meta:
        description = "Detects Dridex socks5 module"
        author = "@VK_Intel"
        date = "2020-04-06"
        reference = "https://twitter.com/VK_Intel/status/1247058432223477760"
        id = "cee256b1-ad80-55dd-bbd3-0d3f7bc49664"
    strings:
        $s0 = "socks5_2_x32.dll"
        $s1 = "socks5_2_x64.dll"
    condition:
        any of ($s*) and pe.exports("start")
}

rule crime_win32_hvnc_banker_gen {
    meta:
        description = "Detects malware banker hidden VNC"
        author = "@VK_Intel"
        reference = "https://twitter.com/VK_Intel/status/1247058432223477760"
        date = "2020-04-06"
        id = "5e13f4a9-2231-524f-82b2-fbc6d6a43b6f"
    condition:
        pe.exports("VncStartServer") and pe.exports("VncStopServer")
}