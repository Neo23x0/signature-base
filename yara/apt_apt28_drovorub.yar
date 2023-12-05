 rule APT_APT28_generic_poco_openssl {
    meta:
        description = "Rule to detect statically linked POCO and OpenSSL libraries (COULD be Drovorub related and should be further investigated)"
        author = "NSA / FBI"
        reference = "https://www.nsa.gov/news-features/press-room/Article/2311407/nsa-and-fbi-expose-russian-previously-undisclosed-malware-drovorub-in-cybersecu/"
        date = "2020-08-13"
        score = 50
    strings:
        $mw1 = { 89 F1 48 89 FE 48 89 D7 48 F7 C6 FF FF FF FF 0F 84 6B 02 00 00 48 F7 C7
                 FF FF FF FF 0F 84 5E 02 00 00 48 8D 2D }

        $mw2 = { 41 54 49 89 D4 55 53 F6 47 19 04 48 8B 2E 75 08 31 DB F6 45 00 03 75 } 
        $mw3 = { 85C0BA15000000750989D05BC30F1F44 0000BE }
          
        $mw4 = { 53 8A 47 08 3C 06 74 21 84 C0 74 1D 3C 07 74 20 B9 ?? ?? ?? ?? BA FD 03 
                 00 00 BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 E8 06 3C 01 77 2B 48 8B 1F 48 8B 73 
                 10 48 89 DF E8 ?? ?? ?? ?? 48 8D 43 08 48 C7 43 10 00 00 00 00 48 C7 43 28 00 00 00 00 48 
                 89 43 18 48 89 43 20 5B C3 }
    condition:
        all of them
}

rule APT_APT28_drovorub_library_and_unique_strings {
    meta:
        description = "Rule to detect Drovorub-server, Drovorub-agent, and Drovorub-client"
        author = "NSA / FBI"
        reference = "https://www.nsa.gov/news-features/press-room/Article/2311407/nsa-and-fbi-expose-russian-previously-undisclosed-malware-drovorub-in-cybersecu/"
        date = "2020-08-13"
        score = 75
        id = "8e010356-09c7-5897-9cbe-051cd0800502"
    strings:
        $s1 = "Poco" ascii wide
        $s2 = "Json" ascii wide
        $s3 = "OpenSSL" ascii wide 

        $a1 = "clientid" ascii wide 
        $a2 = "-----BEGIN" ascii wide 
        $a3 = "-----END" ascii wide 
        $a4 = "tunnel" ascii wide
    condition:
        (filesize > 1MB and filesize < 10MB and (uint32(0) == 0x464c457f)) and (#s1 > 20 and #s2 > 15 and #s3 > 15 and all of ($a*)) 
}

rule APT_APT28_drovorub_unique_network_comms_strings {
    meta:
        description = "Rule to detect Drovorub-server, Drovorub-agent, or Drovorub-client based"
        author = "NSA / FBI"
        reference = "https://www.nsa.gov/news-features/press-room/Article/2311407/nsa-and-fbi-expose-russian-previously-undisclosed-malware-drovorub-in-cybersecu/"
        date = "2020-08-13"
        score = 75
        id = "c6a930e8-c1c0-5d96-9051-7516df848b45"
    strings:
        $s_01 = "action" wide ascii
        $s_02 = "auth.commit" wide ascii
        $s_03 = "auth.hello" wide ascii
        $s_04 = "auth.login" wide ascii
        $s_05 = "auth.pending" wide ascii
        $s_06 = "client_id" wide ascii
        $s_07 = "client_login" wide ascii
        $s_08 = "client_pass" wide ascii
        $s_09 = "clientid" wide ascii
        $s_10 = "clientkey_base64" wide ascii 
        $s_11 = "file_list_request" wide ascii 
        $s_12 = "module_list_request" wide ascii 
        $s_13 = "monitor" wide ascii
        $s_14 = "net_list_request" wide ascii 
        $s_15 = "server finished" wide ascii 
        $s_16 = "serverid" wide ascii
        $s_17 = "tunnel" wide ascii
     condition:
        all of them
}
/* FPs
48505c956c005576b1292495102a5a4d37a830dc936ce85204d2783e13082c1f

rule APT_APT28_drovorub_kernel_module_unique_strings {
    meta:
        description = "Rule detects the Drovorub-kernel module based on unique strings"
        author = "NSA / FBI"
        reference = "https://www.nsa.gov/news-features/press-room/Article/2311407/nsa-and-fbi-expose-russian-previously-undisclosed-malware-drovorub-in-cybersecu/"
        date = "2020-08-13"
        score = 75
    strings:
        $s_01 = "/proc" wide ascii
        $s_02 = "/proc/net/packet" wide ascii 
        $s_03 = "/proc/net/raw" wide ascii 
        $s_04 = "/proc/net/tcp" wide ascii 
        $s_05 = "/proc/net/tcp6" wide ascii 
        $s_06 = "/proc/net/udp" wide ascii 
        $s_07 = "/proc/net/udp6" wide ascii 
        $s_08 = "cs02" wide ascii
        $s_09 = "do_fork" wide ascii
        $s_10 = "es01" wide ascii
        $s_11 = "g001" wide ascii
        $s_12 = "g002" wide ascii
        $s_13 = "i001" wide ascii
        $s_14 = "i002" wide ascii
        $s_15 = "i003" wide ascii
        $s_16 = "i004" wide ascii
        $s_17 = "module" wide ascii
        $s_18 = "sc!^2a" wide ascii
        $s_19 = "sysfs" wide ascii
        $s_20 = "tr01" wide ascii
        $s_21 = "tr02" wide ascii
        $s_22 = "tr03" wide ascii
        $s_23 = "tr04" wide ascii
        $s_24 = "tr05" wide ascii
        $s_25 = "tr06" wide ascii
        $s_26 = "tr07" wide ascii
        $s_27 = "tr08" wide ascii
        $s_28 = "tr09" wide ascii
    condition:
        all of them
}
*/