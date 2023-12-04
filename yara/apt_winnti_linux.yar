rule APT_MAL_WinntiLinux_Dropper_AzazelFork_May19 : azazel_fork {
    meta:
        description = "Detection of Linux variant of Winnti"
        author = "Silas Cutler (havex [@] chronicle.security), Chronicle Security"
        version = "1.0"
        date = "2019-05-15"
        TLP = "White"
        sha256 = "4741c2884d1ca3a40dadd3f3f61cb95a59b11f99a0f980dbadc663b85eb77a2a"
    strings:
        $config_decr = { 48 89 45 F0 C7 45 EC 08 01 00 00 C7 45 FC 28 00 00 00 EB 31 8B 45 FC 48 63 D0 48 8B 45 F0 48 01 C2 8B 45 FC 48 63 C8 48 8B 45 F0 48 01 C8 0F B6 00 89 C1 8B 45 F8 89 C6 8B 45 FC 01 F0 31 C8 88 02 83 45 FC 01 }
        $export1 = "our_sockets"
        $export2 = "get_our_pids"
    condition:
        uint16(0) == 0x457f and all of them
}

rule APT_MAL_WinntiLinux_Main_AzazelFork_May19 {
    meta:
        description = "Detection of Linux variant of Winnti"
        author = "Silas Cutler (havex [@] chronicle.security), Chronicle Security"
        version = "1.0"
        date = "2019-05-15"
        TLP = "White"
        sha256 = "ae9d6848f33644795a0cc3928a76ea194b99da3c10f802db22034d9f695a0c23"
    strings:
        $uuid_lookup = "/usr/sbin/dmidecode  | grep -i 'UUID' |cut -d' ' -f2 2>/dev/null"
        $dbg_msg = "[advNetSrv] can not create a PF_INET socket"
        $rtti_name1 = "CNetBase"
        $rtti_name2 = "CMyEngineNetEvent"
        $rtti_name3 = "CBufferCache"
        $rtti_name4 = "CSocks5Base"
        $rtti_name5 = "CDataEngine"
        $rtti_name6 = "CSocks5Mgr"
        $rtti_name7 = "CRemoteMsg"
    condition:
        uint16(0) == 0x457f and ( ($dbg_msg and 1 of ($rtti*)) or (5 of ($rtti*)) or ($uuid_lookup and 2 of ($rtti*)) )
}
