// low hanging fruits ;)

rule HKTL_NET_NAME_FakeFileMaker {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/DamonMohammadbagher/FakeFileMaker"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "FakeFileMaker" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_Aggressor {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/k8gege/Aggressor"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "Aggressor" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_pentestscripts {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/c4bbage/pentestscripts"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "pentestscripts" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_WMIPersistence {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/mdsecactivebreach/WMIPersistence"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "WMIPersistence" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_ADCollector {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/dev-2null/ADCollector"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        hash = "5391239f479c26e699b6f3a1d6a0a8aa1a0cf9a8"
        hash = "9dd0f322dd57b906da1e543c44e764954704abae"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "ADCollector" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_MaliciousClickOnceGenerator {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/Mr-Un1k0d3r/MaliciousClickOnceGenerator"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "MaliciousClickOnceGenerator" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_directInjectorPOC {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/badBounty/directInjectorPOC"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "directInjectorPOC" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_AsStrongAsFuck {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/Charterino/AsStrongAsFuck"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "AsStrongAsFuck" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_MagentoScanner {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/soufianetahiri/MagentoScanner"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "MagentoScanner" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_RevengeRAT_Stub_CSsharp {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/NYAN-x-CAT/RevengeRAT-Stub-CSsharp"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "RevengeRAT-Stub-CSsharp" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_SharPyShell {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/antonioCoco/SharPyShell"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "SharPyShell" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_GhostLoader {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/TheWover/GhostLoader"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "GhostLoader" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_DotNetInject {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/dtrizna/DotNetInject"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "DotNetInject" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_ATPMiniDump {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/b4rtik/ATPMiniDump"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "ATPMiniDump" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule SUSP_NET_NAME_ConfuserEx {
    meta:
        description = "Detects ConfuserEx packed file"
        reference = "https://github.com/yck1509/ConfuserEx"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        score = 40
        date = "2021-01-22"
        modified = "2021-01-25"
    strings:
        $name = "ConfuserEx" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_SharpBuster {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/passthehashbrowns/SharpBuster"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "SharpBuster" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_AmsiBypass {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/0xB455/AmsiBypass"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
		hash = "8fa4ba512b34a898c4564a8eac254b6a786d195b"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "AmsiBypass" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_Recon_AD {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/outflanknl/Recon-AD"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "Recon-AD" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_SharpWatchdogs {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/RITRedteam/SharpWatchdogs"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "SharpWatchdogs" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_SharpCat {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/Cn33liz/SharpCat"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "SharpCat" ascii wide fullword
        $compile = "AssemblyTitle" ascii wide fullword
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_aspnetcore_bypassing_authentication {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/jackowild/aspnetcore-bypassing-authentication"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "aspnetcore-bypassing-authentication" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_K8tools {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/k8gege/K8tools"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "K8tools" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_HTTPSBeaconShell {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/limbenjamin/HTTPSBeaconShell"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "HTTPSBeaconShell" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_Ghostpack_CompiledBinaries {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "Ghostpack-CompiledBinaries" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_metasploit_sharp {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/VolatileMindsLLC/metasploit-sharp"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "metasploit-sharp" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_trevorc2 {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/trustedsec/trevorc2"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "trevorc2" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_petaqc2 {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/fozavci/petaqc2"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "petaqc2" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_NativePayload_DNS2 {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/DamonMohammadbagher/NativePayload_DNS2"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "NativePayload_DNS2" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_cve_2017_7269_tool {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/zcgonvh/cve-2017-7269-tool"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "cve-2017-7269-tool" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_AggressiveProxy {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/EncodeGroup/AggressiveProxy"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "AggressiveProxy" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_MSBuildAPICaller {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/rvrsh3ll/MSBuildAPICaller"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "MSBuildAPICaller" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_GrayKeylogger {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/DarkSecDevelopers/GrayKeylogger"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "GrayKeylogger" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_weevely3 {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/epinna/weevely3"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "weevely3" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_FudgeC2 {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/Ziconius/FudgeC2"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "FudgeC2" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_NativePayload_Reverse_tcp {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/DamonMohammadbagher/NativePayload_Reverse_tcp"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "NativePayload_Reverse_tcp" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_SharpHose {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/ustayready/SharpHose"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "SharpHose" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_RAT_NjRat_0_7d_modded_source_code {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/AliBawazeEer/RAT-NjRat-0.7d-modded-source-code"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "RAT-NjRat-0.7d-modded-source-code" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_RdpThief {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/0x09AL/RdpThief"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "RdpThief" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_RunasCs {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/antonioCoco/RunasCs"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "RunasCs" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_NativePayload_IP6DNS {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/DamonMohammadbagher/NativePayload_IP6DNS"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "NativePayload_IP6DNS" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_NativePayload_ARP {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/DamonMohammadbagher/NativePayload_ARP"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "NativePayload_ARP" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_C2Bridge {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/cobbr/C2Bridge"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "C2Bridge" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_Infrastructure_Assessment {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/NyaMeeEain/Infrastructure-Assessment"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "Infrastructure-Assessment" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_shellcodeTester {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/tophertimzen/shellcodeTester"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "shellcodeTester" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_gray_hat_csharp_code {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/brandonprry/gray_hat_csharp_code"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "gray_hat_csharp_code" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_NativePayload_ReverseShell {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/DamonMohammadbagher/NativePayload_ReverseShell"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "NativePayload_ReverseShell" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_DotNetAVBypass {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/mandreko/DotNetAVBypass"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "DotNetAVBypass" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_HexyRunner {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/bao7uo/HexyRunner"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "HexyRunner" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_SharpOffensiveShell {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/darkr4y/SharpOffensiveShell"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "SharpOffensiveShell" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_reconness {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/reconness/reconness"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "reconness" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_tvasion {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/loadenmb/tvasion"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "tvasion" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_ibombshell {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/Telefonica/ibombshell"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "ibombshell" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_RemoteProcessInjection {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/Mr-Un1k0d3r/RemoteProcessInjection"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "RemoteProcessInjection" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_njRAT_0_7d_Stub_CSharp {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/NYAN-x-CAT/njRAT-0.7d-Stub-CSharp"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "njRAT-0.7d-Stub-CSharp" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_CACTUSTORCH {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/mdsecactivebreach/CACTUSTORCH"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "CACTUSTORCH" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_PandaSniper {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/QAX-A-Team/PandaSniper"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "PandaSniper" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_xbapAppWhitelistBypassPOC {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/jpginc/xbapAppWhitelistBypassPOC"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "xbapAppWhitelistBypassPOC" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_StageStrike {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/RedXRanger/StageStrike"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "StageStrike" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

