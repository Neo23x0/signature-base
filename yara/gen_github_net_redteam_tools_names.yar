// low hanging fruits ;)

rule HKTL_NET_NAME_FakeFileMaker {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/DamonMohammadbagher/FakeFileMaker"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "FakeFileMaker" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_WMIPersistence {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/mdsecactivebreach/WMIPersistence"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "WMIPersistence" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

/*
rule HKTL_NET_NAME_ADCollector {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/dev-2null/ADCollector"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        hash = "5391239f479c26e699b6f3a1d6a0a8aa1a0cf9a8"
        hash = "9dd0f322dd57b906da1e543c44e764954704abae"
        author = "Arnim Rupp"
        date = "2021-01-22"
        modified = "2022-09-15"
    strings:
        $s_name = "ADCollector" ascii wide
        $s_compile = "AssemblyTitle" ascii wide

        $fp1 = "Symantec Threat Defense" wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of ($s*)
        and not 1 of ($fp*)
}
*/

rule HKTL_NET_AdCollector_Sep22_1 {
   meta:
      description = "Detects ADCollector Tool - a lightweight tool to quickly extract valuable information from the Active Directory environment for both attacking and defending"
      author = "Florian Roth"
      reference = "https://github.com/dev-2null/ADCollector"
      date = "2022-09-15"
      score = 75
      hash1 = "241390219a0a773463601ca68b77af97453c20af00a66492a7a78c04d481d338"
      hash2 = "cc086eb7316e68661e3d547b414890d5029c5cc460134d8b628f4b0be7f27fb3"
   strings:
      $x1 = "ADCollector.exe --SPNs --Term key --Acls 'CN=Domain Admins,CN=Users,DC=lab,DC=local'" wide fullword
      $s1 = "ADCollector.exe" wide fullword
      $s2 = "ENCRYPTED_TEXT_PASSWORD_ALLOWED" ascii fullword
      $s3 = "\\Policies\\{31B2F340-016D-11D2-945F-00C04FB984F9}\\MACHINE\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf" wide
      $s4 = "[-] Password Does Not Expire Accounts:" wide
      $s5 = "  * runAs:       {0}" wide fullword
   condition:
      uint16(0) == 0x5a4d and
      filesize < 300KB and ( 1 of ($x*) or 3 of them )
}

rule HKTL_NET_NAME_MaliciousClickOnceGenerator {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/Mr-Un1k0d3r/MaliciousClickOnceGenerator"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
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
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
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
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
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
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
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
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
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
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
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
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
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
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp"
        date = "2021-01-22"
        modified = "2022-06-28"
    strings:
        $name = "DotNetInject" ascii wide
        $compile = "AssemblyTitle" ascii wide

        $fp1 = "GetDotNetInjector" ascii /* MS Txt2AI 489044cadaa0175e36d286fcbe5720fd56b6a0c063beac452b2316c2714332b0 */
        $fp2 = "JetBrains.TeamCity.Injector." wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550)
        and filesize < 20MB
        and $name and $compile
        and not 1 of ($fp*)
}

rule HKTL_NET_NAME_ATPMiniDump {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/b4rtik/ATPMiniDump"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
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
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
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
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
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
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
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
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
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
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
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
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "SharpCat" ascii wide fullword
        $compile = "AssemblyTitle" ascii wide fullword
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_K8tools {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/k8gege/K8tools"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
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
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
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
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
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
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
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
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "trevorc2" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_NativePayload_DNS2 {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/DamonMohammadbagher/NativePayload_DNS2"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "NativePayload_DNS2" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_AggressiveProxy {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/EncodeGroup/AggressiveProxy"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
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
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
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
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
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
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
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
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
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
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
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
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
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
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
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
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
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
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
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
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
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
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
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
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
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
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
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
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
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
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
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
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
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
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
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
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
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
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
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
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
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
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
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
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
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
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "RemoteProcessInjection" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_CACTUSTORCH {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/mdsecactivebreach/CACTUSTORCH"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
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
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
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
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
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
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "StageStrike" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

