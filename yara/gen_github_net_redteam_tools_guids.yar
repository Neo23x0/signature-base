// These rules have room for false positives if e.g. a dual use tool is contained within a hack tool repo.
// Could also be done with https://yara.readthedocs.io/en/stable/modules/dotnet.html#c.typelib but that needs an extra module.

import "pe"

rule HKTL_NET_GUID_CSharpSetThreadContext {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/djhohnstein/CSharpSetThreadContext"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "a1e28c8c-b3bd-44de-85b9-8aa7c18a714d" ascii wide
        $typelibguid0up = "A1E28C8C-B3BD-44DE-85B9-8AA7C18A714D" ascii wide
        $typelibguid1lo = "87c5970e-0c77-4182-afe2-3fe96f785ebb" ascii wide
        $typelibguid1up = "87C5970E-0C77-4182-AFE2-3FE96F785EBB" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DLL_Injection {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/ihack4falafel/DLL-Injection"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "3d7e1433-f81a-428a-934f-7cc7fcf1149d" ascii wide
        $typelibguid0up = "3D7E1433-F81A-428A-934F-7CC7FCF1149D" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_LimeUSB_Csharp {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/LimeUSB-Csharp"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "94ea43ab-7878-4048-a64e-2b21b3b4366d" ascii wide
        $typelibguid0up = "94EA43AB-7878-4048-A64E-2B21B3B4366D" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Ladon {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/k8gege/Ladon"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "c335405f-5df2-4c7d-9b53-d65adfbed412" ascii wide
        $typelibguid0up = "C335405F-5DF2-4C7D-9B53-D65ADFBED412" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_WhiteListEvasion {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/khr0x40sh/WhiteListEvasion"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "858386df-4656-4a1e-94b7-47f6aa555658" ascii wide
        $typelibguid0up = "858386DF-4656-4A1E-94B7-47F6AA555658" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Lime_Downloader {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/Lime-Downloader"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "ec7afd4c-fbc4-47c1-99aa-6ebb05094173" ascii wide
        $typelibguid0up = "EC7AFD4C-FBC4-47C1-99AA-6EBB05094173" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DarkEye {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/K1ngSoul/DarkEye"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "0bdb9c65-14ed-4205-ab0c-ea2151866a7f" ascii wide
        $typelibguid0up = "0BDB9C65-14ED-4205-AB0C-EA2151866A7F" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpKatz {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/b4rtik/SharpKatz"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "8568b4c1-2940-4f6c-bf4e-4383ef268be9" ascii wide
        $typelibguid0up = "8568B4C1-2940-4F6C-BF4E-4383EF268BE9" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_ExternalC2 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/ryhanson/ExternalC2"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "7266acbb-b10d-4873-9b99-12d2043b1d4e" ascii wide
        $typelibguid0up = "7266ACBB-B10D-4873-9B99-12D2043B1D4E" ascii wide
        $typelibguid1lo = "5d9515d0-df67-40ed-a6b2-6619620ef0ef" ascii wide
        $typelibguid1up = "5D9515D0-DF67-40ED-A6B2-6619620EF0EF" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Povlsomware {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/povlteksttv/Povlsomware"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "fe0d5aa7-538f-42f6-9ece-b141560f7781" ascii wide
        $typelibguid0up = "FE0D5AA7-538F-42F6-9ECE-B141560F7781" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_RunShellcode {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/zerosum0x0/RunShellcode"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "a3ec18a3-674c-4131-a7f5-acbed034b819" ascii wide
        $typelibguid0up = "A3EC18A3-674C-4131-A7F5-ACBED034B819" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpLoginPrompt {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/shantanu561993/SharpLoginPrompt"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "c12e69cd-78a0-4960-af7e-88cbd794af97" ascii wide
        $typelibguid0up = "C12E69CD-78A0-4960-AF7E-88CBD794AF97" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Adamantium_Thief {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/LimerBoy/Adamantium-Thief"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "e6104bc9-fea9-4ee9-b919-28156c1f2ede" ascii wide
        $typelibguid0up = "E6104BC9-FEA9-4EE9-B919-28156C1F2EDE" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_PSByPassCLM {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/padovah4ck/PSByPassCLM"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "46034038-0113-4d75-81fd-eb3b483f2662" ascii wide
        $typelibguid0up = "46034038-0113-4D75-81FD-EB3B483F2662" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_physmem2profit {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/FSecureLABS/physmem2profit"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "814708c9-2320-42d2-a45f-31e42da06a94" ascii wide
        $typelibguid0up = "814708C9-2320-42D2-A45F-31E42DA06A94" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_NoAmci {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/med0x2e/NoAmci"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "352e80ec-72a5-4aa6-aabe-4f9a20393e8e" ascii wide
        $typelibguid0up = "352E80EC-72A5-4AA6-AABE-4F9A20393E8E" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpBlock {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/CCob/SharpBlock"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "3cf25e04-27e4-4d19-945e-dadc37c81152" ascii wide
        $typelibguid0up = "3CF25E04-27E4-4D19-945E-DADC37C81152" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_nopowershell {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/bitsadmin/nopowershell"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "555ad0ac-1fdb-4016-8257-170a74cb2f55" ascii wide
        $typelibguid0up = "555AD0AC-1FDB-4016-8257-170A74CB2F55" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_LimeLogger {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/LimeLogger"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "068d14ef-f0a1-4f9d-8e27-58b4317830c6" ascii wide
        $typelibguid0up = "068D14EF-F0A1-4F9D-8E27-58B4317830C6" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_AggressorScripts {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/harleyQu1nn/AggressorScripts"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "afd1ff09-2632-4087-a30c-43591f32e4e8" ascii wide
        $typelibguid0up = "AFD1FF09-2632-4087-A30C-43591F32E4E8" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Gopher {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/EncodeGroup/Gopher"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "b5152683-2514-49ce-9aca-1bc43df1e234" ascii wide
        $typelibguid0up = "B5152683-2514-49CE-9ACA-1BC43DF1E234" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_AVIator {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Ch0pin/AVIator"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "4885a4a3-4dfa-486c-b378-ae94a221661a" ascii wide
        $typelibguid0up = "4885A4A3-4DFA-486C-B378-AE94A221661A" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_njCrypter {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/0xPh0enix/njCrypter"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "8a87b003-4b43-467b-a509-0c8be05bf5a5" ascii wide
        $typelibguid0up = "8A87B003-4B43-467B-A509-0C8BE05BF5A5" ascii wide
        $typelibguid1lo = "80b13bff-24a5-4193-8e51-c62a414060ec" ascii wide
        $typelibguid1up = "80B13BFF-24A5-4193-8E51-C62A414060EC" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpMiniDump {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/b4rtik/SharpMiniDump"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "6ffccf81-6c3c-4d3f-b15f-35a86d0b497f" ascii wide
        $typelibguid0up = "6FFCCF81-6C3C-4D3F-B15F-35A86D0B497F" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_CinaRAT {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/wearelegal/CinaRAT"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "8586f5b1-2ef4-4f35-bd45-c6206fdc0ebc" ascii wide
        $typelibguid0up = "8586F5B1-2EF4-4F35-BD45-C6206FDC0EBC" ascii wide
        $typelibguid1lo = "fe184ab5-f153-4179-9bf5-50523987cf1f" ascii wide
        $typelibguid1up = "FE184AB5-F153-4179-9BF5-50523987CF1F" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_ToxicEye {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/LimerBoy/ToxicEye"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "1bcfe538-14f4-4beb-9a3f-3f9472794902" ascii wide
        $typelibguid0up = "1BCFE538-14F4-4BEB-9A3F-3F9472794902" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Disable_Windows_Defender {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/Disable-Windows-Defender"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "501e3fdc-575d-492e-90bc-703fb6280ee2" ascii wide
        $typelibguid0up = "501E3FDC-575D-492E-90BC-703FB6280EE2" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DInvoke_PoC {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/dtrizna/DInvoke_PoC"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "5a869ab2-291a-49e6-a1b7-0d0f051bef0e" ascii wide
        $typelibguid0up = "5A869AB2-291A-49E6-A1B7-0D0F051BEF0E" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_ReverseShell {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/chango77747/ReverseShell"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "980109e4-c988-47f9-b2b3-88d63fababdc" ascii wide
        $typelibguid0up = "980109E4-C988-47F9-B2B3-88D63FABABDC" ascii wide
        $typelibguid1lo = "8abe8da1-457e-4933-a40d-0958c8925985" ascii wide
        $typelibguid1up = "8ABE8DA1-457E-4933-A40D-0958C8925985" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpC2 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/SharpC2/SharpC2"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "62b9ee4f-1436-4098-9bc1-dd61b42d8b81" ascii wide
        $typelibguid0up = "62B9EE4F-1436-4098-9BC1-DD61B42D8B81" ascii wide
        $typelibguid1lo = "d2f17a91-eb2d-4373-90bf-a26e46c68f76" ascii wide
        $typelibguid1up = "D2F17A91-EB2D-4373-90BF-A26E46C68F76" ascii wide
        $typelibguid2lo = "a9db9fcc-7502-42cd-81ec-3cd66f511346" ascii wide
        $typelibguid2up = "A9DB9FCC-7502-42CD-81EC-3CD66F511346" ascii wide
        $typelibguid3lo = "ca6cc2ee-75fd-4f00-b687-917fa55a4fae" ascii wide
        $typelibguid3up = "CA6CC2EE-75FD-4F00-B687-917FA55A4FAE" ascii wide
        $typelibguid4lo = "a1167b68-446b-4c0c-a8b8-2a7278b67511" ascii wide
        $typelibguid4up = "A1167B68-446B-4C0C-A8B8-2A7278B67511" ascii wide
        $typelibguid5lo = "4d8c2a88-1da5-4abe-8995-6606473d7cf1" ascii wide
        $typelibguid5up = "4D8C2A88-1DA5-4ABE-8995-6606473D7CF1" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SneakyExec {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/HackingThings/SneakyExec"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "612590aa-af68-41e6-8ce2-e831f7fe4ccc" ascii wide
        $typelibguid0up = "612590AA-AF68-41E6-8CE2-E831F7FE4CCC" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_UrbanBishopLocal {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/slyd0g/UrbanBishopLocal"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "88b8515e-a0e8-4208-a9a0-34b01d7ba533" ascii wide
        $typelibguid0up = "88B8515E-A0E8-4208-A9A0-34B01D7BA533" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpShell {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/cobbr/SharpShell"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "bdba47c5-e823-4404-91d0-7f6561279525" ascii wide
        $typelibguid0up = "BDBA47C5-E823-4404-91D0-7F6561279525" ascii wide
        $typelibguid1lo = "b84548dc-d926-4b39-8293-fa0bdef34d49" ascii wide
        $typelibguid1up = "B84548DC-D926-4B39-8293-FA0BDEF34D49" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_EvilWMIProvider {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/sunnyc7/EvilWMIProvider"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "a4020626-f1ec-4012-8b17-a2c8a0204a4b" ascii wide
        $typelibguid0up = "A4020626-F1EC-4012-8B17-A2C8A0204A4B" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_GadgetToJScript {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/med0x2e/GadgetToJScript"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "af9c62a1-f8d2-4be0-b019-0a7873e81ea9" ascii wide
        $typelibguid0up = "AF9C62A1-F8D2-4BE0-B019-0A7873E81EA9" ascii wide
        $typelibguid1lo = "b2b3adb0-1669-4b94-86cb-6dd682ddbea3" ascii wide
        $typelibguid1up = "B2B3ADB0-1669-4B94-86CB-6DD682DDBEA3" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_AzureCLI_Extractor {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/0x09AL/AzureCLI-Extractor"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "a73cad74-f8d6-43e6-9a4c-b87832cdeace" ascii wide
        $typelibguid0up = "A73CAD74-F8D6-43E6-9A4C-B87832CDEACE" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_UAC_Escaper {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/UAC-Escaper"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "95359279-5cfa-46f6-b400-e80542a7336a" ascii wide
        $typelibguid0up = "95359279-5CFA-46F6-B400-E80542A7336A" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_HTTPSBeaconShell {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/limbenjamin/HTTPSBeaconShell"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "aca853dc-9e74-4175-8170-e85372d5f2a9" ascii wide
        $typelibguid0up = "ACA853DC-9E74-4175-8170-E85372D5F2A9" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_AmsiScanBufferBypass {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/rasta-mouse/AmsiScanBufferBypass"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "431ef2d9-5cca-41d3-87ba-c7f5e4582dd2" ascii wide
        $typelibguid0up = "431EF2D9-5CCA-41D3-87BA-C7F5E4582DD2" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_ShellcodeLoader {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Hzllaga/ShellcodeLoader"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "a48fe0e1-30de-46a6-985a-3f2de3c8ac96" ascii wide
        $typelibguid0up = "A48FE0E1-30DE-46A6-985A-3F2DE3C8AC96" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_KeystrokeAPI {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/fabriciorissetto/KeystrokeAPI"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "f6fec17e-e22d-4149-a8a8-9f64c3c905d3" ascii wide
        $typelibguid0up = "F6FEC17E-E22D-4149-A8A8-9F64C3C905D3" ascii wide
        $typelibguid1lo = "b7aa4e23-39a4-49d5-859a-083c789bfea2" ascii wide
        $typelibguid1up = "B7AA4E23-39A4-49D5-859A-083C789BFEA2" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_ShellCodeRunner {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/antman1p/ShellCodeRunner"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "634874b7-bf85-400c-82f0-7f3b4659549a" ascii wide
        $typelibguid0up = "634874B7-BF85-400C-82F0-7F3B4659549A" ascii wide
        $typelibguid1lo = "2f9c3053-077f-45f2-b207-87c3c7b8f054" ascii wide
        $typelibguid1up = "2F9C3053-077F-45F2-B207-87C3C7B8F054" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_OffensiveCSharp {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/diljith369/OffensiveCSharp"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "6c3fbc65-b673-40f0-b1ac-20636df01a85" ascii wide
        $typelibguid0up = "6C3FBC65-B673-40F0-B1AC-20636DF01A85" ascii wide
        $typelibguid1lo = "2bad9d69-ada9-4f1e-b838-9567e1503e93" ascii wide
        $typelibguid1up = "2BAD9D69-ADA9-4F1E-B838-9567E1503E93" ascii wide
        $typelibguid2lo = "512015de-a70f-4887-8eae-e500fd2898ab" ascii wide
        $typelibguid2up = "512015DE-A70F-4887-8EAE-E500FD2898AB" ascii wide
        $typelibguid3lo = "1ee4188c-24ac-4478-b892-36b1029a13b3" ascii wide
        $typelibguid3up = "1EE4188C-24AC-4478-B892-36B1029A13B3" ascii wide
        $typelibguid4lo = "5c6b7361-f9ab-41dc-bfa0-ed5d4b0032a8" ascii wide
        $typelibguid4up = "5C6B7361-F9AB-41DC-BFA0-ED5D4B0032A8" ascii wide
        $typelibguid5lo = "048a6559-d4d3-4ad8-af0f-b7f72b212e90" ascii wide
        $typelibguid5up = "048A6559-D4D3-4AD8-AF0F-B7F72B212E90" ascii wide
        $typelibguid6lo = "3412fbe9-19d3-41d8-9ad2-6461fcb394dc" ascii wide
        $typelibguid6up = "3412FBE9-19D3-41D8-9AD2-6461FCB394DC" ascii wide
        $typelibguid7lo = "9ea4e0dc-9723-4d93-85bb-a4fcab0ad210" ascii wide
        $typelibguid7up = "9EA4E0DC-9723-4D93-85BB-A4FCAB0AD210" ascii wide
        $typelibguid8lo = "6d2b239c-ba1e-43ec-8334-d67d52b77181" ascii wide
        $typelibguid8up = "6D2B239C-BA1E-43EC-8334-D67D52B77181" ascii wide
        $typelibguid9lo = "42e8b9e1-0cf4-46ae-b573-9d0563e41238" ascii wide
        $typelibguid9up = "42E8B9E1-0CF4-46AE-B573-9D0563E41238" ascii wide
        $typelibguid10lo = "0d15e0e3-bcfd-4a85-adcd-0e751dab4dd6" ascii wide
        $typelibguid10up = "0D15E0E3-BCFD-4A85-ADCD-0E751DAB4DD6" ascii wide
        $typelibguid11lo = "644dfd1a-fda5-4948-83c2-8d3b5eda143a" ascii wide
        $typelibguid11up = "644DFD1A-FDA5-4948-83C2-8D3B5EDA143A" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SHAPESHIFTER {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/matterpreter/SHAPESHIFTER"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "a3ddfcaa-66e7-44fd-ad48-9d80d1651228" ascii wide
        $typelibguid0up = "A3DDFCAA-66E7-44FD-AD48-9D80D1651228" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Evasor {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/cyberark/Evasor"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "1c8849ef-ad09-4727-bf81-1f777bd1aef8" ascii wide
        $typelibguid0up = "1C8849EF-AD09-4727-BF81-1F777BD1AEF8" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Stracciatella {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/mgeeky/Stracciatella"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "eaafa0ac-e464-4fc4-9713-48aa9a6716fb" ascii wide
        $typelibguid0up = "EAAFA0AC-E464-4FC4-9713-48AA9A6716FB" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_logger {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/xxczaki/logger"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "9e92a883-3c8b-4572-a73e-bb3e61cfdc16" ascii wide
        $typelibguid0up = "9E92A883-3C8B-4572-A73E-BB3E61CFDC16" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Internal_Monologue {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/eladshamir/Internal-Monologue"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "0c0333db-8f00-4b68-b1db-18a9cacc1486" ascii wide
        $typelibguid0up = "0C0333DB-8F00-4B68-B1DB-18A9CACC1486" ascii wide
        $typelibguid1lo = "84701ace-c584-4886-a3cf-76c57f6e801a" ascii wide
        $typelibguid1up = "84701ACE-C584-4886-A3CF-76C57F6E801A" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_GRAT2 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/r3nhat/GRAT2"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "5e7fce78-1977-444f-a18e-987d708a2cff" ascii wide
        $typelibguid0up = "5E7FCE78-1977-444F-A18E-987D708A2CFF" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_PowerShdll {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/p3nt4/PowerShdll"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "36ebf9aa-2f37-4f1d-a2f1-f2a45deeaf21" ascii wide
        $typelibguid0up = "36EBF9AA-2F37-4F1D-A2F1-F2A45DEEAF21" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_CsharpAmsiBypass {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/WayneJLee/CsharpAmsiBypass"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "4ab3b95d-373c-4197-8ee3-fe0fa66ca122" ascii wide
        $typelibguid0up = "4AB3B95D-373C-4197-8EE3-FE0FA66CA122" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_HastySeries {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/obscuritylabs/HastySeries"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "8435531d-675c-4270-85bf-60db7653bcf6" ascii wide
        $typelibguid0up = "8435531D-675C-4270-85BF-60DB7653BCF6" ascii wide
        $typelibguid1lo = "47db989f-7e33-4e6b-a4a5-c392b429264b" ascii wide
        $typelibguid1up = "47DB989F-7E33-4E6B-A4A5-C392B429264B" ascii wide
        $typelibguid2lo = "300c7489-a05f-4035-8826-261fa449dd96" ascii wide
        $typelibguid2up = "300C7489-A05F-4035-8826-261FA449DD96" ascii wide
        $typelibguid3lo = "41bf8781-ae04-4d80-b38d-707584bf796b" ascii wide
        $typelibguid3up = "41BF8781-AE04-4D80-B38D-707584BF796B" ascii wide
        $typelibguid4lo = "620ed459-18de-4359-bfb0-6d0c4841b6f6" ascii wide
        $typelibguid4up = "620ED459-18DE-4359-BFB0-6D0C4841B6F6" ascii wide
        $typelibguid5lo = "91e7cdfe-0945-45a7-9eaa-0933afe381f2" ascii wide
        $typelibguid5up = "91E7CDFE-0945-45A7-9EAA-0933AFE381F2" ascii wide
        $typelibguid6lo = "c28e121a-60ca-4c21-af4b-93eb237b882f" ascii wide
        $typelibguid6up = "C28E121A-60CA-4C21-AF4B-93EB237B882F" ascii wide
        $typelibguid7lo = "698fac7a-bff1-4c24-b2c3-173a6aae15bf" ascii wide
        $typelibguid7up = "698FAC7A-BFF1-4C24-B2C3-173A6AAE15BF" ascii wide
        $typelibguid8lo = "63a40d94-5318-42ad-a573-e3a1c1284c57" ascii wide
        $typelibguid8up = "63A40D94-5318-42AD-A573-E3A1C1284C57" ascii wide
        $typelibguid9lo = "56b8311b-04b8-4e57-bb58-d62adc0d2e68" ascii wide
        $typelibguid9up = "56B8311B-04B8-4E57-BB58-D62ADC0D2E68" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DreamProtectorFree {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Paskowsky/DreamProtectorFree"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "f7e8a902-2378-426a-bfa5-6b14c4b40aa3" ascii wide
        $typelibguid0up = "F7E8A902-2378-426A-BFA5-6B14C4B40AA3" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_RedSharp {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/padovah4ck/RedSharp"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "30b2e0cf-34dd-4614-a5ca-6578fb684aea" ascii wide
        $typelibguid0up = "30B2E0CF-34DD-4614-A5CA-6578FB684AEA" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_ESC {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NetSPI/ESC"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "06260ce5-61f4-4b81-ad83-7d01c3b37921" ascii wide
        $typelibguid0up = "06260CE5-61F4-4B81-AD83-7D01C3B37921" ascii wide
        $typelibguid1lo = "87fc7ede-4dae-4f00-ac77-9c40803e8248" ascii wide
        $typelibguid1up = "87FC7EDE-4DAE-4F00-AC77-9C40803E8248" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Csharp_Loader {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/Csharp-Loader"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "5fd7f9fc-0618-4dde-a6a0-9faefe96c8a1" ascii wide
        $typelibguid0up = "5FD7F9FC-0618-4DDE-A6A0-9FAEFE96C8A1" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_bantam {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/gellin/bantam"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "14c79bda-2ce6-424d-bd49-4f8d68630b7b" ascii wide
        $typelibguid0up = "14C79BDA-2CE6-424D-BD49-4F8D68630B7B" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpTask {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/jnqpblc/SharpTask"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "13e90a4d-bf7a-4d5a-9979-8b113e3166be" ascii wide
        $typelibguid0up = "13E90A4D-BF7A-4D5A-9979-8B113E3166BE" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_WindowsPlague {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/RITRedteam/WindowsPlague"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "cdf8b024-70c9-413a-ade3-846a43845e99" ascii wide
        $typelibguid0up = "CDF8B024-70C9-413A-ADE3-846A43845E99" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Misc_CSharp {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/jnqpblc/Misc-CSharp"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "d1421ba3-c60b-42a0-98f9-92ba4e653f3d" ascii wide
        $typelibguid0up = "D1421BA3-C60B-42A0-98F9-92BA4E653F3D" ascii wide
        $typelibguid1lo = "2afac0dd-f46f-4f95-8a93-dc17b4f9a3a1" ascii wide
        $typelibguid1up = "2AFAC0DD-F46F-4F95-8A93-DC17B4F9A3A1" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpSpray {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/jnqpblc/SharpSpray"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "51c6e016-1428-441d-82e9-bb0eb599bbc8" ascii wide
        $typelibguid0up = "51C6E016-1428-441D-82E9-BB0EB599BBC8" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Obfuscator {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/3xpl01tc0d3r/Obfuscator"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "8fe5b811-a2cb-417f-af93-6a3cf6650af1" ascii wide
        $typelibguid0up = "8FE5B811-A2CB-417F-AF93-6A3CF6650AF1" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SafetyKatz {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/GhostPack/SafetyKatz"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "8347e81b-89fc-42a9-b22c-f59a6a572dec" ascii wide
        $typelibguid0up = "8347E81B-89FC-42A9-B22C-F59A6A572DEC" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Dropless_Malware {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/Dropless-Malware"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "23b739f7-2355-491e-a7cd-a8485d39d6d6" ascii wide
        $typelibguid0up = "23B739F7-2355-491E-A7CD-A8485D39D6D6" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_UAC_SilentClean {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/EncodeGroup/UAC-SilentClean"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "948152a4-a4a1-4260-a224-204255bfee72" ascii wide
        $typelibguid0up = "948152A4-A4A1-4260-A224-204255BFEE72" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DesktopGrabber {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/DesktopGrabber"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "e6aa0cd5-9537-47a0-8c85-1fbe284a4380" ascii wide
        $typelibguid0up = "E6AA0CD5-9537-47A0-8C85-1FBE284A4380" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_wsManager {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/guillaC/wsManager"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "9480809e-5472-44f3-b076-dcdf7379e766" ascii wide
        $typelibguid0up = "9480809E-5472-44F3-B076-DCDF7379E766" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_UglyEXe {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/fashionproof/UglyEXe"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "233de44b-4ec1-475d-a7d6-16da48d6fc8d" ascii wide
        $typelibguid0up = "233DE44B-4EC1-475D-A7D6-16DA48D6FC8D" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpDump {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/GhostPack/SharpDump"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "79c9bba3-a0ea-431c-866c-77004802d8a0" ascii wide
        $typelibguid0up = "79C9BBA3-A0EA-431C-866C-77004802D8A0" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_EducationalRAT {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/securesean/EducationalRAT"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "8a18fbcf-8cac-482d-8ab7-08a44f0e278e" ascii wide
        $typelibguid0up = "8A18FBCF-8CAC-482D-8AB7-08A44F0E278E" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Stealth_Kid_RAT {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/ctsecurity/Stealth-Kid-RAT"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "bf43cd33-c259-4711-8a0e-1a5c6c13811d" ascii wide
        $typelibguid0up = "BF43CD33-C259-4711-8A0E-1A5C6C13811D" ascii wide
        $typelibguid1lo = "e5b9df9b-a9e4-4754-8731-efc4e2667d88" ascii wide
        $typelibguid1up = "E5B9DF9B-A9E4-4754-8731-EFC4E2667D88" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpCradle {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/anthemtotheego/SharpCradle"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "f70d2b71-4aae-4b24-9dae-55bc819c78bb" ascii wide
        $typelibguid0up = "F70D2B71-4AAE-4B24-9DAE-55BC819C78BB" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_BypassUAC {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/cnsimo/BypassUAC"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "4e7c140d-bcc4-4b15-8c11-adb4e54cc39a" ascii wide
        $typelibguid0up = "4E7C140D-BCC4-4B15-8C11-ADB4E54CC39A" ascii wide
        $typelibguid1lo = "cec553a7-1370-4bbc-9aae-b2f5dbde32b0" ascii wide
        $typelibguid1up = "CEC553A7-1370-4BBC-9AAE-B2F5DBDE32B0" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_hanzoInjection {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/P0cL4bs/hanzoInjection"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "32e22e25-b033-4d98-a0b3-3d2c3850f06c" ascii wide
        $typelibguid0up = "32E22E25-B033-4D98-A0B3-3D2C3850F06C" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_clr_meterpreter {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/OJ/clr-meterpreter"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "6840b249-1a0e-433b-be79-a927696ea4b3" ascii wide
        $typelibguid0up = "6840B249-1A0E-433B-BE79-A927696EA4B3" ascii wide
        $typelibguid1lo = "67c09d37-ac18-4f15-8dd6-b5da721c0df6" ascii wide
        $typelibguid1up = "67C09D37-AC18-4F15-8DD6-B5DA721C0DF6" ascii wide
        $typelibguid2lo = "e05d0deb-d724-4448-8c4c-53d6a8e670f3" ascii wide
        $typelibguid2up = "E05D0DEB-D724-4448-8C4C-53D6A8E670F3" ascii wide
        $typelibguid3lo = "c3cc72bf-62a2-4034-af66-e66da73e425d" ascii wide
        $typelibguid3up = "C3CC72BF-62A2-4034-AF66-E66DA73E425D" ascii wide
        $typelibguid4lo = "7ace3762-d8e1-4969-a5a0-dcaf7b18164e" ascii wide
        $typelibguid4up = "7ACE3762-D8E1-4969-A5A0-DCAF7B18164E" ascii wide
        $typelibguid5lo = "3296e4a3-94b5-4232-b423-44f4c7421cb3" ascii wide
        $typelibguid5up = "3296E4A3-94B5-4232-B423-44F4C7421CB3" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_BYTAGE {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/KNIF/BYTAGE"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "8e46ba56-e877-4dec-be1e-394cb1b5b9de" ascii wide
        $typelibguid0up = "8E46BA56-E877-4DEC-BE1E-394CB1B5B9DE" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_MultiOS_ReverseShell {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/belane/MultiOS_ReverseShell"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "df0dd7a1-9f6b-4b0f-801e-e17e73b0801d" ascii wide
        $typelibguid0up = "DF0DD7A1-9F6B-4B0F-801E-E17E73B0801D" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_HideFromAMSI {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/0r13lc0ch4v1/HideFromAMSI"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "b91d2d44-794c-49b8-8a75-2fbec3fe3fe3" ascii wide
        $typelibguid0up = "B91D2D44-794C-49B8-8A75-2FBEC3FE3FE3" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DotNetAVBypass_Master {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/lockfale/DotNetAVBypass-Master"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "4854c8dc-82b0-4162-86e0-a5bbcbc10240" ascii wide
        $typelibguid0up = "4854C8DC-82B0-4162-86E0-A5BBCBC10240" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpDPAPI {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/GhostPack/SharpDPAPI"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "5f026c27-f8e6-4052-b231-8451c6a73838" ascii wide
        $typelibguid0up = "5F026C27-F8E6-4052-B231-8451C6A73838" ascii wide
        $typelibguid1lo = "2f00a05b-263d-4fcc-846b-da82bd684603" ascii wide
        $typelibguid1up = "2F00A05B-263D-4FCC-846B-DA82BD684603" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Telegra_Csharp_C2 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/sf197/Telegra_Csharp_C2"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "1d79fabc-2ba2-4604-a4b6-045027340c85" ascii wide
        $typelibguid0up = "1D79FABC-2BA2-4604-A4B6-045027340C85" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpCompile {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/SpiderLabs/SharpCompile"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "63f81b73-ff18-4a36-b095-fdcb4776da4c" ascii wide
        $typelibguid0up = "63F81B73-FF18-4A36-B095-FDCB4776DA4C" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Carbuncle {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/checkymander/Carbuncle"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "3f239b73-88ae-413b-b8c8-c01a35a0d92e" ascii wide
        $typelibguid0up = "3F239B73-88AE-413B-B8C8-C01A35A0D92E" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_OSSFileTool {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/B1eed/OSSFileTool"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "207aca5d-dcd6-41fb-8465-58b39efcde8b" ascii wide
        $typelibguid0up = "207ACA5D-DCD6-41FB-8465-58B39EFCDE8B" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Rubeus {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/GhostPack/Rubeus"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "658c8b7f-3664-4a95-9572-a3e5871dfc06" ascii wide
        $typelibguid0up = "658C8B7F-3664-4A95-9572-A3E5871DFC06" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Simple_Loader {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/cribdragg3r/Simple-Loader"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "035ae711-c0e9-41da-a9a2-6523865e8694" ascii wide
        $typelibguid0up = "035AE711-C0E9-41DA-A9A2-6523865E8694" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Minidump {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/3xpl01tc0d3r/Minidump"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "15c241aa-e73c-4b38-9489-9a344ac268a3" ascii wide
        $typelibguid0up = "15C241AA-E73C-4B38-9489-9A344AC268A3" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpBypassUAC {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/FatRodzianko/SharpBypassUAC"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "0d588c86-c680-4b0d-9aed-418f1bb94255" ascii wide
        $typelibguid0up = "0D588C86-C680-4B0D-9AED-418F1BB94255" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpPack {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Lexus89/SharpPack"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid1lo = "b59c7741-d522-4a41-bf4d-9badddebb84a" ascii wide
        $typelibguid1up = "B59C7741-D522-4A41-BF4D-9BADDDEBB84A" ascii wide
        $typelibguid2lo = "fd6bdf7a-fef4-4b28-9027-5bf750f08048" ascii wide
        $typelibguid2up = "FD6BDF7A-FEF4-4B28-9027-5BF750F08048" ascii wide
        $typelibguid3lo = "6dd22880-dac5-4b4d-9c91-8c35cc7b8180" ascii wide
        $typelibguid3up = "6DD22880-DAC5-4B4D-9C91-8C35CC7B8180" ascii wide
        $typelibguid5lo = "f3037587-1a3b-41f1-aa71-b026efdb2a82" ascii wide
        $typelibguid5up = "F3037587-1A3B-41F1-AA71-B026EFDB2A82" ascii wide
        $typelibguid6lo = "41a90a6a-f9ed-4a2f-8448-d544ec1fd753" ascii wide
        $typelibguid6up = "41A90A6A-F9ED-4A2F-8448-D544EC1FD753" ascii wide
        $typelibguid7lo = "3787435b-8352-4bd8-a1c6-e5a1b73921f4" ascii wide
        $typelibguid7up = "3787435B-8352-4BD8-A1C6-E5A1B73921F4" ascii wide
        $typelibguid8lo = "fdd654f5-5c54-4d93-bf8e-faf11b00e3e9" ascii wide
        $typelibguid8up = "FDD654F5-5C54-4D93-BF8E-FAF11B00E3E9" ascii wide
        $typelibguid9lo = "aec32155-d589-4150-8fe7-2900df4554c8" ascii wide
        $typelibguid9up = "AEC32155-D589-4150-8FE7-2900DF4554C8" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Salsa_tools {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Hackplayers/Salsa-tools"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "276004bb-5200-4381-843c-934e4c385b66" ascii wide
        $typelibguid0up = "276004BB-5200-4381-843C-934E4C385B66" ascii wide
        $typelibguid1lo = "cfcbf7b6-1c69-4b1f-8651-6bdb4b55f6b9" ascii wide
        $typelibguid1up = "CFCBF7B6-1C69-4B1F-8651-6BDB4B55F6B9" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_WindowsDefender_Payload_Downloader {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/notkohlrexo/WindowsDefender-Payload-Downloader"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "2f8b4d26-7620-4e11-b296-bc46eba3adfc" ascii wide
        $typelibguid0up = "2F8B4D26-7620-4E11-B296-BC46EBA3ADFC" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Privilege_Escalation {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Mrakovic-ORG/Privilege_Escalation"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "ed54b904-5645-4830-8e68-52fd9ecbb2eb" ascii wide
        $typelibguid0up = "ED54B904-5645-4830-8E68-52FD9ECBB2EB" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Marauder {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/maraudershell/Marauder"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "fff0a9a3-dfd4-402b-a251-6046d765ad78" ascii wide
        $typelibguid0up = "FFF0A9A3-DFD4-402B-A251-6046D765AD78" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_AV_Evasion_Tool {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/1y0n/AV_Evasion_Tool"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "1937ee16-57d7-4a5f-88f4-024244f19dc6" ascii wide
        $typelibguid0up = "1937EE16-57D7-4A5F-88F4-024244F19DC6" ascii wide
        $typelibguid1lo = "7898617d-08d2-4297-adfe-5edd5c1b828b" ascii wide
        $typelibguid1up = "7898617D-08D2-4297-ADFE-5EDD5C1B828B" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Fenrir {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/nccgroup/Fenrir"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "aecec195-f143-4d02-b946-df0e1433bd2e" ascii wide
        $typelibguid0up = "AECEC195-F143-4D02-B946-DF0E1433BD2E" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_StormKitty {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/LimerBoy/StormKitty"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "a16abbb4-985b-4db2-a80c-21268b26c73d" ascii wide
        $typelibguid0up = "A16ABBB4-985B-4DB2-A80C-21268B26C73D" ascii wide
        $typelibguid1lo = "98075331-1f86-48c8-ae29-29da39a8f98b" ascii wide
        $typelibguid1up = "98075331-1F86-48C8-AE29-29DA39A8F98B" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Crypter_Runtime_AV_s_bypass {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/netreverse/Crypter-Runtime-AV-s-bypass"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "c25e39a9-8215-43aa-96a3-da0e9512ec18" ascii wide
        $typelibguid0up = "C25E39A9-8215-43AA-96A3-DA0E9512EC18" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_RunAsUser {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/atthacks/RunAsUser"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "9dff282c-93b9-4063-bf8a-b6798371d35a" ascii wide
        $typelibguid0up = "9DFF282C-93B9-4063-BF8A-B6798371D35A" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_HWIDbypass {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/yunseok/HWIDbypass"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "47e08791-d124-4746-bc50-24bd1ee719a6" ascii wide
        $typelibguid0up = "47E08791-D124-4746-BC50-24BD1EE719A6" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_XORedReflectiveDLL {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/r3nhat/XORedReflectiveDLL"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "c0e49392-04e3-4abb-b931-5202e0eb4c73" ascii wide
        $typelibguid0up = "C0E49392-04E3-4ABB-B931-5202E0EB4C73" ascii wide
        $typelibguid1lo = "30eef7d6-cee8-490b-829f-082041bc3141" ascii wide
        $typelibguid1up = "30EEF7D6-CEE8-490B-829F-082041BC3141" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Sharp_Suite {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/FuzzySecurity/Sharp-Suite"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "19657be4-51ca-4a85-8ab1-f6666008b1f3" ascii wide
        $typelibguid0up = "19657BE4-51CA-4A85-8AB1-F6666008B1F3" ascii wide
        $typelibguid1lo = "0a382d9a-897f-431a-81c2-a4e08392c587" ascii wide
        $typelibguid1up = "0A382D9A-897F-431A-81C2-A4E08392C587" ascii wide
        $typelibguid2lo = "467ee2a9-2f01-4a71-9647-2a2d9c31e608" ascii wide
        $typelibguid2up = "467EE2A9-2F01-4A71-9647-2A2D9C31E608" ascii wide
        $typelibguid3lo = "eacaa2b8-43e5-4888-826d-2f6902e16546" ascii wide
        $typelibguid3up = "EACAA2B8-43E5-4888-826D-2F6902E16546" ascii wide
        $typelibguid4lo = "629f86e6-44fe-4c9c-b043-1c9b64be6d5a" ascii wide
        $typelibguid4up = "629F86E6-44FE-4C9C-B043-1C9B64BE6D5A" ascii wide
        $typelibguid5lo = "ecf2ffe4-1744-4745-8693-5790d66bb1b8" ascii wide
        $typelibguid5up = "ECF2FFE4-1744-4745-8693-5790D66BB1B8" ascii wide
        $typelibguid6lo = "0a621f4c-8082-4c30-b131-ba2c98db0533" ascii wide
        $typelibguid6up = "0A621F4C-8082-4C30-B131-BA2C98DB0533" ascii wide
        $typelibguid7lo = "72019dfe-608e-4ab2-a8f1-66c95c425620" ascii wide
        $typelibguid7up = "72019DFE-608E-4AB2-A8F1-66C95C425620" ascii wide
        $typelibguid8lo = "f0d28809-b712-4380-9a59-407b7b2badd5" ascii wide
        $typelibguid8up = "F0D28809-B712-4380-9A59-407B7B2BADD5" ascii wide
        $typelibguid9lo = "956a5a4d-2007-4857-9259-51cd0fb5312a" ascii wide
        $typelibguid9up = "956A5A4D-2007-4857-9259-51CD0FB5312A" ascii wide
        $typelibguid10lo = "a3b7c697-4bb6-455d-9fda-4ab54ae4c8d2" ascii wide
        $typelibguid10up = "A3B7C697-4BB6-455D-9FDA-4AB54AE4C8D2" ascii wide
        $typelibguid11lo = "a5f883ce-1f96-4456-bb35-40229191420c" ascii wide
        $typelibguid11up = "A5F883CE-1F96-4456-BB35-40229191420C" ascii wide
        $typelibguid12lo = "28978103-d90d-4618-b22e-222727f40313" ascii wide
        $typelibguid12up = "28978103-D90D-4618-B22E-222727F40313" ascii wide
        $typelibguid13lo = "0c70c839-9565-4881-8ea1-408c1ebe38ce" ascii wide
        $typelibguid13up = "0C70C839-9565-4881-8EA1-408C1EBE38CE" ascii wide
        $typelibguid14lo = "fa1d9a36-415a-4855-8c01-54b6e9fc6965" ascii wide
        $typelibguid14up = "FA1D9A36-415A-4855-8C01-54B6E9FC6965" ascii wide
        $typelibguid15lo = "252676f8-8a19-4664-bfb8-5a947e48c32a" ascii wide
        $typelibguid15up = "252676F8-8A19-4664-BFB8-5A947E48C32A" ascii wide
        $typelibguid16lo = "447edefc-b429-42bc-b3bc-63a9af19dbd6" ascii wide
        $typelibguid16up = "447EDEFC-B429-42BC-B3BC-63A9AF19DBD6" ascii wide
        $typelibguid17lo = "04d0b3a6-eaab-413d-b9e2-512fa8ebd02f" ascii wide
        $typelibguid17up = "04D0B3A6-EAAB-413D-B9E2-512FA8EBD02F" ascii wide
        $typelibguid18lo = "5611236e-2557-45b8-be29-5d1f074d199e" ascii wide
        $typelibguid18up = "5611236E-2557-45B8-BE29-5D1F074D199E" ascii wide
        $typelibguid19lo = "53f622eb-0ca3-4e9b-9dc8-30c832df1c7b" ascii wide
        $typelibguid19up = "53F622EB-0CA3-4E9B-9DC8-30C832DF1C7B" ascii wide
        $typelibguid20lo = "414187db-5feb-43e5-a383-caa48b5395f1" ascii wide
        $typelibguid20up = "414187DB-5FEB-43E5-A383-CAA48B5395F1" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_rat_shell {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/stphivos/rat-shell"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "7a15f8f6-6ce2-4ca4-919d-2056b70cc76a" ascii wide
        $typelibguid0up = "7A15F8F6-6CE2-4CA4-919D-2056B70CC76A" ascii wide
        $typelibguid1lo = "1659d65d-93a8-4bae-97d5-66d738fc6f6c" ascii wide
        $typelibguid1up = "1659D65D-93A8-4BAE-97D5-66D738FC6F6C" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_dotnet_gargoyle {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/countercept/dotnet-gargoyle"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "76435f79-f8af-4d74-8df5-d598a551b895" ascii wide
        $typelibguid0up = "76435F79-F8AF-4D74-8DF5-D598A551B895" ascii wide
        $typelibguid1lo = "5a3fc840-5432-4925-b5bc-abc536429cb5" ascii wide
        $typelibguid1up = "5A3FC840-5432-4925-B5BC-ABC536429CB5" ascii wide
        $typelibguid2lo = "6f0bbb2a-e200-4d76-b8fa-f93c801ac220" ascii wide
        $typelibguid2up = "6F0BBB2A-E200-4D76-B8FA-F93C801AC220" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_aresskit {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/BlackVikingPro/aresskit"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "8dca0e42-f767-411d-9704-ae0ba4a44ae8" ascii wide
        $typelibguid0up = "8DCA0E42-F767-411D-9704-AE0BA4A44AE8" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DLL_Injector {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/tmthrgd/DLL-Injector"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "4581a449-7d20-4c59-8da2-7fd830f1fd5e" ascii wide
        $typelibguid0up = "4581A449-7D20-4C59-8DA2-7FD830F1FD5E" ascii wide
        $typelibguid1lo = "05f4b238-25ce-40dc-a890-d5bbb8642ee4" ascii wide
        $typelibguid1up = "05F4B238-25CE-40DC-A890-D5BBB8642EE4" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_TruffleSnout {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/dsnezhkov/TruffleSnout"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "33842d77-bce3-4ee8-9ee2-9769898bb429" ascii wide
        $typelibguid0up = "33842D77-BCE3-4EE8-9EE2-9769898BB429" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Anti_Analysis {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/Anti-Analysis"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "3092c8df-e9e4-4b75-b78e-f81a0058a635" ascii wide
        $typelibguid0up = "3092C8DF-E9E4-4B75-B78E-F81A0058A635" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_BackNet {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/valsov/BackNet"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "9fdae122-cd1e-467d-a6fa-a98c26e76348" ascii wide
        $typelibguid0up = "9FDAE122-CD1E-467D-A6FA-A98C26E76348" ascii wide
        $typelibguid1lo = "243c279e-33a6-46a1-beab-2864cc7a499f" ascii wide
        $typelibguid1up = "243C279E-33A6-46A1-BEAB-2864CC7A499F" ascii wide
        $typelibguid2lo = "a7301384-7354-47fd-a4c5-65b74e0bbb46" ascii wide
        $typelibguid2up = "A7301384-7354-47FD-A4C5-65B74E0BBB46" ascii wide
        $typelibguid3lo = "982dc5b6-1123-428a-83dd-d212490c859f" ascii wide
        $typelibguid3up = "982DC5B6-1123-428A-83DD-D212490C859F" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_AllTheThings {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/johnjohnsp1/AllTheThings"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "0547ff40-5255-42a2-beb7-2ff0dbf7d3ba" ascii wide
        $typelibguid0up = "0547FF40-5255-42A2-BEB7-2FF0DBF7D3BA" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_AddReferenceDotRedTeam {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/ceramicskate0/AddReferenceDotRedTeam"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "73c79d7e-17d4-46c9-be5a-ecef65b924e4" ascii wide
        $typelibguid0up = "73C79D7E-17D4-46C9-BE5A-ECEF65B924E4" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Lime_Crypter {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/Lime-Crypter"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "f93c99ed-28c9-48c5-bb90-dd98f18285a6" ascii wide
        $typelibguid0up = "F93C99ED-28C9-48C5-BB90-DD98F18285A6" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_BrowserGhost {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/QAX-A-Team/BrowserGhost"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "2133c634-4139-466e-8983-9a23ec99e01b" ascii wide
        $typelibguid0up = "2133C634-4139-466E-8983-9A23EC99E01B" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
        and not pe.is_dll()
}

rule HKTL_NET_GUID_SharpShot {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/tothi/SharpShot"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "057aef75-861b-4e4b-a372-cfbd8322c8e1" ascii wide
        $typelibguid0up = "057AEF75-861B-4E4B-A372-CFBD8322C8E1" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Offensive__NET {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/mrjamiebowman/Offensive-.NET"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "11fe5fae-b7c1-484a-b162-d5578a802c9c" ascii wide
        $typelibguid0up = "11FE5FAE-B7C1-484A-B162-D5578A802C9C" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_RuralBishop {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/rasta-mouse/RuralBishop"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "fe4414d9-1d7e-4eeb-b781-d278fe7a5619" ascii wide
        $typelibguid0up = "FE4414D9-1D7E-4EEB-B781-D278FE7A5619" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DeviceGuardBypasses {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/tyranid/DeviceGuardBypasses"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "f318466d-d310-49ad-a967-67efbba29898" ascii wide
        $typelibguid0up = "F318466D-D310-49AD-A967-67EFBBA29898" ascii wide
        $typelibguid1lo = "3705800f-1424-465b-937d-586e3a622a4f" ascii wide
        $typelibguid1up = "3705800F-1424-465B-937D-586E3A622A4F" ascii wide
        $typelibguid2lo = "256607c2-4126-4272-a2fa-a1ffc0a734f0" ascii wide
        $typelibguid2up = "256607C2-4126-4272-A2FA-A1FFC0A734F0" ascii wide
        $typelibguid3lo = "4e6ceea1-f266-401c-b832-f91432d46f42" ascii wide
        $typelibguid3up = "4E6CEEA1-F266-401C-B832-F91432D46F42" ascii wide
        $typelibguid4lo = "1e6e9b03-dd5f-4047-b386-af7a7904f884" ascii wide
        $typelibguid4up = "1E6E9B03-DD5F-4047-B386-AF7A7904F884" ascii wide
        $typelibguid5lo = "d85e3601-0421-4efa-a479-f3370c0498fd" ascii wide
        $typelibguid5up = "D85E3601-0421-4EFA-A479-F3370C0498FD" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_AMSI_Handler {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/two06/AMSI_Handler"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "d829426c-986c-40a4-8ee2-58d14e090ef2" ascii wide
        $typelibguid0up = "D829426C-986C-40A4-8EE2-58D14E090EF2" ascii wide
        $typelibguid1lo = "86652418-5605-43fd-98b5-859828b072be" ascii wide
        $typelibguid1up = "86652418-5605-43FD-98B5-859828B072BE" ascii wide
        $typelibguid2lo = "1043649f-18e1-41c4-ae8d-ac4d9a86c2fc" ascii wide
        $typelibguid2up = "1043649F-18E1-41C4-AE8D-AC4D9A86C2FC" ascii wide
        $typelibguid3lo = "1d920b03-c537-4659-9a8c-09fb1d615e98" ascii wide
        $typelibguid3up = "1D920B03-C537-4659-9A8C-09FB1D615E98" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_RAT_TelegramSpyBot {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/SebastianEPH/RAT.TelegramSpyBot"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "8653fa88-9655-440e-b534-26c3c760a0d3" ascii wide
        $typelibguid0up = "8653FA88-9655-440E-B534-26C3C760A0D3" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_TheHackToolBoxTeek {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/teeknofil/TheHackToolBoxTeek"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "2aa8c254-b3b3-469c-b0c9-dcbe1dd101c0" ascii wide
        $typelibguid0up = "2AA8C254-B3B3-469C-B0C9-DCBE1DD101C0" ascii wide
        $typelibguid1lo = "afeff505-14c1-4ecf-b714-abac4fbd48e7" ascii wide
        $typelibguid1up = "AFEFF505-14C1-4ECF-B714-ABAC4FBD48E7" ascii wide
        $typelibguid2lo = "4cf42167-a5cf-4b2d-85b4-8e764c08d6b3" ascii wide
        $typelibguid2up = "4CF42167-A5CF-4B2D-85B4-8E764C08D6B3" ascii wide
        $typelibguid3lo = "118a90b7-598a-4cfc-859e-8013c8b9339c" ascii wide
        $typelibguid3up = "118A90B7-598A-4CFC-859E-8013C8B9339C" ascii wide
        $typelibguid4lo = "3075dd9a-4283-4d38-a25e-9f9845e5adcb" ascii wide
        $typelibguid4up = "3075DD9A-4283-4D38-A25E-9F9845E5ADCB" ascii wide
        $typelibguid5lo = "295655e8-2348-4700-9ebc-aa57df54887e" ascii wide
        $typelibguid5up = "295655E8-2348-4700-9EBC-AA57DF54887E" ascii wide
        $typelibguid6lo = "74efe601-9a93-46c3-932e-b80ab6570e42" ascii wide
        $typelibguid6up = "74EFE601-9A93-46C3-932E-B80AB6570E42" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_USBTrojan {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/mashed-potatoes/USBTrojan"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "4eee900e-adc5-46a7-8d7d-873fd6aea83e" ascii wide
        $typelibguid0up = "4EEE900E-ADC5-46A7-8D7D-873FD6AEA83E" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_IIS_backdoor {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/WBGlIl/IIS_backdoor"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "3fda4aa9-6fc1-473f-9048-7edc058c4f65" ascii wide
        $typelibguid0up = "3FDA4AA9-6FC1-473F-9048-7EDC058C4F65" ascii wide
        $typelibguid1lo = "73ca4159-5d13-4a27-8965-d50c41ab203c" ascii wide
        $typelibguid1up = "73CA4159-5D13-4A27-8965-D50C41AB203C" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_ShellGen {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/jasondrawdy/ShellGen"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "c6894882-d29d-4ae1-aeb7-7d0a9b915013" ascii wide
        $typelibguid0up = "C6894882-D29D-4AE1-AEB7-7D0A9B915013" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Mass_RAT {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/Mass-RAT"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "6c43a753-9565-48b2-a372-4210bb1e0d75" ascii wide
        $typelibguid0up = "6C43A753-9565-48B2-A372-4210BB1E0D75" ascii wide
        $typelibguid1lo = "92ba2a7e-c198-4d43-929e-1cfe54b64d95" ascii wide
        $typelibguid1up = "92BA2A7E-C198-4D43-929E-1CFE54B64D95" ascii wide
        $typelibguid2lo = "4cb9bbee-fb92-44fa-a427-b7245befc2f3" ascii wide
        $typelibguid2up = "4CB9BBEE-FB92-44FA-A427-B7245BEFC2F3" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Browser_ExternalC2 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/mdsecactivebreach/Browser-ExternalC2"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "10a730cd-9517-42d5-b3e3-a2383515cca9" ascii wide
        $typelibguid0up = "10A730CD-9517-42D5-B3E3-A2383515CCA9" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_OffensivePowerShellTasking {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/leechristensen/OffensivePowerShellTasking"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "d432c332-3b48-4d06-bedb-462e264e6688" ascii wide
        $typelibguid0up = "D432C332-3B48-4D06-BEDB-462E264E6688" ascii wide
        $typelibguid1lo = "5796276f-1c7a-4d7b-a089-550a8c19d0e8" ascii wide
        $typelibguid1up = "5796276F-1C7A-4D7B-A089-550A8C19D0E8" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DoHC2 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/SpiderLabs/DoHC2"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "9877a948-2142-4094-98de-e0fbb1bc4062" ascii wide
        $typelibguid0up = "9877A948-2142-4094-98DE-E0FBB1BC4062" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SyscallPOC {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/SolomonSklash/SyscallPOC"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "1e54637b-c887-42a9-af6a-b4bd4e28cda9" ascii wide
        $typelibguid0up = "1E54637B-C887-42A9-AF6A-B4BD4E28CDA9" ascii wide
        $typelibguid1lo = "198d5599-d9fc-4a74-87f4-5077318232ad" ascii wide
        $typelibguid1up = "198D5599-D9FC-4A74-87F4-5077318232AD" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Pen_Test_Tools {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/awillard1/Pen-Test-Tools"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "922e7fdc-33bf-48de-bc26-a81f85462115" ascii wide
        $typelibguid0up = "922E7FDC-33BF-48DE-BC26-A81F85462115" ascii wide
        $typelibguid1lo = "ad5205dd-174d-4332-96d9-98b076d6fd82" ascii wide
        $typelibguid1up = "AD5205DD-174D-4332-96D9-98B076D6FD82" ascii wide
        $typelibguid2lo = "b67e7550-f00e-48b3-ab9b-4332b1254a86" ascii wide
        $typelibguid2up = "B67E7550-F00E-48B3-AB9B-4332B1254A86" ascii wide
        $typelibguid3lo = "5e95120e-b002-4495-90a1-cd3aab2a24dd" ascii wide
        $typelibguid3up = "5E95120E-B002-4495-90A1-CD3AAB2A24DD" ascii wide
        $typelibguid4lo = "295017f2-dc31-4a87-863d-0b9956c2b55a" ascii wide
        $typelibguid4up = "295017F2-DC31-4A87-863D-0B9956C2B55A" ascii wide
        $typelibguid5lo = "abbaa2f7-1452-43a6-b98e-10b2c8c2ba46" ascii wide
        $typelibguid5up = "ABBAA2F7-1452-43A6-B98E-10B2C8C2BA46" ascii wide
        $typelibguid6lo = "a4043d4c-167b-4326-8be4-018089650382" ascii wide
        $typelibguid6up = "A4043D4C-167B-4326-8BE4-018089650382" ascii wide
        $typelibguid7lo = "51abfd75-b179-496e-86db-62ee2a8de90d" ascii wide
        $typelibguid7up = "51ABFD75-B179-496E-86DB-62EE2A8DE90D" ascii wide
        $typelibguid8lo = "a06da7f8-f87e-4065-81d8-abc33cb547f8" ascii wide
        $typelibguid8up = "A06DA7F8-F87E-4065-81D8-ABC33CB547F8" ascii wide
        $typelibguid9lo = "ee510712-0413-49a1-b08b-1f0b0b33d6ef" ascii wide
        $typelibguid9up = "EE510712-0413-49A1-B08B-1F0B0B33D6EF" ascii wide
        $typelibguid10lo = "9780da65-7e25-412e-9aa1-f77d828819d6" ascii wide
        $typelibguid10up = "9780DA65-7E25-412E-9AA1-F77D828819D6" ascii wide
        $typelibguid11lo = "7913fe95-3ad5-41f5-bf7f-e28f080724fe" ascii wide
        $typelibguid11up = "7913FE95-3AD5-41F5-BF7F-E28F080724FE" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_The_Collection {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Tlgyt/The-Collection"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "579159ff-3a3d-46a7-b069-91204feb21cd" ascii wide
        $typelibguid0up = "579159FF-3A3D-46A7-B069-91204FEB21CD" ascii wide
        $typelibguid1lo = "5b7dd9be-c8c3-4c4f-a353-fefb89baa7b3" ascii wide
        $typelibguid1up = "5B7DD9BE-C8C3-4C4F-A353-FEFB89BAA7B3" ascii wide
        $typelibguid2lo = "43edcb1f-3098-4a23-a7f2-895d927bc661" ascii wide
        $typelibguid2up = "43EDCB1F-3098-4A23-A7F2-895D927BC661" ascii wide
        $typelibguid3lo = "5f19919d-cd51-4e77-973f-875678360a6f" ascii wide
        $typelibguid3up = "5F19919D-CD51-4E77-973F-875678360A6F" ascii wide
        $typelibguid4lo = "17fbc926-e17e-4034-ba1b-fb2eb57f5dd3" ascii wide
        $typelibguid4up = "17FBC926-E17E-4034-BA1B-FB2EB57F5DD3" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Change_Lockscreen {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/nccgroup/Change-Lockscreen"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "78642ab3-eaa6-4e9c-a934-e7b0638bc1cc" ascii wide
        $typelibguid0up = "78642AB3-EAA6-4E9C-A934-E7B0638BC1CC" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_LOLBITS {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Kudaes/LOLBITS"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "29d09aa4-ea0c-47c2-973c-1d768087d527" ascii wide
        $typelibguid0up = "29D09AA4-EA0C-47C2-973C-1D768087D527" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Keylogger {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/BlackVikingPro/Keylogger"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "7afbc9bf-32d9-460f-8a30-35e30aa15879" ascii wide
        $typelibguid0up = "7AFBC9BF-32D9-460F-8A30-35E30AA15879" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_CVE_2020_1337 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/neofito/CVE-2020-1337"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "d9c2e3c1-e9cc-42b0-a67c-b6e1a4f962cc" ascii wide
        $typelibguid0up = "D9C2E3C1-E9CC-42B0-A67C-B6E1A4F962CC" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpLogger {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/djhohnstein/SharpLogger"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "36e00152-e073-4da8-aa0c-375b6dd680c4" ascii wide
        $typelibguid0up = "36E00152-E073-4DA8-AA0C-375B6DD680C4" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_AsyncRAT_C_Sharp {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "619b7612-dfea-442a-a927-d997f99c497b" ascii wide
        $typelibguid0up = "619B7612-DFEA-442A-A927-D997F99C497B" ascii wide
        $typelibguid1lo = "424b81be-2fac-419f-b4bc-00ccbe38491f" ascii wide
        $typelibguid1up = "424B81BE-2FAC-419F-B4BC-00CCBE38491F" ascii wide
        $typelibguid2lo = "37e20baf-3577-4cd9-bb39-18675854e255" ascii wide
        $typelibguid2up = "37E20BAF-3577-4CD9-BB39-18675854E255" ascii wide
        $typelibguid3lo = "dafe686a-461b-402b-bbd7-2a2f4c87c773" ascii wide
        $typelibguid3up = "DAFE686A-461B-402B-BBD7-2A2F4C87C773" ascii wide
        $typelibguid4lo = "ee03faa9-c9e8-4766-bd4e-5cd54c7f13d3" ascii wide
        $typelibguid4up = "EE03FAA9-C9E8-4766-BD4E-5CD54C7F13D3" ascii wide
        $typelibguid5lo = "8bfc8ed2-71cc-49dc-9020-2c8199bc27b6" ascii wide
        $typelibguid5up = "8BFC8ED2-71CC-49DC-9020-2C8199BC27B6" ascii wide
        $typelibguid6lo = "d640c36b-2c66-449b-a145-eb98322a67c8" ascii wide
        $typelibguid6up = "D640C36B-2C66-449B-A145-EB98322A67C8" ascii wide
        $typelibguid7lo = "8de42da3-be99-4e7e-a3d2-3f65e7c1abce" ascii wide
        $typelibguid7up = "8DE42DA3-BE99-4E7E-A3D2-3F65E7C1ABCE" ascii wide
        $typelibguid8lo = "bee88186-769a-452c-9dd9-d0e0815d92bf" ascii wide
        $typelibguid8up = "BEE88186-769A-452C-9DD9-D0E0815D92BF" ascii wide
        $typelibguid9lo = "9042b543-13d1-42b3-a5b6-5cc9ad55e150" ascii wide
        $typelibguid9up = "9042B543-13D1-42B3-A5B6-5CC9AD55E150" ascii wide
        $typelibguid10lo = "6aa4e392-aaaf-4408-b550-85863dd4baaf" ascii wide
        $typelibguid10up = "6AA4E392-AAAF-4408-B550-85863DD4BAAF" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DarkFender {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/0xyg3n/DarkFender"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "12fdf7ce-4a7c-41b6-9b32-766ddd299beb" ascii wide
        $typelibguid0up = "12FDF7CE-4A7C-41B6-9B32-766DDD299BEB" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

/* FPs with IronPython
rule HKTL_NET_GUID_IronKit {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/nshalabi/IronKit"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        score = 50
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "68e40495-c34a-4539-b43e-9e4e6f11a9fb" ascii wide
        $typelibguid0up = "68E40495-C34A-4539-B43E-9E4E6F11A9FB" ascii wide
        $typelibguid1lo = "641cd52d-3886-4a74-b590-2a05621502a4" ascii wide
        $typelibguid1up = "641CD52D-3886-4A74-B590-2A05621502A4" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
*/

rule HKTL_NET_GUID_MinerDropper {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/DylanAlloy/MinerDropper"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "46a7af83-1da7-40b2-9d86-6fd6223f6791" ascii wide
        $typelibguid0up = "46A7AF83-1DA7-40B2-9D86-6FD6223F6791" ascii wide
        $typelibguid1lo = "8433a693-f39d-451b-955b-31c3e7fa6825" ascii wide
        $typelibguid1up = "8433A693-F39D-451B-955B-31C3E7FA6825" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpDomainSpray {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/HunnicCyber/SharpDomainSpray"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "76ffa92b-429b-4865-970d-4e7678ac34ea" ascii wide
        $typelibguid0up = "76FFA92B-429B-4865-970D-4E7678AC34EA" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_iSpyKeylogger {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/mwsrc/iSpyKeylogger"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "ccc0a386-c4ce-42ef-aaea-b2af7eff4ad8" ascii wide
        $typelibguid0up = "CCC0A386-C4CE-42EF-AAEA-B2AF7EFF4AD8" ascii wide
        $typelibguid1lo = "816b8b90-2975-46d3-aac9-3c45b26437fa" ascii wide
        $typelibguid1up = "816B8B90-2975-46D3-AAC9-3C45B26437FA" ascii wide
        $typelibguid2lo = "279b5533-d3ac-438f-ba89-3fe9de2da263" ascii wide
        $typelibguid2up = "279B5533-D3AC-438F-BA89-3FE9DE2DA263" ascii wide
        $typelibguid3lo = "88d3dc02-2853-4bf0-b6dc-ad31f5135d26" ascii wide
        $typelibguid3up = "88D3DC02-2853-4BF0-B6DC-AD31F5135D26" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SolarFlare {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/mubix/solarflare"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-15"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "ca60e49e-eee9-409b-8d1a-d19f1d27b7e4" ascii wide
        $typelibguid0up = "CA60E49E-EEE9-409B-8D1A-D19F1D27B7E4" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Snaffler {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/SnaffCon/Snaffler"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "2aa060b4-de88-4d2a-a26a-760c1cefec3e" ascii wide
        $typelibguid0up = "2AA060B4-DE88-4D2A-A26A-760C1CEFEC3E" ascii wide
        $typelibguid1lo = "b118802d-2e46-4e41-aac7-9ee890268f8b" ascii wide
        $typelibguid1up = "B118802D-2E46-4E41-AAC7-9EE890268F8B" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpShares {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/djhohnstein/SharpShares/"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "fe9fdde5-3f38-4f14-8c64-c3328c215cf2" ascii wide
        $typelibguid0up = "FE9FDDE5-3F38-4F14-8C64-C3328C215CF2" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpEDRChecker {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/PwnDexter/SharpEDRChecker"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-18"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "bdfee233-3fed-42e5-aa64-492eb2ac7047" ascii wide
        $typelibguid0up = "BDFEE233-3FED-42E5-AA64-492EB2AC7047" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpClipHistory {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/FSecureLABS/SharpClipHistory"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-21"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "1126d5b4-efc7-4b33-a594-b963f107fe82" ascii wide
        $typelibguid0up = "1126D5B4-EFC7-4B33-A594-B963F107FE82" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpGPO_RemoteAccessPolicies {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/FSecureLABS/SharpGPO-RemoteAccessPolicies"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-21"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "fbb1abcf-2b06-47a0-9311-17ba3d0f2a50" ascii wide
        $typelibguid0up = "FBB1ABCF-2B06-47A0-9311-17BA3D0F2A50" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Absinthe {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/cameronhotchkies/Absinthe"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-21"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "9936ae73-fb4e-4c5e-a5fb-f8aaeb3b9bd6" ascii wide
        $typelibguid0up = "9936AE73-FB4E-4C5E-A5FB-F8AAEB3B9BD6" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_ExploitRemotingService {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/tyranid/ExploitRemotingService"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-21"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "fd17ae38-2fd3-405f-b85b-e9d14e8e8261" ascii wide
        $typelibguid0up = "FD17AE38-2FD3-405F-B85B-E9D14E8E8261" ascii wide
        $typelibguid1lo = "1850b9bb-4a23-4d74-96b8-58f274674566" ascii wide
        $typelibguid1up = "1850B9BB-4A23-4D74-96B8-58F274674566" ascii wide
        $typelibguid2lo = "297cbca1-efa3-4f2a-8d5f-e1faf02ba587" ascii wide
        $typelibguid2up = "297CBCA1-EFA3-4F2A-8D5F-E1FAF02BA587" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Xploit {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/shargon/Xploit"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-21"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "4545cfde-9ee5-4f1b-b966-d128af0b9a6e" ascii wide
        $typelibguid0up = "4545CFDE-9EE5-4F1B-B966-D128AF0B9A6E" ascii wide
        $typelibguid1lo = "33849d2b-3be8-41e8-a1e2-614c94c4533c" ascii wide
        $typelibguid1up = "33849D2B-3BE8-41E8-A1E2-614C94C4533C" ascii wide
        $typelibguid2lo = "c2dc73cc-a959-4965-8499-a9e1720e594b" ascii wide
        $typelibguid2up = "C2DC73CC-A959-4965-8499-A9E1720E594B" ascii wide
        $typelibguid3lo = "77059fa1-4b7d-4406-bc1a-cb261086f915" ascii wide
        $typelibguid3up = "77059FA1-4B7D-4406-BC1A-CB261086F915" ascii wide
        $typelibguid4lo = "a4a04c4d-5490-4309-9c90-351e5e5fd6d1" ascii wide
        $typelibguid4up = "A4A04C4D-5490-4309-9C90-351E5E5FD6D1" ascii wide
        $typelibguid5lo = "ca64f918-3296-4b7d-9ce6-b98389896765" ascii wide
        $typelibguid5up = "CA64F918-3296-4B7D-9CE6-B98389896765" ascii wide
        $typelibguid6lo = "10fe32a0-d791-47b2-8530-0b19d91434f7" ascii wide
        $typelibguid6up = "10FE32A0-D791-47B2-8530-0B19D91434F7" ascii wide
        $typelibguid7lo = "679bba57-3063-4f17-b491-4f0a730d6b02" ascii wide
        $typelibguid7up = "679BBA57-3063-4F17-B491-4F0A730D6B02" ascii wide
        $typelibguid8lo = "0981e164-5930-4ba0-983c-1cf679e5033f" ascii wide
        $typelibguid8up = "0981E164-5930-4BA0-983C-1CF679E5033F" ascii wide
        $typelibguid9lo = "2a844ca2-5d6c-45b5-963b-7dca1140e16f" ascii wide
        $typelibguid9up = "2A844CA2-5D6C-45B5-963B-7DCA1140E16F" ascii wide
        $typelibguid10lo = "7d75ca11-8745-4382-b3eb-c41416dbc48c" ascii wide
        $typelibguid10up = "7D75CA11-8745-4382-B3EB-C41416DBC48C" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_PoC {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/thezdi/PoC"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-21"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "89f9d411-e273-41bb-8711-209fd251ca88" ascii wide
        $typelibguid0up = "89F9D411-E273-41BB-8711-209FD251CA88" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpGPOAbuse {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/FSecureLABS/SharpGPOAbuse"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-21"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "4f495784-b443-4838-9fa6-9149293af785" ascii wide
        $typelibguid0up = "4F495784-B443-4838-9FA6-9149293AF785" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Watson {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/rasta-mouse/Watson"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-21"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "49ad5f38-9e37-4967-9e84-fe19c7434ed7" ascii wide
        $typelibguid0up = "49AD5F38-9E37-4967-9E84-FE19C7434ED7" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_StandIn {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/FuzzySecurity/StandIn"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-21"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "01c142ba-7af1-48d6-b185-81147a2f7db7" ascii wide
        $typelibguid0up = "01C142BA-7AF1-48D6-B185-81147A2F7DB7" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_azure_password_harvesting {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/guardicore/azure_password_harvesting"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-21"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "7ad1ff2d-32ac-4c54-b615-9bb164160dac" ascii wide
        $typelibguid0up = "7AD1FF2D-32AC-4C54-B615-9BB164160DAC" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_PowerOPS {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/fdiskyou/PowerOPS"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-21"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "2a3c5921-7442-42c3-8cb9-24f21d0b2414" ascii wide
        $typelibguid0up = "2A3C5921-7442-42C3-8CB9-24F21D0B2414" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Random_CSharpTools {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/xorrior/Random-CSharpTools"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-21"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "f7fc19da-67a3-437d-b3b0-2a257f77a00b" ascii wide
        $typelibguid0up = "F7FC19DA-67A3-437D-B3B0-2A257F77A00B" ascii wide
        $typelibguid1lo = "47e85bb6-9138-4374-8092-0aeb301fe64b" ascii wide
        $typelibguid1up = "47E85BB6-9138-4374-8092-0AEB301FE64B" ascii wide
        $typelibguid2lo = "c7d854d8-4e3a-43a6-872f-e0710e5943f7" ascii wide
        $typelibguid2up = "C7D854D8-4E3A-43A6-872F-E0710E5943F7" ascii wide
        $typelibguid3lo = "d6685430-8d8d-4e2e-b202-de14efa25211" ascii wide
        $typelibguid3up = "D6685430-8D8D-4E2E-B202-DE14EFA25211" ascii wide
        $typelibguid4lo = "1df925fc-9a89-4170-b763-1c735430b7d0" ascii wide
        $typelibguid4up = "1DF925FC-9A89-4170-B763-1C735430B7D0" ascii wide
        $typelibguid5lo = "817cc61b-8471-4c1e-b5d6-c754fc550a03" ascii wide
        $typelibguid5up = "817CC61B-8471-4C1E-B5D6-C754FC550A03" ascii wide
        $typelibguid6lo = "60116613-c74e-41b9-b80e-35e02f25891e" ascii wide
        $typelibguid6up = "60116613-C74E-41B9-B80E-35E02F25891E" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_CVE_2020_0668 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/RedCursorSecurityConsulting/CVE-2020-0668"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "1b4c5ec1-2845-40fd-a173-62c450f12ea5" ascii wide
        $typelibguid0up = "1B4C5EC1-2845-40FD-A173-62C450F12EA5" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_WindowsRpcClients {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/tyranid/WindowsRpcClients"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "843d8862-42eb-49ee-94e6-bca798dd33ea" ascii wide
        $typelibguid0up = "843D8862-42EB-49EE-94E6-BCA798DD33EA" ascii wide
        $typelibguid1lo = "632e4c3b-3013-46fc-bc6e-22828bf629e3" ascii wide
        $typelibguid1up = "632E4C3B-3013-46FC-BC6E-22828BF629E3" ascii wide
        $typelibguid2lo = "a2091d2f-6f7e-4118-a203-4cea4bea6bfa" ascii wide
        $typelibguid2up = "A2091D2F-6F7E-4118-A203-4CEA4BEA6BFA" ascii wide
        $typelibguid3lo = "950ef8ce-ec92-4e02-b122-0d41d83065b8" ascii wide
        $typelibguid3up = "950EF8CE-EC92-4E02-B122-0D41D83065B8" ascii wide
        $typelibguid4lo = "d51301bc-31aa-4475-8944-882ecf80e10d" ascii wide
        $typelibguid4up = "D51301BC-31AA-4475-8944-882ECF80E10D" ascii wide
        $typelibguid5lo = "823ff111-4de2-4637-af01-4bdc3ca4cf15" ascii wide
        $typelibguid5up = "823FF111-4DE2-4637-AF01-4BDC3CA4CF15" ascii wide
        $typelibguid6lo = "5d28f15e-3bb8-4088-abe0-b517b31d4595" ascii wide
        $typelibguid6up = "5D28F15E-3BB8-4088-ABE0-B517B31D4595" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpFruit {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/rvrsh3ll/SharpFruit"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "3da2f6de-75be-4c9d-8070-08da45e79761" ascii wide
        $typelibguid0up = "3DA2F6DE-75BE-4C9D-8070-08DA45E79761" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpWitness {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/rasta-mouse/SharpWitness"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "b9f6ec34-4ccc-4247-bcef-c1daab9b4469" ascii wide
        $typelibguid0up = "B9F6EC34-4CCC-4247-BCEF-C1DAAB9B4469" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_RexCrypter {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/syrex1013/RexCrypter"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "10cd7c1c-e56d-4b1b-80dc-e4c496c5fec5" ascii wide
        $typelibguid0up = "10CD7C1C-E56D-4B1B-80DC-E4C496C5FEC5" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharPersist {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/fireeye/SharPersist"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "9d1b853e-58f1-4ba5-aefc-5c221ca30e48" ascii wide
        $typelibguid0up = "9D1B853E-58F1-4BA5-AEFC-5C221CA30E48" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_CVE_2019_1253 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/padovah4ck/CVE-2019-1253"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "584964c1-f983-498d-8370-23e27fdd0399" ascii wide
        $typelibguid0up = "584964C1-F983-498D-8370-23E27FDD0399" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_scout {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/jaredhaight/scout"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "d9c76e82-b848-47d4-8f22-99bf22a8ee11" ascii wide
        $typelibguid0up = "D9C76E82-B848-47D4-8F22-99BF22A8EE11" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Grouper2 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/l0ss/Grouper2/"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "5decaea3-2610-4065-99dc-65b9b4ba6ccd" ascii wide
        $typelibguid0up = "5DECAEA3-2610-4065-99DC-65B9B4BA6CCD" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_CasperStager {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/ustayready/CasperStager"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "c653a9f2-0939-43c8-9b93-fed5e2e4c7e6" ascii wide
        $typelibguid0up = "C653A9F2-0939-43C8-9B93-FED5E2E4C7E6" ascii wide
        $typelibguid1lo = "48dfc55e-6ae5-4a36-abef-14bc09d7510b" ascii wide
        $typelibguid1up = "48DFC55E-6AE5-4A36-ABEF-14BC09D7510B" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_TellMeYourSecrets {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/0xbadjuju/TellMeYourSecrets"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "9b448062-7219-4d82-9a0a-e784c4b3aa27" ascii wide
        $typelibguid0up = "9B448062-7219-4D82-9A0A-E784C4B3AA27" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpExcel4_DCOM {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/rvrsh3ll/SharpExcel4-DCOM"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "68b83ce5-bbd9-4ee3-b1cc-5e9223fab52b" ascii wide
        $typelibguid0up = "68B83CE5-BBD9-4EE3-B1CC-5E9223FAB52B" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpShooter {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/mdsecactivebreach/SharpShooter"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "56598f1c-6d88-4994-a392-af337abe5777" ascii wide
        $typelibguid0up = "56598F1C-6D88-4994-A392-AF337ABE5777" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_NoMSBuild {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/rvrsh3ll/NoMSBuild"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "034a7b9f-18df-45da-b870-0e1cef500215" ascii wide
        $typelibguid0up = "034A7B9F-18DF-45DA-B870-0E1CEF500215" ascii wide
        $typelibguid1lo = "59b449d7-c1e8-4f47-80b8-7375178961db" ascii wide
        $typelibguid1up = "59B449D7-C1E8-4F47-80B8-7375178961DB" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_TeleShadow2 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/ParsingTeam/TeleShadow2"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "42c5c356-39cf-4c07-96df-ebb0ccf78ca4" ascii wide
        $typelibguid0up = "42C5C356-39CF-4C07-96DF-EBB0CCF78CA4" ascii wide
        $typelibguid1lo = "0242b5b1-4d26-413e-8c8c-13b4ed30d510" ascii wide
        $typelibguid1up = "0242B5B1-4D26-413E-8C8C-13B4ED30D510" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_BadPotato {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/BeichenDream/BadPotato"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "0527a14f-1591-4d94-943e-d6d784a50549" ascii wide
        $typelibguid0up = "0527A14F-1591-4D94-943E-D6D784A50549" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_LethalHTA {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/codewhitesec/LethalHTA"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "784cde17-ff0f-4e43-911a-19119e89c43f" ascii wide
        $typelibguid0up = "784CDE17-FF0F-4E43-911A-19119E89C43F" ascii wide
        $typelibguid1lo = "7e2de2c0-61dc-43ab-a0ec-c27ee2172ea6" ascii wide
        $typelibguid1up = "7E2DE2C0-61DC-43AB-A0EC-C27EE2172EA6" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpStat {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Raikia/SharpStat"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "ffc5c721-49c8-448d-8ff4-2e3a7b7cc383" ascii wide
        $typelibguid0up = "FFC5C721-49C8-448D-8FF4-2E3A7B7CC383" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SneakyService {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/malcomvetter/SneakyService"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "897819d5-58e0-46a0-8e1a-91ea6a269d84" ascii wide
        $typelibguid0up = "897819D5-58E0-46A0-8E1A-91EA6A269D84" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpExec {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/anthemtotheego/SharpExec"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "7fbad126-e21c-4c4e-a9f0-613fcf585a71" ascii wide
        $typelibguid0up = "7FBAD126-E21C-4C4E-A9F0-613FCF585A71" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpCOM {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/rvrsh3ll/SharpCOM"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "51960f7d-76fe-499f-afbd-acabd7ba50d1" ascii wide
        $typelibguid0up = "51960F7D-76FE-499F-AFBD-ACABD7BA50D1" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Inception {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/two06/Inception"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "03d96b8c-efd1-44a9-8db2-0b74db5d247a" ascii wide
        $typelibguid0up = "03D96B8C-EFD1-44A9-8DB2-0B74DB5D247A" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_sharpwmi {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/QAX-A-Team/sharpwmi"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "bb357d38-6dc1-4f20-a54c-d664bd20677e" ascii wide
        $typelibguid0up = "BB357D38-6DC1-4F20-A54C-D664BD20677E" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_CVE_2019_1064 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/RythmStick/CVE-2019-1064"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "ff97e98a-635e-4ea9-b2d0-1a13f6bdbc38" ascii wide
        $typelibguid0up = "FF97E98A-635E-4EA9-B2D0-1A13F6BDBC38" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Tokenvator {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/0xbadjuju/Tokenvator"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "4b2b3bd4-d28f-44cc-96b3-4a2f64213109" ascii wide
        $typelibguid0up = "4B2B3BD4-D28F-44CC-96B3-4A2F64213109" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_WheresMyImplant {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/0xbadjuju/WheresMyImplant"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "cca59e4e-ce4d-40fc-965f-34560330c7e6" ascii wide
        $typelibguid0up = "CCA59E4E-CE4D-40FC-965F-34560330C7E6" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Naga {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/byt3bl33d3r/Naga"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "99428732-4979-47b6-a323-0bb7d6d07c95" ascii wide
        $typelibguid0up = "99428732-4979-47B6-A323-0BB7D6D07C95" ascii wide
        $typelibguid1lo = "a2c9488f-6067-4b17-8c6f-2d464e65c535" ascii wide
        $typelibguid1up = "A2C9488F-6067-4B17-8C6F-2D464E65C535" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpBox {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/P1CKLES/SharpBox"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "616c1afb-2944-42ed-9951-bf435cadb600" ascii wide
        $typelibguid0up = "616C1AFB-2944-42ED-9951-BF435CADB600" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_rundotnetdll32 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/0xbadjuju/rundotnetdll32"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "a766db28-94b6-4ed1-aef9-5200bbdd8ca7" ascii wide
        $typelibguid0up = "A766DB28-94B6-4ED1-AEF9-5200BBDD8CA7" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_AntiDebug {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/malcomvetter/AntiDebug"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "997265c1-1342-4d44-aded-67964a32f859" ascii wide
        $typelibguid0up = "997265C1-1342-4D44-ADED-67964A32F859" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DInvisibleRegistry {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NVISO-BE/DInvisibleRegistry"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "31d576fb-9fb9-455e-ab02-c78981634c65" ascii wide
        $typelibguid0up = "31D576FB-9FB9-455E-AB02-C78981634C65" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_TikiTorch {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/rasta-mouse/TikiTorch"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "806c6c72-4adc-43d9-b028-6872fa48d334" ascii wide
        $typelibguid0up = "806C6C72-4ADC-43D9-B028-6872FA48D334" ascii wide
        $typelibguid1lo = "2ef9d8f7-6b77-4b75-822b-6a53a922c30f" ascii wide
        $typelibguid1up = "2EF9D8F7-6B77-4B75-822B-6A53A922C30F" ascii wide
        $typelibguid2lo = "8f5f3a95-f05c-4dce-8bc3-d0a0d4153db6" ascii wide
        $typelibguid2up = "8F5F3A95-F05C-4DCE-8BC3-D0A0D4153DB6" ascii wide
        $typelibguid3lo = "1f707405-9708-4a34-a809-2c62b84d4f0a" ascii wide
        $typelibguid3up = "1F707405-9708-4A34-A809-2C62B84D4F0A" ascii wide
        $typelibguid4lo = "97421325-b6d8-49e5-adf0-e2126abc17ee" ascii wide
        $typelibguid4up = "97421325-B6D8-49E5-ADF0-E2126ABC17EE" ascii wide
        $typelibguid5lo = "06c247da-e2e1-47f3-bc3c-da0838a6df1f" ascii wide
        $typelibguid5up = "06C247DA-E2E1-47F3-BC3C-DA0838A6DF1F" ascii wide
        $typelibguid6lo = "fc700ac6-5182-421f-8853-0ad18cdbeb39" ascii wide
        $typelibguid6up = "FC700AC6-5182-421F-8853-0AD18CDBEB39" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_HiveJack {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Viralmaniar/HiveJack"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "e12e62fe-bea3-4989-bf04-6f76028623e3" ascii wide
        $typelibguid0up = "E12E62FE-BEA3-4989-BF04-6F76028623E3" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DecryptAutoLogon {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/securesean/DecryptAutoLogon"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "015a37fc-53d0-499b-bffe-ab88c5086040" ascii wide
        $typelibguid0up = "015A37FC-53D0-499B-BFFE-AB88C5086040" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_UnstoppableService {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/malcomvetter/UnstoppableService"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "0c117ee5-2a21-dead-beef-8cc7f0caaa86" ascii wide
        $typelibguid0up = "0C117EE5-2A21-DEAD-BEEF-8CC7F0CAAA86" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpWMI {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/GhostPack/SharpWMI"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "6dd22880-dac5-4b4d-9c91-8c35cc7b8180" ascii wide
        $typelibguid0up = "6DD22880-DAC5-4B4D-9C91-8C35CC7B8180" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_EWSToolkit {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/rasta-mouse/EWSToolkit"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "ca536d67-53c9-43b5-8bc8-9a05fdc567ed" ascii wide
        $typelibguid0up = "CA536D67-53C9-43B5-8BC8-9A05FDC567ED" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SweetPotato {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/CCob/SweetPotato"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "6aeb5004-6093-4c23-aeae-911d64cacc58" ascii wide
        $typelibguid0up = "6AEB5004-6093-4C23-AEAE-911D64CACC58" ascii wide
        $typelibguid1lo = "1bf9c10f-6f89-4520-9d2e-aaf17d17ba5e" ascii wide
        $typelibguid1up = "1BF9C10F-6F89-4520-9D2E-AAF17D17BA5E" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_memscan {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/nccgroup/memscan"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "79462f87-8418-4834-9356-8c11e44ce189" ascii wide
        $typelibguid0up = "79462F87-8418-4834-9356-8C11E44CE189" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpStay {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/0xthirteen/SharpStay"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "2963c954-7b1e-47f5-b4fa-2fc1f0d56aea" ascii wide
        $typelibguid0up = "2963C954-7B1E-47F5-B4FA-2FC1F0D56AEA" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpLocker {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Pickfordmatt/SharpLocker"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "a6f8500f-68bc-4efc-962a-6c6e68d893af" ascii wide
        $typelibguid0up = "A6F8500F-68BC-4EFC-962A-6C6E68D893AF" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SauronEye {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/vivami/SauronEye"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "0f43043d-8957-4ade-a0f4-25c1122e8118" ascii wide
        $typelibguid0up = "0F43043D-8957-4ADE-A0F4-25C1122E8118" ascii wide
        $typelibguid1lo = "086bf0ca-f1e4-4e8f-9040-a8c37a49fa26" ascii wide
        $typelibguid1up = "086BF0CA-F1E4-4E8F-9040-A8C37A49FA26" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_sitrep {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/mdsecactivebreach/sitrep"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "12963497-988f-46c0-9212-28b4b2b1831b" ascii wide
        $typelibguid0up = "12963497-988F-46C0-9212-28B4B2B1831B" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpClipboard {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/slyd0g/SharpClipboard"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "97484211-4726-4129-86aa-ae01d17690be" ascii wide
        $typelibguid0up = "97484211-4726-4129-86AA-AE01D17690BE" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpCookieMonster {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/m0rv4i/SharpCookieMonster"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "566c5556-1204-4db9-9dc8-a24091baaa8e" ascii wide
        $typelibguid0up = "566C5556-1204-4DB9-9DC8-A24091BAAA8E" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_p0wnedShell {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Cn33liz/p0wnedShell"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "2e9b1462-f47c-48ca-9d85-004493892381" ascii wide
        $typelibguid0up = "2E9B1462-F47C-48CA-9D85-004493892381" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpMove {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/0xthirteen/SharpMove"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "8bf82bbe-909c-4777-a2fc-ea7c070ff43e" ascii wide
        $typelibguid0up = "8BF82BBE-909C-4777-A2FC-EA7C070FF43E" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_C_Sharp_R_A_T_Client {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/AdvancedHacker101/C-Sharp-R.A.T-Client"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "6d9e8852-e86c-4e36-9cb4-b3c3853ed6b8" ascii wide
        $typelibguid0up = "6D9E8852-E86C-4E36-9CB4-B3C3853ED6B8" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpPrinter {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/rvrsh3ll/SharpPrinter"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "41b2d1e5-4c5d-444c-aa47-629955401ed9" ascii wide
        $typelibguid0up = "41B2D1E5-4C5D-444C-AA47-629955401ED9" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_EvilFOCA {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/ElevenPaths/EvilFOCA"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "f26bdb4a-5846-4bec-8f52-3c39d32df495" ascii wide
        $typelibguid0up = "F26BDB4A-5846-4BEC-8F52-3C39D32DF495" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_PoshC2_Misc {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/nettitude/PoshC2_Misc"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "85773eb7-b159-45fe-96cd-11bad51da6de" ascii wide
        $typelibguid0up = "85773EB7-B159-45FE-96CD-11BAD51DA6DE" ascii wide
        $typelibguid1lo = "9d32ad59-4093-420d-b45c-5fff391e990d" ascii wide
        $typelibguid1up = "9D32AD59-4093-420D-B45C-5FFF391E990D" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Sharpire {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/0xbadjuju/Sharpire"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "39b75120-07fe-4833-a02e-579ff8b68331" ascii wide
        $typelibguid0up = "39B75120-07FE-4833-A02E-579FF8B68331" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Sharp_SMBExec {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/checkymander/Sharp-SMBExec"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "344ee55a-4e32-46f2-a003-69ad52b55945" ascii wide
        $typelibguid0up = "344EE55A-4E32-46F2-A003-69AD52B55945" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_MiscTools {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/rasta-mouse/MiscTools"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "384e9647-28a9-4835-8fa7-2472b1acedc0" ascii wide
        $typelibguid0up = "384E9647-28A9-4835-8FA7-2472B1ACEDC0" ascii wide
        $typelibguid1lo = "d7ec0ef5-157c-4533-bbcd-0fe070fbf8d9" ascii wide
        $typelibguid1up = "D7EC0EF5-157C-4533-BBCD-0FE070FBF8D9" ascii wide
        $typelibguid2lo = "10085d98-48b9-42a8-b15b-cb27a243761b" ascii wide
        $typelibguid2up = "10085D98-48B9-42A8-B15B-CB27A243761B" ascii wide
        $typelibguid3lo = "6aacd159-f4e7-4632-bad1-2ae8526a9633" ascii wide
        $typelibguid3up = "6AACD159-F4E7-4632-BAD1-2AE8526A9633" ascii wide
        $typelibguid4lo = "49a6719e-11a8-46e6-ad7a-1db1be9fea37" ascii wide
        $typelibguid4up = "49A6719E-11A8-46E6-AD7A-1DB1BE9FEA37" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_MemoryMapper {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/jasondrawdy/MemoryMapper"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "b9fbf3ac-05d8-4cd5-9694-b224d4e6c0ea" ascii wide
        $typelibguid0up = "B9FBF3AC-05D8-4CD5-9694-B224D4E6C0EA" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_VanillaRAT {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/DannyTheSloth/VanillaRAT"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "d0f2ee67-0a50-423d-bfe6-845da892a2db" ascii wide
        $typelibguid0up = "D0F2EE67-0A50-423D-BFE6-845DA892A2DB" ascii wide
        $typelibguid1lo = "a593fcd2-c8ab-45f6-9aeb-8ab5e20ab402" ascii wide
        $typelibguid1up = "A593FCD2-C8AB-45F6-9AEB-8AB5E20AB402" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_UnmanagedPowerShell {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/leechristensen/UnmanagedPowerShell"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "dfc4eebb-7384-4db5-9bad-257203029bd9" ascii wide
        $typelibguid0up = "DFC4EEBB-7384-4DB5-9BAD-257203029BD9" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Quasar {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/quasar/Quasar"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "cfda6d2e-8ab3-4349-b89a-33e1f0dab32b" ascii wide
        $typelibguid0up = "CFDA6D2E-8AB3-4349-B89A-33E1F0DAB32B" ascii wide
        $typelibguid1lo = "c7c363ba-e5b6-4e18-9224-39bc8da73172" ascii wide
        $typelibguid1up = "C7C363BA-E5B6-4E18-9224-39BC8DA73172" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpAdidnsdump {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/b4rtik/SharpAdidnsdump"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "cdb02bc2-5f62-4c8a-af69-acc3ab82e741" ascii wide
        $typelibguid0up = "CDB02BC2-5F62-4C8A-AF69-ACC3AB82E741" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DotNetToJScript {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/tyranid/DotNetToJScript"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "7e3f231c-0d0b-4025-812c-0ef099404861" ascii wide
        $typelibguid0up = "7E3F231C-0D0B-4025-812C-0EF099404861" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Inferno {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/LimerBoy/Inferno"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "26d498f7-37ae-476c-97b0-3761e3a919f0" ascii wide
        $typelibguid0up = "26D498F7-37AE-476C-97B0-3761E3A919F0" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpSearch {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/djhohnstein/SharpSearch"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "98fee742-8410-4f20-8b2d-d7d789ab003d" ascii wide
        $typelibguid0up = "98FEE742-8410-4F20-8B2D-D7D789AB003D" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpSecDump {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/G0ldenGunSec/SharpSecDump"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "e2fdd6cc-9886-456c-9021-ee2c47cf67b7" ascii wide
        $typelibguid0up = "E2FDD6CC-9886-456C-9021-EE2C47CF67B7" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Net_GPPPassword {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/outflanknl/Net-GPPPassword"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "00fcf72c-d148-4dd0-9ca4-0181c4bd55c3" ascii wide
        $typelibguid0up = "00FCF72C-D148-4DD0-9CA4-0181C4BD55C3" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_FileSearcher {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NVISO-BE/FileSearcher"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "2c879479-5027-4ce9-aaac-084db0e6d630" ascii wide
        $typelibguid0up = "2C879479-5027-4CE9-AAAC-084DB0E6D630" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_ADFSDump {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/fireeye/ADFSDump"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "9ee27d63-6ac9-4037-860b-44e91bae7f0d" ascii wide
        $typelibguid0up = "9EE27D63-6AC9-4037-860B-44E91BAE7F0D" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpRDP {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/0xthirteen/SharpRDP"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "f1df1d0f-ff86-4106-97a8-f95aaf525c54" ascii wide
        $typelibguid0up = "F1DF1D0F-FF86-4106-97A8-F95AAF525C54" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpCall {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/jhalon/SharpCall"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "c1b0a923-0f17-4bc8-ba0f-c87aff43e799" ascii wide
        $typelibguid0up = "C1B0A923-0F17-4BC8-BA0F-C87AFF43E799" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_ysoserial_net {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/pwntester/ysoserial.net"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "e1e8c029-f7cd-4bd1-952e-e819b41520f0" ascii wide
        $typelibguid0up = "E1E8C029-F7CD-4BD1-952E-E819B41520F0" ascii wide
        $typelibguid1lo = "6b40fde7-14ea-4f57-8b7b-cc2eb4a25e6c" ascii wide
        $typelibguid1up = "6B40FDE7-14EA-4F57-8B7B-CC2EB4A25E6C" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_ManagedInjection {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/malcomvetter/ManagedInjection"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "e5182bff-9562-40ff-b864-5a6b30c3b13b" ascii wide
        $typelibguid0up = "E5182BFF-9562-40FF-B864-5A6B30C3B13B" ascii wide
        $typelibguid1lo = "fdedde0d-e095-41c9-93fb-c2219ada55b1" ascii wide
        $typelibguid1up = "FDEDDE0D-E095-41C9-93FB-C2219ADA55B1" ascii wide
        $typelibguid2lo = "0dd00561-affc-4066-8c48-ce950788c3c8" ascii wide
        $typelibguid2up = "0DD00561-AFFC-4066-8C48-CE950788C3C8" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpSocks {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/nettitude/SharpSocks"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "2f43992e-5703-4420-ad0b-17cb7d89c956" ascii wide
        $typelibguid0up = "2F43992E-5703-4420-AD0B-17CB7D89C956" ascii wide
        $typelibguid1lo = "86d10a34-c374-4de4-8e12-490e5e65ddff" ascii wide
        $typelibguid1up = "86D10A34-C374-4DE4-8E12-490E5E65DDFF" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Sharp_WMIExec {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/checkymander/Sharp-WMIExec"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "0a63b0a1-7d1a-4b84-81c3-bbbfe9913029" ascii wide
        $typelibguid0up = "0A63B0A1-7D1A-4B84-81C3-BBBFE9913029" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_KeeThief {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/GhostPack/KeeThief"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid1lo = "39aa6f93-a1c9-497f-bad2-cc42a61d5710" ascii wide
        $typelibguid1up = "39AA6F93-A1C9-497F-BAD2-CC42A61D5710" ascii wide
        $typelibguid3lo = "3fca8012-3bad-41e4-91f4-534aa9a44f96" ascii wide
        $typelibguid3up = "3FCA8012-3BAD-41E4-91F4-534AA9A44F96" ascii wide
        $typelibguid4lo = "ea92f1e6-3f34-48f8-8b0a-f2bbc19220ef" ascii wide
        $typelibguid4up = "EA92F1E6-3F34-48F8-8B0A-F2BBC19220EF" ascii wide
        $typelibguid5lo = "c23b51c4-2475-4fc6-9b3a-27d0a2b99b0f" ascii wide
        $typelibguid5up = "C23B51C4-2475-4FC6-9B3A-27D0A2B99B0F" ascii wide
        /* $typelibguid6 = "94432a8e-3e06-4776-b9b2-3684a62bb96a" ascii nocase wide FIX FPS with Microsoft files */ 
        $typelibguid7lo = "80ba63a4-7d41-40e9-a722-6dd58b28bf7e" ascii wide
        $typelibguid7up = "80BA63A4-7D41-40E9-A722-6DD58B28BF7E" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_fakelogonscreen {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/bitsadmin/fakelogonscreen"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "d35a55bd-3189-498b-b72f-dc798172e505" ascii wide
        $typelibguid0up = "D35A55BD-3189-498B-B72F-DC798172E505" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_PoshSecFramework {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/PoshSec/PoshSecFramework"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "b1ac6aa0-2f1a-4696-bf4b-0e41cf2f4b6b" ascii wide
        $typelibguid0up = "B1AC6AA0-2F1A-4696-BF4B-0E41CF2F4B6B" ascii wide
        $typelibguid1lo = "78bfcfc2-ef1c-4514-bce6-934b251666d2" ascii wide
        $typelibguid1up = "78BFCFC2-EF1C-4514-BCE6-934B251666D2" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpAttack {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/jaredhaight/SharpAttack"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "5f0ceca3-5997-406c-adf5-6c7fbb6cba17" ascii wide
        $typelibguid0up = "5F0CECA3-5997-406C-ADF5-6C7FBB6CBA17" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Altman {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/keepwn/Altman"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "64cdcd2b-7356-4079-af78-e22210e66154" ascii wide
        $typelibguid0up = "64CDCD2B-7356-4079-AF78-E22210E66154" ascii wide
        $typelibguid1lo = "f1dee29d-ca98-46ea-9d13-93ae1fda96e1" ascii wide
        $typelibguid1up = "F1DEE29D-CA98-46EA-9D13-93AE1FDA96E1" ascii wide
        $typelibguid2lo = "33568320-56e8-4abb-83f8-548e8d6adac2" ascii wide
        $typelibguid2up = "33568320-56E8-4ABB-83F8-548E8D6ADAC2" ascii wide
        $typelibguid3lo = "470ec930-70a3-4d71-b4ff-860fcb900e85" ascii wide
        $typelibguid3up = "470EC930-70A3-4D71-B4FF-860FCB900E85" ascii wide
        $typelibguid4lo = "9514574d-6819-44f2-affa-6158ac1143b3" ascii wide
        $typelibguid4up = "9514574D-6819-44F2-AFFA-6158AC1143B3" ascii wide
        $typelibguid5lo = "0f3a9c4f-0b11-4373-a0a6-3a6de814e891" ascii wide
        $typelibguid5up = "0F3A9C4F-0B11-4373-A0A6-3A6DE814E891" ascii wide
        $typelibguid6lo = "9624b72e-9702-4d78-995b-164254328151" ascii wide
        $typelibguid6up = "9624B72E-9702-4D78-995B-164254328151" ascii wide
        $typelibguid7lo = "faae59a8-55fc-48b1-a9b5-b1759c9c1010" ascii wide
        $typelibguid7up = "FAAE59A8-55FC-48B1-A9B5-B1759C9C1010" ascii wide
        $typelibguid8lo = "37af4988-f6f2-4f0c-aa2b-5b24f7ed3bf3" ascii wide
        $typelibguid8up = "37AF4988-F6F2-4F0C-AA2B-5B24F7ED3BF3" ascii wide
        $typelibguid9lo = "c82aa2fe-3332-441f-965e-6b653e088abf" ascii wide
        $typelibguid9up = "C82AA2FE-3332-441F-965E-6B653E088ABF" ascii wide
        $typelibguid10lo = "6e531f6c-2c89-447f-8464-aaa96dbcdfff" ascii wide
        $typelibguid10up = "6E531F6C-2C89-447F-8464-AAA96DBCDFFF" ascii wide
        $typelibguid11lo = "231987a1-ea32-4087-8963-2322338f16f6" ascii wide
        $typelibguid11up = "231987A1-EA32-4087-8963-2322338F16F6" ascii wide
        $typelibguid12lo = "7da0d93a-a0ae-41a5-9389-42eff85bb064" ascii wide
        $typelibguid12up = "7DA0D93A-A0AE-41A5-9389-42EFF85BB064" ascii wide
        $typelibguid13lo = "a729f9cc-edc2-4785-9a7d-7b81bb12484c" ascii wide
        $typelibguid13up = "A729F9CC-EDC2-4785-9A7D-7B81BB12484C" ascii wide
        $typelibguid14lo = "55a1fd43-d23e-4d72-aadb-bbd1340a6913" ascii wide
        $typelibguid14up = "55A1FD43-D23E-4D72-AADB-BBD1340A6913" ascii wide
        $typelibguid15lo = "d43f240d-e7f5-43c5-9b51-d156dc7ea221" ascii wide
        $typelibguid15up = "D43F240D-E7F5-43C5-9B51-D156DC7EA221" ascii wide
        $typelibguid16lo = "c2e6c1a0-93b1-4bbc-98e6-8e2b3145db8e" ascii wide
        $typelibguid16up = "C2E6C1A0-93B1-4BBC-98E6-8E2B3145DB8E" ascii wide
        $typelibguid17lo = "714ae6f3-0d03-4023-b753-fed6a31d95c7" ascii wide
        $typelibguid17up = "714AE6F3-0D03-4023-B753-FED6A31D95C7" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_BrowserPass {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/jabiel/BrowserPass"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "3cb59871-0dce-453b-857a-2d1e515b0b66" ascii wide
        $typelibguid0up = "3CB59871-0DCE-453B-857A-2D1E515B0B66" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Mythic {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/its-a-feature/Mythic"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-29"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "91f7a9da-f045-4239-a1e9-487ffdd65986" ascii wide
        $typelibguid0up = "91F7A9DA-F045-4239-A1E9-487FFDD65986" ascii wide
        $typelibguid1lo = "0405205c-c2a0-4f9a-a221-48b5c70df3b6" ascii wide
        $typelibguid1up = "0405205C-C2A0-4F9A-A221-48B5C70DF3B6" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Nuages {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/p3nt4/Nuages"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-29"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "e9e80ac7-4c13-45bd-9bde-ca89aadf1294" ascii wide
        $typelibguid0up = "E9E80AC7-4C13-45BD-9BDE-CA89AADF1294" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpSniper {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/HunnicCyber/SharpSniper"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-29"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "c8bb840c-04ce-4b60-a734-faf15abf7b18" ascii wide
        $typelibguid0up = "C8BB840C-04CE-4B60-A734-FAF15ABF7B18" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpHound3 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/BloodHoundAD/SharpHound3"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-29"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "a517a8de-5834-411d-abda-2d0e1766539c" ascii wide
        $typelibguid0up = "A517A8DE-5834-411D-ABDA-2D0E1766539C" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_BlockEtw {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Soledge/BlockEtw"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-29"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "daedf7b3-8262-4892-adc4-425dd5f85bca" ascii wide
        $typelibguid0up = "DAEDF7B3-8262-4892-ADC4-425DD5F85BCA" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpWifiGrabber {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/r3nhat/SharpWifiGrabber"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-29"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "c0997698-2b73-4982-b25b-d0578d1323c2" ascii wide
        $typelibguid0up = "C0997698-2B73-4982-B25B-D0578D1323C2" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpMapExec {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/cube0x0/SharpMapExec"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-29"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "bd5220f7-e1fb-41d2-91ec-e4c50c6e9b9f" ascii wide
        $typelibguid0up = "BD5220F7-E1FB-41D2-91EC-E4C50C6E9B9F" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_k8fly {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/zzwlpx/k8fly"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-29"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "13b6c843-f3d4-4585-b4f3-e2672a47931e" ascii wide
        $typelibguid0up = "13B6C843-F3D4-4585-B4F3-E2672A47931E" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Stealer {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/malwares/Stealer"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-29"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "8fcd4931-91a2-4e18-849b-70de34ab75df" ascii wide
        $typelibguid0up = "8FCD4931-91A2-4E18-849B-70DE34AB75DF" ascii wide
        $typelibguid1lo = "e48811ca-8af8-4e73-85dd-2045b9cca73a" ascii wide
        $typelibguid1up = "E48811CA-8AF8-4E73-85DD-2045B9CCA73A" ascii wide
        $typelibguid2lo = "d3d8a1cc-e123-4905-b3de-374749122fcf" ascii wide
        $typelibguid2up = "D3D8A1CC-E123-4905-B3DE-374749122FCF" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_PortTran {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/k8gege/PortTran"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-29"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "3a074374-77e8-4312-8746-37f3cb00e82c" ascii wide
        $typelibguid0up = "3A074374-77E8-4312-8746-37F3CB00E82C" ascii wide
        $typelibguid1lo = "67a73bac-f59d-4227-9220-e20a2ef42782" ascii wide
        $typelibguid1up = "67A73BAC-F59D-4227-9220-E20A2EF42782" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}


rule HKTL_NET_GUID_gray_keylogger_2 {
    meta:
        description = "Detects VB.NET red/black-team tools via typelibguid"
        reference = "https://github.com/graysuit/gray-keylogger-2"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-30"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "e94ca3ff-c0e5-4d1a-ad5e-f6ebbe365067" ascii wide
        $typelibguid0up = "E94CA3FF-C0E5-4D1A-AD5E-F6EBBE365067" ascii wide
        $typelibguid1lo = "1ed07564-b411-4626-88e5-e1cd8ecd860a" ascii wide
        $typelibguid1up = "1ED07564-B411-4626-88E5-E1CD8ECD860A" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Lime_Miner {
    meta:
        description = "Detects VB.NET red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/Lime-Miner"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-30"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "13958fb9-dfc1-4e2c-8a8d-a5e68abdbc66" ascii wide
        $typelibguid0up = "13958FB9-DFC1-4E2C-8A8D-A5E68ABDBC66" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_BlackNET {
    meta:
        description = "Detects VB.NET red/black-team tools via typelibguid"
        reference = "https://github.com/BlackHacker511/BlackNET"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-30"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "c2b90883-abee-4cfa-af66-dfd93ec617a5" ascii wide
        $typelibguid0up = "C2B90883-ABEE-4CFA-AF66-DFD93EC617A5" ascii wide
        $typelibguid1lo = "8bb6f5b4-e7c7-4554-afd1-48f368774837" ascii wide
        $typelibguid1up = "8BB6F5B4-E7C7-4554-AFD1-48F368774837" ascii wide
        $typelibguid2lo = "983ae28c-91c3-4072-8cdf-698b2ff7a967" ascii wide
        $typelibguid2up = "983AE28C-91C3-4072-8CDF-698B2FF7A967" ascii wide
        $typelibguid3lo = "9ac18cdc-3711-4719-9cfb-5b5f2d51fd5a" ascii wide
        $typelibguid3up = "9AC18CDC-3711-4719-9CFB-5B5F2D51FD5A" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_PlasmaRAT {
    meta:
        description = "Detects VB.NET red/black-team tools via typelibguid"
        reference = "https://github.com/mwsrc/PlasmaRAT"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-30"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "b8a2147c-074c-46e1-bb99-c8431a6546ce" ascii wide
        $typelibguid0up = "B8A2147C-074C-46E1-BB99-C8431A6546CE" ascii wide
        $typelibguid1lo = "0fcfde33-213f-4fb6-ac15-efb20393d4f3" ascii wide
        $typelibguid1up = "0FCFDE33-213F-4FB6-AC15-EFB20393D4F3" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Lime_RAT {
    meta:
        description = "Detects VB.NET red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/Lime-RAT"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-30"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "e58ac447-ab07-402a-9c96-95e284a76a8d" ascii wide
        $typelibguid0up = "E58AC447-AB07-402A-9C96-95E284A76A8D" ascii wide
        $typelibguid1lo = "8fb35dab-73cd-4163-8868-c4dbcbdf0c17" ascii wide
        $typelibguid1up = "8FB35DAB-73CD-4163-8868-C4DBCBDF0C17" ascii wide
        $typelibguid2lo = "37845f5b-35fe-4dce-bbec-2d07c7904fb0" ascii wide
        $typelibguid2up = "37845F5B-35FE-4DCE-BBEC-2D07C7904FB0" ascii wide
        $typelibguid3lo = "83c453cf-0d29-4690-b9dc-567f20e63894" ascii wide
        $typelibguid3up = "83C453CF-0D29-4690-B9DC-567F20E63894" ascii wide
        $typelibguid4lo = "8b1f0a69-a930-42e3-9c13-7de0d04a4add" ascii wide
        $typelibguid4up = "8B1F0A69-A930-42E3-9C13-7DE0D04A4ADD" ascii wide
        $typelibguid5lo = "eaaeccf6-75d2-4616-b045-36eea09c8b28" ascii wide
        $typelibguid5up = "EAAECCF6-75D2-4616-B045-36EEA09C8B28" ascii wide
        $typelibguid6lo = "5b2ec674-0aa4-4209-94df-b6c995ad59c4" ascii wide
        $typelibguid6up = "5B2EC674-0AA4-4209-94DF-B6C995AD59C4" ascii wide
        $typelibguid7lo = "e2cc7158-aee6-4463-95bf-fb5295e9e37a" ascii wide
        $typelibguid7up = "E2CC7158-AEE6-4463-95BF-FB5295E9E37A" ascii wide
        $typelibguid8lo = "d04ecf62-6da9-4308-804a-e789baa5cc38" ascii wide
        $typelibguid8up = "D04ECF62-6DA9-4308-804A-E789BAA5CC38" ascii wide
        $typelibguid9lo = "8026261f-ac68-4ccf-97b2-3b55b7d6684d" ascii wide
        $typelibguid9up = "8026261F-AC68-4CCF-97B2-3B55B7D6684D" ascii wide
        $typelibguid10lo = "212cdfac-51f1-4045-a5c0-6e638f89fce0" ascii wide
        $typelibguid10up = "212CDFAC-51F1-4045-A5C0-6E638F89FCE0" ascii wide
        $typelibguid11lo = "c1b608bb-7aed-488d-aa3b-0c96625d26c0" ascii wide
        $typelibguid11up = "C1B608BB-7AED-488D-AA3B-0C96625D26C0" ascii wide
        $typelibguid12lo = "4c84e7ec-f197-4321-8862-d5d18783e2fe" ascii wide
        $typelibguid12up = "4C84E7EC-F197-4321-8862-D5D18783E2FE" ascii wide
        $typelibguid13lo = "3fc17adb-67d4-4a8d-8770-ecfd815f73ee" ascii wide
        $typelibguid13up = "3FC17ADB-67D4-4A8D-8770-ECFD815F73EE" ascii wide
        $typelibguid14lo = "f1ab854b-6282-4bdf-8b8b-f2911a008948" ascii wide
        $typelibguid14up = "F1AB854B-6282-4BDF-8B8B-F2911A008948" ascii wide
        $typelibguid15lo = "aef6547e-3822-4f96-9708-bcf008129b2b" ascii wide
        $typelibguid15up = "AEF6547E-3822-4F96-9708-BCF008129B2B" ascii wide
        $typelibguid16lo = "a336f517-bca9-465f-8ff8-2756cfd0cad9" ascii wide
        $typelibguid16up = "A336F517-BCA9-465F-8FF8-2756CFD0CAD9" ascii wide
        $typelibguid17lo = "5de018bd-941d-4a5d-bed5-fbdd111aba76" ascii wide
        $typelibguid17up = "5DE018BD-941D-4A5D-BED5-FBDD111ABA76" ascii wide
        $typelibguid18lo = "bbfac1f9-cd4f-4c44-af94-1130168494d0" ascii wide
        $typelibguid18up = "BBFAC1F9-CD4F-4C44-AF94-1130168494D0" ascii wide
        $typelibguid19lo = "1c79cea1-ebf3-494c-90a8-51691df41b86" ascii wide
        $typelibguid19up = "1C79CEA1-EBF3-494C-90A8-51691DF41B86" ascii wide
        $typelibguid20lo = "927104e1-aa17-4167-817c-7673fe26d46e" ascii wide
        $typelibguid20up = "927104E1-AA17-4167-817C-7673FE26D46E" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_njRAT {
    meta:
        description = "Detects VB.NET red/black-team tools via typelibguid"
        reference = "https://github.com/mwsrc/njRAT"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-30"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "5a542c1b-2d36-4c31-b039-26a88d3967da" ascii wide
        $typelibguid0up = "5A542C1B-2D36-4C31-B039-26A88D3967DA" ascii wide
        $typelibguid1lo = "6b07082a-9256-42c3-999a-665e9de49f33" ascii wide
        $typelibguid1up = "6B07082A-9256-42C3-999A-665E9DE49F33" ascii wide
        $typelibguid2lo = "c0a9a70f-63e8-42ca-965d-73a1bc903e62" ascii wide
        $typelibguid2up = "C0A9A70F-63E8-42CA-965D-73A1BC903E62" ascii wide
        $typelibguid3lo = "70bd11de-7da1-4a89-b459-8daacc930c20" ascii wide
        $typelibguid3up = "70BD11DE-7DA1-4A89-B459-8DAACC930C20" ascii wide
        $typelibguid4lo = "fc790ee5-163a-40f9-a1e2-9863c290ff8b" ascii wide
        $typelibguid4up = "FC790EE5-163A-40F9-A1E2-9863C290FF8B" ascii wide
        $typelibguid5lo = "cb3c28b2-2a4f-4114-941c-ce929fec94d3" ascii wide
        $typelibguid5up = "CB3C28B2-2A4F-4114-941C-CE929FEC94D3" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Manager {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/TheWover/Manager"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021-01-21"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "dda73ee9-0f41-4c09-9cad-8215abd60b33" ascii wide
        $typelibguid0up = "DDA73EE9-0F41-4C09-9CAD-8215ABD60B33" ascii wide
        $typelibguid1lo = "6a0f2422-d4d1-4b7e-84ad-56dc0fd2dfc5" ascii wide
        $typelibguid1up = "6A0F2422-D4D1-4B7E-84AD-56DC0FD2DFC5" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_neo_ConfuserEx {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/XenocodeRCE/neo-ConfuserEx"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021-01-21"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "e98490bb-63e5-492d-b14e-304de928f81a" ascii wide
        $typelibguid0up = "E98490BB-63E5-492D-B14E-304DE928F81A" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpAllowedToAct {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/pkb1s/SharpAllowedToAct"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021-01-21"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "dac5448a-4ad1-490a-846a-18e4e3e0cf9a" ascii wide
        $typelibguid0up = "DAC5448A-4AD1-490A-846A-18E4E3E0CF9A" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SuperSQLInjectionV1 {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/shack2/SuperSQLInjectionV1"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021-01-21"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "d5688068-fc89-467d-913f-037a785caca7" ascii wide
        $typelibguid0up = "D5688068-FC89-467D-913F-037A785CACA7" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_ADSearch {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/tomcarver16/ADSearch"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021-01-21"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "4da5f1b7-8936-4413-91f7-57d6e072b4a7" ascii wide
        $typelibguid0up = "4DA5F1B7-8936-4413-91F7-57D6E072B4A7" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_privilege_escalation_awesome_scripts_suite {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021-01-21"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "1928358e-a64b-493f-a741-ae8e3d029374" ascii wide
        $typelibguid0up = "1928358E-A64B-493F-A741-AE8E3D029374" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_CVE_2020_1206_POC {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/ZecOps/CVE-2020-1206-POC"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021-01-21"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "3523ca04-a12d-4b40-8837-1a1d28ef96de" ascii wide
        $typelibguid0up = "3523CA04-A12D-4B40-8837-1A1D28EF96DE" ascii wide
        $typelibguid1lo = "d3a2f24a-ddc6-4548-9b3d-470e70dbcaab" ascii wide
        $typelibguid1up = "D3A2F24A-DDC6-4548-9B3D-470E70DBCAAB" ascii wide
        $typelibguid2lo = "fb30ee05-4a35-45f7-9a0a-829aec7e47d9" ascii wide
        $typelibguid2up = "FB30EE05-4A35-45F7-9A0A-829AEC7E47D9" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DInvoke {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/TheWover/DInvoke"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021-01-21"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "b77fdab5-207c-4cdb-b1aa-348505c54229" ascii wide
        $typelibguid0up = "B77FDAB5-207C-4CDB-B1AA-348505C54229" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpChisel {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/shantanu561993/SharpChisel"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021-01-21"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "f5f21e2d-eb7e-4146-a7e1-371fd08d6762" ascii wide
        $typelibguid0up = "F5F21E2D-EB7E-4146-A7E1-371FD08D6762" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpScribbles {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/V1V1/SharpScribbles"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021-01-21"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "aa61a166-31ef-429d-a971-ca654cd18c3b" ascii wide
        $typelibguid0up = "AA61A166-31EF-429D-A971-CA654CD18C3B" ascii wide
        $typelibguid1lo = "0dc1b824-c6e7-4881-8788-35aecb34d227" ascii wide
        $typelibguid1up = "0DC1B824-C6E7-4881-8788-35AECB34D227" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpReg {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/jnqpblc/SharpReg"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021-01-21"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "8ef25b00-ed6a-4464-bdec-17281a4aa52f" ascii wide
        $typelibguid0up = "8EF25B00-ED6A-4464-BDEC-17281A4AA52F" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_MemeVM {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/TobitoFatitoRE/MemeVM"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021-01-21"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "ef18f7f2-1f03-481c-98f9-4a18a2f12c11" ascii wide
        $typelibguid0up = "EF18F7F2-1F03-481C-98F9-4A18A2F12C11" ascii wide
        $typelibguid1lo = "77b2c83b-ca34-4738-9384-c52f0121647c" ascii wide
        $typelibguid1up = "77B2C83B-CA34-4738-9384-C52F0121647C" ascii wide
        $typelibguid2lo = "14d5d12e-9a32-4516-904e-df3393626317" ascii wide
        $typelibguid2up = "14D5D12E-9A32-4516-904E-DF3393626317" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpDir {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/jnqpblc/SharpDir"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021-01-21"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "c7a07532-12a3-4f6a-a342-161bb060b789" ascii wide
        $typelibguid0up = "C7A07532-12A3-4F6A-A342-161BB060B789" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_AtYourService {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/mitchmoser/AtYourService"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021-01-21"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "bc72386f-8b4c-44de-99b7-b06a8de3ce3f" ascii wide
        $typelibguid0up = "BC72386F-8B4C-44DE-99B7-B06A8DE3CE3F" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_LockLess {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/GhostPack/LockLess"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021-01-21"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "a91421cb-7909-4383-ba43-c2992bbbac22" ascii wide
        $typelibguid0up = "A91421CB-7909-4383-BA43-C2992BBBAC22" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_EasyNet {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/TheWover/EasyNet"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021-01-21"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "3097d856-25c2-42c9-8d59-2cdad8e8ea12" ascii wide
        $typelibguid0up = "3097D856-25C2-42C9-8D59-2CDAD8E8EA12" ascii wide
        $typelibguid1lo = "ba33f716-91e0-4cf7-b9bd-b4d558f9a173" ascii wide
        $typelibguid1up = "BA33F716-91E0-4CF7-B9BD-B4D558F9A173" ascii wide
        $typelibguid2lo = "37d6dd3f-5457-4d8b-a2e1-c7b156b176e5" ascii wide
        $typelibguid2up = "37D6DD3F-5457-4D8B-A2E1-C7B156B176E5" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpByeBear {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/S3cur3Th1sSh1t/SharpByeBear"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021-01-21"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "a6b84e35-2112-4df2-a31b-50fde4458c5e" ascii wide
        $typelibguid0up = "A6B84E35-2112-4DF2-A31B-50FDE4458C5E" ascii wide
        $typelibguid1lo = "3e82f538-6336-4fff-aeec-e774676205da" ascii wide
        $typelibguid1up = "3E82F538-6336-4FFF-AEEC-E774676205DA" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpHide {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/outflanknl/SharpHide"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021-01-21"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "443d8cbf-899c-4c22-b4f6-b7ac202d4e37" ascii wide
        $typelibguid0up = "443D8CBF-899C-4C22-B4F6-B7AC202D4E37" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpSvc {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/jnqpblc/SharpSvc"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021-01-21"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "52856b03-5acd-45e0-828e-13ccb16942d1" ascii wide
        $typelibguid0up = "52856B03-5ACD-45E0-828E-13CCB16942D1" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpCrashEventLog {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/slyd0g/SharpCrashEventLog"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021-01-21"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "98cb495f-4d47-4722-b08f-cefab2282b18" ascii wide
        $typelibguid0up = "98CB495F-4D47-4722-B08F-CEFAB2282B18" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DotNetToJScript_LanguageModeBreakout {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/FuzzySecurity/DotNetToJScript-LanguageModeBreakout"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021-01-21"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "deadb33f-fa94-41b5-813d-e72d8677a0cf" ascii wide
        $typelibguid0up = "DEADB33F-FA94-41B5-813D-E72D8677A0CF" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharPermission {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/mitchmoser/SharPermission"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021-01-21"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "84d2b661-3267-49c8-9f51-8f72f21aea47" ascii wide
        $typelibguid0up = "84D2B661-3267-49C8-9F51-8F72F21AEA47" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_RegistryStrikesBack {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/mdsecactivebreach/RegistryStrikesBack"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021-01-21"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "90ebd469-d780-4431-9bd8-014b00057665" ascii wide
        $typelibguid0up = "90EBD469-D780-4431-9BD8-014B00057665" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_CloneVault {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/mdsecactivebreach/CloneVault"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021-01-21"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "0a344f52-6780-4d10-9a4a-cb9439f9d3de" ascii wide
        $typelibguid0up = "0A344F52-6780-4D10-9A4A-CB9439F9D3DE" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_donut {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/TheWover/donut"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021-01-21"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "98ca74c7-a074-434d-9772-75896e73ceaa" ascii wide
        $typelibguid0up = "98CA74C7-A074-434D-9772-75896E73CEAA" ascii wide
        $typelibguid1lo = "3c9a6b88-bed2-4ba8-964c-77ec29bf1846" ascii wide
        $typelibguid1up = "3C9A6B88-BED2-4BA8-964C-77EC29BF1846" ascii wide
        $typelibguid2lo = "4fcdf3a3-aeef-43ea-9297-0d3bde3bdad2" ascii wide
        $typelibguid2up = "4FCDF3A3-AEEF-43EA-9297-0D3BDE3BDAD2" ascii wide
        $typelibguid3lo = "361c69f5-7885-4931-949a-b91eeab170e3" ascii wide
        $typelibguid3up = "361C69F5-7885-4931-949A-B91EEAB170E3" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpHandler {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/jfmaes/SharpHandler"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021-01-21"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "46e39aed-0cff-47c6-8a63-6826f147d7bd" ascii wide
        $typelibguid0up = "46E39AED-0CFF-47C6-8A63-6826F147D7BD" ascii wide
        $typelibguid1lo = "11dc83c6-8186-4887-b228-9dc4fd281a23" ascii wide
        $typelibguid1up = "11DC83C6-8186-4887-B228-9DC4FD281A23" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Driver_Template {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/FuzzySecurity/Driver-Template"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021-01-21"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "bdb79ad6-639f-4dc2-8b8a-cd9107da3d69" ascii wide
        $typelibguid0up = "BDB79AD6-639F-4DC2-8B8A-CD9107DA3D69" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_NashaVM {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/Mrakovic-ORG/NashaVM"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021-01-21"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "f9e63498-6e92-4afd-8c13-4f63a3d964c3" ascii wide
        $typelibguid0up = "F9E63498-6E92-4AFD-8C13-4F63A3D964C3" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpSQLPwn {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/lefayjey/SharpSQLPwn.git"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2022-11-21"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "c442ea6a-9aa1-4d9c-9c9d-7560a327089c" ascii wide
        $typelibguid0up = "C442EA6A-9AA1-4D9C-9C9D-7560A327089C" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Group3r {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/Group3r/Group3r.git"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2022-11-21"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "868a6c76-c903-4a94-96fd-a2c6ba75691c" ascii wide
        $typelibguid0up = "868A6C76-C903-4A94-96FD-A2C6BA75691C" ascii wide
        $typelibguid1lo = "caa7ab97-f83b-432c-8f9c-c5f1530f59f7" ascii wide
        $typelibguid1up = "CAA7AB97-F83B-432C-8F9C-C5F1530F59F7" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_TokenStomp {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/MartinIngesen/TokenStomp"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2022-11-21"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "8aac271f-9b0b-4dc3-8aa6-812bb7a57e7b" ascii wide
        $typelibguid0up = "8AAC271F-9B0B-4DC3-8AA6-812BB7A57E7B" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_KrbRelay {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/cube0x0/KrbRelay"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2022-11-21"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "ed839154-90d8-49db-8cdd-972d1a6b2cfd" ascii wide
        $typelibguid0up = "ED839154-90D8-49DB-8CDD-972D1A6B2CFD" ascii wide
        $typelibguid1lo = "3b47eebc-0d33-4e0b-bab5-782d2d3680af" ascii wide
        $typelibguid1up = "3B47EEBC-0D33-4E0B-BAB5-782D2D3680AF" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SQLRecon {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/skahwah/SQLRecon"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-01-20"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "612c7c82-d501-417a-b8db-73204fdfda06" ascii wide
        $typelibguid0up = "612C7C82-D501-417A-B8DB-73204FDFDA06" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Certify {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/GhostPack/Certify"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-03-06"
        modified = "2023-04-06"
        hash = "da585a8d4985082873cb86204d546d3f53668e034c61e42d247b11e92b5e8fc3"
    strings:
        $typelibguid0lo = "64524ca5-e4d0-41b3-acc3-3bdbefd40c97" ascii wide
        $typelibguid0up = "64524CA5-E4D0-41B3-ACC3-3BDBEFD40C97" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Aladdin {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/nettitude/Aladdin"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-03-13"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "b2b3adb0-1669-4b94-86cb-6dd682ddbea3" ascii wide
        $typelibguid0up = "B2B3ADB0-1669-4B94-86CB-6DD682DDBEA3" ascii wide
        $typelibguid1lo = "c47e4d64-cc7f-490e-8f09-055e009f33ba" ascii wide
        $typelibguid1up = "C47E4D64-CC7F-490E-8F09-055E009F33BA" ascii wide
        $typelibguid2lo = "32a91b0f-30cd-4c75-be79-ccbd6345de99" ascii wide
        $typelibguid2up = "32A91B0F-30CD-4C75-BE79-CCBD6345DE99" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpLdapRelayScan {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/klezVirus/SharpLdapRelayScan"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-03-15"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "a93ee706-a71c-4cc1-bf37-f26c27825b68" ascii wide
        $typelibguid0up = "A93EE706-A71C-4CC1-BF37-F26C27825B68" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_LdapSignCheck {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/cube0x0/LdapSignCheck"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-03-15"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "21f398a9-bc35-4bd2-b906-866f21409744" ascii wide
        $typelibguid0up = "21F398A9-BC35-4BD2-B906-866F21409744" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpSCCM {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/Mayyhem/SharpSCCM"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-03-15"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "03652836-898e-4a9f-b781-b7d86e750f60" ascii wide
        $typelibguid0up = "03652836-898E-4A9F-B781-B7D86E750F60" ascii wide
        $typelibguid1lo = "e4d9ef39-0fce-4573-978b-abf8df6aec23" ascii wide
        $typelibguid1up = "E4D9EF39-0FCE-4573-978B-ABF8DF6AEC23" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Koh {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/GhostPack/Koh"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-03-18"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "4d5350c8-7f8c-47cf-8cde-c752018af17e" ascii wide
        $typelibguid0up = "4D5350C8-7F8C-47CF-8CDE-C752018AF17E" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_ForgeCert {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/GhostPack/ForgeCert"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-03-18"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "bd346689-8ee6-40b3-858b-4ed94f08d40a" ascii wide
        $typelibguid0up = "BD346689-8EE6-40B3-858B-4ED94F08D40A" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Crassus {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/vu-ls/Crassus"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-03-18"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "7e9729aa-4cf2-4d0a-8183-7fb7ce7a5b1a" ascii wide
        $typelibguid0up = "7E9729AA-4CF2-4D0A-8183-7FB7CE7A5B1A" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_RestrictedAdmin {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/GhostPack/RestrictedAdmin"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-03-18"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "79f11fc0-abff-4e1f-b07c-5d65653d8952" ascii wide
        $typelibguid0up = "79F11FC0-ABFF-4E1F-B07C-5D65653D8952" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_p2p {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid (p2p Remote Desktop is dual use but 100% flagged as malicious on VT)"
        reference = "https://github.com/miroslavpejic85/p2p"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-03-19"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "33456e72-f8e8-4384-88c4-700867df12e2" ascii wide
        $typelibguid0up = "33456E72-F8E8-4384-88C4-700867DF12E2" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpWSUS {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/nettitude/SharpWSUS"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-03-22"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "42cabb74-1199-40f1-9354-6294bba8d3a4" ascii wide
        $typelibguid0up = "42CABB74-1199-40F1-9354-6294BBA8D3A4" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpImpersonation {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/S3cur3Th1sSh1t/SharpImpersonation"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-03-22"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "27a85262-8c87-4147-a908-46728ab7fc73" ascii wide
        $typelibguid0up = "27A85262-8C87-4147-A908-46728AB7FC73" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpCloud {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/chrismaddalena/SharpCloud"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-03-22"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "ca4e257e-69c1-45c5-9375-ba7874371892" ascii wide
        $typelibguid0up = "CA4E257E-69C1-45C5-9375-BA7874371892" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpSSDP {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/rvrsh3ll/SharpSSDP"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-03-22"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "6e383de4-de89-4247-a41a-79db1dc03aaa" ascii wide
        $typelibguid0up = "6E383DE4-DE89-4247-A41A-79DB1DC03AAA" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_WireTap {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/djhohnstein/WireTap"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-03-22"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "b5067468-f656-450a-b29c-1c84cfe8dde5" ascii wide
        $typelibguid0up = "B5067468-F656-450A-B29C-1C84CFE8DDE5" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_KittyLitter {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/djhohnstein/KittyLitter"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-03-22"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "449cf269-4798-4268-9a0d-9a17a08869ba" ascii wide
        $typelibguid0up = "449CF269-4798-4268-9A0D-9A17A08869BA" ascii wide
        $typelibguid1lo = "e7a509a4-2d44-4e10-95bf-b86cb7767c2c" ascii wide
        $typelibguid1up = "E7A509A4-2D44-4E10-95BF-B86CB7767C2C" ascii wide
        $typelibguid2lo = "b2b8dd4f-eba6-42a1-a53d-9a00fe785d66" ascii wide
        $typelibguid2up = "B2B8DD4F-EBA6-42A1-A53D-9A00FE785D66" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpView {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/tevora-threat/SharpView"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-03-22"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "22a156ea-2623-45c7-8e50-e864d9fc44d3" ascii wide
        $typelibguid0up = "22A156EA-2623-45C7-8E50-E864D9FC44D3" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Farmer {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/mdsecactivebreach/Farmer"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-03-22"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "37da2573-d9b5-4fc2-ae11-ccb6130cea9f" ascii wide
        $typelibguid0up = "37DA2573-D9B5-4FC2-AE11-CCB6130CEA9F" ascii wide
        $typelibguid1lo = "49acf861-1c10-49a1-bf26-139a3b3a9227" ascii wide
        $typelibguid1up = "49ACF861-1C10-49A1-BF26-139A3B3A9227" ascii wide
        $typelibguid2lo = "9a6c028f-423f-4c2c-8db3-b3499139b822" ascii wide
        $typelibguid2up = "9A6C028F-423F-4C2C-8DB3-B3499139B822" ascii wide
        $typelibguid3lo = "1c896837-e729-46a9-92b9-3bbe7ac2c90d" ascii wide
        $typelibguid3up = "1C896837-E729-46A9-92B9-3BBE7AC2C90D" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_AESShellCodeInjector {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/san3ncrypt3d/AESShellCodeInjector"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-03-22"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "b016da9e-12a1-4f1d-91a1-d681ae54e92c" ascii wide
        $typelibguid0up = "B016DA9E-12A1-4F1D-91A1-D681AE54E92C" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpChromium {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/djhohnstein/SharpChromium"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-03-22"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "2133c634-4139-466e-8983-9a23ec99e01b" ascii wide
        $typelibguid0up = "2133C634-4139-466E-8983-9A23EC99E01B" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Get_RBCD_Threaded {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/FatRodzianko/Get-RBCD-Threaded"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-03-22"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "e20dc2ed-6455-4101-9d78-fccac1cb7a18" ascii wide
        $typelibguid0up = "E20DC2ED-6455-4101-9D78-FCCAC1CB7A18" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Whisker {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/eladshamir/Whisker"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-03-22"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "42750ac0-1bff-4f25-8c9d-9af144403bad" ascii wide
        $typelibguid0up = "42750AC0-1BFF-4F25-8C9D-9AF144403BAD" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_ShadowSpray {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/Dec0ne/ShadowSpray"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-03-22"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "7e47d586-ddc6-4382-848c-5cf0798084e1" ascii wide
        $typelibguid0up = "7E47D586-DDC6-4382-848C-5CF0798084E1" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_MalSCCM {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/nettitude/MalSCCM"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-03-22"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "5439cecd-3bb3-4807-b33f-e4c299b71ca2" ascii wide
        $typelibguid0up = "5439CECD-3BB3-4807-B33F-E4C299B71CA2" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SpoolSample {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/leechristensen/SpoolSample"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-03-22"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "640c36b4-f417-4d85-b031-83a9d23c140b" ascii wide
        $typelibguid0up = "640C36B4-F417-4D85-B031-83A9D23C140B" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpOxidResolver {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/S3cur3Th1sSh1t/SharpOxidResolver"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-03-22"
        modified = "2023-04-06"
    strings:
        $typelibguid0lo = "ce59f8ff-0ecf-41e9-a1fd-1776ca0b703d" ascii wide
        $typelibguid0up = "CE59F8FF-0ECF-41E9-A1FD-1776CA0B703D" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

