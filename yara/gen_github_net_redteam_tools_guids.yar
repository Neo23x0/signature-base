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
        modified = "2025-08-15"
        id = "883bb859-d5ab-501d-8c83-0c5a2cf1f6c8"
    strings:
        $typelibguid0lo = "a1e28c8c-b3bd-44de-85b9-8aa7c18a714d" ascii wide
        $typelibguid1lo = "87c5970e-0c77-4182-afe2-3fe96f785ebb" ascii wide
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
        modified = "2025-08-15"
        id = "aec4fc28-9aa2-5eef-9fb1-d187a83a72b3"
    strings:
        $typelibguid0lo = "3d7e1433-f81a-428a-934f-7cc7fcf1149d" ascii wide
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
        modified = "2025-08-15"
        id = "dfa96b36-e84c-510b-b16b-bd686777b83d"
    strings:
        $typelibguid0lo = "94ea43ab-7878-4048-a64e-2b21b3b4366d" ascii wide
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
        modified = "2025-08-15"
        id = "57e3d2fa-d430-561b-9d42-cf58cda5ed7a"
    strings:
        $typelibguid0lo = "c335405f-5df2-4c7d-9b53-d65adfbed412" ascii wide
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
        modified = "2025-08-15"
        id = "cd2740d0-0315-5a32-b34a-1998024fcc06"
    strings:
        $typelibguid0lo = "858386df-4656-4a1e-94b7-47f6aa555658" ascii wide
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
        modified = "2025-08-15"
        id = "bfb0f97c-6d95-5e11-ad11-5297bcf7c3df"
    strings:
        $typelibguid0lo = "ec7afd4c-fbc4-47c1-99aa-6ebb05094173" ascii wide
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
        modified = "2025-08-15"
        id = "5dc6702f-a398-5be2-9df8-9a2ddc636a1f"
    strings:
        $typelibguid0lo = "0bdb9c65-14ed-4205-ab0c-ea2151866a7f" ascii wide
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
        modified = "2025-08-15"
        id = "ff084b4c-4b00-5504-85ee-d6d17b5be504"
    strings:
        $typelibguid0lo = "8568b4c1-2940-4f6c-bf4e-4383ef268be9" ascii wide
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
        modified = "2025-08-15"
        id = "1bbdfbb9-a3e8-5ffe-9db9-b50937e6a14d"
    strings:
        $typelibguid0lo = "7266acbb-b10d-4873-9b99-12d2043b1d4e" ascii wide
        $typelibguid1lo = "5d9515d0-df67-40ed-a6b2-6619620ef0ef" ascii wide
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
        modified = "2025-08-15"
        id = "0eba43d2-b415-5e72-9677-4a3238ff7c34"
    strings:
        $typelibguid0lo = "fe0d5aa7-538f-42f6-9ece-b141560f7781" ascii wide
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
        modified = "2025-08-15"
        id = "249da967-68b0-59b1-b414-4eb4fe67b8f3"
    strings:
        $typelibguid0lo = "a3ec18a3-674c-4131-a7f5-acbed034b819" ascii wide
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
        modified = "2025-08-15"
        id = "e9a493d9-21b6-5ff1-9e5e-e8fbacc34c0c"
    strings:
        $typelibguid0lo = "c12e69cd-78a0-4960-af7e-88cbd794af97" ascii wide
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
        modified = "2025-08-15"
        id = "82225b2e-ab4a-50b8-a3fd-7ad4947d052e"
    strings:
        $typelibguid0lo = "e6104bc9-fea9-4ee9-b919-28156c1f2ede" ascii wide
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
        modified = "2025-08-15"
        id = "dad6729f-3d96-5d2d-b72c-a96d1a3eae74"
    strings:
        $typelibguid0lo = "46034038-0113-4d75-81fd-eb3b483f2662" ascii wide
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
        modified = "2025-08-15"
        id = "75a27970-c469-53da-b0c3-b3d0faea0b6f"
    strings:
        $typelibguid0lo = "814708c9-2320-42d2-a45f-31e42da06a94" ascii wide
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
        modified = "2025-08-15"
        id = "5fab1551-9d35-53cf-a04f-c14370119553"
    strings:
        $typelibguid0lo = "352e80ec-72a5-4aa6-aabe-4f9a20393e8e" ascii wide
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
        modified = "2025-08-15"
        id = "b84538da-1b0e-50c7-abfa-e93d6de5a49b"
    strings:
        $typelibguid0lo = "3cf25e04-27e4-4d19-945e-dadc37c81152" ascii wide
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
        modified = "2025-08-15"
        id = "0fd7496b-e34f-51f7-9270-ad424ed6a7a8"
    strings:
        $typelibguid0lo = "555ad0ac-1fdb-4016-8257-170a74cb2f55" ascii wide
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
        modified = "2025-08-15"
        id = "0798f01b-76b7-5c4d-9ddb-5e377b86f8b9"
    strings:
        $typelibguid0lo = "068d14ef-f0a1-4f9d-8e27-58b4317830c6" ascii wide
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
        modified = "2025-08-15"
        id = "d5903db5-010b-5b9d-8a5b-5d61aec52e7a"
    strings:
        $typelibguid0lo = "afd1ff09-2632-4087-a30c-43591f32e4e8" ascii wide
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
        modified = "2025-08-15"
        id = "e3015719-9085-584d-8237-f377ec995149"
    strings:
        $typelibguid0lo = "b5152683-2514-49ce-9aca-1bc43df1e234" ascii wide
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
        modified = "2025-08-15"
        id = "52acd520-52aa-5bb9-ab3b-66a940aa5f5a"
    strings:
        $typelibguid0lo = "4885a4a3-4dfa-486c-b378-ae94a221661a" ascii wide
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
        modified = "2025-08-15"
        id = "c30c8323-9418-521a-a4fc-6be0113b99b5"
    strings:
        $typelibguid0lo = "8a87b003-4b43-467b-a509-0c8be05bf5a5" ascii wide
        $typelibguid1lo = "80b13bff-24a5-4193-8e51-c62a414060ec" ascii wide
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
        modified = "2025-08-15"
        id = "e91e6711-d992-5a8a-97e6-1ed7847f38a4"
    strings:
        $typelibguid0lo = "6ffccf81-6c3c-4d3f-b15f-35a86d0b497f" ascii wide
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
        modified = "2025-08-15"
        id = "c6b4c919-0fc6-5096-b29b-963142a2c831"
    strings:
        $typelibguid0lo = "8586f5b1-2ef4-4f35-bd45-c6206fdc0ebc" ascii wide
        $typelibguid1lo = "fe184ab5-f153-4179-9bf5-50523987cf1f" ascii wide
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
        modified = "2025-08-15"
        id = "0b7b62ce-9c24-5d81-8d87-22f6e461a62b"
    strings:
        $typelibguid0lo = "1bcfe538-14f4-4beb-9a3f-3f9472794902" ascii wide
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
        modified = "2025-08-15"
        id = "9a673427-e66e-594b-942a-64a2272319f3"
    strings:
        $typelibguid0lo = "501e3fdc-575d-492e-90bc-703fb6280ee2" ascii wide
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
        modified = "2025-08-15"
        id = "f3b0ef47-a92c-5c5d-a9e2-09579fcb438e"
    strings:
        $typelibguid0lo = "5a869ab2-291a-49e6-a1b7-0d0f051bef0e" ascii wide
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
        modified = "2025-08-15"
        id = "876932d5-a65d-5230-9cb8-24038ad8af0d"
    strings:
        $typelibguid0lo = "980109e4-c988-47f9-b2b3-88d63fababdc" ascii wide
        $typelibguid1lo = "8abe8da1-457e-4933-a40d-0958c8925985" ascii wide
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
        modified = "2025-08-15"
        id = "2ed6d74e-2b95-5c70-807a-4da5e62f5853"
    strings:
        $typelibguid0lo = "62b9ee4f-1436-4098-9bc1-dd61b42d8b81" ascii wide
        $typelibguid1lo = "d2f17a91-eb2d-4373-90bf-a26e46c68f76" ascii wide
        $typelibguid2lo = "a9db9fcc-7502-42cd-81ec-3cd66f511346" ascii wide
        $typelibguid3lo = "ca6cc2ee-75fd-4f00-b687-917fa55a4fae" ascii wide
        $typelibguid4lo = "a1167b68-446b-4c0c-a8b8-2a7278b67511" ascii wide
        $typelibguid5lo = "4d8c2a88-1da5-4abe-8995-6606473d7cf1" ascii wide
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
        modified = "2025-08-15"
        id = "853b630d-77ba-5847-a129-c9fa0538f81b"
    strings:
        $typelibguid0lo = "612590aa-af68-41e6-8ce2-e831f7fe4ccc" ascii wide
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
        modified = "2025-08-15"
        id = "53b690ec-7d20-5e46-b368-b458ce56073d"
    strings:
        $typelibguid0lo = "88b8515e-a0e8-4208-a9a0-34b01d7ba533" ascii wide
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
        modified = "2025-08-15"
        id = "5966be44-c010-5c63-9576-1aaf36397d6c"
    strings:
        $typelibguid0lo = "bdba47c5-e823-4404-91d0-7f6561279525" ascii wide
        $typelibguid1lo = "b84548dc-d926-4b39-8293-fa0bdef34d49" ascii wide
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
        modified = "2025-08-15"
        id = "3a6cf00e-28c4-5e6f-a28d-b3f28fca6eed"
    strings:
        $typelibguid0lo = "a4020626-f1ec-4012-8b17-a2c8a0204a4b" ascii wide
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
        modified = "2025-08-15"
        id = "e296795f-d006-52a9-92c4-fb60c930564b"
    strings:
        $typelibguid0lo = "af9c62a1-f8d2-4be0-b019-0a7873e81ea9" ascii wide
        $typelibguid1lo = "b2b3adb0-1669-4b94-86cb-6dd682ddbea3" ascii wide
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
        modified = "2025-08-15"
        id = "f595545a-a7a6-577c-b3f4-febf7bf1b6c3"
    strings:
        $typelibguid0lo = "a73cad74-f8d6-43e6-9a4c-b87832cdeace" ascii wide
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
        modified = "2025-08-15"
        id = "ea95ff3c-0cbb-5230-b5e4-bd8b2ff975eb"
    strings:
        $typelibguid0lo = "95359279-5cfa-46f6-b400-e80542a7336a" ascii wide
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
        modified = "2025-08-15"
        id = "d66e3566-6082-570a-a168-f44c9d8c7619"
    strings:
        $typelibguid0lo = "aca853dc-9e74-4175-8170-e85372d5f2a9" ascii wide
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
        modified = "2025-08-15"
        id = "12a15e61-30fb-50a3-a59b-39f9871444f0"
    strings:
        $typelibguid0lo = "431ef2d9-5cca-41d3-87ba-c7f5e4582dd2" ascii wide
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
        modified = "2025-08-15"
        id = "b8787dac-48a3-5711-86ba-0fda86b6224e"
    strings:
        $typelibguid0lo = "a48fe0e1-30de-46a6-985a-3f2de3c8ac96" ascii wide
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
        modified = "2025-08-15"
        id = "e715bce8-531b-5e2a-bd02-b2fc4990c499"
    strings:
        $typelibguid0lo = "f6fec17e-e22d-4149-a8a8-9f64c3c905d3" ascii wide
        $typelibguid1lo = "b7aa4e23-39a4-49d5-859a-083c789bfea2" ascii wide
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
        modified = "2025-08-15"
        id = "949364e7-dcb6-5afd-ade9-cc34a6e15e97"
    strings:
        $typelibguid0lo = "634874b7-bf85-400c-82f0-7f3b4659549a" ascii wide
        $typelibguid1lo = "2f9c3053-077f-45f2-b207-87c3c7b8f054" ascii wide
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
        modified = "2025-08-15"
        id = "339f6858-6076-5320-ba5f-2903e642ea42"
    strings:
        $typelibguid0lo = "6c3fbc65-b673-40f0-b1ac-20636df01a85" ascii wide
        $typelibguid1lo = "2bad9d69-ada9-4f1e-b838-9567e1503e93" ascii wide
        $typelibguid2lo = "512015de-a70f-4887-8eae-e500fd2898ab" ascii wide
        $typelibguid3lo = "1ee4188c-24ac-4478-b892-36b1029a13b3" ascii wide
        $typelibguid4lo = "5c6b7361-f9ab-41dc-bfa0-ed5d4b0032a8" ascii wide
        $typelibguid5lo = "048a6559-d4d3-4ad8-af0f-b7f72b212e90" ascii wide
        $typelibguid6lo = "3412fbe9-19d3-41d8-9ad2-6461fcb394dc" ascii wide
        $typelibguid7lo = "9ea4e0dc-9723-4d93-85bb-a4fcab0ad210" ascii wide
        $typelibguid8lo = "6d2b239c-ba1e-43ec-8334-d67d52b77181" ascii wide
        $typelibguid9lo = "42e8b9e1-0cf4-46ae-b573-9d0563e41238" ascii wide
        $typelibguid10lo = "0d15e0e3-bcfd-4a85-adcd-0e751dab4dd6" ascii wide
        $typelibguid11lo = "644dfd1a-fda5-4948-83c2-8d3b5eda143a" ascii wide
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
        modified = "2025-08-15"
        id = "8903c65a-624f-5e8d-a3f6-4572b56bd2f7"
    strings:
        $typelibguid0lo = "a3ddfcaa-66e7-44fd-ad48-9d80d1651228" ascii wide
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
        modified = "2025-08-15"
        id = "457959ed-3e90-52c7-89f9-e1b17b35260e"
    strings:
        $typelibguid0lo = "1c8849ef-ad09-4727-bf81-1f777bd1aef8" ascii wide
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
        modified = "2025-08-15"
        id = "5b1a8102-6d59-5f2f-8ae2-b3c1f75a561d"
    strings:
        $typelibguid0lo = "eaafa0ac-e464-4fc4-9713-48aa9a6716fb" ascii wide
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
        modified = "2025-08-15"
        id = "82937fef-8280-5bc6-af4a-55c5cb3a7553"
    strings:
        $typelibguid0lo = "9e92a883-3c8b-4572-a73e-bb3e61cfdc16" ascii wide
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
        modified = "2025-08-15"
        id = "ce2773a2-b0b7-560e-ba21-3f018ddcacb3"
    strings:
        $typelibguid0lo = "0c0333db-8f00-4b68-b1db-18a9cacc1486" ascii wide
        $typelibguid1lo = "84701ace-c584-4886-a3cf-76c57f6e801a" ascii wide
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
        modified = "2025-08-15"
        id = "e731d563-0d16-5f84-8127-624a71f8b646"
    strings:
        $typelibguid0lo = "5e7fce78-1977-444f-a18e-987d708a2cff" ascii wide
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
        modified = "2025-08-15"
        id = "3f582a47-078e-525f-9d02-4ee7a455a3b2"
    strings:
        $typelibguid0lo = "36ebf9aa-2f37-4f1d-a2f1-f2a45deeaf21" ascii wide
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
        modified = "2025-08-15"
        id = "ca97004e-edc1-5b5a-ac67-e81ae24631aa"
    strings:
        $typelibguid0lo = "4ab3b95d-373c-4197-8ee3-fe0fa66ca122" ascii wide
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
        modified = "2025-08-15"
        id = "0d35acf4-c763-593c-94e2-c499d3826375"
    strings:
        $typelibguid0lo = "8435531d-675c-4270-85bf-60db7653bcf6" ascii wide
        $typelibguid1lo = "47db989f-7e33-4e6b-a4a5-c392b429264b" ascii wide
        $typelibguid2lo = "300c7489-a05f-4035-8826-261fa449dd96" ascii wide
        $typelibguid3lo = "41bf8781-ae04-4d80-b38d-707584bf796b" ascii wide
        $typelibguid4lo = "620ed459-18de-4359-bfb0-6d0c4841b6f6" ascii wide
        $typelibguid5lo = "91e7cdfe-0945-45a7-9eaa-0933afe381f2" ascii wide
        $typelibguid6lo = "c28e121a-60ca-4c21-af4b-93eb237b882f" ascii wide
        $typelibguid7lo = "698fac7a-bff1-4c24-b2c3-173a6aae15bf" ascii wide
        $typelibguid8lo = "63a40d94-5318-42ad-a573-e3a1c1284c57" ascii wide
        $typelibguid9lo = "56b8311b-04b8-4e57-bb58-d62adc0d2e68" ascii wide
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
        modified = "2025-08-15"
        id = "9ebee989-3441-5a76-b243-08de978b541c"
    strings:
        $typelibguid0lo = "f7e8a902-2378-426a-bfa5-6b14c4b40aa3" ascii wide
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
        modified = "2025-08-15"
        id = "2aa62d61-075c-5664-a7fc-2b9d84b954ed"
    strings:
        $typelibguid0lo = "30b2e0cf-34dd-4614-a5ca-6578fb684aea" ascii wide
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
        modified = "2025-08-15"
        id = "a57c47e8-62bf-5425-9735-35a3e3a0c218"
    strings:
        $typelibguid0lo = "06260ce5-61f4-4b81-ad83-7d01c3b37921" ascii wide
        $typelibguid1lo = "87fc7ede-4dae-4f00-ac77-9c40803e8248" ascii wide
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
        modified = "2025-08-15"
        id = "bf0c3d93-cbea-54c7-b950-fd4e5a600d07"
    strings:
        $typelibguid0lo = "5fd7f9fc-0618-4dde-a6a0-9faefe96c8a1" ascii wide
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
        modified = "2025-08-15"
        id = "0ed3f5e5-d954-51e2-b7fb-4c25ca3d9f10"
    strings:
        $typelibguid0lo = "14c79bda-2ce6-424d-bd49-4f8d68630b7b" ascii wide
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
        modified = "2025-08-15"
        id = "2cdd1a15-c70c-5eea-b5a7-8b4a445b9323"
    strings:
        $typelibguid0lo = "13e90a4d-bf7a-4d5a-9979-8b113e3166be" ascii wide
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
        modified = "2025-08-15"
        id = "89729c43-ae01-5c1f-af04-06d7a6c4e7fc"
    strings:
        $typelibguid0lo = "cdf8b024-70c9-413a-ade3-846a43845e99" ascii wide
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
        modified = "2025-08-15"
        id = "d25fa706-2254-5a82-a961-f57a0daa447c"
    strings:
        $typelibguid0lo = "d1421ba3-c60b-42a0-98f9-92ba4e653f3d" ascii wide
        $typelibguid1lo = "2afac0dd-f46f-4f95-8a93-dc17b4f9a3a1" ascii wide
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
        modified = "2025-08-15"
        id = "e9312c96-be10-5942-a4da-1fe708cc6699"
    strings:
        $typelibguid0lo = "51c6e016-1428-441d-82e9-bb0eb599bbc8" ascii wide
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
        modified = "2025-08-15"
        id = "d9988b00-1f10-5421-8ffe-49849a5d5902"
    strings:
        $typelibguid0lo = "8fe5b811-a2cb-417f-af93-6a3cf6650af1" ascii wide
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
        modified = "2025-08-15"
        id = "5f6d7432-0bb5-5782-98ec-2c2168f2fc1f"
    strings:
        $typelibguid0lo = "8347e81b-89fc-42a9-b22c-f59a6a572dec" ascii wide
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
        modified = "2025-08-15"
        id = "0da3b6d8-2002-590e-a8d5-f6c84acfb083"
    strings:
        $typelibguid0lo = "23b739f7-2355-491e-a7cd-a8485d39d6d6" ascii wide
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
        modified = "2025-08-15"
        id = "2dde9632-10c5-5c91-8bd9-2fb80d6f0c49"
    strings:
        $typelibguid0lo = "948152a4-a4a1-4260-a224-204255bfee72" ascii wide
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
        modified = "2025-08-15"
        id = "7db07291-d6d4-5527-a879-27f899dbd6fe"
    strings:
        $typelibguid0lo = "e6aa0cd5-9537-47a0-8c85-1fbe284a4380" ascii wide
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
        modified = "2025-08-15"
        id = "b8c330dc-74aa-5a33-8af6-17c9beb8be81"
    strings:
        $typelibguid0lo = "9480809e-5472-44f3-b076-dcdf7379e766" ascii wide
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
        modified = "2025-08-15"
        id = "5833e6c5-f078-5eb5-9519-76710d7da0e1"
    strings:
        $typelibguid0lo = "233de44b-4ec1-475d-a7d6-16da48d6fc8d" ascii wide
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
        modified = "2025-08-15"
        id = "b613092f-9006-5405-b07e-59737410ac1e"
    strings:
        $typelibguid0lo = "79c9bba3-a0ea-431c-866c-77004802d8a0" ascii wide
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
        modified = "2025-08-15"
        id = "b1d54bea-a6c4-5c57-9ee1-7438d503b01d"
    strings:
        $typelibguid0lo = "8a18fbcf-8cac-482d-8ab7-08a44f0e278e" ascii wide
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
        modified = "2025-08-15"
        id = "f26e040a-dcc7-518f-89f2-3333f83fa14a"
    strings:
        $typelibguid0lo = "bf43cd33-c259-4711-8a0e-1a5c6c13811d" ascii wide
        $typelibguid1lo = "e5b9df9b-a9e4-4754-8731-efc4e2667d88" ascii wide
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
        modified = "2025-08-15"
        id = "e2123a73-2609-559d-a122-923ebf8fd668"
    strings:
        $typelibguid0lo = "f70d2b71-4aae-4b24-9dae-55bc819c78bb" ascii wide
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
        modified = "2025-08-15"
        id = "327f581e-1d8c-5d20-bdd7-a29810c619c9"
    strings:
        $typelibguid0lo = "4e7c140d-bcc4-4b15-8c11-adb4e54cc39a" ascii wide
        $typelibguid1lo = "cec553a7-1370-4bbc-9aae-b2f5dbde32b0" ascii wide
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
        modified = "2025-08-15"
        id = "c432bf68-49bf-57c7-bbfa-7bd2f3506c52"
    strings:
        $typelibguid0lo = "32e22e25-b033-4d98-a0b3-3d2c3850f06c" ascii wide
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
        modified = "2025-08-15"
        id = "1d8a9717-4d80-5fb1-9c57-9b5f6c5a18b0"
    strings:
        $typelibguid0lo = "6840b249-1a0e-433b-be79-a927696ea4b3" ascii wide
        $typelibguid1lo = "67c09d37-ac18-4f15-8dd6-b5da721c0df6" ascii wide
        $typelibguid2lo = "e05d0deb-d724-4448-8c4c-53d6a8e670f3" ascii wide
        $typelibguid3lo = "c3cc72bf-62a2-4034-af66-e66da73e425d" ascii wide
        $typelibguid4lo = "7ace3762-d8e1-4969-a5a0-dcaf7b18164e" ascii wide
        $typelibguid5lo = "3296e4a3-94b5-4232-b423-44f4c7421cb3" ascii wide
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
        modified = "2025-08-15"
        id = "4f87ca2c-3ac1-5733-893e-79665b80ffc3"
    strings:
        $typelibguid0lo = "8e46ba56-e877-4dec-be1e-394cb1b5b9de" ascii wide
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
        modified = "2025-08-15"
        id = "f54bcb1a-b0cd-5988-bf1d-4fa6c012d6b9"
    strings:
        $typelibguid0lo = "df0dd7a1-9f6b-4b0f-801e-e17e73b0801d" ascii wide
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
        modified = "2025-08-15"
        id = "0fa1ce82-b662-5e18-a5da-8359c96cd6e9"
    strings:
        $typelibguid0lo = "b91d2d44-794c-49b8-8a75-2fbec3fe3fe3" ascii wide
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
        modified = "2025-08-15"
        id = "4004271b-4fbe-58bb-9613-a077e76324b3"
    strings:
        $typelibguid0lo = "4854c8dc-82b0-4162-86e0-a5bbcbc10240" ascii wide
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
        modified = "2025-08-15"
        id = "1394323f-b336-548f-925c-c276d439e9eb"
    strings:
        $typelibguid0lo = "5f026c27-f8e6-4052-b231-8451c6a73838" ascii wide
        $typelibguid1lo = "2f00a05b-263d-4fcc-846b-da82bd684603" ascii wide
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
        modified = "2025-08-15"
        id = "495a5f3e-cf05-5a66-b01c-8176ded88768"
    strings:
        $typelibguid0lo = "1d79fabc-2ba2-4604-a4b6-045027340c85" ascii wide
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
        modified = "2025-08-15"
        id = "c5e053c4-1c90-581a-a6c3-087b252254b2"
    strings:
        $typelibguid0lo = "63f81b73-ff18-4a36-b095-fdcb4776da4c" ascii wide
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
        modified = "2025-08-15"
        id = "4a87882e-570b-5b40-a8e3-47ebac01d257"
    strings:
        $typelibguid0lo = "3f239b73-88ae-413b-b8c8-c01a35a0d92e" ascii wide
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
        modified = "2025-08-15"
        id = "fa9aeae1-2aa5-51af-81e2-22a1b6fcda81"
    strings:
        $typelibguid0lo = "207aca5d-dcd6-41fb-8465-58b39efcde8b" ascii wide
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
        modified = "2025-08-15"
        id = "54638fe4-84b5-51a8-8c88-9c50ab09ff49"
    strings:
        $typelibguid0lo = "658c8b7f-3664-4a95-9572-a3e5871dfc06" ascii wide
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
        modified = "2025-08-15"
        id = "4c26aaf9-187d-5990-b956-1bbf630411f0"
    strings:
        $typelibguid0lo = "035ae711-c0e9-41da-a9a2-6523865e8694" ascii wide
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
        modified = "2025-08-15"
        id = "51f64c64-f3fa-5543-83fc-5f0bf881ef03"
    strings:
        $typelibguid0lo = "15c241aa-e73c-4b38-9489-9a344ac268a3" ascii wide
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
        modified = "2025-08-15"
        id = "474d40aa-4bcc-58b5-a129-40bbd3a89e99"
    strings:
        $typelibguid0lo = "0d588c86-c680-4b0d-9aed-418f1bb94255" ascii wide
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
        modified = "2025-08-15"
        id = "633d074a-b8c2-5148-ad80-6226b99be818"
    strings:
        $typelibguid1lo = "b59c7741-d522-4a41-bf4d-9badddebb84a" ascii wide
        $typelibguid2lo = "fd6bdf7a-fef4-4b28-9027-5bf750f08048" ascii wide
        $typelibguid3lo = "6dd22880-dac5-4b4d-9c91-8c35cc7b8180" ascii wide
        $typelibguid5lo = "f3037587-1a3b-41f1-aa71-b026efdb2a82" ascii wide
        $typelibguid6lo = "41a90a6a-f9ed-4a2f-8448-d544ec1fd753" ascii wide
        $typelibguid7lo = "3787435b-8352-4bd8-a1c6-e5a1b73921f4" ascii wide
        $typelibguid8lo = "fdd654f5-5c54-4d93-bf8e-faf11b00e3e9" ascii wide
        $typelibguid9lo = "aec32155-d589-4150-8fe7-2900df4554c8" ascii wide
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
        modified = "2025-08-15"
        id = "50db578e-6ddb-54d1-a978-e3630a3548c3"
    strings:
        $typelibguid0lo = "276004bb-5200-4381-843c-934e4c385b66" ascii wide
        $typelibguid1lo = "cfcbf7b6-1c69-4b1f-8651-6bdb4b55f6b9" ascii wide
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
        modified = "2025-08-15"
        id = "6e494a91-c05e-5a2e-8aa9-77600f3bdd47"
    strings:
        $typelibguid0lo = "2f8b4d26-7620-4e11-b296-bc46eba3adfc" ascii wide
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
        modified = "2025-08-15"
        id = "28615807-6637-57fc-ba56-efc64b041b80"
    strings:
        $typelibguid0lo = "ed54b904-5645-4830-8e68-52fd9ecbb2eb" ascii wide
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
        modified = "2025-08-15"
        id = "f2783477-2853-5dcd-95f5-9f1e07a4a6e8"
    strings:
        $typelibguid0lo = "fff0a9a3-dfd4-402b-a251-6046d765ad78" ascii wide
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
        modified = "2025-08-15"
        id = "d4257465-38a0-56b9-8402-b92e21b96cb0"
    strings:
        $typelibguid0lo = "1937ee16-57d7-4a5f-88f4-024244f19dc6" ascii wide
        $typelibguid1lo = "7898617d-08d2-4297-adfe-5edd5c1b828b" ascii wide
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
        modified = "2025-08-15"
        id = "cfc6312d-5997-5261-b771-c7f3f30bf86c"
    strings:
        $typelibguid0lo = "aecec195-f143-4d02-b946-df0e1433bd2e" ascii wide
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
        modified = "2025-08-15"
        id = "09d66661-5b67-5846-9bea-ec682afb62cf"
    strings:
        $typelibguid0lo = "a16abbb4-985b-4db2-a80c-21268b26c73d" ascii wide
        $typelibguid1lo = "98075331-1f86-48c8-ae29-29da39a8f98b" ascii wide
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
        modified = "2025-08-15"
        id = "726cd57b-d88a-5854-b2e1-76d9bd71a155"
    strings:
        $typelibguid0lo = "c25e39a9-8215-43aa-96a3-da0e9512ec18" ascii wide
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
        modified = "2025-08-15"
        id = "ead7819a-1397-5953-888f-2176e4041375"
    strings:
        $typelibguid0lo = "9dff282c-93b9-4063-bf8a-b6798371d35a" ascii wide
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
        modified = "2025-08-15"
        id = "62b0541b-6eec-546e-8445-85d25bb0d784"
    strings:
        $typelibguid0lo = "47e08791-d124-4746-bc50-24bd1ee719a6" ascii wide
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
        modified = "2025-08-15"
        id = "9b584bfb-98ef-50ee-b546-780c4b210a1b"
    strings:
        $typelibguid0lo = "c0e49392-04e3-4abb-b931-5202e0eb4c73" ascii wide
        $typelibguid1lo = "30eef7d6-cee8-490b-829f-082041bc3141" ascii wide
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
        modified = "2025-08-15"
        modified = "2025-08-15"
        id = "ab3cf358-a41d-584d-baaf-5e8f7232ca85"
    strings:
        $typelibguid0lo = "19657be4-51ca-4a85-8ab1-f6666008b1f3" ascii wide
        $typelibguid1lo = "0a382d9a-897f-431a-81c2-a4e08392c587" ascii wide
        $typelibguid2lo = "467ee2a9-2f01-4a71-9647-2a2d9c31e608" ascii wide
        $typelibguid3lo = "eacaa2b8-43e5-4888-826d-2f6902e16546" ascii wide
        $typelibguid4lo = "629f86e6-44fe-4c9c-b043-1c9b64be6d5a" ascii wide
        $typelibguid5lo = "ecf2ffe4-1744-4745-8693-5790d66bb1b8" ascii wide
        $typelibguid6lo = "0a621f4c-8082-4c30-b131-ba2c98db0533" ascii wide
        $typelibguid7lo = "72019dfe-608e-4ab2-a8f1-66c95c425620" ascii wide
        $typelibguid8lo = "f0d28809-b712-4380-9a59-407b7b2badd5" ascii wide
        $typelibguid9lo = "956a5a4d-2007-4857-9259-51cd0fb5312a" ascii wide
        $typelibguid10lo = "a3b7c697-4bb6-455d-9fda-4ab54ae4c8d2" ascii wide
        $typelibguid11lo = "a5f883ce-1f96-4456-bb35-40229191420c" ascii wide
        $typelibguid12lo = "28978103-d90d-4618-b22e-222727f40313" ascii wide
        $typelibguid13lo = "0c70c839-9565-4881-8ea1-408c1ebe38ce" ascii wide
        $typelibguid14lo = "fa1d9a36-415a-4855-8c01-54b6e9fc6965" ascii wide
        $typelibguid15lo = "252676f8-8a19-4664-bfb8-5a947e48c32a" ascii wide
        $typelibguid16lo = "447edefc-b429-42bc-b3bc-63a9af19dbd6" ascii wide
        $typelibguid17lo = "04d0b3a6-eaab-413d-b9e2-512fa8ebd02f" ascii wide
        $typelibguid18lo = "5611236e-2557-45b8-be29-5d1f074d199e" ascii wide
        $typelibguid19lo = "53f622eb-0ca3-4e9b-9dc8-30c832df1c7b" ascii wide
        $typelibguid20lo = "414187db-5feb-43e5-a383-caa48b5395f1" ascii wide
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
        modified = "2025-08-15"
        id = "8f206175-f7e4-5543-8059-24f102fcd4b9"
    strings:
        $typelibguid0lo = "7a15f8f6-6ce2-4ca4-919d-2056b70cc76a" ascii wide
        $typelibguid1lo = "1659d65d-93a8-4bae-97d5-66d738fc6f6c" ascii wide
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
        modified = "2025-08-15"
        id = "5efd0c83-cb65-5bda-b55e-4a89db5f337c"
    strings:
        $typelibguid0lo = "76435f79-f8af-4d74-8df5-d598a551b895" ascii wide
        $typelibguid1lo = "5a3fc840-5432-4925-b5bc-abc536429cb5" ascii wide
        $typelibguid2lo = "6f0bbb2a-e200-4d76-b8fa-f93c801ac220" ascii wide
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
        modified = "2025-08-15"
        id = "8265cd84-c8e7-5654-9d3a-774dab52d938"
    strings:
        $typelibguid0lo = "8dca0e42-f767-411d-9704-ae0ba4a44ae8" ascii wide
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
        modified = "2025-08-15"
        id = "301e70f4-89ed-539c-b7f3-9fc6ae1393b3"
    strings:
        $typelibguid0lo = "4581a449-7d20-4c59-8da2-7fd830f1fd5e" ascii wide
        $typelibguid1lo = "05f4b238-25ce-40dc-a890-d5bbb8642ee4" ascii wide
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
        modified = "2025-08-15"
        id = "8135d39e-6a9e-567d-840f-8d8c6338cce1"
    strings:
        $typelibguid0lo = "33842d77-bce3-4ee8-9ee2-9769898bb429" ascii wide
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
        modified = "2025-08-15"
        id = "bd527841-065e-57e9-b70e-c9d232072f1b"
    strings:
        $typelibguid0lo = "3092c8df-e9e4-4b75-b78e-f81a0058a635" ascii wide
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
        modified = "2025-08-15"
        id = "91824d18-f46b-5b95-b650-4d710d711cf9"
    strings:
        $typelibguid0lo = "9fdae122-cd1e-467d-a6fa-a98c26e76348" ascii wide
        $typelibguid1lo = "243c279e-33a6-46a1-beab-2864cc7a499f" ascii wide
        $typelibguid2lo = "a7301384-7354-47fd-a4c5-65b74e0bbb46" ascii wide
        $typelibguid3lo = "982dc5b6-1123-428a-83dd-d212490c859f" ascii wide
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
        modified = "2025-08-15"
        id = "c35160cb-ad31-5195-a7c6-0af91a58737d"
    strings:
        $typelibguid0lo = "0547ff40-5255-42a2-beb7-2ff0dbf7d3ba" ascii wide
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
        modified = "2025-08-15"
        id = "59299a72-9b7a-5108-81c2-d8f6d2e99b20"
    strings:
        $typelibguid0lo = "73c79d7e-17d4-46c9-be5a-ecef65b924e4" ascii wide
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
        modified = "2025-08-15"
        id = "484c7a15-7ab2-57d3-848c-0fddff753d52"
    strings:
        $typelibguid0lo = "f93c99ed-28c9-48c5-bb90-dd98f18285a6" ascii wide
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
        modified = "2025-08-15"
        modified = "2025-08-15"
        id = "adcc5d12-c393-5708-ae0b-a85f2187c881"
    strings:
        $typelibguid0lo = "2133c634-4139-466e-8983-9a23ec99e01b" ascii wide
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
        modified = "2025-08-15"
        id = "9d59cd53-53b1-57db-b391-eee4dd6feec0"
    strings:
        $typelibguid0lo = "057aef75-861b-4e4b-a372-cfbd8322c8e1" ascii wide
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
        modified = "2025-08-15"
        id = "b98495fb-0338-5042-a7ce-d117204eb91e"
    strings:
        $typelibguid0lo = "11fe5fae-b7c1-484a-b162-d5578a802c9c" ascii wide
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
        modified = "2025-08-15"
        id = "8fd89465-1ecc-5eda-b2ab-273172ad945d"
    strings:
        $typelibguid0lo = "fe4414d9-1d7e-4eeb-b781-d278fe7a5619" ascii wide
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
        modified = "2025-08-15"
        id = "3790faac-b5be-5999-b35f-71a2ef02b6ed"
    strings:
        $typelibguid0lo = "f318466d-d310-49ad-a967-67efbba29898" ascii wide
        $typelibguid1lo = "3705800f-1424-465b-937d-586e3a622a4f" ascii wide
        $typelibguid2lo = "256607c2-4126-4272-a2fa-a1ffc0a734f0" ascii wide
        $typelibguid3lo = "4e6ceea1-f266-401c-b832-f91432d46f42" ascii wide
        $typelibguid4lo = "1e6e9b03-dd5f-4047-b386-af7a7904f884" ascii wide
        $typelibguid5lo = "d85e3601-0421-4efa-a479-f3370c0498fd" ascii wide
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
        modified = "2025-08-15"
        id = "40768acf-fa9e-531a-83fd-187814ddc2d4"
    strings:
        $typelibguid0lo = "d829426c-986c-40a4-8ee2-58d14e090ef2" ascii wide
        $typelibguid1lo = "86652418-5605-43fd-98b5-859828b072be" ascii wide
        $typelibguid2lo = "1043649f-18e1-41c4-ae8d-ac4d9a86c2fc" ascii wide
        $typelibguid3lo = "1d920b03-c537-4659-9a8c-09fb1d615e98" ascii wide
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
        modified = "2025-08-15"
        id = "57d22201-a051-5040-927c-30da3fc684fd"
    strings:
        $typelibguid0lo = "8653fa88-9655-440e-b534-26c3c760a0d3" ascii wide
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
        modified = "2025-08-15"
        id = "ad8cf2c8-f70e-5f46-92fa-46e1fa5e683c"
    strings:
        $typelibguid0lo = "2aa8c254-b3b3-469c-b0c9-dcbe1dd101c0" ascii wide
        $typelibguid1lo = "afeff505-14c1-4ecf-b714-abac4fbd48e7" ascii wide
        $typelibguid2lo = "4cf42167-a5cf-4b2d-85b4-8e764c08d6b3" ascii wide
        $typelibguid3lo = "118a90b7-598a-4cfc-859e-8013c8b9339c" ascii wide
        $typelibguid4lo = "3075dd9a-4283-4d38-a25e-9f9845e5adcb" ascii wide
        $typelibguid5lo = "295655e8-2348-4700-9ebc-aa57df54887e" ascii wide
        $typelibguid6lo = "74efe601-9a93-46c3-932e-b80ab6570e42" ascii wide
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
        modified = "2025-08-15"
        id = "d25c9033-13e8-5fc9-8561-f8862cca39b8"
    strings:
        $typelibguid0lo = "4eee900e-adc5-46a7-8d7d-873fd6aea83e" ascii wide
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
        modified = "2025-08-15"
        id = "44264dd9-f8e9-5a60-847f-94378e07a327"
    strings:
        $typelibguid0lo = "3fda4aa9-6fc1-473f-9048-7edc058c4f65" ascii wide
        $typelibguid1lo = "73ca4159-5d13-4a27-8965-d50c41ab203c" ascii wide
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
        modified = "2025-08-15"
        id = "538a4f12-5020-5c76-9208-363f435ed9a9"
    strings:
        $typelibguid0lo = "c6894882-d29d-4ae1-aeb7-7d0a9b915013" ascii wide
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
        modified = "2025-08-15"
        id = "90b742da-6fd7-5c72-96cf-7a37a3e5d808"
    strings:
        $typelibguid0lo = "6c43a753-9565-48b2-a372-4210bb1e0d75" ascii wide
        $typelibguid1lo = "92ba2a7e-c198-4d43-929e-1cfe54b64d95" ascii wide
        $typelibguid2lo = "4cb9bbee-fb92-44fa-a427-b7245befc2f3" ascii wide
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
        modified = "2025-08-15"
        id = "8c309522-90e7-5f5a-b456-3a472756d397"
    strings:
        $typelibguid0lo = "10a730cd-9517-42d5-b3e3-a2383515cca9" ascii wide
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
        modified = "2025-08-15"
        id = "d221e24d-a2ef-51e2-95bf-4b91b438d9cf"
    strings:
        $typelibguid0lo = "d432c332-3b48-4d06-bedb-462e264e6688" ascii wide
        $typelibguid1lo = "5796276f-1c7a-4d7b-a089-550a8c19d0e8" ascii wide
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
        modified = "2025-08-15"
        id = "0bb38f10-ca5c-5c18-97c9-540b6367d150"
    strings:
        $typelibguid0lo = "9877a948-2142-4094-98de-e0fbb1bc4062" ascii wide
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
        modified = "2025-08-15"
        id = "1ed5e226-0dcd-5397-b5e8-41f8a14981a1"
    strings:
        $typelibguid0lo = "1e54637b-c887-42a9-af6a-b4bd4e28cda9" ascii wide
        $typelibguid1lo = "198d5599-d9fc-4a74-87f4-5077318232ad" ascii wide
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
        modified = "2025-08-15"
        id = "00fb98a9-e615-5fb6-a555-4326b93e2c24"
    strings:
        $typelibguid0lo = "922e7fdc-33bf-48de-bc26-a81f85462115" ascii wide
        $typelibguid1lo = "ad5205dd-174d-4332-96d9-98b076d6fd82" ascii wide
        $typelibguid2lo = "b67e7550-f00e-48b3-ab9b-4332b1254a86" ascii wide
        $typelibguid3lo = "5e95120e-b002-4495-90a1-cd3aab2a24dd" ascii wide
        $typelibguid4lo = "295017f2-dc31-4a87-863d-0b9956c2b55a" ascii wide
        $typelibguid5lo = "abbaa2f7-1452-43a6-b98e-10b2c8c2ba46" ascii wide
        $typelibguid6lo = "a4043d4c-167b-4326-8be4-018089650382" ascii wide
        $typelibguid7lo = "51abfd75-b179-496e-86db-62ee2a8de90d" ascii wide
        $typelibguid8lo = "a06da7f8-f87e-4065-81d8-abc33cb547f8" ascii wide
        $typelibguid9lo = "ee510712-0413-49a1-b08b-1f0b0b33d6ef" ascii wide
        $typelibguid10lo = "9780da65-7e25-412e-9aa1-f77d828819d6" ascii wide
        $typelibguid11lo = "7913fe95-3ad5-41f5-bf7f-e28f080724fe" ascii wide
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
        modified = "2025-08-15"
        id = "4ae78576-ab75-5679-9a29-4d9a1ff03f15"
    strings:
        $typelibguid0lo = "579159ff-3a3d-46a7-b069-91204feb21cd" ascii wide
        $typelibguid1lo = "5b7dd9be-c8c3-4c4f-a353-fefb89baa7b3" ascii wide
        $typelibguid2lo = "43edcb1f-3098-4a23-a7f2-895d927bc661" ascii wide
        $typelibguid3lo = "5f19919d-cd51-4e77-973f-875678360a6f" ascii wide
        $typelibguid4lo = "17fbc926-e17e-4034-ba1b-fb2eb57f5dd3" ascii wide
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
        modified = "2025-08-15"
        id = "a817c6e8-95f9-56c6-97b8-4be06658629f"
    strings:
        $typelibguid0lo = "78642ab3-eaa6-4e9c-a934-e7b0638bc1cc" ascii wide
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
        modified = "2025-08-15"
        id = "66454ac0-742b-51a3-ac45-1ac9606e8b89"
    strings:
        $typelibguid0lo = "29d09aa4-ea0c-47c2-973c-1d768087d527" ascii wide
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
        modified = "2025-08-15"
        id = "0576756e-26d5-5165-b621-917126a75a38"
    strings:
        $typelibguid0lo = "7afbc9bf-32d9-460f-8a30-35e30aa15879" ascii wide
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
        modified = "2025-08-15"
        id = "4b79867d-761c-5aa8-bf8a-60caa50d8aa6"
    strings:
        $typelibguid0lo = "d9c2e3c1-e9cc-42b0-a67c-b6e1a4f962cc" ascii wide
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
        modified = "2025-08-15"
        id = "5cce395b-4f6f-5015-b45e-7eb79853296a"
    strings:
        $typelibguid0lo = "36e00152-e073-4da8-aa0c-375b6dd680c4" ascii wide
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
        modified = "2025-08-15"
        id = "858a079d-71e8-516e-a2a9-f0969edc758b"
    strings:
        $typelibguid0lo = "619b7612-dfea-442a-a927-d997f99c497b" ascii wide
        $typelibguid1lo = "424b81be-2fac-419f-b4bc-00ccbe38491f" ascii wide
        $typelibguid2lo = "37e20baf-3577-4cd9-bb39-18675854e255" ascii wide
        $typelibguid3lo = "dafe686a-461b-402b-bbd7-2a2f4c87c773" ascii wide
        $typelibguid4lo = "ee03faa9-c9e8-4766-bd4e-5cd54c7f13d3" ascii wide
        $typelibguid5lo = "8bfc8ed2-71cc-49dc-9020-2c8199bc27b6" ascii wide
        $typelibguid6lo = "d640c36b-2c66-449b-a145-eb98322a67c8" ascii wide
        $typelibguid7lo = "8de42da3-be99-4e7e-a3d2-3f65e7c1abce" ascii wide
        $typelibguid8lo = "bee88186-769a-452c-9dd9-d0e0815d92bf" ascii wide
        $typelibguid9lo = "9042b543-13d1-42b3-a5b6-5cc9ad55e150" ascii wide
        $typelibguid10lo = "6aa4e392-aaaf-4408-b550-85863dd4baaf" ascii wide
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
        modified = "2025-08-15"
        id = "0aea5e05-7788-5581-8bcc-d2e75a291dd9"
    strings:
        $typelibguid0lo = "12fdf7ce-4a7c-41b6-9b32-766ddd299beb" ascii wide
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
        modified = "2025-08-15"
    strings:
        $typelibguid0lo = "68e40495-c34a-4539-b43e-9e4e6f11a9fb" ascii wide
        $typelibguid1lo = "641cd52d-3886-4a74-b590-2a05621502a4" ascii wide
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
        modified = "2025-08-15"
        id = "607f72df-b0c1-53df-bf2c-592f55cbfcb7"
    strings:
        $typelibguid0lo = "46a7af83-1da7-40b2-9d86-6fd6223f6791" ascii wide
        $typelibguid1lo = "8433a693-f39d-451b-955b-31c3e7fa6825" ascii wide
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
        modified = "2025-08-15"
        id = "cffd3350-4a86-5035-ab15-adbc3ac2a0e9"
    strings:
        $typelibguid0lo = "76ffa92b-429b-4865-970d-4e7678ac34ea" ascii wide
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
        modified = "2025-08-15"
        id = "8607de67-b472-5afc-b2b9-cc758b5ec474"
    strings:
        $typelibguid0lo = "ccc0a386-c4ce-42ef-aaea-b2af7eff4ad8" ascii wide
        $typelibguid1lo = "816b8b90-2975-46d3-aac9-3c45b26437fa" ascii wide
        $typelibguid2lo = "279b5533-d3ac-438f-ba89-3fe9de2da263" ascii wide
        $typelibguid3lo = "88d3dc02-2853-4bf0-b6dc-ad31f5135d26" ascii wide
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
        modified = "2025-08-15"
        id = "3645e14c-6025-59fa-a5a2-d8dacba8cd94"
    strings:
        $typelibguid0lo = "ca60e49e-eee9-409b-8d1a-d19f1d27b7e4" ascii wide
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
        modified = "2025-08-15"
        id = "d4b9a8c5-e0d9-5c85-af81-05f6e0f52bff"
    strings:
        $typelibguid0lo = "2aa060b4-de88-4d2a-a26a-760c1cefec3e" ascii wide
        $typelibguid1lo = "b118802d-2e46-4e41-aac7-9ee890268f8b" ascii wide
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
        modified = "2025-08-15"
        id = "e96aa79b-1da2-5b0c-9ac2-b6e201e06ec6"
    strings:
        $typelibguid0lo = "fe9fdde5-3f38-4f14-8c64-c3328c215cf2" ascii wide
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
        modified = "2025-08-15"
        id = "f7ff344e-f8ee-5c3a-bdd1-de3cae8e7dfb"
    strings:
        $typelibguid0lo = "bdfee233-3fed-42e5-aa64-492eb2ac7047" ascii wide
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
        modified = "2025-08-15"
        id = "89ca4717-a4ec-5371-8dc3-bdb9933384af"
    strings:
        $typelibguid0lo = "1126d5b4-efc7-4b33-a594-b963f107fe82" ascii wide
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
        modified = "2025-08-15"
        id = "642c2672-2327-5a4a-af91-6e0559996908"
    strings:
        $typelibguid0lo = "fbb1abcf-2b06-47a0-9311-17ba3d0f2a50" ascii wide
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
        modified = "2025-08-15"
        id = "8f25593b-b9d2-5807-b299-b039ecfd43a5"
    strings:
        $typelibguid0lo = "9936ae73-fb4e-4c5e-a5fb-f8aaeb3b9bd6" ascii wide
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
        modified = "2025-08-15"
        id = "2f0b9635-2b2e-5825-baeb-69d7ae3791b1"
    strings:
        $typelibguid0lo = "fd17ae38-2fd3-405f-b85b-e9d14e8e8261" ascii wide
        $typelibguid1lo = "1850b9bb-4a23-4d74-96b8-58f274674566" ascii wide
        $typelibguid2lo = "297cbca1-efa3-4f2a-8d5f-e1faf02ba587" ascii wide
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
        modified = "2025-08-15"
        id = "11ba6c14-06b6-5d9f-ac69-08ae506877e7"
    strings:
        $typelibguid0lo = "4545cfde-9ee5-4f1b-b966-d128af0b9a6e" ascii wide
        $typelibguid1lo = "33849d2b-3be8-41e8-a1e2-614c94c4533c" ascii wide
        $typelibguid2lo = "c2dc73cc-a959-4965-8499-a9e1720e594b" ascii wide
        $typelibguid3lo = "77059fa1-4b7d-4406-bc1a-cb261086f915" ascii wide
        $typelibguid4lo = "a4a04c4d-5490-4309-9c90-351e5e5fd6d1" ascii wide
        $typelibguid5lo = "ca64f918-3296-4b7d-9ce6-b98389896765" ascii wide
        $typelibguid6lo = "10fe32a0-d791-47b2-8530-0b19d91434f7" ascii wide
        $typelibguid7lo = "679bba57-3063-4f17-b491-4f0a730d6b02" ascii wide
        $typelibguid8lo = "0981e164-5930-4ba0-983c-1cf679e5033f" ascii wide
        $typelibguid9lo = "2a844ca2-5d6c-45b5-963b-7dca1140e16f" ascii wide
        $typelibguid10lo = "7d75ca11-8745-4382-b3eb-c41416dbc48c" ascii wide
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
        modified = "2025-08-15"
        id = "5669bc1a-b32e-5ae7-bf94-8ed2a124c765"
    strings:
        $typelibguid0lo = "89f9d411-e273-41bb-8711-209fd251ca88" ascii wide
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
        modified = "2025-08-15"
        id = "ea27044f-69be-5db7-8d77-28dafb18c7e5"
    strings:
        $typelibguid0lo = "4f495784-b443-4838-9fa6-9149293af785" ascii wide
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
        modified = "2025-08-15"
        id = "6dc7bb08-0b34-50a0-8ae8-02d96d66a334"
    strings:
        $typelibguid0lo = "49ad5f38-9e37-4967-9e84-fe19c7434ed7" ascii wide
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
        modified = "2025-08-15"
        id = "2af3c28a-ce5d-5dea-9abe-ff54b180049e"
    strings:
        $typelibguid0lo = "01c142ba-7af1-48d6-b185-81147a2f7db7" ascii wide
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
        modified = "2025-08-15"
        id = "681cf9da-d664-5402-b7ac-eb2cfad85da9"
    strings:
        $typelibguid0lo = "7ad1ff2d-32ac-4c54-b615-9bb164160dac" ascii wide
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
        modified = "2025-08-15"
        id = "3ef9f099-13c9-5b6f-8615-232240530078"
    strings:
        $typelibguid0lo = "2a3c5921-7442-42c3-8cb9-24f21d0b2414" ascii wide
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
        modified = "2025-08-15"
        id = "ad8b5573-ad20-50cd-927b-a6401b10e653"
    strings:
        $typelibguid0lo = "f7fc19da-67a3-437d-b3b0-2a257f77a00b" ascii wide
        $typelibguid1lo = "47e85bb6-9138-4374-8092-0aeb301fe64b" ascii wide
        $typelibguid2lo = "c7d854d8-4e3a-43a6-872f-e0710e5943f7" ascii wide
        $typelibguid3lo = "d6685430-8d8d-4e2e-b202-de14efa25211" ascii wide
        $typelibguid4lo = "1df925fc-9a89-4170-b763-1c735430b7d0" ascii wide
        $typelibguid5lo = "817cc61b-8471-4c1e-b5d6-c754fc550a03" ascii wide
        $typelibguid6lo = "60116613-c74e-41b9-b80e-35e02f25891e" ascii wide
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
        modified = "2025-08-15"
        id = "54c87578-f0f1-5108-a736-b6acd9624d29"
    strings:
        $typelibguid0lo = "1b4c5ec1-2845-40fd-a173-62c450f12ea5" ascii wide
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
        modified = "2025-08-15"
        id = "70fd7431-8c32-52a4-be9f-2a19ef77f2cc"
    strings:
        $typelibguid0lo = "843d8862-42eb-49ee-94e6-bca798dd33ea" ascii wide
        $typelibguid1lo = "632e4c3b-3013-46fc-bc6e-22828bf629e3" ascii wide
        $typelibguid2lo = "a2091d2f-6f7e-4118-a203-4cea4bea6bfa" ascii wide
        $typelibguid3lo = "950ef8ce-ec92-4e02-b122-0d41d83065b8" ascii wide
        $typelibguid4lo = "d51301bc-31aa-4475-8944-882ecf80e10d" ascii wide
        $typelibguid5lo = "823ff111-4de2-4637-af01-4bdc3ca4cf15" ascii wide
        $typelibguid6lo = "5d28f15e-3bb8-4088-abe0-b517b31d4595" ascii wide
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
        modified = "2025-08-15"
        id = "bf318530-b17d-5275-84b2-c284528bdae6"
    strings:
        $typelibguid0lo = "3da2f6de-75be-4c9d-8070-08da45e79761" ascii wide
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
        modified = "2025-08-15"
        id = "5e707da6-b2dd-511e-89ad-d19b93e8fca6"
    strings:
        $typelibguid0lo = "b9f6ec34-4ccc-4247-bcef-c1daab9b4469" ascii wide
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
        modified = "2025-08-15"
        id = "5ebbeab3-3e93-5544-8f74-3d1b47335d8b"
    strings:
        $typelibguid0lo = "10cd7c1c-e56d-4b1b-80dc-e4c496c5fec5" ascii wide
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
        modified = "2025-08-15"
        id = "0c181186-7bb4-502b-8937-60cfd88ce689"
    strings:
        $typelibguid0lo = "9d1b853e-58f1-4ba5-aefc-5c221ca30e48" ascii wide
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
        modified = "2025-08-15"
        id = "3e18b533-1b85-5eaf-bb3d-aa5b90fd2e28"
    strings:
        $typelibguid0lo = "584964c1-f983-498d-8370-23e27fdd0399" ascii wide
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
        modified = "2025-08-15"
        id = "cd24cca7-3bc0-5e7a-9817-dc3b26ec8358"
    strings:
        $typelibguid0lo = "d9c76e82-b848-47d4-8f22-99bf22a8ee11" ascii wide
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
        modified = "2025-08-15"
        id = "a9cd9a16-b2a5-5d15-af89-7a8d0f1835bb"
    strings:
        $typelibguid0lo = "5decaea3-2610-4065-99dc-65b9b4ba6ccd" ascii wide
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
        modified = "2025-08-15"
        id = "0ad18d2b-b7cc-5316-a8e8-b05d4439b8e1"
    strings:
        $typelibguid0lo = "c653a9f2-0939-43c8-9b93-fed5e2e4c7e6" ascii wide
        $typelibguid1lo = "48dfc55e-6ae5-4a36-abef-14bc09d7510b" ascii wide
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
        modified = "2025-08-15"
        id = "b00c353b-0446-5faa-87e5-0a7ba6ec2286"
    strings:
        $typelibguid0lo = "9b448062-7219-4d82-9a0a-e784c4b3aa27" ascii wide
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
        modified = "2025-08-15"
        id = "12d3f26b-40ca-5034-a7c2-9be9c8a7599b"
    strings:
        $typelibguid0lo = "68b83ce5-bbd9-4ee3-b1cc-5e9223fab52b" ascii wide
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
        modified = "2025-08-15"
        id = "a59e6fe9-dbaf-5830-8cf1-485ff4dd939a"
    strings:
        $typelibguid0lo = "56598f1c-6d88-4994-a392-af337abe5777" ascii wide
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
        modified = "2025-08-15"
        id = "9bc0661d-c60f-582b-8f88-87e3dfa13ddd"
    strings:
        $typelibguid0lo = "034a7b9f-18df-45da-b870-0e1cef500215" ascii wide
        $typelibguid1lo = "59b449d7-c1e8-4f47-80b8-7375178961db" ascii wide
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
        modified = "2025-08-15"
        id = "5b22f2c4-0bd1-5a5a-8867-8fbc773d2b44"
    strings:
        $typelibguid0lo = "42c5c356-39cf-4c07-96df-ebb0ccf78ca4" ascii wide
        $typelibguid1lo = "0242b5b1-4d26-413e-8c8c-13b4ed30d510" ascii wide
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
        modified = "2025-08-15"
        id = "8bee12fc-fc29-5256-b559-d914ef202c0c"
    strings:
        $typelibguid0lo = "0527a14f-1591-4d94-943e-d6d784a50549" ascii wide
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
        modified = "2025-08-15"
        id = "e8e1ad03-a5f0-5508-b78d-0de7bdaf4704"
    strings:
        $typelibguid0lo = "784cde17-ff0f-4e43-911a-19119e89c43f" ascii wide
        $typelibguid1lo = "7e2de2c0-61dc-43ab-a0ec-c27ee2172ea6" ascii wide
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
        modified = "2025-08-15"
        id = "649c6cc0-e43b-558c-9567-00f352af528b"
    strings:
        $typelibguid0lo = "ffc5c721-49c8-448d-8ff4-2e3a7b7cc383" ascii wide
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
        modified = "2025-08-15"
        id = "d02d34f0-7aa1-5110-b7ea-670b5fb98150"
    strings:
        $typelibguid0lo = "897819d5-58e0-46a0-8e1a-91ea6a269d84" ascii wide
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
        modified = "2025-08-15"
        id = "5faff0aa-9ffe-5ac0-b9e0-ca9f79350036"
    strings:
        $typelibguid0lo = "7fbad126-e21c-4c4e-a9f0-613fcf585a71" ascii wide
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
        modified = "2025-08-15"
        id = "94da3da4-a8aa-5735-9a04-1f2447a330aa"
    strings:
        $typelibguid0lo = "51960f7d-76fe-499f-afbd-acabd7ba50d1" ascii wide
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
        modified = "2025-08-15"
        id = "8d18f1d5-9c9a-5258-9f96-fa24b702c6ad"
    strings:
        $typelibguid0lo = "03d96b8c-efd1-44a9-8db2-0b74db5d247a" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpWMI_1 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/QAX-A-Team/sharpwmi"
        old_rule_name = "HKTL_NET_GUID_sharpwmi"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "cd5a1c7b-a45a-5541-b1b0-cf19c991ed22"
    strings:
        $typelibguid0lo = "bb357d38-6dc1-4f20-a54c-d664bd20677e" ascii wide
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
        modified = "2025-08-15"
        id = "4640e874-faa4-58dc-a3f3-18246a343f15"
    strings:
        $typelibguid0lo = "ff97e98a-635e-4ea9-b2d0-1a13f6bdbc38" ascii wide
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
        modified = "2025-08-15"
        id = "84ebb6b3-cf11-5172-95d4-d114bfeb0bc7"
    strings:
        $typelibguid0lo = "4b2b3bd4-d28f-44cc-96b3-4a2f64213109" ascii wide
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
        modified = "2025-08-15"
        id = "c99523ce-e2c0-5a21-89d1-70c0dd970731"
    strings:
        $typelibguid0lo = "cca59e4e-ce4d-40fc-965f-34560330c7e6" ascii wide
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
        modified = "2025-08-15"
        id = "3a9d3154-a8f1-57a4-8b61-498e2ebdfa42"
    strings:
        $typelibguid0lo = "99428732-4979-47b6-a323-0bb7d6d07c95" ascii wide
        $typelibguid1lo = "a2c9488f-6067-4b17-8c6f-2d464e65c535" ascii wide
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
        modified = "2025-08-15"
        id = "fda1a67f-d746-5ddb-a33f-97d608b13bc9"
    strings:
        $typelibguid0lo = "616c1afb-2944-42ed-9951-bf435cadb600" ascii wide
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
        modified = "2025-08-15"
        id = "266c8add-d2ca-5e46-8594-5d190447d133"
    strings:
        $typelibguid0lo = "a766db28-94b6-4ed1-aef9-5200bbdd8ca7" ascii wide
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
        modified = "2025-08-15"
        id = "f381081b-d0cb-593d-ad3d-28816f770b67"
    strings:
        $typelibguid0lo = "997265c1-1342-4d44-aded-67964a32f859" ascii wide
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
        modified = "2025-08-15"
        id = "98409bbe-6346-5825-b7f7-c1afeac2b038"
    strings:
        $typelibguid0lo = "31d576fb-9fb9-455e-ab02-c78981634c65" ascii wide
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
        modified = "2025-08-15"
        id = "354ee690-a0d0-5cc5-a73b-53b916ed0169"
    strings:
        $typelibguid0lo = "806c6c72-4adc-43d9-b028-6872fa48d334" ascii wide
        $typelibguid1lo = "2ef9d8f7-6b77-4b75-822b-6a53a922c30f" ascii wide
        $typelibguid2lo = "8f5f3a95-f05c-4dce-8bc3-d0a0d4153db6" ascii wide
        $typelibguid3lo = "1f707405-9708-4a34-a809-2c62b84d4f0a" ascii wide
        $typelibguid4lo = "97421325-b6d8-49e5-adf0-e2126abc17ee" ascii wide
        $typelibguid5lo = "06c247da-e2e1-47f3-bc3c-da0838a6df1f" ascii wide
        $typelibguid6lo = "fc700ac6-5182-421f-8853-0ad18cdbeb39" ascii wide
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
        modified = "2025-08-15"
        id = "10567ef4-780f-5e93-9061-3214116d6bbb"
    strings:
        $typelibguid0lo = "e12e62fe-bea3-4989-bf04-6f76028623e3" ascii wide
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
        modified = "2025-08-15"
        id = "3ef58da9-16c1-54cf-9d06-a05680548cf5"
    strings:
        $typelibguid0lo = "015a37fc-53d0-499b-bffe-ab88c5086040" ascii wide
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
        modified = "2025-08-15"
        id = "8c65fbee-d779-57a8-851b-7583be66c67a"
    strings:
        $typelibguid0lo = "0c117ee5-2a21-dead-beef-8cc7f0caaa86" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpWMI_2 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/GhostPack/SharpWMI"
        old_rule_name = "HKTL_NET_GUID_SharpWMI"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "e6ab2f5e-2a5a-5be9-9b66-96cb745fd199"
    strings:
        $typelibguid0lo = "6dd22880-dac5-4b4d-9c91-8c35cc7b8180" ascii wide
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
        modified = "2025-08-15"
        id = "acde7744-d17f-5e47-a5e2-ff4f4c4d8093"
    strings:
        $typelibguid0lo = "ca536d67-53c9-43b5-8bc8-9a05fdc567ed" ascii wide
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
        modified = "2025-08-15"
        id = "0e347d94-51eb-5589-93d8-b19fec7f2365"
    strings:
        $typelibguid0lo = "6aeb5004-6093-4c23-aeae-911d64cacc58" ascii wide
        $typelibguid1lo = "1bf9c10f-6f89-4520-9d2e-aaf17d17ba5e" ascii wide
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
        modified = "2025-08-15"
        id = "35175fe1-a583-50d1-8b0c-71f19b898817"
    strings:
        $typelibguid0lo = "79462f87-8418-4834-9356-8c11e44ce189" ascii wide
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
        modified = "2025-08-15"
        id = "e5bde5a9-8e09-59ce-ad01-e29836813cf8"
    strings:
        $typelibguid0lo = "2963c954-7b1e-47f5-b4fa-2fc1f0d56aea" ascii wide
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
        modified = "2025-08-15"
        id = "9525422a-d670-5475-abdc-b7ecd1ab9943"
    strings:
        $typelibguid0lo = "a6f8500f-68bc-4efc-962a-6c6e68d893af" ascii wide
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
        modified = "2025-08-15"
        id = "3b624dde-a63e-58ac-a4db-af931f1d8553"
    strings:
        $typelibguid0lo = "0f43043d-8957-4ade-a0f4-25c1122e8118" ascii wide
        $typelibguid1lo = "086bf0ca-f1e4-4e8f-9040-a8c37a49fa26" ascii wide
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
        modified = "2025-08-15"
        id = "5f2ac63e-4be1-520c-82b1-1957027a63e2"
    strings:
        $typelibguid0lo = "12963497-988f-46c0-9212-28b4b2b1831b" ascii wide
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
        modified = "2025-08-15"
        id = "fd1b7786-8853-5858-ab03-da350e44f738"
    strings:
        $typelibguid0lo = "97484211-4726-4129-86aa-ae01d17690be" ascii wide
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
        modified = "2025-08-15"
        id = "87be6949-f4f5-5a5a-b804-c627ed0f4355"
    strings:
        $typelibguid0lo = "566c5556-1204-4db9-9dc8-a24091baaa8e" ascii wide
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
        modified = "2025-08-15"
        id = "390b94d1-dda9-5a85-80ae-c79a3f7b0b9d"
    strings:
        $typelibguid0lo = "2e9b1462-f47c-48ca-9d85-004493892381" ascii wide
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
        modified = "2025-08-15"
        id = "e52392f9-614c-596e-8efd-aa0a2fa44e60"
    strings:
        $typelibguid0lo = "8bf82bbe-909c-4777-a2fc-ea7c070ff43e" ascii wide
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
        modified = "2025-08-15"
        id = "f5df8257-d202-58e3-9c4a-1dfc9dd52f2a"
    strings:
        $typelibguid0lo = "6d9e8852-e86c-4e36-9cb4-b3c3853ed6b8" ascii wide
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
        modified = "2025-08-15"
        id = "10270351-ad80-5330-971b-bc8f635f05f4"
    strings:
        $typelibguid0lo = "41b2d1e5-4c5d-444c-aa47-629955401ed9" ascii wide
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
        modified = "2025-08-15"
        id = "2b2f5f6f-4224-5013-9e85-0ac088826bea"
    strings:
        $typelibguid0lo = "f26bdb4a-5846-4bec-8f52-3c39d32df495" ascii wide
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
        modified = "2025-08-15"
        id = "245803cb-63d8-5c75-b672-912091cf4a80"
    strings:
        $typelibguid0lo = "85773eb7-b159-45fe-96cd-11bad51da6de" ascii wide
        $typelibguid1lo = "9d32ad59-4093-420d-b45c-5fff391e990d" ascii wide
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
        modified = "2025-08-15"
        id = "32bdaa0f-3afc-5e0e-a20f-e21f33909af7"
    strings:
        $typelibguid0lo = "39b75120-07fe-4833-a02e-579ff8b68331" ascii wide
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
        modified = "2025-08-15"
        id = "6a1024af-734c-5974-af50-db51dbd694ff"
    strings:
        $typelibguid0lo = "344ee55a-4e32-46f2-a003-69ad52b55945" ascii wide
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
        modified = "2025-08-15"
        id = "ce49cc7b-a5a5-52b7-a7bf-bbb0c5b29b8a"
    strings:
        $typelibguid0lo = "384e9647-28a9-4835-8fa7-2472b1acedc0" ascii wide
        $typelibguid1lo = "d7ec0ef5-157c-4533-bbcd-0fe070fbf8d9" ascii wide
        $typelibguid2lo = "10085d98-48b9-42a8-b15b-cb27a243761b" ascii wide
        $typelibguid3lo = "6aacd159-f4e7-4632-bad1-2ae8526a9633" ascii wide
        $typelibguid4lo = "49a6719e-11a8-46e6-ad7a-1db1be9fea37" ascii wide
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
        modified = "2025-08-15"
        id = "c978be10-315c-54e7-afea-f97e9a5f2d18"
    strings:
        $typelibguid0lo = "b9fbf3ac-05d8-4cd5-9694-b224d4e6c0ea" ascii wide
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
        modified = "2025-08-15"
        id = "9448e8d0-5bfc-5683-b633-284e43d24642"
    strings:
        $typelibguid0lo = "d0f2ee67-0a50-423d-bfe6-845da892a2db" ascii wide
        $typelibguid1lo = "a593fcd2-c8ab-45f6-9aeb-8ab5e20ab402" ascii wide
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
        modified = "2025-08-15"
        id = "49ff1362-0ac5-580d-97f3-516f2a10072b"
    strings:
        $typelibguid0lo = "dfc4eebb-7384-4db5-9bad-257203029bd9" ascii wide
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
        modified = "2025-08-15"
        id = "b938cf7d-27fd-5fa2-b0e5-d4da5670f3ef"
    strings:
        $typelibguid0lo = "cfda6d2e-8ab3-4349-b89a-33e1f0dab32b" ascii wide
        $typelibguid1lo = "c7c363ba-e5b6-4e18-9224-39bc8da73172" ascii wide
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
        modified = "2025-08-15"
        id = "51d50b22-4e73-5378-9e0d-ad7730987293"
    strings:
        $typelibguid0lo = "cdb02bc2-5f62-4c8a-af69-acc3ab82e741" ascii wide
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
        modified = "2025-08-15"
        id = "31827074-fc63-5690-b6c7-8e89daacc07f"
    strings:
        $typelibguid0lo = "7e3f231c-0d0b-4025-812c-0ef099404861" ascii wide
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
        modified = "2025-08-15"
        id = "af2d9832-c7f9-5879-a19b-a3c4d91b8b3f"
    strings:
        $typelibguid0lo = "26d498f7-37ae-476c-97b0-3761e3a919f0" ascii wide
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
        modified = "2025-08-15"
        id = "459d8a34-f311-5459-8257-e7aa519174b5"
    strings:
        $typelibguid0lo = "98fee742-8410-4f20-8b2d-d7d789ab003d" ascii wide
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
        modified = "2025-08-15"
        id = "492dfb79-541a-589d-ac69-468e9b2ab9db"
    strings:
        $typelibguid0lo = "e2fdd6cc-9886-456c-9021-ee2c47cf67b7" ascii wide
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
        modified = "2025-08-15"
        id = "a718f9fc-acf5-536e-81d6-d393cebe8f77"
    strings:
        $typelibguid0lo = "00fcf72c-d148-4dd0-9ca4-0181c4bd55c3" ascii wide
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
        modified = "2025-08-15"
        id = "1b5f1f68-f87b-5e60-94a4-e2556b4e6c5d"
    strings:
        $typelibguid0lo = "2c879479-5027-4ce9-aaac-084db0e6d630" ascii wide
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
        modified = "2025-08-15"
        id = "8cb2edcd-3696-5857-90ca-e99b1af54320"
    strings:
        $typelibguid0lo = "9ee27d63-6ac9-4037-860b-44e91bae7f0d" ascii wide
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
        modified = "2025-08-15"
        id = "d316ec0b-0313-52bb-923d-512fa08112f9"
    strings:
        $typelibguid0lo = "f1df1d0f-ff86-4106-97a8-f95aaf525c54" ascii wide
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
        modified = "2025-08-15"
        id = "172415b6-0383-5da4-a88f-8ebe5daf9294"
    strings:
        $typelibguid0lo = "c1b0a923-0f17-4bc8-ba0f-c87aff43e799" ascii wide
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
        modified = "2025-08-15"
        id = "80483cd4-76e6-5629-bed7-4ae2e455222c"
    strings:
        $typelibguid0lo = "e1e8c029-f7cd-4bd1-952e-e819b41520f0" ascii wide
        $typelibguid1lo = "6b40fde7-14ea-4f57-8b7b-cc2eb4a25e6c" ascii wide
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
        modified = "2025-08-15"
        id = "c66e7666-b54f-532d-90e1-870292047aec"
    strings:
        $typelibguid0lo = "e5182bff-9562-40ff-b864-5a6b30c3b13b" ascii wide
        $typelibguid1lo = "fdedde0d-e095-41c9-93fb-c2219ada55b1" ascii wide
        $typelibguid2lo = "0dd00561-affc-4066-8c48-ce950788c3c8" ascii wide
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
        modified = "2025-08-15"
        id = "343061d9-e24e-5d49-939f-b94c295b17ac"
    strings:
        $typelibguid0lo = "2f43992e-5703-4420-ad0b-17cb7d89c956" ascii wide
        $typelibguid1lo = "86d10a34-c374-4de4-8e12-490e5e65ddff" ascii wide
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
        modified = "2025-08-15"
        id = "ae08a5a2-06d5-55fe-803a-7f4696220904"
    strings:
        $typelibguid0lo = "0a63b0a1-7d1a-4b84-81c3-bbbfe9913029" ascii wide
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
        modified = "2025-08-15"
        id = "71fef0e9-223a-5834-9d1c-f3fb8b66a809"
    strings:
        $typelibguid1lo = "39aa6f93-a1c9-497f-bad2-cc42a61d5710" ascii wide
        $typelibguid3lo = "3fca8012-3bad-41e4-91f4-534aa9a44f96" ascii wide
        $typelibguid4lo = "ea92f1e6-3f34-48f8-8b0a-f2bbc19220ef" ascii wide
        $typelibguid5lo = "c23b51c4-2475-4fc6-9b3a-27d0a2b99b0f" ascii wide
        /* $typelibguid6 = "94432a8e-3e06-4776-b9b2-3684a62bb96a" ascii nocase wide FIX FPS with Microsoft files */ 
        $typelibguid7lo = "80ba63a4-7d41-40e9-a722-6dd58b28bf7e" ascii wide
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
        modified = "2025-08-15"
        id = "cc20290c-3f34-5e81-9337-c582f1ee7ade"
    strings:
        $typelibguid0lo = "d35a55bd-3189-498b-b72f-dc798172e505" ascii wide
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
        modified = "2025-08-15"
        id = "a91620f3-3f21-525a-bc87-94d21cd126be"
    strings:
        $typelibguid0lo = "b1ac6aa0-2f1a-4696-bf4b-0e41cf2f4b6b" ascii wide
        $typelibguid1lo = "78bfcfc2-ef1c-4514-bce6-934b251666d2" ascii wide
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
        modified = "2025-08-15"
        id = "1eb911ab-3fb9-54b7-8afb-66328f30d563"
    strings:
        $typelibguid0lo = "5f0ceca3-5997-406c-adf5-6c7fbb6cba17" ascii wide
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
        modified = "2025-08-15"
        id = "21acc8af-9497-5842-90a9-7a9300585d5d"
    strings:
        $typelibguid0lo = "64cdcd2b-7356-4079-af78-e22210e66154" ascii wide
        $typelibguid1lo = "f1dee29d-ca98-46ea-9d13-93ae1fda96e1" ascii wide
        $typelibguid2lo = "33568320-56e8-4abb-83f8-548e8d6adac2" ascii wide
        $typelibguid3lo = "470ec930-70a3-4d71-b4ff-860fcb900e85" ascii wide
        $typelibguid4lo = "9514574d-6819-44f2-affa-6158ac1143b3" ascii wide
        $typelibguid5lo = "0f3a9c4f-0b11-4373-a0a6-3a6de814e891" ascii wide
        $typelibguid6lo = "9624b72e-9702-4d78-995b-164254328151" ascii wide
        $typelibguid7lo = "faae59a8-55fc-48b1-a9b5-b1759c9c1010" ascii wide
        $typelibguid8lo = "37af4988-f6f2-4f0c-aa2b-5b24f7ed3bf3" ascii wide
        $typelibguid9lo = "c82aa2fe-3332-441f-965e-6b653e088abf" ascii wide
        $typelibguid10lo = "6e531f6c-2c89-447f-8464-aaa96dbcdfff" ascii wide
        $typelibguid11lo = "231987a1-ea32-4087-8963-2322338f16f6" ascii wide
        $typelibguid12lo = "7da0d93a-a0ae-41a5-9389-42eff85bb064" ascii wide
        $typelibguid13lo = "a729f9cc-edc2-4785-9a7d-7b81bb12484c" ascii wide
        $typelibguid14lo = "55a1fd43-d23e-4d72-aadb-bbd1340a6913" ascii wide
        $typelibguid15lo = "d43f240d-e7f5-43c5-9b51-d156dc7ea221" ascii wide
        $typelibguid16lo = "c2e6c1a0-93b1-4bbc-98e6-8e2b3145db8e" ascii wide
        $typelibguid17lo = "714ae6f3-0d03-4023-b753-fed6a31d95c7" ascii wide
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
        modified = "2025-08-15"
        id = "bad36c36-dbed-527c-a2f5-4dceff1abe4b"
    strings:
        $typelibguid0lo = "3cb59871-0dce-453b-857a-2d1e515b0b66" ascii wide
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
        modified = "2025-08-15"
        id = "44237fac-1526-5587-83a1-61d7a54f7da9"
    strings:
        $typelibguid0lo = "91f7a9da-f045-4239-a1e9-487ffdd65986" ascii wide
        $typelibguid1lo = "0405205c-c2a0-4f9a-a221-48b5c70df3b6" ascii wide
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
        modified = "2025-08-15"
        id = "5ad947e2-bd71-50d4-9bbf-4d018c7ff36a"
    strings:
        $typelibguid0lo = "e9e80ac7-4c13-45bd-9bde-ca89aadf1294" ascii wide
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
        modified = "2025-08-15"
        id = "14e6a3b8-5e1f-5dd8-9b51-22522ac317e7"
    strings:
        $typelibguid0lo = "c8bb840c-04ce-4b60-a734-faf15abf7b18" ascii wide
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
        modified = "2025-08-15"
        id = "58001912-88a1-527d-9d3e-d7c376a1fce4"
    strings:
        $typelibguid0lo = "a517a8de-5834-411d-abda-2d0e1766539c" ascii wide
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
        modified = "2025-08-15"
        id = "c2b72fef-6549-5b53-8ccf-232e8d152e96"
    strings:
        $typelibguid0lo = "daedf7b3-8262-4892-adc4-425dd5f85bca" ascii wide
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
        modified = "2025-08-15"
        id = "1a457672-743c-56f0-a4d7-6c25f9ce2345"
    strings:
        $typelibguid0lo = "c0997698-2b73-4982-b25b-d0578d1323c2" ascii wide
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
        modified = "2025-08-15"
        id = "b4922734-a486-5c4d-9bd7-5146cfecbf01"
    strings:
        $typelibguid0lo = "bd5220f7-e1fb-41d2-91ec-e4c50c6e9b9f" ascii wide
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
        modified = "2025-08-15"
        id = "3421e6fb-df65-5e2e-ae46-37f9c763c6a1"
    strings:
        $typelibguid0lo = "13b6c843-f3d4-4585-b4f3-e2672a47931e" ascii wide
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
        modified = "2025-08-15"
        id = "c721a0ac-e898-52aa-9bdf-a19bc0bd783d"
    strings:
        $typelibguid0lo = "8fcd4931-91a2-4e18-849b-70de34ab75df" ascii wide
        $typelibguid1lo = "e48811ca-8af8-4e73-85dd-2045b9cca73a" ascii wide
        $typelibguid2lo = "d3d8a1cc-e123-4905-b3de-374749122fcf" ascii wide
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
        modified = "2025-08-15"
        id = "844e58a2-54f5-51e8-8176-6a478a136603"
    strings:
        $typelibguid0lo = "3a074374-77e8-4312-8746-37f3cb00e82c" ascii wide
        $typelibguid1lo = "67a73bac-f59d-4227-9220-e20a2ef42782" ascii wide
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
        modified = "2025-08-15"
        id = "40ab8103-9151-5a5c-8b70-ab3bfd3896f9"
    strings:
        $typelibguid0lo = "e94ca3ff-c0e5-4d1a-ad5e-f6ebbe365067" ascii wide
        $typelibguid1lo = "1ed07564-b411-4626-88e5-e1cd8ecd860a" ascii wide
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
        modified = "2025-08-15"
        id = "d0631817-10a2-55bf-a41d-226fa0dcb9f9"
    strings:
        $typelibguid0lo = "13958fb9-dfc1-4e2c-8a8d-a5e68abdbc66" ascii wide
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
        modified = "2025-08-15"
        id = "9fbb3c11-7b11-5910-9c8b-247aeefbaa87"
    strings:
        $typelibguid0lo = "c2b90883-abee-4cfa-af66-dfd93ec617a5" ascii wide
        $typelibguid1lo = "8bb6f5b4-e7c7-4554-afd1-48f368774837" ascii wide
        $typelibguid2lo = "983ae28c-91c3-4072-8cdf-698b2ff7a967" ascii wide
        $typelibguid3lo = "9ac18cdc-3711-4719-9cfb-5b5f2d51fd5a" ascii wide
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
        modified = "2025-08-15"
        id = "13362cba-f9b2-50c8-95cc-504e585bdd42"
    strings:
        $typelibguid0lo = "b8a2147c-074c-46e1-bb99-c8431a6546ce" ascii wide
        $typelibguid1lo = "0fcfde33-213f-4fb6-ac15-efb20393d4f3" ascii wide
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
        modified = "2025-08-15"
        id = "31a0e9ca-9da1-557a-bcc5-1351fa90a0e1"
    strings:
        $typelibguid0lo = "e58ac447-ab07-402a-9c96-95e284a76a8d" ascii wide
        $typelibguid1lo = "8fb35dab-73cd-4163-8868-c4dbcbdf0c17" ascii wide
        $typelibguid2lo = "37845f5b-35fe-4dce-bbec-2d07c7904fb0" ascii wide
        $typelibguid3lo = "83c453cf-0d29-4690-b9dc-567f20e63894" ascii wide
        $typelibguid4lo = "8b1f0a69-a930-42e3-9c13-7de0d04a4add" ascii wide
        $typelibguid5lo = "eaaeccf6-75d2-4616-b045-36eea09c8b28" ascii wide
        $typelibguid6lo = "5b2ec674-0aa4-4209-94df-b6c995ad59c4" ascii wide
        $typelibguid7lo = "e2cc7158-aee6-4463-95bf-fb5295e9e37a" ascii wide
        $typelibguid8lo = "d04ecf62-6da9-4308-804a-e789baa5cc38" ascii wide
        $typelibguid9lo = "8026261f-ac68-4ccf-97b2-3b55b7d6684d" ascii wide
        $typelibguid10lo = "212cdfac-51f1-4045-a5c0-6e638f89fce0" ascii wide
        $typelibguid11lo = "c1b608bb-7aed-488d-aa3b-0c96625d26c0" ascii wide
        $typelibguid12lo = "4c84e7ec-f197-4321-8862-d5d18783e2fe" ascii wide
        $typelibguid13lo = "3fc17adb-67d4-4a8d-8770-ecfd815f73ee" ascii wide
        $typelibguid14lo = "f1ab854b-6282-4bdf-8b8b-f2911a008948" ascii wide
        $typelibguid15lo = "aef6547e-3822-4f96-9708-bcf008129b2b" ascii wide
        $typelibguid16lo = "a336f517-bca9-465f-8ff8-2756cfd0cad9" ascii wide
        $typelibguid17lo = "5de018bd-941d-4a5d-bed5-fbdd111aba76" ascii wide
        $typelibguid18lo = "bbfac1f9-cd4f-4c44-af94-1130168494d0" ascii wide
        $typelibguid19lo = "1c79cea1-ebf3-494c-90a8-51691df41b86" ascii wide
        $typelibguid20lo = "927104e1-aa17-4167-817c-7673fe26d46e" ascii wide
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
        modified = "2025-08-15"
        id = "2140d69e-fb15-50a2-ba85-b7c8293003fb"
    strings:
        $typelibguid0lo = "5a542c1b-2d36-4c31-b039-26a88d3967da" ascii wide
        $typelibguid1lo = "6b07082a-9256-42c3-999a-665e9de49f33" ascii wide
        $typelibguid2lo = "c0a9a70f-63e8-42ca-965d-73a1bc903e62" ascii wide
        $typelibguid3lo = "70bd11de-7da1-4a89-b459-8daacc930c20" ascii wide
        $typelibguid4lo = "fc790ee5-163a-40f9-a1e2-9863c290ff8b" ascii wide
        $typelibguid5lo = "cb3c28b2-2a4f-4114-941c-ce929fec94d3" ascii wide
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
        modified = "2025-08-15"
        id = "eef65d2c-ddbc-50c3-a6a0-e7032a55e92d"
    strings:
        $typelibguid0lo = "dda73ee9-0f41-4c09-9cad-8215abd60b33" ascii wide
        $typelibguid1lo = "6a0f2422-d4d1-4b7e-84ad-56dc0fd2dfc5" ascii wide
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
        modified = "2025-08-15"
        id = "d73117a6-4512-5545-a4f4-72d8cf708340"
    strings:
        $typelibguid0lo = "e98490bb-63e5-492d-b14e-304de928f81a" ascii wide
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
        modified = "2025-08-15"
        id = "13b7f5e0-4d34-533d-a182-b3fe7c93ca43"
    strings:
        $typelibguid0lo = "dac5448a-4ad1-490a-846a-18e4e3e0cf9a" ascii wide
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
        modified = "2025-08-15"
        id = "247bef0d-7873-51c7-97b8-1be6dfe7708d"
    strings:
        $typelibguid0lo = "d5688068-fc89-467d-913f-037a785caca7" ascii wide
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
        modified = "2025-08-15"
        id = "399ea06d-b36a-542b-bccc-8e8f935a35c6"
    strings:
        $typelibguid0lo = "4da5f1b7-8936-4413-91f7-57d6e072b4a7" ascii wide
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
        modified = "2025-08-15"
        id = "fa218dfa-4b56-5a62-b149-63394bd0b604"
    strings:
        $typelibguid0lo = "1928358e-a64b-493f-a741-ae8e3d029374" ascii wide
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
        modified = "2025-08-15"
        id = "d70472f3-b19f-5097-bd70-99a7e7812ac4"
    strings:
        $typelibguid0lo = "3523ca04-a12d-4b40-8837-1a1d28ef96de" ascii wide
        $typelibguid1lo = "d3a2f24a-ddc6-4548-9b3d-470e70dbcaab" ascii wide
        $typelibguid2lo = "fb30ee05-4a35-45f7-9a0a-829aec7e47d9" ascii wide
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
        modified = "2025-08-15"
        id = "f3b0ef47-a92c-5c5d-a9e2-09579fcb438e"
    strings:
        $typelibguid0lo = "b77fdab5-207c-4cdb-b1aa-348505c54229" ascii wide
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
        modified = "2025-08-15"
        id = "3b7e6703-ebe8-5a98-839f-7d0349ab483f"
    strings:
        $typelibguid0lo = "f5f21e2d-eb7e-4146-a7e1-371fd08d6762" ascii wide
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
        modified = "2025-08-15"
        id = "47125b76-9388-5372-8810-d198f623367a"
    strings:
        $typelibguid0lo = "aa61a166-31ef-429d-a971-ca654cd18c3b" ascii wide
        $typelibguid1lo = "0dc1b824-c6e7-4881-8788-35aecb34d227" ascii wide
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
        modified = "2025-08-15"
        id = "d89b07b0-bb29-5c77-888b-322e439b4c82"
    strings:
        $typelibguid0lo = "8ef25b00-ed6a-4464-bdec-17281a4aa52f" ascii wide
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
        modified = "2025-08-15"
        id = "c98d84d5-4b0a-53df-b8d4-0b360930eb0c"
    strings:
        $typelibguid0lo = "ef18f7f2-1f03-481c-98f9-4a18a2f12c11" ascii wide
        $typelibguid1lo = "77b2c83b-ca34-4738-9384-c52f0121647c" ascii wide
        $typelibguid2lo = "14d5d12e-9a32-4516-904e-df3393626317" ascii wide
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
        modified = "2025-08-15"
        id = "f64ed564-d198-59e8-9abe-b2814b95c85f"
    strings:
        $typelibguid0lo = "c7a07532-12a3-4f6a-a342-161bb060b789" ascii wide
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
        modified = "2025-08-15"
        id = "3077dd0c-6936-5340-8da9-e8643de4d864"
    strings:
        $typelibguid0lo = "bc72386f-8b4c-44de-99b7-b06a8de3ce3f" ascii wide
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
        modified = "2025-08-15"
        id = "f9b31f57-d721-5b6c-be63-b8309cba788a"
    strings:
        $typelibguid0lo = "a91421cb-7909-4383-ba43-c2992bbbac22" ascii wide
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
        modified = "2025-08-15"
        id = "8408a057-4910-5d7b-80bc-78df17c95bf7"
    strings:
        $typelibguid0lo = "3097d856-25c2-42c9-8d59-2cdad8e8ea12" ascii wide
        $typelibguid1lo = "ba33f716-91e0-4cf7-b9bd-b4d558f9a173" ascii wide
        $typelibguid2lo = "37d6dd3f-5457-4d8b-a2e1-c7b156b176e5" ascii wide
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
        modified = "2025-08-15"
        id = "4a7f2514-2519-5fd5-9d17-110a67f829e7"
    strings:
        $typelibguid0lo = "a6b84e35-2112-4df2-a31b-50fde4458c5e" ascii wide
        $typelibguid1lo = "3e82f538-6336-4fff-aeec-e774676205da" ascii wide
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
        modified = "2025-08-15"
        id = "928e00c1-549a-58f5-9e7e-982a4319691a"
    strings:
        $typelibguid0lo = "443d8cbf-899c-4c22-b4f6-b7ac202d4e37" ascii wide
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
        modified = "2025-08-15"
        id = "cbc1d7d4-f3b4-5d02-84ae-621398cb7b51"
    strings:
        $typelibguid0lo = "52856b03-5acd-45e0-828e-13ccb16942d1" ascii wide
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
        modified = "2025-08-15"
        id = "85d31989-ad96-5005-a747-8a19a67fdd80"
    strings:
        $typelibguid0lo = "98cb495f-4d47-4722-b08f-cefab2282b18" ascii wide
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
        modified = "2025-08-15"
        id = "8c8cf79f-8e69-5293-b27a-1f8593061627"
    strings:
        $typelibguid0lo = "deadb33f-fa94-41b5-813d-e72d8677a0cf" ascii wide
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
        modified = "2025-08-15"
        id = "d5027f51-f3ca-53cd-96d7-c355b5c2e6fa"
    strings:
        $typelibguid0lo = "84d2b661-3267-49c8-9f51-8f72f21aea47" ascii wide
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
        modified = "2025-08-15"
        id = "1577ed24-0e17-54f9-bc29-bb209acf9645"
    strings:
        $typelibguid0lo = "90ebd469-d780-4431-9bd8-014b00057665" ascii wide
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
        modified = "2025-08-15"
        id = "3340a095-d926-5c85-b7ed-03151712538d"
    strings:
        $typelibguid0lo = "0a344f52-6780-4d10-9a4a-cb9439f9d3de" ascii wide
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
        modified = "2025-08-15"
        id = "564dfd0a-af9b-505f-a6f0-de2a5c5c63f3"
    strings:
        $typelibguid0lo = "98ca74c7-a074-434d-9772-75896e73ceaa" ascii wide
        $typelibguid1lo = "3c9a6b88-bed2-4ba8-964c-77ec29bf1846" ascii wide
        $typelibguid2lo = "4fcdf3a3-aeef-43ea-9297-0d3bde3bdad2" ascii wide
        $typelibguid3lo = "361c69f5-7885-4931-949a-b91eeab170e3" ascii wide
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
        modified = "2025-08-15"
        id = "b71198a9-4d00-5d75-bc36-7c40655c84a3"
    strings:
        $typelibguid0lo = "46e39aed-0cff-47c6-8a63-6826f147d7bd" ascii wide
        $typelibguid1lo = "11dc83c6-8186-4887-b228-9dc4fd281a23" ascii wide
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
        modified = "2025-08-15"
        id = "539f88c5-e779-55e0-98df-299a9068de9b"
    strings:
        $typelibguid0lo = "bdb79ad6-639f-4dc2-8b8a-cd9107da3d69" ascii wide
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
        modified = "2025-08-15"
        id = "3abbf636-01f4-547a-98c0-d7bfec07e31a"
    strings:
        $typelibguid0lo = "f9e63498-6e92-4afd-8c13-4f63a3d964c3" ascii wide
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
        modified = "2025-08-15"
        id = "b533d61a-8693-5c3c-8b31-2117262cad4e"
    strings:
        $typelibguid0lo = "c442ea6a-9aa1-4d9c-9c9d-7560a327089c" ascii wide
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
        modified = "2025-08-15"
        id = "0571d71e-50ca-5c1b-b750-34acc2d06687"
    strings:
        $typelibguid0lo = "868a6c76-c903-4a94-96fd-a2c6ba75691c" ascii wide
        $typelibguid1lo = "caa7ab97-f83b-432c-8f9c-c5f1530f59f7" ascii wide
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
        modified = "2025-08-15"
        id = "e4266969-ab03-50dc-b5b1-f4bb1c9846f4"
    strings:
        $typelibguid0lo = "8aac271f-9b0b-4dc3-8aa6-812bb7a57e7b" ascii wide
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
        modified = "2025-08-15"
        id = "3f59986c-8bd8-5e70-b3eb-038247d1ccd7"
    strings:
        $typelibguid0lo = "ed839154-90d8-49db-8cdd-972d1a6b2cfd" ascii wide
        $typelibguid1lo = "3b47eebc-0d33-4e0b-bab5-782d2d3680af" ascii wide
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
        modified = "2025-08-15"
        id = "f9ea5283-0a5c-5bde-966c-80869ee25888"
    strings:
        $typelibguid0lo = "612c7c82-d501-417a-b8db-73204fdfda06" ascii wide
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
        modified = "2025-08-11"
        hash = "da585a8d4985082873cb86204d546d3f53668e034c61e42d247b11e92b5e8fc3"
        id = "69f120fe-bd4d-59ba-b1b9-528ab300e450"
    strings:
        $typelibguid0_v1 = "64524ca5-e4d0-41b3-acc3-3bdbefd40c97" ascii wide
        $typelibguid0_v2 = "15cfadd8-5f6c-424b-81dc-c028312d025f" ascii wide
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
        modified = "2025-08-15"
        id = "3f0a954c-f3b3-5e5d-a71d-11f60b026a48"
    strings:
        $typelibguid0lo = "b2b3adb0-1669-4b94-86cb-6dd682ddbea3" ascii wide
        $typelibguid1lo = "c47e4d64-cc7f-490e-8f09-055e009f33ba" ascii wide
        $typelibguid2lo = "32a91b0f-30cd-4c75-be79-ccbd6345de99" ascii wide
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
        modified = "2025-08-15"
        id = "554a5487-ac53-512f-8f6f-ad8186144715"
    strings:
        $typelibguid0lo = "a93ee706-a71c-4cc1-bf37-f26c27825b68" ascii wide
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
        modified = "2025-08-15"
        id = "a8b902f0-61a5-509e-8307-79bf557e5f61"
    strings:
        $typelibguid0lo = "21f398a9-bc35-4bd2-b906-866f21409744" ascii wide
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
        modified = "2025-08-15"
        id = "276269b1-e3b3-5774-a86a-1c3a8bca8209"
    strings:
        $typelibguid0lo = "03652836-898e-4a9f-b781-b7d86e750f60" ascii wide
        $typelibguid1lo = "e4d9ef39-0fce-4573-978b-abf8df6aec23" ascii wide
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
        modified = "2025-08-15"
        id = "9702526c-b10d-553d-a803-47e352533858"
    strings:
        $typelibguid0lo = "4d5350c8-7f8c-47cf-8cde-c752018af17e" ascii wide
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
        modified = "2025-08-15"
        id = "06b3ffbb-5a76-50a0-86dc-b9658bf2d7ec"
    strings:
        $typelibguid0lo = "bd346689-8ee6-40b3-858b-4ed94f08d40a" ascii wide
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
        modified = "2025-08-15"
        id = "d4f94aa3-0431-5ac1-8718-0f0526c3714f"
    strings:
        $typelibguid0lo = "7e9729aa-4cf2-4d0a-8183-7fb7ce7a5b1a" ascii wide
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
        modified = "2025-08-15"
        id = "1b3572a5-bb21-58bb-91f9-963a0a17d699"
    strings:
        $typelibguid0lo = "79f11fc0-abff-4e1f-b07c-5d65653d8952" ascii wide
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
        modified = "2025-08-15"
        id = "e7b2b4bd-f1e1-5062-9b36-5df44ae374ea"
    strings:
        $typelibguid0lo = "33456e72-f8e8-4384-88c4-700867df12e2" ascii wide
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
        modified = "2025-08-15"
        id = "f020eea9-4ff4-5242-b9b2-53284505dab4"
    strings:
        $typelibguid0lo = "42cabb74-1199-40f1-9354-6294bba8d3a4" ascii wide
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
        modified = "2025-08-15"
        id = "5815c5bd-e3e8-5f2f-b03e-8a05fb4f6e91"
    strings:
        $typelibguid0lo = "27a85262-8c87-4147-a908-46728ab7fc73" ascii wide
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
        modified = "2025-08-15"
        id = "048b0239-ea13-58ff-af35-fd505b4c977a"
    strings:
        $typelibguid0lo = "ca4e257e-69c1-45c5-9375-ba7874371892" ascii wide
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
        modified = "2025-08-15"
        id = "8441e940-ab7c-5467-9db8-35f71bd57580"
    strings:
        $typelibguid0lo = "6e383de4-de89-4247-a41a-79db1dc03aaa" ascii wide
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
        modified = "2025-08-15"
        id = "5513a295-8907-5a9c-adca-760b33004229"
    strings:
        $typelibguid0lo = "b5067468-f656-450a-b29c-1c84cfe8dde5" ascii wide
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
        modified = "2025-08-15"
        id = "f457b91f-4adb-5be6-b9c2-f6cc39d4bdaf"
    strings:
        $typelibguid0lo = "449cf269-4798-4268-9a0d-9a17a08869ba" ascii wide
        $typelibguid1lo = "e7a509a4-2d44-4e10-95bf-b86cb7767c2c" ascii wide
        $typelibguid2lo = "b2b8dd4f-eba6-42a1-a53d-9a00fe785d66" ascii wide
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
        modified = "2025-08-15"
        id = "2ae1bc26-c137-55ce-ae2e-3204ff07f671"
    strings:
        $typelibguid0lo = "22a156ea-2623-45c7-8e50-e864d9fc44d3" ascii wide
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
        modified = "2025-08-15"
        id = "f69745b9-4ebd-547a-9af3-bc340b076e5d"
    strings:
        $typelibguid0lo = "37da2573-d9b5-4fc2-ae11-ccb6130cea9f" ascii wide
        $typelibguid1lo = "49acf861-1c10-49a1-bf26-139a3b3a9227" ascii wide
        $typelibguid2lo = "9a6c028f-423f-4c2c-8db3-b3499139b822" ascii wide
        $typelibguid3lo = "1c896837-e729-46a9-92b9-3bbe7ac2c90d" ascii wide
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
        modified = "2025-08-15"
        id = "6253e30b-7c92-5237-a706-e93403a7c0b6"
    strings:
        $typelibguid0lo = "b016da9e-12a1-4f1d-91a1-d681ae54e92c" ascii wide
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
        modified = "2025-08-15"
        id = "5364956a-e199-556a-8055-0e7b9a7b14c8"
    strings:
        $typelibguid0lo = "2133c634-4139-466e-8983-9a23ec99e01b" ascii wide
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
        modified = "2025-08-15"
        id = "fdef6dc3-da1a-5a98-a822-94e443981fdd"
    strings:
        $typelibguid0lo = "e20dc2ed-6455-4101-9d78-fccac1cb7a18" ascii wide
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
        modified = "2025-08-15"
        id = "ecb0c59f-2111-58d9-8dc9-dfe005cad3be"
    strings:
        $typelibguid0lo = "42750ac0-1bff-4f25-8c9d-9af144403bad" ascii wide
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
        modified = "2025-08-15"
        id = "91dd52ef-07a1-5ffd-b5c3-59bca18d4c7c"
    strings:
        $typelibguid0lo = "7e47d586-ddc6-4382-848c-5cf0798084e1" ascii wide
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
        modified = "2025-08-15"
        id = "4a88532b-e2bc-5ce9-828d-6ef62d91f6b9"
    strings:
        $typelibguid0lo = "5439cecd-3bb3-4807-b33f-e4c299b71ca2" ascii wide
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
        modified = "2025-08-15"
        id = "38346575-cf5b-59bf-b2b2-21aacf05b8a4"
    strings:
        $typelibguid0lo = "640c36b4-f417-4d85-b031-83a9d23c140b" ascii wide
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
        modified = "2025-08-15"
        id = "e8a957bc-3319-51c2-8289-01bd0b8a632a"
    strings:
        $typelibguid0lo = "ce59f8ff-0ecf-41e9-a1fd-1776ca0b703d" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Sharpcat {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/theart42/Sharpcat"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-11-30"
        id = "450d13c6-93ae-5bf5-bdde-d874ab6c0cd5"
    strings:
        $typelibguid0 = "d16fd95f-23ce-4f8d-8763-b9f5a9cdd0c3" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpNamedPipePTH {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/S3cur3Th1sSh1t/SharpNamedPipePTH"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-11-30"
        id = "561b95a5-f32b-5fe8-9e67-3f702306be93"
    strings:
        $typelibguid0 = "344ee55a-4e32-46f2-a003-69ad52b55945" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpTokenFinder {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/HuskyHacks/SharpTokenFinder"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-12-06"
        id = "60fd06be-041b-5fa8-8f25-41b26605ea90"
    strings:
        $typelibguid0 = "572804d3-dbd6-450a-be64-2e3cb54fd173" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpRODC {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/wh0amitz/SharpRODC"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-12-06"
        id = "60779e7a-048f-5095-b853-fd90c4f7449e"
    strings:
        $typelibguid0 = "d305f8a3-019a-4cdf-909c-069d5b483613" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_GMSAPasswordReader {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/rvazarkar/GMSAPasswordReader"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-12-06"
        id = "dc74bfce-90a1-53bd-bfe4-cb7c9c75da53"
    strings:
        $typelibguid0 = "c8112750-972d-4efa-a75b-da9b8a4533c7" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpShareFinder {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/mvelazc0/SharpShareFinder"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-12-19"
        id = "bb485347-ea9b-5f26-99ad-bedc38bfecd5"
    strings:
        $typelibguid0 = "64bfeb18-b65c-4a83-bde0-b54363b09b71" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}


rule HKTL_NET_GUID_POSTDump {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/YOLOP0wn/POSTDump"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-12-19"
        id = "7f33e76c-0227-5c23-b821-c5c9753e2384"
    strings:
        $typelibguid0 = "e54195f0-060c-4b24-98f2-ad9fb5351045" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

