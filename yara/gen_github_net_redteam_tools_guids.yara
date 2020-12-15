import "pe"

rule HKTL_NET_GUID_CSharpSetThreadContext {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/djhohnstein/CSharpSetThreadContext"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "a1e28c8c-b3bd-44de-85b9-8aa7c18a714d" ascii nocase wide
        $typelibguid1 = "87c5970e-0c77-4182-afe2-3fe96f785ebb" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DLL_Injection {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/ihack4falafel/DLL-Injection"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "3d7e1433-f81a-428a-934f-7cc7fcf1149d" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_LimeUSB_Csharp {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/LimeUSB-Csharp"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "94ea43ab-7878-4048-a64e-2b21b3b4366d" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Ladon {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/k8gege/Ladon"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "c335405f-5df2-4c7d-9b53-d65adfbed412" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_WhiteListEvasion {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/khr0x40sh/WhiteListEvasion"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "858386df-4656-4a1e-94b7-47f6aa555658" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Lime_Downloader {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/Lime-Downloader"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "ec7afd4c-fbc4-47c1-99aa-6ebb05094173" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DarkEye {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/K1ngSoul/DarkEye"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "0bdb9c65-14ed-4205-ab0c-ea2151866a7f" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpKatz {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/b4rtik/SharpKatz"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "8568b4c1-2940-4f6c-bf4e-4383ef268be9" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_ExternalC2 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/ryhanson/ExternalC2"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "7266acbb-b10d-4873-9b99-12d2043b1d4e" ascii nocase wide
        $typelibguid1 = "5d9515d0-df67-40ed-a6b2-6619620ef0ef" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Povlsomware {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/povlteksttv/Povlsomware"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "fe0d5aa7-538f-42f6-9ece-b141560f7781" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_RunShellcode {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/zerosum0x0/RunShellcode"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "a3ec18a3-674c-4131-a7f5-acbed034b819" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpLoginPrompt {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/shantanu561993/SharpLoginPrompt"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "c12e69cd-78a0-4960-af7e-88cbd794af97" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Adamantium_Thief {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/LimerBoy/Adamantium-Thief"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "e6104bc9-fea9-4ee9-b919-28156c1f2ede" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_PSByPassCLM {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/padovah4ck/PSByPassCLM"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "46034038-0113-4d75-81fd-eb3b483f2662" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_physmem2profit {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/FSecureLABS/physmem2profit"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "814708c9-2320-42d2-a45f-31e42da06a94" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_NoAmci {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/med0x2e/NoAmci"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "352e80ec-72a5-4aa6-aabe-4f9a20393e8e" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpBlock {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/CCob/SharpBlock"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "3cf25e04-27e4-4d19-945e-dadc37c81152" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_nopowershell {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/bitsadmin/nopowershell"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "555ad0ac-1fdb-4016-8257-170a74cb2f55" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_LimeLogger {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/LimeLogger"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "068d14ef-f0a1-4f9d-8e27-58b4317830c6" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_AggressorScripts {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/harleyQu1nn/AggressorScripts"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "afd1ff09-2632-4087-a30c-43591f32e4e8" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Gopher {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/EncodeGroup/Gopher"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "b5152683-2514-49ce-9aca-1bc43df1e234" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_AVIator {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Ch0pin/AVIator"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "4885a4a3-4dfa-486c-b378-ae94a221661a" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_njCrypter {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/0xPh0enix/njCrypter"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "8a87b003-4b43-467b-a509-0c8be05bf5a5" ascii nocase wide
        $typelibguid1 = "80b13bff-24a5-4193-8e51-c62a414060ec" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpMiniDump {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/b4rtik/SharpMiniDump"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "6ffccf81-6c3c-4d3f-b15f-35a86d0b497f" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_CinaRAT {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/wearelegal/CinaRAT"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "8586f5b1-2ef4-4f35-bd45-c6206fdc0ebc" ascii nocase wide
        $typelibguid1 = "fe184ab5-f153-4179-9bf5-50523987cf1f" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_ToxicEye {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/LimerBoy/ToxicEye"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "1bcfe538-14f4-4beb-9a3f-3f9472794902" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Disable_Windows_Defender {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/Disable-Windows-Defender"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "501e3fdc-575d-492e-90bc-703fb6280ee2" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DInvoke_PoC {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/dtrizna/DInvoke_PoC"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "5a869ab2-291a-49e6-a1b7-0d0f051bef0e" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_ReverseShell {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/chango77747/ReverseShell"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "980109e4-c988-47f9-b2b3-88d63fababdc" ascii nocase wide
        $typelibguid1 = "8abe8da1-457e-4933-a40d-0958c8925985" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpC2 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/SharpC2/SharpC2"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "62b9ee4f-1436-4098-9bc1-dd61b42d8b81" ascii nocase wide
        $typelibguid1 = "d2f17a91-eb2d-4373-90bf-a26e46c68f76" ascii nocase wide
        $typelibguid2 = "a9db9fcc-7502-42cd-81ec-3cd66f511346" ascii nocase wide
        $typelibguid3 = "ca6cc2ee-75fd-4f00-b687-917fa55a4fae" ascii nocase wide
        $typelibguid4 = "a1167b68-446b-4c0c-a8b8-2a7278b67511" ascii nocase wide
        $typelibguid5 = "4d8c2a88-1da5-4abe-8995-6606473d7cf1" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SneakyExec {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/HackingThings/SneakyExec"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "612590aa-af68-41e6-8ce2-e831f7fe4ccc" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_UrbanBishopLocal {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/slyd0g/UrbanBishopLocal"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "88b8515e-a0e8-4208-a9a0-34b01d7ba533" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpShell {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/cobbr/SharpShell"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "bdba47c5-e823-4404-91d0-7f6561279525" ascii nocase wide
        $typelibguid1 = "b84548dc-d926-4b39-8293-fa0bdef34d49" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_EvilWMIProvider {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/sunnyc7/EvilWMIProvider"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "a4020626-f1ec-4012-8b17-a2c8a0204a4b" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_GadgetToJScript {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/med0x2e/GadgetToJScript"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "af9c62a1-f8d2-4be0-b019-0a7873e81ea9" ascii nocase wide
        $typelibguid1 = "b2b3adb0-1669-4b94-86cb-6dd682ddbea3" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_AzureCLI_Extractor {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/0x09AL/AzureCLI-Extractor"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "a73cad74-f8d6-43e6-9a4c-b87832cdeace" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_UAC_Escaper {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/UAC-Escaper"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "95359279-5cfa-46f6-b400-e80542a7336a" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_HTTPSBeaconShell {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/limbenjamin/HTTPSBeaconShell"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "aca853dc-9e74-4175-8170-e85372d5f2a9" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_AmsiScanBufferBypass {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/rasta-mouse/AmsiScanBufferBypass"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "431ef2d9-5cca-41d3-87ba-c7f5e4582dd2" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_ShellcodeLoader {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Hzllaga/ShellcodeLoader"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "a48fe0e1-30de-46a6-985a-3f2de3c8ac96" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_KeystrokeAPI {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/fabriciorissetto/KeystrokeAPI"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "f6fec17e-e22d-4149-a8a8-9f64c3c905d3" ascii nocase wide
        $typelibguid1 = "b7aa4e23-39a4-49d5-859a-083c789bfea2" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_ShellCodeRunner {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/antman1p/ShellCodeRunner"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "634874b7-bf85-400c-82f0-7f3b4659549a" ascii nocase wide
        $typelibguid1 = "2f9c3053-077f-45f2-b207-87c3c7b8f054" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_OffensiveCSharp {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/diljith369/OffensiveCSharp"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "6c3fbc65-b673-40f0-b1ac-20636df01a85" ascii nocase wide
        $typelibguid1 = "2bad9d69-ada9-4f1e-b838-9567e1503e93" ascii nocase wide
        $typelibguid2 = "512015de-a70f-4887-8eae-e500fd2898ab" ascii nocase wide
        $typelibguid3 = "1ee4188c-24ac-4478-b892-36b1029a13b3" ascii nocase wide
        $typelibguid4 = "5c6b7361-f9ab-41dc-bfa0-ed5d4b0032a8" ascii nocase wide
        $typelibguid5 = "048a6559-d4d3-4ad8-af0f-b7f72b212e90" ascii nocase wide
        $typelibguid6 = "3412fbe9-19d3-41d8-9ad2-6461fcb394dc" ascii nocase wide
        $typelibguid7 = "9ea4e0dc-9723-4d93-85bb-a4fcab0ad210" ascii nocase wide
        $typelibguid8 = "6d2b239c-ba1e-43ec-8334-d67d52b77181" ascii nocase wide
        $typelibguid9 = "42e8b9e1-0cf4-46ae-b573-9d0563e41238" ascii nocase wide
        $typelibguid10 = "0d15e0e3-bcfd-4a85-adcd-0e751dab4dd6" ascii nocase wide
        $typelibguid11 = "644dfd1a-fda5-4948-83c2-8d3b5eda143a" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SHAPESHIFTER {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/matterpreter/SHAPESHIFTER"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "a3ddfcaa-66e7-44fd-ad48-9d80d1651228" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Evasor {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/cyberark/Evasor"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "1c8849ef-ad09-4727-bf81-1f777bd1aef8" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Stracciatella {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/mgeeky/Stracciatella"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "eaafa0ac-e464-4fc4-9713-48aa9a6716fb" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_logger {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/xxczaki/logger"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "9e92a883-3c8b-4572-a73e-bb3e61cfdc16" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Internal_Monologue {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/eladshamir/Internal-Monologue"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "0c0333db-8f00-4b68-b1db-18a9cacc1486" ascii nocase wide
        $typelibguid1 = "84701ace-c584-4886-a3cf-76c57f6e801a" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_GRAT2 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/r3nhat/GRAT2"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "5e7fce78-1977-444f-a18e-987d708a2cff" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_PowerShdll {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/p3nt4/PowerShdll"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "36ebf9aa-2f37-4f1d-a2f1-f2a45deeaf21" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_CsharpAmsiBypass {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/WayneJLee/CsharpAmsiBypass"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "4ab3b95d-373c-4197-8ee3-fe0fa66ca122" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_HastySeries {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/obscuritylabs/HastySeries"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "8435531d-675c-4270-85bf-60db7653bcf6" ascii nocase wide
        $typelibguid1 = "47db989f-7e33-4e6b-a4a5-c392b429264b" ascii nocase wide
        $typelibguid2 = "300c7489-a05f-4035-8826-261fa449dd96" ascii nocase wide
        $typelibguid3 = "41bf8781-ae04-4d80-b38d-707584bf796b" ascii nocase wide
        $typelibguid4 = "620ed459-18de-4359-bfb0-6d0c4841b6f6" ascii nocase wide
        $typelibguid5 = "91e7cdfe-0945-45a7-9eaa-0933afe381f2" ascii nocase wide
        $typelibguid6 = "c28e121a-60ca-4c21-af4b-93eb237b882f" ascii nocase wide
        $typelibguid7 = "698fac7a-bff1-4c24-b2c3-173a6aae15bf" ascii nocase wide
        $typelibguid8 = "63a40d94-5318-42ad-a573-e3a1c1284c57" ascii nocase wide
        $typelibguid9 = "56b8311b-04b8-4e57-bb58-d62adc0d2e68" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DreamProtectorFree {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Paskowsky/DreamProtectorFree"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "f7e8a902-2378-426a-bfa5-6b14c4b40aa3" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_RedSharp {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/padovah4ck/RedSharp"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "30b2e0cf-34dd-4614-a5ca-6578fb684aea" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_ESC {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NetSPI/ESC"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "06260ce5-61f4-4b81-ad83-7d01c3b37921" ascii nocase wide
        $typelibguid1 = "87fc7ede-4dae-4f00-ac77-9c40803e8248" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Csharp_Loader {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/Csharp-Loader"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "5fd7f9fc-0618-4dde-a6a0-9faefe96c8a1" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_bantam {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/gellin/bantam"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "14c79bda-2ce6-424d-bd49-4f8d68630b7b" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpTask {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/jnqpblc/SharpTask"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "13e90a4d-bf7a-4d5a-9979-8b113e3166be" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_WindowsPlague {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/RITRedteam/WindowsPlague"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "cdf8b024-70c9-413a-ade3-846a43845e99" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Misc_CSharp {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/jnqpblc/Misc-CSharp"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "d1421ba3-c60b-42a0-98f9-92ba4e653f3d" ascii nocase wide
        $typelibguid1 = "2afac0dd-f46f-4f95-8a93-dc17b4f9a3a1" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpSpray {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/jnqpblc/SharpSpray"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "51c6e016-1428-441d-82e9-bb0eb599bbc8" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Obfuscator {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/3xpl01tc0d3r/Obfuscator"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "8fe5b811-a2cb-417f-af93-6a3cf6650af1" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SafetyKatz {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/GhostPack/SafetyKatz"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "8347e81b-89fc-42a9-b22c-f59a6a572dec" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Dropless_Malware {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/Dropless-Malware"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "23b739f7-2355-491e-a7cd-a8485d39d6d6" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_UAC_SilentClean {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/EncodeGroup/UAC-SilentClean"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "948152a4-a4a1-4260-a224-204255bfee72" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DesktopGrabber {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/DesktopGrabber"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "e6aa0cd5-9537-47a0-8c85-1fbe284a4380" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_wsManager {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/guillaC/wsManager"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "9480809e-5472-44f3-b076-dcdf7379e766" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_UglyEXe {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/fashionproof/UglyEXe"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "233de44b-4ec1-475d-a7d6-16da48d6fc8d" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpDump {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/GhostPack/SharpDump"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "79c9bba3-a0ea-431c-866c-77004802d8a0" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_EducationalRAT {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/securesean/EducationalRAT"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "8a18fbcf-8cac-482d-8ab7-08a44f0e278e" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Stealth_Kid_RAT {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/ctsecurity/Stealth-Kid-RAT"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "bf43cd33-c259-4711-8a0e-1a5c6c13811d" ascii nocase wide
        $typelibguid1 = "e5b9df9b-a9e4-4754-8731-efc4e2667d88" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpCradle {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/anthemtotheego/SharpCradle"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "f70d2b71-4aae-4b24-9dae-55bc819c78bb" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_BypassUAC {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/cnsimo/BypassUAC"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "4e7c140d-bcc4-4b15-8c11-adb4e54cc39a" ascii nocase wide
        $typelibguid1 = "cec553a7-1370-4bbc-9aae-b2f5dbde32b0" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_hanzoInjection {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/P0cL4bs/hanzoInjection"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "32e22e25-b033-4d98-a0b3-3d2c3850f06c" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_clr_meterpreter {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/OJ/clr-meterpreter"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "6840b249-1a0e-433b-be79-a927696ea4b3" ascii nocase wide
        $typelibguid1 = "67c09d37-ac18-4f15-8dd6-b5da721c0df6" ascii nocase wide
        $typelibguid2 = "e05d0deb-d724-4448-8c4c-53d6a8e670f3" ascii nocase wide
        $typelibguid3 = "c3cc72bf-62a2-4034-af66-e66da73e425d" ascii nocase wide
        $typelibguid4 = "7ace3762-d8e1-4969-a5a0-dcaf7b18164e" ascii nocase wide
        $typelibguid5 = "3296e4a3-94b5-4232-b423-44f4c7421cb3" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_BYTAGE {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/KNIF/BYTAGE"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "8e46ba56-e877-4dec-be1e-394cb1b5b9de" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_MultiOS_ReverseShell {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/belane/MultiOS_ReverseShell"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "df0dd7a1-9f6b-4b0f-801e-e17e73b0801d" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_HideFromAMSI {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/0r13lc0ch4v1/HideFromAMSI"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "b91d2d44-794c-49b8-8a75-2fbec3fe3fe3" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DotNetAVBypass_Master {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/lockfale/DotNetAVBypass-Master"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "4854c8dc-82b0-4162-86e0-a5bbcbc10240" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpDPAPI {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/GhostPack/SharpDPAPI"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "5f026c27-f8e6-4052-b231-8451c6a73838" ascii nocase wide
        $typelibguid1 = "2f00a05b-263d-4fcc-846b-da82bd684603" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Telegra_Csharp_C2 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/sf197/Telegra_Csharp_C2"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "1d79fabc-2ba2-4604-a4b6-045027340c85" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpCompile {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/SpiderLabs/SharpCompile"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "63f81b73-ff18-4a36-b095-fdcb4776da4c" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Carbuncle {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/checkymander/Carbuncle"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "3f239b73-88ae-413b-b8c8-c01a35a0d92e" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_OSSFileTool {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/B1eed/OSSFileTool"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "207aca5d-dcd6-41fb-8465-58b39efcde8b" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Rubeus {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/GhostPack/Rubeus"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "658c8b7f-3664-4a95-9572-a3e5871dfc06" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Simple_Loader {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/cribdragg3r/Simple-Loader"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "035ae711-c0e9-41da-a9a2-6523865e8694" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Minidump {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/3xpl01tc0d3r/Minidump"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "15c241aa-e73c-4b38-9489-9a344ac268a3" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpBypassUAC {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/FatRodzianko/SharpBypassUAC"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "0d588c86-c680-4b0d-9aed-418f1bb94255" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpPack {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Lexus89/SharpPack"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "22a156ea-2623-45c7-8e50-e864d9fc44d3" ascii nocase wide
        $typelibguid1 = "b59c7741-d522-4a41-bf4d-9badddebb84a" ascii nocase wide
        $typelibguid2 = "fd6bdf7a-fef4-4b28-9027-5bf750f08048" ascii nocase wide
        $typelibguid3 = "6dd22880-dac5-4b4d-9c91-8c35cc7b8180" ascii nocase wide
        $typelibguid4 = "7760248f-9247-4206-be42-a6952aa46da2" ascii nocase wide
        $typelibguid5 = "f3037587-1a3b-41f1-aa71-b026efdb2a82" ascii nocase wide
        $typelibguid6 = "41a90a6a-f9ed-4a2f-8448-d544ec1fd753" ascii nocase wide
        $typelibguid7 = "3787435b-8352-4bd8-a1c6-e5a1b73921f4" ascii nocase wide
        $typelibguid8 = "fdd654f5-5c54-4d93-bf8e-faf11b00e3e9" ascii nocase wide
        $typelibguid9 = "aec32155-d589-4150-8fe7-2900df4554c8" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Salsa_tools {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Hackplayers/Salsa-tools"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "276004bb-5200-4381-843c-934e4c385b66" ascii nocase wide
        $typelibguid1 = "cfcbf7b6-1c69-4b1f-8651-6bdb4b55f6b9" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_WindowsDefender_Payload_Downloader {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/notkohlrexo/WindowsDefender-Payload-Downloader"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "2f8b4d26-7620-4e11-b296-bc46eba3adfc" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Privilege_Escalation {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Mrakovic-ORG/Privilege_Escalation"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "ed54b904-5645-4830-8e68-52fd9ecbb2eb" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Marauder {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/maraudershell/Marauder"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "fff0a9a3-dfd4-402b-a251-6046d765ad78" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_AV_Evasion_Tool {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/1y0n/AV_Evasion_Tool"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "1937ee16-57d7-4a5f-88f4-024244f19dc6" ascii nocase wide
        $typelibguid1 = "7898617d-08d2-4297-adfe-5edd5c1b828b" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Fenrir {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/nccgroup/Fenrir"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "aecec195-f143-4d02-b946-df0e1433bd2e" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_StormKitty {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/LimerBoy/StormKitty"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "a16abbb4-985b-4db2-a80c-21268b26c73d" ascii nocase wide
        $typelibguid1 = "98075331-1f86-48c8-ae29-29da39a8f98b" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Crypter_Runtime_AV_s_bypass {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/netreverse/Crypter-Runtime-AV-s-bypass"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "c25e39a9-8215-43aa-96a3-da0e9512ec18" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_RunAsUser {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/atthacks/RunAsUser"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "9dff282c-93b9-4063-bf8a-b6798371d35a" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_HWIDbypass {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/yunseok/HWIDbypass"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "47e08791-d124-4746-bc50-24bd1ee719a6" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_XORedReflectiveDLL {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/r3nhat/XORedReflectiveDLL"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "c0e49392-04e3-4abb-b931-5202e0eb4c73" ascii nocase wide
        $typelibguid1 = "30eef7d6-cee8-490b-829f-082041bc3141" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Sharp_Suite {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/FuzzySecurity/Sharp-Suite"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "467ee2a9-2f01-4a71-9647-2a2d9c31e608" ascii nocase wide
        $typelibguid1 = "5611236e-2557-45b8-be29-5d1f074d199e" ascii nocase wide
        $typelibguid2 = "447edefc-b429-42bc-b3bc-63a9af19dbd6" ascii nocase wide
        $typelibguid3 = "eacaa2b8-43e5-4888-826d-2f6902e16546" ascii nocase wide
        $typelibguid4 = "a3b7c697-4bb6-455d-9fda-4ab54ae4c8d2" ascii nocase wide
        $typelibguid5 = "a5f883ce-1f96-4456-bb35-40229191420c" ascii nocase wide
        $typelibguid6 = "28978103-d90d-4618-b22e-222727f40313" ascii nocase wide
        $typelibguid7 = "252676f8-8a19-4664-bfb8-5a947e48c32a" ascii nocase wide
        $typelibguid8 = "414187db-5feb-43e5-a383-caa48b5395f1" ascii nocase wide
        $typelibguid9 = "0c70c839-9565-4881-8ea1-408c1ebe38ce" ascii nocase wide
        $typelibguid10 = "0a382d9a-897f-431a-81c2-a4e08392c587" ascii nocase wide
        $typelibguid11 = "629f86e6-44fe-4c9c-b043-1c9b64be6d5a" ascii nocase wide
        $typelibguid12 = "f0d28809-b712-4380-9a59-407b7b2badd5" ascii nocase wide
        $typelibguid13 = "956a5a4d-2007-4857-9259-51cd0fb5312a" ascii nocase wide
        $typelibguid14 = "53f622eb-0ca3-4e9b-9dc8-30c832df1c7b" ascii nocase wide
        $typelibguid15 = "72019dfe-608e-4ab2-a8f1-66c95c425620" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_rat_shell {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/stphivos/rat-shell"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "7a15f8f6-6ce2-4ca4-919d-2056b70cc76a" ascii nocase wide
        $typelibguid1 = "1659d65d-93a8-4bae-97d5-66d738fc6f6c" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_dotnet_gargoyle {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/countercept/dotnet-gargoyle"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "76435f79-f8af-4d74-8df5-d598a551b895" ascii nocase wide
        $typelibguid1 = "5a3fc840-5432-4925-b5bc-abc536429cb5" ascii nocase wide
        $typelibguid2 = "6f0bbb2a-e200-4d76-b8fa-f93c801ac220" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_aresskit {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/BlackVikingPro/aresskit"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "8dca0e42-f767-411d-9704-ae0ba4a44ae8" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DLL_Injector {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/tmthrgd/DLL-Injector"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "4581a449-7d20-4c59-8da2-7fd830f1fd5e" ascii nocase wide
        $typelibguid1 = "05f4b238-25ce-40dc-a890-d5bbb8642ee4" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_TruffleSnout {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/dsnezhkov/TruffleSnout"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "33842d77-bce3-4ee8-9ee2-9769898bb429" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Anti_Analysis {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/Anti-Analysis"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "3092c8df-e9e4-4b75-b78e-f81a0058a635" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_BackNet {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/valsov/BackNet"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "9fdae122-cd1e-467d-a6fa-a98c26e76348" ascii nocase wide
        $typelibguid1 = "243c279e-33a6-46a1-beab-2864cc7a499f" ascii nocase wide
        $typelibguid2 = "a7301384-7354-47fd-a4c5-65b74e0bbb46" ascii nocase wide
        $typelibguid3 = "982dc5b6-1123-428a-83dd-d212490c859f" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_AllTheThings {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/johnjohnsp1/AllTheThings"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "0547ff40-5255-42a2-beb7-2ff0dbf7d3ba" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_AddReferenceDotRedTeam {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/ceramicskate0/AddReferenceDotRedTeam"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "73c79d7e-17d4-46c9-be5a-ecef65b924e4" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Lime_Crypter {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/Lime-Crypter"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "f93c99ed-28c9-48c5-bb90-dd98f18285a6" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_BrowserGhost {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/QAX-A-Team/BrowserGhost"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "2133c634-4139-466e-8983-9a23ec99e01b" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpShot {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/tothi/SharpShot"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "057aef75-861b-4e4b-a372-cfbd8322c8e1" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Offensive__NET {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/mrjamiebowman/Offensive-.NET"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "11fe5fae-b7c1-484a-b162-d5578a802c9c" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_RuralBishop {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/rasta-mouse/RuralBishop"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "fe4414d9-1d7e-4eeb-b781-d278fe7a5619" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DeviceGuardBypasses {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/tyranid/DeviceGuardBypasses"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "f318466d-d310-49ad-a967-67efbba29898" ascii nocase wide
        $typelibguid1 = "3705800f-1424-465b-937d-586e3a622a4f" ascii nocase wide
        $typelibguid2 = "256607c2-4126-4272-a2fa-a1ffc0a734f0" ascii nocase wide
        $typelibguid3 = "4e6ceea1-f266-401c-b832-f91432d46f42" ascii nocase wide
        $typelibguid4 = "1e6e9b03-dd5f-4047-b386-af7a7904f884" ascii nocase wide
        $typelibguid5 = "d85e3601-0421-4efa-a479-f3370c0498fd" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_AMSI_Handler {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/two06/AMSI_Handler"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "d829426c-986c-40a4-8ee2-58d14e090ef2" ascii nocase wide
        $typelibguid1 = "86652418-5605-43fd-98b5-859828b072be" ascii nocase wide
        $typelibguid2 = "1043649f-18e1-41c4-ae8d-ac4d9a86c2fc" ascii nocase wide
        $typelibguid3 = "1d920b03-c537-4659-9a8c-09fb1d615e98" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_RAT_TelegramSpyBot {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/SebastianEPH/RAT.TelegramSpyBot"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "8653fa88-9655-440e-b534-26c3c760a0d3" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_TheHackToolBoxTeek {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/teeknofil/TheHackToolBoxTeek"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "2aa8c254-b3b3-469c-b0c9-dcbe1dd101c0" ascii nocase wide
        $typelibguid1 = "afeff505-14c1-4ecf-b714-abac4fbd48e7" ascii nocase wide
        $typelibguid2 = "4cf42167-a5cf-4b2d-85b4-8e764c08d6b3" ascii nocase wide
        $typelibguid3 = "118a90b7-598a-4cfc-859e-8013c8b9339c" ascii nocase wide
        $typelibguid4 = "3075dd9a-4283-4d38-a25e-9f9845e5adcb" ascii nocase wide
        $typelibguid5 = "295655e8-2348-4700-9ebc-aa57df54887e" ascii nocase wide
        $typelibguid6 = "74efe601-9a93-46c3-932e-b80ab6570e42" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_USBTrojan {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/mashed-potatoes/USBTrojan"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "4eee900e-adc5-46a7-8d7d-873fd6aea83e" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_IIS_backdoor {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/WBGlIl/IIS_backdoor"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "3fda4aa9-6fc1-473f-9048-7edc058c4f65" ascii nocase wide
        $typelibguid1 = "73ca4159-5d13-4a27-8965-d50c41ab203c" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_ShellGen {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/jasondrawdy/ShellGen"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "c6894882-d29d-4ae1-aeb7-7d0a9b915013" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Mass_RAT {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/Mass-RAT"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "6c43a753-9565-48b2-a372-4210bb1e0d75" ascii nocase wide
        $typelibguid1 = "92ba2a7e-c198-4d43-929e-1cfe54b64d95" ascii nocase wide
        $typelibguid2 = "4cb9bbee-fb92-44fa-a427-b7245befc2f3" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Browser_ExternalC2 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/mdsecactivebreach/Browser-ExternalC2"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "10a730cd-9517-42d5-b3e3-a2383515cca9" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_OffensivePowerShellTasking {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/leechristensen/OffensivePowerShellTasking"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "d432c332-3b48-4d06-bedb-462e264e6688" ascii nocase wide
        $typelibguid1 = "5796276f-1c7a-4d7b-a089-550a8c19d0e8" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DoHC2 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/SpiderLabs/DoHC2"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "9877a948-2142-4094-98de-e0fbb1bc4062" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SyscallPOC {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/SolomonSklash/SyscallPOC"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "1e54637b-c887-42a9-af6a-b4bd4e28cda9" ascii nocase wide
        $typelibguid1 = "198d5599-d9fc-4a74-87f4-5077318232ad" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Pen_Test_Tools {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/awillard1/Pen-Test-Tools"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "922e7fdc-33bf-48de-bc26-a81f85462115" ascii nocase wide
        $typelibguid1 = "ad5205dd-174d-4332-96d9-98b076d6fd82" ascii nocase wide
        $typelibguid2 = "b67e7550-f00e-48b3-ab9b-4332b1254a86" ascii nocase wide
        $typelibguid3 = "5e95120e-b002-4495-90a1-cd3aab2a24dd" ascii nocase wide
        $typelibguid4 = "295017f2-dc31-4a87-863d-0b9956c2b55a" ascii nocase wide
        $typelibguid5 = "abbaa2f7-1452-43a6-b98e-10b2c8c2ba46" ascii nocase wide
        $typelibguid6 = "a4043d4c-167b-4326-8be4-018089650382" ascii nocase wide
        $typelibguid7 = "51abfd75-b179-496e-86db-62ee2a8de90d" ascii nocase wide
        $typelibguid8 = "a06da7f8-f87e-4065-81d8-abc33cb547f8" ascii nocase wide
        $typelibguid9 = "ee510712-0413-49a1-b08b-1f0b0b33d6ef" ascii nocase wide
        $typelibguid10 = "9780da65-7e25-412e-9aa1-f77d828819d6" ascii nocase wide
        $typelibguid11 = "7913fe95-3ad5-41f5-bf7f-e28f080724fe" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_The_Collection {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Tlgyt/The-Collection"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "579159ff-3a3d-46a7-b069-91204feb21cd" ascii nocase wide
        $typelibguid1 = "5b7dd9be-c8c3-4c4f-a353-fefb89baa7b3" ascii nocase wide
        $typelibguid2 = "43edcb1f-3098-4a23-a7f2-895d927bc661" ascii nocase wide
        $typelibguid3 = "5f19919d-cd51-4e77-973f-875678360a6f" ascii nocase wide
        $typelibguid4 = "17fbc926-e17e-4034-ba1b-fb2eb57f5dd3" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Change_Lockscreen {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/nccgroup/Change-Lockscreen"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "78642ab3-eaa6-4e9c-a934-e7b0638bc1cc" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_LOLBITS {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Kudaes/LOLBITS"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "29d09aa4-ea0c-47c2-973c-1d768087d527" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Keylogger {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/BlackVikingPro/Keylogger"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "7afbc9bf-32d9-460f-8a30-35e30aa15879" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_CVE_2020_1337 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/neofito/CVE-2020-1337"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "d9c2e3c1-e9cc-42b0-a67c-b6e1a4f962cc" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpLogger {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/djhohnstein/SharpLogger"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "36e00152-e073-4da8-aa0c-375b6dd680c4" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_AsyncRAT_C_Sharp {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "619b7612-dfea-442a-a927-d997f99c497b" ascii nocase wide
        $typelibguid1 = "424b81be-2fac-419f-b4bc-00ccbe38491f" ascii nocase wide
        $typelibguid2 = "37e20baf-3577-4cd9-bb39-18675854e255" ascii nocase wide
        $typelibguid3 = "dafe686a-461b-402b-bbd7-2a2f4c87c773" ascii nocase wide
        $typelibguid4 = "ee03faa9-c9e8-4766-bd4e-5cd54c7f13d3" ascii nocase wide
        $typelibguid5 = "8bfc8ed2-71cc-49dc-9020-2c8199bc27b6" ascii nocase wide
        $typelibguid6 = "d640c36b-2c66-449b-a145-eb98322a67c8" ascii nocase wide
        $typelibguid7 = "8de42da3-be99-4e7e-a3d2-3f65e7c1abce" ascii nocase wide
        $typelibguid8 = "bee88186-769a-452c-9dd9-d0e0815d92bf" ascii nocase wide
        $typelibguid9 = "9042b543-13d1-42b3-a5b6-5cc9ad55e150" ascii nocase wide
        $typelibguid10 = "6aa4e392-aaaf-4408-b550-85863dd4baaf" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DarkFender {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/0xyg3n/DarkFender"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "12fdf7ce-4a7c-41b6-9b32-766ddd299beb" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

/* FPs with IronPython
rule HKTL_NET_GUID_IronKit {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/nshalabi/IronKit"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        score = 50
        date = "2020-12-13"
    strings:
        $typelibguid0 = "68e40495-c34a-4539-b43e-9e4e6f11a9fb" ascii nocase wide
        $typelibguid1 = "641cd52d-3886-4a74-b590-2a05621502a4" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
*/

rule HKTL_NET_GUID_MinerDropper {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/DylanAlloy/MinerDropper"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "46a7af83-1da7-40b2-9d86-6fd6223f6791" ascii nocase wide
        $typelibguid1 = "8433a693-f39d-451b-955b-31c3e7fa6825" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpDomainSpray {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/HunnicCyber/SharpDomainSpray"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "76ffa92b-429b-4865-970d-4e7678ac34ea" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_iSpyKeylogger {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/mwsrc/iSpyKeylogger"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "ccc0a386-c4ce-42ef-aaea-b2af7eff4ad8" ascii nocase wide
        $typelibguid1 = "816b8b90-2975-46d3-aac9-3c45b26437fa" ascii nocase wide
        $typelibguid2 = "279b5533-d3ac-438f-ba89-3fe9de2da263" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SolarFlare {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/mubix/solarflare"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-15"
    strings:
        $typelibguid0 = "ca60e49e-eee9-409b-8d1a-d19f1d27b7e4" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

