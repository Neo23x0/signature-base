/*
    PavinLoader detection kit - static YARA rules
    =============================================
    Family ..... Trojan.PavinLoader (Malwarebytes naming); Trojan.PavinLoader.BAT for
                 the scheduled-task persistence files (C:\Windows\System32\Tasks\dllhost
                 and \taskhostw).
    Verified ... static analysis of incident evidence captured 2026-10-26 .. 2026-10-29.
                 No evidence file was executed while authoring these rules; all strings
                 were harvested from byte-level inspection only.

    Scope ...... fake .NET solution "CatalogIngestor" ("Ingestion Labs", version
                 2.3.0.0, DQ-* ticket IDs) whose loader lives in Internal.targets;
                 the two WiX 3.11.1.2318 MSI masquerades; and the injected web
                 download button (class "file-download-btnn").

    Obfuscation notes (why strings look odd):
      * Internal.targets hides .NET API names behind XML numeric character
        references, e.g. R&#101;p&#108;a&#99;e = "Replace",
        &#83;o&#97;p&#72;e&#120;B&#105;n&#97;r&#121; = "SoapHexBinary".
        The rules match the verbatim entity-encoded forms seen in the sample.
      * MSI payloads (Internal.targets, Resources.resx ...) are inside compressed
        cabinets, so they are NOT plaintext in the .msi. The MSI rules therefore
        combine plaintext _StringPool markers: the hidden WiX silent-exec command
        line (MsiHiddenProperties=WixSilentExec64CmdLine) running
        cmd.exe /d /s /c "cd /d <dir> && start "" <name>.lnk", plus vendor context.
        This combination avoids triggering on genuine NVIDIA PhysX / Qualcomm
        installers, which lack the lnk-launch silent-exec chain.
*/

rule PavinLoader_MSBuild_Loader_InternalTargets
{
    meta:
        author = "fotedev"
        date = "2026-10-29"
        description = "PavinLoader MSBuild loader (Internal.targets): reads Resources.resx via $([System.IO.File]::ReadAllText(...)), extracts ResN values with a name=value regex, applies Replace('p','') plus a digit/letter substitution chain equivalent to XOR-6 per nibble, decodes with SoapHexBinary.Parse, rotates via Substring(142132), then loads the assembly in memory via $([System.AppDomain]::CurrentDomain.Load(...)).CreateInstance(CloneExtensions.FallbackProvider5). Requires MSBUILDENABLEALLPROPERTYFUNCTIONS=1 (set by build.cmd)."
        reference = "Verified incident 2026-10-29; Trojan.PavinLoader (Malwarebytes); fake solution CatalogIngestor / Ingestion Labs"
        family = "Trojan.PavinLoader"
        hash = "e20c494d8d081353f4d188ba88304028496165467486903338142a94b634ef5a"
    strings:
        $readall = "$([System.IO.File]::ReadAllText('$(MSBuildProjectDirectory)\\Resources.resx'))"
        $resextract = "&quot;[^&gt;]*&gt;&lt;value&gt;([0-9a-z]+)&lt;/value&gt;"
        $deletp = "e('p','').R&#101;p&#108;a&#99;e('0','A')"
        $soap = "&#83;o&#97;p&#72;e&#120;B&#105;n&#97;r&#121;]::&#80;a&#114;s&#101;("
        $appdomain_load = "C&#117;r&#114;e&#110;t&#68;o&#109;a&#105;n.L&#111;a&#100;("
        $rotate = "(142132)"
        $fallback5 = "CloneExtensions.FallbackProvider5"
        $createinstance = "C&#114;e&#97;t&#101;I&#110;s&#116;a&#110;c&#101;($(ProjectCapabilityCache))"
    condition:
        filesize < 1MB and 3 of them
}

rule PavinLoader_CatalogIngestor_Kit_Metadata
{
    meta:
        author = "fotedev"
        date = "2026-10-29"
        description = "PavinLoader fake-solution kit files (CatalogIngestor.csproj.user, CatalogIngestor.Shared.props, README.md, Internal.targets header): PackageRestoreData977/575 carrier blobs, alias properties PackageIcon=Res1 / NuGetAuditSuppress=Res3 / PackageTags=Res2 / Description=Res4, DQ-* TODO tickets, and the api.nuget.org/v3-flatcontainer/iqbydwfv/index.json slug in TargetPlatformMinVersion."
        reference = "Verified incident 2026-10-29; Trojan.PavinLoader (Malwarebytes)"
        family = "Trojan.PavinLoader"
        hash_csproj_user = "1e9b7994ba27d3fce3e9692c0dc021faa2c44643f3179ebfab5998ac8ca51853"
        hash_shared_props = "4325d00f7cbeb5460ad74d351d9cd6d6958a7db70500861bdaa95c7574dc1541"
        hash_readme = "a8771dc85b3a6be73bcb7ada8867c3780f990ee563cf3804242517bf7eac2972"
    strings:
        $hdr_importcache = "CatalogIngestor : project import cache"
        $hdr_cipipeline = "CatalogIngestor : CI pipeline configuration"
        $hdr_sharedprops = "CatalogIngestor : shared package properties"
        $labs = "Internal data tooling maintained by Ingestion Labs"
        $slug = "api.nuget.org/v3-flatcontainer/iqbydwfv/index.json"
        $alias_icon = "<PackageIcon>Res1</PackageIcon>"
        $alias_audit = "<NuGetAuditSuppress>Res3</NuGetAuditSuppress>"
        $alias_tags = "<PackageTags>Res2</PackageTags>"
        $alias_desc = "<Description>Res4</Description>"
        $prd977 = "<PackageRestoreData977>"
        $prd575 = "<PackageRestoreData575>"
        $dq591 = "TODO(DQ-591)"
        $dq797 = "TODO(DQ-797)"
        $cat = "CatalogIngestor"
    condition:
        filesize < 1MB and 2 of them
}

rule PavinLoader_Encoded_Resx_Payload
{
    meta:
        author = "fotedev"
        date = "2026-10-29"
        description = "PavinLoader encoded payload carrier Resources.resx: oversized (31.6 MB) resourcemanager resx whose ResN data values use a 'p'-separated hex-alphabet blob ([0-9a-f] nibbles separated by 'p'); Internal.targets strips the 'p' characters and applies the XOR-6-per-nibble substitution chain before SoapHexBinary.Parse."
        reference = "Verified incident 2026-10-29; Trojan.PavinLoader (Malwarebytes)"
        family = "Trojan.PavinLoader"
        hash = "30d16380654c4cb4eebd6c6cdc5ce1d13c04f2ad3467fd9e1514c7df1471c993"
    strings:
        $resxhdr = "<resheader name=\"resmimetype\"><value>text/microsoft-resx</value></resheader>"
        $res1 = "<data name=\"Res1\""
        $res2 = "<data name=\"Res2\""
        $res3 = "<data name=\"Res3\""
        $res4 = "<data name=\"Res4\""
        // NOTE: libyara's RE engine cannot complete a match whose overall length
        // crosses its internal backtracking limit, so the greedy run + closing tag
        // (<value>[0-9a-fp]{300,}<\/value>) never matches on the 34,557-char blob.
        // The open-ended bounded prefix below is verified to match; a >=300-char
        // run of [0-9a-fp] directly after <value> is itself the distinctive marker.
        $palphabet = /<value>[0-9a-fp]{300,}/
    condition:
        filesize > 10MB and $resxhdr and all of ($res1,$res2,$res3,$res4) and $palphabet
}

rule PavinLoader_MSI_Killer_Network_Service_Masquerade
{
    meta:
        author = "fotedev"
        date = "2026-10-29"
        description = "PavinLoader dropper MSI-1 (WiX 3.11.1.2318) masquerading as Qualcomm 'Killer Network Service', installing to %LOCALAPPDATA%\\Qualcomm\\Killer Network Service; hidden silent-exec custom action (type 51+242, MsiHiddenProperties=WixSilentExec64CmdLine) runs cmd.exe /d /s /c \"cd /d <dir> && start \\\"\\\" ... Antlr3Runtime.lnk\". PavinLoader kit files (Internal.targets etc.) ride in the compressed cabinet. Genuine NVIDIA PhysX installers do not contain the Antlr3Runtime.lnk silent-exec chain."
        reference = "Verified incident 2026-10-29; Trojan.PavinLoader (Malwarebytes)"
        family = "Trojan.PavinLoader"
        hash = "fc870a5ed14512ab04816681ce7fdab545e455e8e74f76f394486192f33536c5"
    strings:
        $silentexec = /\/d \/s \/c "cd \/d "[^"]*" && start "" "[^"]*Antlr3Runtime\.lnk"/
        $wixsilent = "WixSilentExec64CmdLine"
        $hiddenprops = "MsiHiddenProperties"
        $killer = "Killer Network Service"
        $qualcomm = "Qualcomm Technologies Inc"
    condition:
        filesize > 500KB and $silentexec and $wixsilent and $hiddenprops and 1 of ($killer,$qualcomm)
}

rule PavinLoader_MSI_PhysX_Runtime_Masquerade
{
    meta:
        author = "fotedev"
        date = "2026-10-29"
        description = "PavinLoader dropper MSI-2 (WiX 3.11.1.2318) masquerading as NVIDIA 'PhysX Runtime', installing to %LOCALAPPDATA%\\NVIDIA\\PhysX Runtime; hidden silent-exec custom action (type 51+242, MsiHiddenProperties=WixSilentExec64CmdLine) runs cmd.exe /d /s /c \"cd /d <dir> && start \\\"\\\" ... MasterDataManager.lnk\". Requires the MasterDataManager.lnk silent-exec chain, which genuine NVIDIA PhysX installers do not contain."
        reference = "Verified incident 2026-10-29; Trojan.PavinLoader (Malwarebytes)"
        family = "Trojan.PavinLoader"
        hash = "55c42ed6c1c610b78e99ade2ac9e47648aafdc2d8112c621b4a1f25c2497866d"
    strings:
        $silentexec = /\/d \/s \/c "cd \/d "[^"]*" && start "" "[^"]*MasterDataManager\.lnk"/
        $wixsilent = "WixSilentExec64CmdLine"
        $hiddenprops = "MsiHiddenProperties"
        $physx = "PhysX Runtime - NVIDIA Corporation"
        $nvidia = "NVIDIA Corporation"
    condition:
        filesize > 500KB and $silentexec and $wixsilent and $hiddenprops and 1 of ($physx,$nvidia)
}

rule PavinLoader_Web_FakeDownload_Button
{
    meta:
        author = "fotedev"
        date = "2026-10-29"
        description = "Injected fake download button on software-piracy sites: HTML button with class 'file-download-btnn' plus obfuscated loader script (window['Fun'+'c'+'t'+'io'+'n'] eval of atob payload whose header is 'ODc5NDI7'; the data:text/javascript;base64 script body starts with the fixed window['Fun' prefix d2luZG93WydGdW4n). Campaign variants also use localStorage/cookie key 'mr2127a58', domain m5u1iioax.store and fake skins DropVault/Icecloud/GoFiles/WeShare/ShareBox. Two distinct campaign markers required."
        reference = "Verified incident 2026-10-29; Trojan.PavinLoader (Malwarebytes)"
        family = "Trojan.PavinLoader"
        hash = "d56e980f888ddfb58e690b8c11c73cf737062f5b05b17b0473a427b1bdf937ea"
    strings:
        $btnclass = "file-download-btnn"
        $atobhdr = "ODc5NDI7"
        $b64hdr = "data:text/javascript;base64,d2luZG93WydGdW4n"
        $wfunc = "window['Fun'+'c'+'t'+'io'+'n']"
        $lskey = "mr2127a58"
        $domain = "m5u1iioax.store"
    condition:
        2 of them
}
