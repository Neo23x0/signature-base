
rule HKTL_Koh_TokenStealer
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project."
        author = "Will Schroeder (@harmj0y)"
        reference = "https://github.com/GhostPack/Koh"
        id = "76b6cc9f-5db7-5e9b-939c-e713bad8137a"
    strings:
        $x_typelibguid = "4d5350c8-7f8c-47cf-8cde-c752018af17e" ascii

        $s1 = "[*] Already SYSTEM, not elevating" wide fullword
        $s2 = "S-1-[0-59]-\\d{2}-\\d{8,10}-\\d{8,10}-\\d{8,10}-[1-9]\\d{2}" wide
        $s3 = "0x[0-9A-Fa-f]+$" wide
        $s4 = "\\Koh.pdb" ascii
    condition:
        uint16(0) == 0x5A4D and 1 of ($x*) or 3 of them
}