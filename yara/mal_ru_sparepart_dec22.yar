
rule MAL_Backdoor_SPAREPART_SleepGenerator {
    meta:
        author = "Mandiant"
        date = "2022-12-14"
        description = "Detects the algorithm used to determine the next sleep timer"
        version = "1"
        weight = "100"
        hash = "f9cd5b145e372553dded92628db038d8"
        disclaimer = "This rule is meant for hunting and is not tested to run in a production environment."
        reference = "https://www.mandiant.com/resources/blog/trojanized-windows-installers-ukrainian-government"
        id = "b9cd46e4-0e06-5ead-8379-adcfc3c384d0"
    strings:
        $ = {C1 E8 06 89 [5] C1 E8 02 8B}
        $ = {c1 e9 03 33 c1 [3] c1 e9 05 33 c1 83 e0 01}
        $ = {8B 80 FC 00 00 00}
        $ = {D1 E8 [4] c1 E1 0f 0b c1}
    condition:
        all of them
}

rule MAL_Backdoor_SPAREPART_Struct {
    meta:
        author = "Mandiant"
        date = "2022-12-14"
        description = "Detects the PDB and a struct used in SPAREPART"
        hash = "f9cd5b145e372553dded92628db038d8"
        disclaimer = "This rule is meant for hunting and is not tested to run in a production environment."
        reference = "https://www.mandiant.com/resources/blog/trojanized-windows-installers-ukrainian-government"
        id = "a04296d5-c146-5142-a8e8-418651f6b755"
    strings:
        $pdb = "c:\\Users\\user\\Desktop\\ImageAgent\\ImageAgent\\PreAgent\\src\\builder\\agent.pdb" ascii nocase
        $struct = { 44 89 ac ?? ?? ?? ?? ?? 4? 8b ac ?? ?? ?? ?? ?? 4? 83 c5 28 89 84 ?? ?? ?? ?? ?? 89 8c ?? ?? ?? ?? ?? 89 54 ?? ?? 44 89 44 ?? ?? 44 89 4c ?? ?? 44 89 54 ?? ?? 44 89 5c ?? ?? 89 5c ?? ?? 89 7c ?? ?? 89 74 ?? ?? 89 6c ?? ?? 44 89 74 ?? ?? 44 89 7c ?? ?? 44 89 64 ?? ?? 8b 84 ?? ?? ?? ?? ?? 44 8b c8 8b 84 ?? ?? ?? ?? ?? 44 8b c0 4? 8d 15 ?? ?? ?? ?? 4? 8b cd ff 15 ?? ?? ?? ??  }
    condition:
       (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and
       $pdb and
       $struct and
       filesize < 20KB
} 
