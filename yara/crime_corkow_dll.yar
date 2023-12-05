import "pe"

rule CorkowDLL {
    meta:
        description = "Rule to detect the Corkow DLL files"
        author = "Group IB"
        date = "01.02.2016"
        referenced = "https://www.group-ib.ru/brochures/Group-IB-Corkow-Report-EN.pdf"
        id = "cc9d2bb3-8db3-54a0-bd05-7f054ce84633"
    strings:
        $binary1 = { 60 [0-8] 9C [0-8] BB ?? ?? ?? ?? [0-8] 81 EB ?? ?? ?? ?? [0-8] E8 ?? 00 00 00 [0-8] 58 [0-8] 2B C3 }
        $binary2 = { (FF 75 ?? | 53) FF 75 10 FF 75 0C FF 75 08 E8 ?? ?? ?? ?? [3-9] C9 C2 0C 00 }
    condition:
         uint16(0) == 0x5a4d and (
            all of ($binary*) and (
               pe.exports("Control_RunDLL") or
               pe.exports("ServiceMain") or
               pe.exports("DllGetClassObject")
            ) or (
               pe.exports("ServiceMain") and  /* Service DLL */
               pe.exports("Control_RunDLL")   /* Sufficiently specific in this combination */
            )
         )
}
