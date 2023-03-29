
rule EXT_MSIL_SUSP_OBFUSC_XorStringsNet {
    meta:
        description = "Detects XorStringsNET string encryption, and other obfuscators derived from it"
        author = "dr4k0nia"
        version = "1.0"
        reference = "https://github.com/dr4k0nia/yara-rules"
        score = 75
        date = "26/03/2023"
    strings:
        $pattern = { 06 1E 58 07 8E 69 FE 17 }

        // .NET marker
        $a1 = ".cctor" ascii fullword
    condition:
        uint16(0) == 0x5a4d
        and filesize < 25MB
        and all of them
}
