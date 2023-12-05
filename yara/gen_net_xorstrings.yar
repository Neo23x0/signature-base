
rule MSIL_SUSP_OBFUSC_XorStringsNet {
    meta:
        description = "Detects XorStringsNET string encryption, and other obfuscators derived from it"
        author = "dr4k0nia"
        version = "1.0"
        reference = "https://github.com/dr4k0nia/yara-rules"
        score = 75
        date = "26/03/2023"
        id = "f0724ca6-4bfe-5b88-9396-a58aa7461fd6"
    strings:
        $pattern = { 06 1E 58 07 8E 69 FE 17 }

        // .NET marker
        $a1 = "_CorDllMain" ascii
        $a2 = "_CorExeMain" ascii
        $a3 = "mscorlib" ascii fullword
        $a4 = ".cctor" ascii fullword
        $a5 = "System.Private.Corlib" ascii
        $a6 = "<Module>" ascii fullword
        $a7 = "<PrivateImplementationsDetails{" ascii
    condition:
        uint16(0) == 0x5a4d
        and filesize < 25MB
        and $pattern 
        and 2 of ($a*)
}

