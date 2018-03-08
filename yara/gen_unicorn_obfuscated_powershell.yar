rule gen_unicorn_obfuscated_powershell {
    meta:
        description = "PowerShell payload obfuscated by Unicorn toolkit"
        author = "John Lambert @JohnLaTwC"
        date = "2018-03-07"
        hash = "b93d2fe6a671a6a967f31d5b3a0a16d4f93abcaf25188a2bbdc0894087adb10d"
        reference = "https://github.com/trustedsec/unicorn/"
    strings:
        $h1 = "powershell"
        $s1 = ".value.toString() 'JAB"
        $s2 = "-w 1 -C \"sv"
    condition:
        filesize < 20KB
        and uint32be(0) == 0x706f7765
        and $h1 at 0
        and (
           uint16be(filesize-2) == 0x2722 or  /* Footer 1 */
           ( uint16be(filesize-2) == 0x220a and uint8(filesize-3) == 0x27 )  /* Footer 2 */
        )
        and all of ($s*)
}
