rule gen_unicorn_obfuscated_powershell {
    meta:
        description = "PowerShell payload obfuscated by Unicorn toolkit"
        author = "John Lambert @JohnLaTwC"
        date = "2018-04-03"
        hash = "b93d2fe6a671a6a967f31d5b3a0a16d4f93abcaf25188a2bbdc0894087adb10d"
        hash2 = "1afb9795cb489abce39f685a420147a2875303a07c32bf7eec398125300a460b"
        reference = "https://github.com/trustedsec/unicorn/"
        id = "0235795b-6d0b-5bba-8ae6-606c3b613c86"
    strings:
        $h1 = "powershell"
        $sa1 = ".value.toString() 'JAB"
        $sa2 = ".value.toString() ('JAB"
        $sb1 = "-w 1 -C \"s"
        $sb2 = "/w 1 /C \"s"        
    condition:
        filesize < 20KB
        and uint32be(0) == 0x706f7765
        and $h1 at 0
        and (
           uint16be(filesize-2) == 0x2722 or  /* Footer 1 */
           ( uint16be(filesize-2) == 0x220a and uint8(filesize-3) == 0x27 )  or /* Footer 2 */
           ( uint16be(filesize-2) == 0x2922 and uint8(filesize-3) == 0x27 )  /* Footer 3 */
        )
        and ( 1 of ($sa*) and 1 of ($sb*) )
}
