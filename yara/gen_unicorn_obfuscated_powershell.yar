rule gen_unicorn_obfuscated_powershell
{
    meta: 
        description = "PowerShell payload obfuscated by Unicorn toolkit"
        author = "John Lambert @JohnLaTwC"
        date = "2018-03-07"
        hash = "b93d2fe6a671a6a967f31d5b3a0a16d4f93abcaf25188a2bbdc0894087adb10d"
        reference = "https://github.com/trustedsec/unicorn/"
    strings:
        $h1 = "powershell"
        $footer = /('"|'\)")/
        $s1 = ".value.toString()" 
        $s2 = "-w 1" 
        $p1 = /;sv \w{1,3} \w{1,3};/ 
        $p2 = /;s'*v ['|\w]{1,4} ['|\w]{1,4};/ 
        $b64 = /'JAB[a-zA-Z0-9=+\/]{50,}/
    condition:
        filesize < 20KB
        and $h1 at 0
        and @footer[1] > (filesize - 5)
        and all of ($s*)
        and #b64 == 1
        and 1 of ($p*)
}
