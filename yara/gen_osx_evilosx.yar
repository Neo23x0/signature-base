rule OSX_backdoor_EvilOSX {
    meta:
        description = "EvilOSX MacOS/OSX backdoor"
        author = "John Lambert @JohnLaTwC"
        reference = "https://github.com/Marten4n6/EvilOSX, https://twitter.com/JohnLaTwC/status/966139336436498432"
        date = "2018-02-23"
        hash = "89e5b8208daf85f549d9b7df8e2a062e47f15a5b08462a4224f73c0a6223972a"

        id = "6940e355-53d2-51e3-afd0-13303a311e9a"
    strings:
        $h1 = "#!/usr/bin/env"
        $s0 = "import base64" fullword ascii
        $s1 = "b64decode" fullword ascii

        //strings present in decoded python script:
        $x0 = "EvilOSX" fullword ascii
        $x1 = "get_launch_agent_directory" fullword ascii

        //Base64 encoded versions of these strings
        //EvilOSX
        $enc_x0 = /(AHYAaQBsAE8AUwBYA|dmlsT1NY|RQB2AGkAbABPAFMAWA|RXZpbE9TW|UAdgBpAGwATwBTAFgA|V2aWxPU1)/ ascii

        //get_launch_agent_directory
        $enc_x1 = /(AGUAdABfAGwAYQB1AG4AYwBoAF8AYQBnAGUAbgB0AF8AZABpAHIAZQBjAHQAbwByAHkA|cAZQB0AF8AbABhAHUAbgBjAGgAXwBhAGcAZQBuAHQAXwBkAGkAcgBlAGMAdABvAHIAeQ|dldF9sYXVuY2hfYWdlbnRfZGlyZWN0b3J5|Z2V0X2xhdW5jaF9hZ2VudF9kaXJlY3Rvcn|ZwBlAHQAXwBsAGEAdQBuAGMAaABfAGEAZwBlAG4AdABfAGQAaQByAGUAYwB0AG8AcgB5A|ZXRfbGF1bmNoX2FnZW50X2RpcmVjdG9ye)/ ascii

    condition:
        uint32(0) == 0x752f2123
        and $h1 at 0
        and filesize < 30KB
        and all of ($s*)
        and
            1 of ($x*)
            or 1 of ($enc_x*)
}
