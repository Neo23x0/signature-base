rule Persistence_Agent_MacOS {
    meta:
        description = "Detects a Python agent that establishes persistence on macOS"
        author = "John Lambert @JohnLaTwC"
        reference = "https://ghostbin.com/paste/mz5nf"
        hash = "4288a81779a492b5b02bad6e90b2fa6212fa5f8ee87cc5ec9286ab523fc02446 cec7be2126d388707907b4f9d681121fd1e3ca9f828c029b02340ab1331a5524 e1cf136be50c4486ae8f5e408af80b90229f3027511b4beed69495a042af95be"

    strings:
        $h1 = "#!/usr/bin/env python"
        $s_1= "<plist" ascii fullword
        $s_2= "ProgramArguments" ascii fullword
        $s_3= "Library" ascii fullword
        $sinterval_1= "StartInterval" ascii fullword
        $sinterval_2= "RunAtLoad" ascii fullword

        //<plist
        $e_1 = /(AHAAbABpAHMAdA|cGxpc3|PABwAGwAaQBzAHQA|PHBsaXN0|wAcABsAGkAcwB0A|xwbGlzd)/ ascii

        //ProgramArguments
        $e_2 =/(AAcgBvAGcAcgBhAG0AQQByAGcAdQBtAGUAbgB0AHMA|AHIAbwBnAHIAYQBtAEEAcgBnAHUAbQBlAG4AdABzA|Byb2dyYW1Bcmd1bWVudH|cm9ncmFtQXJndW1lbnRz|UAByAG8AZwByAGEAbQBBAHIAZwB1AG0AZQBuAHQAcw|UHJvZ3JhbUFyZ3VtZW50c)/ ascii
        //Library
        $e_4 = /(AGkAYgByAGEAcgB5A|aWJyYXJ5|TABpAGIAcgBhAHIAeQ|TGlicmFye|wAaQBiAHIAYQByAHkA|xpYnJhcn)/ ascii

        //StartInterval
        $einterval_a = /(AHQAYQByAHQASQBuAHQAZQByAHYAYQBsA|dGFydEludGVydmFs|MAdABhAHIAdABJAG4AdABlAHIAdgBhAGwA|N0YXJ0SW50ZXJ2YW|U3RhcnRJbnRlcnZhb|UwB0AGEAcgB0AEkAbgB0AGUAcgB2AGEAbA)/ ascii
        $einterval_b = /(AHUAbgBBAHQATABvAGEAZA|dW5BdExvYW|IAdQBuAEEAdABMAG8AYQBkA|J1bkF0TG9hZ|UgB1AG4AQQB0AEwAbwBhAGQA|UnVuQXRMb2Fk)/ ascii

    condition:
        $h1 at 0
        and filesize < 120KB
        and
        (
            (all of ($s_*) and 1 of ($sinterval*))
            or
            (all of ($e_*) and 1 of ($einterval*))
        )

}
