
rule EXT_NK_GOLDBACKDOOR_inital_shellcode {
    meta:
        author= "Silas Cutler (silas@Stairwell.com)"
        description = "Detection for initial shellcode loader used to deploy GOLDBACDOOR"
        version = "0.1"
        date = "2022-04-21"
        reference = "https://stairwell.com/wp-content/uploads/2022/04/Stairwell-threat-report-The-ink-stained-trail-of-GOLDBACKDOOR.pdf"
        score = 80
        id = "daab8e54-11b3-51cc-8bee-55b078f3e791"
    strings:
        $ = { C7 45 C4 25 6C 6F 63 50 8D 45 C4 C7 45 C8 61 6C 61 70 8B F9 C7 45
              CC 70 64 61 74 50 B9 BD 88 17 75 C7 45 D0 61 25 5C 6C 8B DA C7 45 D4 6F
              67 5F 67 C7 45 D8 6F 6C 64 2E C7 45 DC 74 78 74 00 }
        // Import loaders
        $ = { 51 50 57 56 B9 E6 8E 85 35 E8 ?? ?? ?? ?? FF D0 }
        $ = { 6A 40 68 00 10 00 00 52 6A 00 FF 75 E0 B9 E3 18 90 72 E8 ?? ?? ?? ?? FF D0}
    condition:
        all of them
}

rule EXT_NK_GOLDBACKDOOR_injected_shellcode {
    meta:
        author= "Silas Cutler (silas@Stairwell.com)"
        description = "Detection for injected shellcode that decodes GOLDBACKDOOR"
        version = "0.1"
        date = "2022-04-21"
        reference = "https://stairwell.com/wp-content/uploads/2022/04/Stairwell-threat-report-The-ink-stained-trail-of-GOLDBACKDOOR.pdf"
        score = 80
        id = "aa921f01-98cc-51ab-877a-e7beede77e36"
    strings:
        $dec_routine = { 8A 19 57 8B FA 8B 51 01 83 C1 05 85 D2 74 0E 56 8B C1 8B F2 30 18 40 83 EE 01 75 F8 5E 57 }
        $rtlfillmemory_load = { B9 4B 17 CD 5B 55 56 33 ED 55 6A 10 50 E8 86 00 00 00 FF D0 }
        $ = "StartModule"
        $log_file_name = { C7 44 24 3C 25 6C 6F 63 50 8D 44 24 40 C7 44 24 44 61 6C 
                           61 70 50 B9 BD 88 17 75 C7 44 24 4C 70 64 61 74 C7 44 24 
                           50 61 25 5C 6C C7 44 24 54 6F 67 5F 67 C7 44 24 58 6F 6C
                           64 32 C7 44 24 5C 2E 74 78 74 }
         $ = { B9 8E 8A DD 8D 8B F0 E8 E9 FB FF FF FF D0 }
    condition:
       3 of them
}

rule EXT_NK_GOLDBACKDOOR_generic_shellcode {
    meta:
        author= "Silas Cutler (silas@Stairwell.com)"
        description = "Generic detection for shellcode used to drop GOLDBACKDOOR"
        version = "0.1"
        date = "2022-04-21"
        reference = "https://stairwell.com/wp-content/uploads/2022/04/Stairwell-threat-report-The-ink-stained-trail-of-GOLDBACKDOOR.pdf"
        score = 75
        id = "70081d63-0b26-5358-8444-5adc3a44aaa0"
    strings:
        $ = { B9 8E 8A DD 8D 8B F0 E8 ?? ?? ?? ?? FF D0 }
        $ = { B9 8E AB 6F 40 [1-10] 50 [1-10] E8 ?? ?? ?? ?? FF D0 }
    condition:
        all of them
}
