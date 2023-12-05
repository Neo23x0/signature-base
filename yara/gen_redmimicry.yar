
rule HKTL_RedMimicry_Agent {
    meta:
        date        = "2020-06-22"
        modified = "2023-01-06"
        author      = "mirar@chaosmail.org"
        sharing     = "tlp:white"
        description = "matches the RedMimicry agent executable and payload"
        reference   = "https://redmimicry.com"

        id = "a4d4ec77-4a0d-5afd-9181-85433e8b5fda"
    strings:
        $reg0 = "HKEY_CURRENT_USER\\" ascii
        $reg1 = "HKEY_LOCAL_MACHINE\\" ascii
        $reg2 = "HKEY_CURRENT_CONFIG\\" ascii
        $reg3 = "HKEY_CLASSES_ROOT\\" ascii
        $cmd0 = "C:\\Windows\\System32\\cmd.exe" ascii fullword
        $lua0 = "client_recv" ascii fullword
        $lua1 = "client_send" ascii fullword
        $lua2 = "$LuaVersion: " ascii
        $sym0 = "VirtualAllocEx" wide fullword
        $sym1 = "kernel32.dll" wide fullword

    condition:
        all of them
}

rule HKTL_RedMimicry_WinntiLoader {
    meta:
        date        = "2020-06-22"
        modified = "2023-01-10"
        author      = "mirar@chaosmail.org"
        sharing     = "tlp:white"
        description = "matches the Winnti 'Cooper' loader version used for the RedMimicry breach emulation"
        reference   = "https://redmimicry.com"

        id = "a8be1377-faa0-560d-a12c-0369b1f91180"
    strings:
        $s0 = "Cooper" ascii fullword
        $s1 = "stone64.dll" ascii fullword
        /* $s2 = "XML" ascii fullword */
        /*
        .text:0000000180004450                                     loc_180004450:                          ; CODE XREF: sub_1800043F0+80?j
        .text:0000000180004450 49 63 D0                                            movsxd  rdx, r8d
        .text:0000000180004453 43 8D 0C 01                                         lea     ecx, [r9+r8]
        .text:0000000180004457 41 FF C0                                            inc     r8d
        .text:000000018000445A 42 32 0C 1A                                         xor     cl, [rdx+r11]
        .text:000000018000445E 0F B6 C1                                            movzx   eax, cl
        .text:0000000180004461 C0 E9 04                                            shr     cl, 4
        .text:0000000180004464 C0 E0 04                                            shl     al, 4
        .text:0000000180004467 02 C1                                               add     al, cl
        .text:0000000180004469 42 88 04 1A                                         mov     [rdx+r11], al
        .text:000000018000446D 44 3B 03                                            cmp     r8d, [rbx]
        .text:0000000180004470 72 DE                                               jb      short loc_180004450
        */
        $decoding_loop = { 49 63 D0 43 8D 0C 01 41 FF C0 42 32 0C 1A 0F B6 C1 C0 E9 04 C0 E0 04 02 C1 42 88 04 1A 44 3B 03 72 DE }
    condition:
        all of them
}