rule apt3_bemstour_strings
{
meta:

description = "Detects strings used by the Bemstour exploitation tool"
author = "Mark Lechtik"
company = "Check Point Software Technologies LTD."
date = "2019-06-25"
sha256 = "0b28433a2b7993da65e95a45c2adf7bc37edbd2a8db717b85666d6c88140698a"
uuid = "8b76e10a-040f-505e-9dff-cd0a689b121e"
strings:

$dbg_print_1 = "leaked address is 0x%llx" ascii wide
$dbg_print_2 = "========== %s ==========" ascii wide
$dbg_print_3 = "detailVersion:%d" ascii wide
$dbg_print_4 = "create pipe twice failed" ascii wide
$dbg_print_5 = "WSAStartup function failed with error: %d" ascii wide
$dbg_print_6 = "can't open input file." ascii wide
$dbg_print_7 = "Allocate Buffer Failed." ascii wide
$dbg_print_8 = "Connect to target failed." ascii wide
$dbg_print_9 = "connect successful." ascii wide
$dbg_print_10 = "not supported Platform" ascii wide
$dbg_print_11 = "Wait several seconds." ascii wide
$dbg_print_12 = "not set where to write ListEntry ." ascii wide
$dbg_print_13 = "backdoor not installed." ascii wide
$dbg_print_14 = "REConnect to target failed." ascii wide
$dbg_print_15 = "Construct TreeConnectAndX Request Failed." ascii wide
$dbg_print_16 = "Construct NTCreateAndXRequest  Failed." ascii wide
$dbg_print_17 = "Construct Trans2  Failed." ascii wide
$dbg_print_18 = "Construct ConsWXR  Failed." ascii wide
$dbg_print_19 = "Construct ConsTransSecondary  Failed." ascii wide
$dbg_print_20 = "if you don't want to input password , use server2003 version.." ascii wide

$cmdline_1 = "Command format  %s TargetIp domainname username password 2" ascii wide
$cmdline_2 = "Command format  %s TargetIp domainname username password 1" ascii wide
$cmdline_3 = "cmd.exe /c net user test test /add && cmd.exe /c net localgroup administrators test /add" ascii wide
$cmdline_4 = "hello.exe  \"C:\\WINDOWS\\DEBUG\\test.exe\"" ascii wide
$cmdline_5 = "parameter not right" ascii wide

$smb_param_1 = "browser" ascii wide
$smb_param_2 = "spoolss" ascii wide
$smb_param_3 = "srvsvc" ascii wide
$smb_param_4 = "\\PIPE\\LANMAN" ascii wide
$smb_param_5 = "Werttys for Workgroups 3.1a" ascii wide
$smb_param_6 = "PC NETWORK PROGRAM 1.0" ascii wide
$smb_param_7 = "LANMAN1.0" ascii wide
$smb_param_8 = "LM1.2X002" ascii wide
$smb_param_9 = "LANMAN2.1" ascii wide
$smb_param_10 = "NT LM 0.12" ascii wide
$smb_param_12 = "WORKGROUP" ascii wide
$smb_param_13 = "Windows Server 2003 3790 Service Pack 2" ascii wide
$smb_param_14 = "Windows Server 2003 5.2" ascii wide
$smb_param_15 = "Windows 2002 Service Pack 2 2600" ascii wide
$smb_param_16 = "Windows 2002 5.1" ascii wide
$smb_param_17 = "PC NETWORK PROGRAM 1.0" ascii wide
$smb_param_18 = "Windows 2002 5.1" ascii wide
$smb_param_19 = "Windows for Workgroups 3.1a" ascii wide

$unique_str_1 = "WIN-NGJ7GKNROVS"
$unique_str_2 = "XD-A31C2E0087B2"

condition:
    uint16(0) == 0x5a4d and (5 of ($dbg_print*) or 2 of ($cmdline*) or 1 of ($unique_str*)) and 3 of ($smb_param*)
}




rule apt3_bemstour_implant_byte_patch
{
meta:

description = "Detects an implant used by Bemstour exploitation tool (APT3)"
author = "Mark Lechtik"
company = "Check Point Software Technologies LTD."
date = "2019-06-25"
sha256 = "0b28433a2b7993da65e95a45c2adf7bc37edbd2a8db717b85666d6c88140698a"

/*

0x41b7e1L C745B8558BEC83                mov dword ptr [ebp - 0x48], 0x83ec8b55
0x41b7e8L C745BCEC745356                mov dword ptr [ebp - 0x44], 0x565374ec
0x41b7efL C745C08B750833                mov dword ptr [ebp - 0x40], 0x3308758b
0x41b7f6L C745C4C957C745                mov dword ptr [ebp - 0x3c], 0x45c757c9
0x41b7fdL C745C88C4C6F61                mov dword ptr [ebp - 0x38], 0x616f4c8c

*/

uuid = "c30434c3-8949-566c-b6a6-29bffdaf961d"
strings:

$chunk_1 = {

C7 45 ?? 55 8B EC 83
C7 45 ?? EC 74 53 56
C7 45 ?? 8B 75 08 33
C7 45 ?? C9 57 C7 45
C7 45 ?? 8C 4C 6F 61

}

condition:
    any of them
}


rule apt3_bemstour_implant_command_stack_variable
{
meta:

description = "Detecs an implant used by Bemstour exploitation tool (APT3)"
author = "Mark Lechtik"
company = "Check Point Software Technologies LTD."
date = "2019-06-25"
sha256 = "0b28433a2b7993da65e95a45c2adf7bc37edbd2a8db717b85666d6c88140698a"


uuid = "c773da5a-2d3f-5a0a-af2e-28ad382622b3"
strings:


/*

0x41ba18L C78534FFFFFF636D642E          mov dword ptr [ebp - 0xcc], 0x2e646d63
0x41ba22L C78538FFFFFF65786520          mov dword ptr [ebp - 0xc8], 0x20657865
0x41ba2cL C7853CFFFFFF2F632063          mov dword ptr [ebp - 0xc4], 0x6320632f
0x41ba36L C78540FFFFFF6F707920          mov dword ptr [ebp - 0xc0], 0x2079706f
0x41ba40L C78544FFFFFF2577696E          mov dword ptr [ebp - 0xbc], 0x6e697725
0x41ba4aL C78548FFFFFF64697225          mov dword ptr [ebp - 0xb8], 0x25726964
0x41ba54L C7854CFFFFFF5C737973          mov dword ptr [ebp - 0xb4], 0x7379735c
0x41ba5eL C78550FFFFFF74656D33          mov dword ptr [ebp - 0xb0], 0x336d6574
0x41ba68L C78554FFFFFF325C636D          mov dword ptr [ebp - 0xac], 0x6d635c32
0x41ba72L C78558FFFFFF642E6578          mov dword ptr [ebp - 0xa8], 0x78652e64
0x41ba7cL C7855CFFFFFF65202577          mov dword ptr [ebp - 0xa4], 0x77252065
0x41ba86L C78560FFFFFF696E6469          mov dword ptr [ebp - 0xa0], 0x69646e69
0x41ba90L C78564FFFFFF72255C73          mov dword ptr [ebp - 0x9c], 0x735c2572
0x41ba9aL C78568FFFFFF79737465          mov dword ptr [ebp - 0x98], 0x65747379
0x41baa4L C7856CFFFFFF6D33325C          mov dword ptr [ebp - 0x94], 0x5c32336d
0x41baaeL C78570FFFFFF73657468          mov dword ptr [ebp - 0x90], 0x68746573
0x41bab8L C78574FFFFFF632E6578          mov dword ptr [ebp - 0x8c], 0x78652e63
0x41bac2L C78578FFFFFF65202F79          mov dword ptr [ebp - 0x88], 0x792f2065
0x41baccL 83A57CFFFFFF00                and dword ptr [ebp - 0x84], 0

*/

$chunk_1 = {

C7 85 ?? ?? ?? ?? 63 6D 64 2E
C7 85 ?? ?? ?? ?? 65 78 65 20
C7 85 ?? ?? ?? ?? 2F 63 20 63
C7 85 ?? ?? ?? ?? 6F 70 79 20
C7 85 ?? ?? ?? ?? 25 77 69 6E
C7 85 ?? ?? ?? ?? 64 69 72 25
C7 85 ?? ?? ?? ?? 5C 73 79 73
C7 85 ?? ?? ?? ?? 74 65 6D 33
C7 85 ?? ?? ?? ?? 32 5C 63 6D
C7 85 ?? ?? ?? ?? 64 2E 65 78
C7 85 ?? ?? ?? ?? 65 20 25 77
C7 85 ?? ?? ?? ?? 69 6E 64 69
C7 85 ?? ?? ?? ?? 72 25 5C 73
C7 85 ?? ?? ?? ?? 79 73 74 65
C7 85 ?? ?? ?? ?? 6D 33 32 5C
C7 85 ?? ?? ?? ?? 73 65 74 68
C7 85 ?? ?? ?? ?? 63 2E 65 78
C7 85 ?? ?? ?? ?? 65 20 2F 79
83 A5 ?? ?? ?? ?? 00
}




/*

0x41baeeL C785D8FEFFFF636D6420          mov dword ptr [ebp - 0x128], 0x20646d63
0x41baf8L C785DCFEFFFF2F632022          mov dword ptr [ebp - 0x124], 0x2220632f
0x41bb02L C785E0FEFFFF6E657420          mov dword ptr [ebp - 0x120], 0x2074656e
0x41bb0cL C785E4FEFFFF75736572          mov dword ptr [ebp - 0x11c], 0x72657375
0x41bb16L C785E8FEFFFF20636573          mov dword ptr [ebp - 0x118], 0x73656320
0x41bb20L C785ECFEFFFF73757070          mov dword ptr [ebp - 0x114], 0x70707573
0x41bb2aL C785F0FEFFFF6F727420          mov dword ptr [ebp - 0x110], 0x2074726f
0x41bb34L C785F4FEFFFF3171617A          mov dword ptr [ebp - 0x10c], 0x7a617131
0x41bb3eL C785F8FEFFFF23454443          mov dword ptr [ebp - 0x108], 0x43444523
0x41bb48L C785FCFEFFFF202F6164          mov dword ptr [ebp - 0x104], 0x64612f20
0x41bb52L C78500FFFFFF64202626          mov dword ptr [ebp - 0x100], 0x26262064
0x41bb5cL C78504FFFFFF206E6574          mov dword ptr [ebp - 0xfc], 0x74656e20
0x41bb66L C78508FFFFFF206C6F63          mov dword ptr [ebp - 0xf8], 0x636f6c20
0x41bb70L C7850CFFFFFF616C6772          mov dword ptr [ebp - 0xf4], 0x72676c61
0x41bb7aL C78510FFFFFF6F757020          mov dword ptr [ebp - 0xf0], 0x2070756f
0x41bb84L C78514FFFFFF61646D69          mov dword ptr [ebp - 0xec], 0x696d6461
0x41bb8eL C78518FFFFFF6E697374          mov dword ptr [ebp - 0xe8], 0x7473696e
0x41bb98L C7851CFFFFFF7261746F          mov dword ptr [ebp - 0xe4], 0x6f746172
0x41bba2L C78520FFFFFF72732063          mov dword ptr [ebp - 0xe0], 0x63207372
0x41bbacL C78524FFFFFF65737375          mov dword ptr [ebp - 0xdc], 0x75737365
0x41bbb6L C78528FFFFFF70706F72          mov dword ptr [ebp - 0xd8], 0x726f7070
0x41bbc0L C7852CFFFFFF74202F61          mov dword ptr [ebp - 0xd4], 0x612f2074
0x41bbcaL C78530FFFFFF64642200          mov dword ptr [ebp - 0xd0], 0x226464
0x41bbd4L 6A5C                          push 0x5c

*/

$chunk_2 = {

C7 85 ?? ?? ?? ?? 63 6D 64 20
C7 85 ?? ?? ?? ?? 2F 63 20 22
C7 85 ?? ?? ?? ?? 6E 65 74 20
C7 85 ?? ?? ?? ?? 75 73 65 72
C7 85 ?? ?? ?? ?? 20 63 65 73
C7 85 ?? ?? ?? ?? 73 75 70 70
C7 85 ?? ?? ?? ?? 6F 72 74 20
C7 85 ?? ?? ?? ?? 31 71 61 7A
C7 85 ?? ?? ?? ?? 23 45 44 43
C7 85 ?? ?? ?? ?? 20 2F 61 64
C7 85 ?? ?? ?? ?? 64 20 26 26
C7 85 ?? ?? ?? ?? 20 6E 65 74
C7 85 ?? ?? ?? ?? 20 6C 6F 63
C7 85 ?? ?? ?? ?? 61 6C 67 72
C7 85 ?? ?? ?? ?? 6F 75 70 20
C7 85 ?? ?? ?? ?? 61 64 6D 69
C7 85 ?? ?? ?? ?? 6E 69 73 74
C7 85 ?? ?? ?? ?? 72 61 74 6F
C7 85 ?? ?? ?? ?? 72 73 20 63
C7 85 ?? ?? ?? ?? 65 73 73 75
C7 85 ?? ?? ?? ?? 70 70 6F 72
C7 85 ?? ?? ?? ?? 74 20 2F 61
C7 85 ?? ?? ?? ?? 64 64 22 00
6A 5C

}

/*

0x41be22L C745D057696E45                mov dword ptr [ebp - 0x30], 0x456e6957
0x41be29L C745D478656300                mov dword ptr [ebp - 0x2c], 0x636578
0x41be30L C7459C47657450                mov dword ptr [ebp - 0x64], 0x50746547
0x41be37L C745A0726F6341                mov dword ptr [ebp - 0x60], 0x41636f72
0x41be3eL C745A464647265                mov dword ptr [ebp - 0x5c], 0x65726464
0x41be45L C745A873730000                mov dword ptr [ebp - 0x58], 0x7373
0x41be4cL C745C443726561                mov dword ptr [ebp - 0x3c], 0x61657243
0x41be53L C745C874654669                mov dword ptr [ebp - 0x38], 0x69466574
0x41be5aL C745CC6C654100                mov dword ptr [ebp - 0x34], 0x41656c
0x41be61L C745B857726974                mov dword ptr [ebp - 0x48], 0x74697257
0x41be68L C745BC6546696C                mov dword ptr [ebp - 0x44], 0x6c694665
0x41be6fL C745C065000000                mov dword ptr [ebp - 0x40], 0x65
0x41be76L C745AC436C6F73                mov dword ptr [ebp - 0x54], 0x736f6c43
0x41be7dL C745B06548616E                mov dword ptr [ebp - 0x50], 0x6e614865
0x41be84L C745B4646C6500                mov dword ptr [ebp - 0x4c], 0x656c64
0x41be8bL 894DE8                        mov dword ptr [ebp - 0x18], ecx

*/

$chunk_3 = {

C7 45 ?? 57 69 6E 45
C7 45 ?? 78 65 63 00
C7 45 ?? 47 65 74 50
C7 45 ?? 72 6F 63 41
C7 45 ?? 64 64 72 65
C7 45 ?? 73 73 00 00
C7 45 ?? 43 72 65 61
C7 45 ?? 74 65 46 69
C7 45 ?? 6C 65 41 00
C7 45 ?? 57 72 69 74
C7 45 ?? 65 46 69 6C
C7 45 ?? 65 00 00 00
C7 45 ?? 43 6C 6F 73
C7 45 ?? 65 48 61 6E
C7 45 ?? 64 6C 65 00
89 4D ??

}


   condition:
       any of them
}
