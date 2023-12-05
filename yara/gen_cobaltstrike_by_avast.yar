
rule Cobaltbaltstrike_RAW_Payload_dns_stager_x86
{
  meta:
    author = "Avast Threat Intel Team"
    description = "Detects CobaltStrike payloads"
    reference = "https://github.com/avast/ioc"
    id = "817c4a72-7be1-5a58-987d-fe203d7778ea"
  strings:
    // x86 default eop
    $h01 = { FC E8 89 00 00 00 60 89 E5 31 D2 64 8B 52 30 8B 52 0C 8B 52 14 8B 72 28 }
  condition:
    /*
    Payload API list:
    Offset  | Hash value  | API name
    0x00a3  | 0xe553a458  | kernel32.dll_VirtualAlloc
    0x00bd  | 0x0726774c  | kernel32.dll_LoadLibraryA
    0x012f  | 0xc99cc96a  | dnsapi.dll_DnsQuery_A
    0x0198  | 0x56a2b5f0  | kernel32.dll_ExitProcess
    0x01a4  | 0xe035f044  | kernel32.dll_Sleep
    0x01e4  | 0xcc8e00f4  | kernel32.dll_lstrlenA
    */
    uint32(@h01+0x00a3) == 0xe553a458 and
    uint32(@h01+0x00bd) == 0x0726774c and
    uint32(@h01+0x012f) == 0xc99cc96a and
    uint32(@h01+0x0198) == 0x56a2b5f0 and
    uint32(@h01+0x01a4) == 0xe035f044 and
    uint32(@h01+0x01e4) == 0xcc8e00f4
}

rule Cobaltbaltstrike_RAW_Payload_smb_stager_x86
{
  meta:
    author = "Avast Threat Intel Team"
    description = "Detects CobaltStrike payloads"
    reference = "https://github.com/avast/ioc"
    id = "29911a14-08ea-54de-9c07-630c6516bd49"
  strings:
    // x86 default eop
    $h01 = { FC E8 89 00 00 00 60 89 E5 31 D2 64 8B 52 30 8B 52 0C 8B 52 14 8B 72 28 }
  condition:
    /*
    Payload API list:
    Offset  | Hash value  | API name
    0x00a1  | 0xe553a458  | kernel32.dll_VirtualAlloc
    0x00c4  | 0xd4df7045  | kernel32.dll_CreateNamedPipeA
    0x00d2  | 0xe27d6f28  | kernel32.dll_ConnectNamedPipe
    0x00f8  | 0xbb5f9ead  | kernel32.dll_ReadFile
    0x010d  | 0xbb5f9ead  | kernel32.dll_ReadFile
    0x0131  | 0xfcddfac0  | kernel32.dll_DisconnectNamedPipe
    0x0139  | 0x528796c6  | kernel32.dll_CloseHandle
    0x014b  | 0x56a2b5f0  | kernel32.dll_ExitProcess
    */
    uint32(@h01+0x00a1) == 0xe553a458 and
    uint32(@h01+0x00c4) == 0xd4df7045 and
    uint32(@h01+0x00d2) == 0xe27d6f28 and
    uint32(@h01+0x00f8) == 0xbb5f9ead and
    uint32(@h01+0x010d) == 0xbb5f9ead and
    uint32(@h01+0x0131) == 0xfcddfac0 and
    uint32(@h01+0x0139) == 0x528796c6 and
    uint32(@h01+0x014b) == 0x56a2b5f0
}

rule Cobaltbaltstrike_RAW_Payload_TCP_Bind_x86
{
  meta:
    author = "Avast Threat Intel Team"
    description = "Detects CobaltStrike payloads"
    reference = "https://github.com/avast/ioc"
    id = "ec0a9e27-3650-5393-a93b-2a461b9a0e29"
  strings:
    // x86 default eop
    $h01 = { FC E8 89 00 00 00 60 89 E5 31 D2 64 8B 52 30 8B 52 0C 8B 52 14 8B 72 28 }
  condition:
    /*
    Payload API list:
    Offset  | Hash value  | API name
    0x009c  | 0x0726774c  | kernel32.dll_LoadLibraryA
    0x00ac  | 0x006b8029  | ws2_32.dll_WSAStartup
    0x00bb  | 0xe0df0fea  | ws2_32.dll_WSASocketA
    0x00d5  | 0x6737dbc2  | ws2_32.dll_bind
    0x00de  | 0xff38e9b7  | ws2_32.dll_listen
    0x00e8  | 0xe13bec74  | ws2_32.dll_accept
    0x00f1  | 0x614d6e75  | ws2_32.dll_closesocket
    0x00fa  | 0x56a2b5f0  | kernel32.dll_ExitProcess
    0x0107  | 0x5fc8d902  | ws2_32.dll_recv
    0x011a  | 0xe553a458  | kernel32.dll_VirtualAlloc
    0x0128  | 0x5fc8d902  | ws2_32.dll_recv
    0x013d  | 0x614d6e75  | ws2_32.dll_closesocket
    */
    uint32(@h01+0x009c) == 0x0726774c and
    uint32(@h01+0x00ac) == 0x006b8029 and
    uint32(@h01+0x00bb) == 0xe0df0fea and
    uint32(@h01+0x00d5) == 0x6737dbc2 and
    uint32(@h01+0x00de) == 0xff38e9b7 and
    uint32(@h01+0x00e8) == 0xe13bec74 and
    uint32(@h01+0x00f1) == 0x614d6e75 and
    uint32(@h01+0x00fa) == 0x56a2b5f0 and
    uint32(@h01+0x0107) == 0x5fc8d902 and
    uint32(@h01+0x011a) == 0xe553a458 and
    uint32(@h01+0x0128) == 0x5fc8d902 and
    uint32(@h01+0x013d) == 0x614d6e75
}

rule Cobaltbaltstrike_RAW_Payload_TCP_Bind_x64
{
  meta:
    author = "Avast Threat Intel Team"
    description = "Detects CobaltStrike payloads"
    reference = "https://github.com/avast/ioc"
    id = "3575408a-3309-5723-a49a-9c2088d43de9"
  strings:
    // x64 default eop
    $h01 = { FC 48 83 E4 F0 E8 C8 00 00 00 41 51 41 50 52 51 56 48 31 D2 65 48 8B 52 }
  condition:
    /*
    Payload API list:
    Offset  | Hash value  | API name
    0x0100  | 0x0726774c  | kernel32.dll_LoadLibraryA
    0x0111  | 0x006b8029  | ws2_32.dll_WSAStartup
    0x012d  | 0xe0df0fea  | ws2_32.dll_WSASocketA
    0x0142  | 0x6737dbc2  | ws2_32.dll_bind
    0x0150  | 0xff38e9b7  | ws2_32.dll_listen
    0x0161  | 0xe13bec74  | ws2_32.dll_accept
    0x016f  | 0x614d6e75  | ws2_32.dll_closesocket
    0x0198  | 0x5fc8d902  | ws2_32.dll_recv
    0x01b8  | 0xe553a458  | kernel32.dll_VirtualAlloc
    0x01d2  | 0x5fc8d902  | ws2_32.dll_recv
    0x01ee  | 0x614d6e75  | ws2_32.dll_closesocket
    */
    uint32(@h01+0x0100) == 0x0726774c and
    uint32(@h01+0x0111) == 0x006b8029 and
    uint32(@h01+0x012d) == 0xe0df0fea and
    uint32(@h01+0x0142) == 0x6737dbc2 and
    uint32(@h01+0x0150) == 0xff38e9b7 and
    uint32(@h01+0x0161) == 0xe13bec74 and
    uint32(@h01+0x016f) == 0x614d6e75 and
    uint32(@h01+0x0198) == 0x5fc8d902 and
    uint32(@h01+0x01b8) == 0xe553a458 and
    uint32(@h01+0x01d2) == 0x5fc8d902 and
    uint32(@h01+0x01ee) == 0x614d6e75
}

rule Cobaltbaltstrike_RAW_Payload_TCP_Reverse_x86
{
  meta:
    author = "Avast Threat Intel Team"
    description = "Detects CobaltStrike payloads"
    reference = "https://github.com/avast/ioc"
    id = "ac824189-614d-5bff-9bbb-a4244cace563"
  strings:
    // x86 default eop
    $h01 = { FC E8 89 00 00 00 60 89 E5 31 D2 64 8B 52 30 8B 52 0C 8B 52 14 8B 72 28 }
  condition:
    /*
    Payload API list:
    Offset  | Hash value  | API name
    0x009c  | 0x0726774c  | kernel32.dll_LoadLibraryA
    0x00ac  | 0x006b8029  | ws2_32.dll_WSAStartup
    0x00bb  | 0xe0df0fea  | ws2_32.dll_WSASocketA
    0x00d5  | 0x6174a599  | ws2_32.dll_connect
    0x00e5  | 0x56a2b5f0  | kernel32.dll_ExitProcess
    0x00f2  | 0x5fc8d902  | ws2_32.dll_recv
    0x0105  | 0xe553a458  | kernel32.dll_VirtualAlloc
    0x0113  | 0x5fc8d902  | ws2_32.dll_recv
    */
    uint32(@h01+0x009c) == 0x0726774c and
    uint32(@h01+0x00ac) == 0x006b8029 and
    uint32(@h01+0x00bb) == 0xe0df0fea and
    uint32(@h01+0x00d5) == 0x6174a599 and
    uint32(@h01+0x00e5) == 0x56a2b5f0 and
    uint32(@h01+0x00f2) == 0x5fc8d902 and
    uint32(@h01+0x0105) == 0xe553a458 and
    uint32(@h01+0x0113) == 0x5fc8d902
}

rule Cobaltbaltstrike_RAW_Payload_TCP_Reverse_x64
{
  meta:
    author = "Avast Threat Intel Team"
    description = "Detects CobaltStrike payloads"
    reference = "https://github.com/avast/ioc"
    id = "21151a9c-1d15-514f-b33b-c9eff08463fb"
  strings:
    // x64 default eop
    $h01 = { FC 48 83 E4 F0 E8 C8 00 00 00 41 51 41 50 52 51 56 48 31 D2 65 48 8B 52 }
  condition:
    /*
    Payload API list:
    Offset  | Hash value  | API name
    0x0100  | 0x0726774c  | kernel32.dll_LoadLibraryA
    0x0111  | 0x006b8029  | ws2_32.dll_WSAStartup
    0x012d  | 0xe0df0fea  | ws2_32.dll_WSASocketA
    0x0142  | 0x6174a599  | ws2_32.dll_connect
    0x016b  | 0x5fc8d902  | ws2_32.dll_recv
    0x018b  | 0xe553a458  | kernel32.dll_VirtualAlloc
    0x01a5  | 0x5fc8d902  | ws2_32.dll_recv
    0x01c1  | 0x614d6e75  | ws2_32.dll_closesocket
    */
    uint32(@h01+0x0100) == 0x0726774c and
    uint32(@h01+0x0111) == 0x006b8029 and
    uint32(@h01+0x012d) == 0xe0df0fea and
    uint32(@h01+0x0142) == 0x6174a599 and
    uint32(@h01+0x016b) == 0x5fc8d902 and
    uint32(@h01+0x018b) == 0xe553a458 and
    uint32(@h01+0x01a5) == 0x5fc8d902 and
    uint32(@h01+0x01c1) == 0x614d6e75
}

rule Cobaltbaltstrike_RAW_Payload_http_stager_x86
{
  meta:
    author = "Avast Threat Intel Team"
    description = "Detects CobaltStrike payloads"
    reference = "https://github.com/avast/ioc"
    id = "01f89b14-55f2-5a5e-b0d5-6bca609621fe"
  strings:
    // x86 default eop
    $h01 = { FC E8 89 00 00 00 60 89 E5 31 D2 64 8B 52 30 8B 52 0C 8B 52 14 8B 72 28 }
  condition:
    /*
    Payload API list:
    Offset  | Hash value  | API name
    0x009c  | 0x0726774c  | kernel32.dll_LoadLibraryA
    0x00aa  | 0xa779563a  | wininet.dll_InternetOpenA
    0x00c6  | 0xc69f8957  | wininet.dll_InternetConnectA
    0x00de  | 0x3b2e55eb  | wininet.dll_HttpOpenRequestA
    0x00f2  | 0x7b18062d  | wininet.dll_HttpSendRequestA
    0x010b  | 0x5de2c5aa  | kernel32.dll_GetLastError
    0x0114  | 0x315e2145  | user32.dll_GetDesktopWindow
    0x0123  | 0x0be057b7  | wininet.dll_InternetErrorDlg
    0x02c4  | 0x56a2b5f0  | kernel32.dll_ExitProcess
    0x02d8  | 0xe553a458  | kernel32.dll_VirtualAlloc
    0x02f3  | 0xe2899612  | wininet.dll_InternetReadFile
    */
    uint32(@h01+0x009c) == 0x0726774c and
    uint32(@h01+0x00aa) == 0xa779563a and
    uint32(@h01+0x00c6) == 0xc69f8957 and
    uint32(@h01+0x00de) == 0x3b2e55eb and
    uint32(@h01+0x00f2) == 0x7b18062d and
    uint32(@h01+0x010b) == 0x5de2c5aa and
    uint32(@h01+0x0114) == 0x315e2145 and
    uint32(@h01+0x0123) == 0x0be057b7 and
    uint32(@h01+0x02c4) == 0x56a2b5f0 and
    uint32(@h01+0x02d8) == 0xe553a458 and
    uint32(@h01+0x02f3) == 0xe2899612
}

rule Cobaltbaltstrike_RAW_Payload_http_stager_x64
{
  meta:
    author = "Avast Threat Intel Team"
    description = "Detects CobaltStrike payloads"
    reference = "https://github.com/avast/ioc"
    id = "7eeeb2a1-4903-5649-ae30-fd43367ab468"
  strings:
    // x64 default eop
    $h01 = { FC 48 83 E4 F0 E8 C8 00 00 00 41 51 41 50 52 51 56 48 31 D2 65 48 8B 52 }
  condition:
    /*
    Payload API list:
    Offset  | Hash value  | API name
    0x00e9  | 0x0726774c  | kernel32.dll_LoadLibraryA
    0x0101  | 0xa779563a  | wininet.dll_InternetOpenA
    0x0120  | 0xc69f8957  | wininet.dll_InternetConnectA
    0x013f  | 0x3b2e55eb  | wininet.dll_HttpOpenRequestA
    0x0163  | 0x7b18062d  | wininet.dll_HttpSendRequestA
    0x0308  | 0x56a2b5f0  | kernel32.dll_ExitProcess
    0x0324  | 0xe553a458  | kernel32.dll_VirtualAlloc
    0x0342  | 0xe2899612  | wininet.dll_InternetReadFile
    */
    uint32(@h01+0x00e9) == 0x0726774c and
    uint32(@h01+0x0101) == 0xa779563a and
    uint32(@h01+0x0120) == 0xc69f8957 and
    uint32(@h01+0x013f) == 0x3b2e55eb and
    uint32(@h01+0x0163) == 0x7b18062d and
    uint32(@h01+0x0308) == 0x56a2b5f0 and
    uint32(@h01+0x0324) == 0xe553a458 and
    uint32(@h01+0x0342) == 0xe2899612
}


rule Cobaltbaltstrike_RAW_Payload_https_stager_x86
{
  meta:
    author = "Avast Threat Intel Team"
    description = "Detects CobaltStrike payloads"
    reference = "https://github.com/avast/ioc"
    id = "f1d7e939-92b5-5441-8014-b2390854d059"
  strings:
    // x86 default eop
    $h01 = { FC E8 89 00 00 00 60 89 E5 31 D2 64 8B 52 30 8B 52 0C 8B 52 14 8B 72 28 }
  condition:
    /*
    Payload API list:
    Offset  | Hash value  | API name
    0x009c  | 0x0726774c  | kernel32.dll_LoadLibraryA
    0x00af  | 0xa779563a  | wininet.dll_InternetOpenA
    0x00cb  | 0xc69f8957  | wininet.dll_InternetConnectA
    0x00e7  | 0x3b2e55eb  | wininet.dll_HttpOpenRequestA
    0x0100  | 0x869e4675  | wininet.dll_InternetSetOptionA
    0x0110  | 0x7b18062d  | wininet.dll_HttpSendRequestA
    0x0129  | 0x5de2c5aa  | kernel32.dll_GetLastError
    0x0132  | 0x315e2145  | user32.dll_GetDesktopWindow
    0x0141  | 0x0be057b7  | wininet.dll_InternetErrorDlg
    0x02e9  | 0x56a2b5f0  | kernel32.dll_ExitProcess
    0x02fd  | 0xe553a458  | kernel32.dll_VirtualAlloc
    0x0318  | 0xe2899612  | wininet.dll_InternetReadFile
    */
    uint32(@h01+0x009c) == 0x0726774c and
    uint32(@h01+0x00af) == 0xa779563a and
    uint32(@h01+0x00cb) == 0xc69f8957 and
    uint32(@h01+0x00e7) == 0x3b2e55eb and
    uint32(@h01+0x0100) == 0x869e4675 and
    uint32(@h01+0x0110) == 0x7b18062d and
    uint32(@h01+0x0129) == 0x5de2c5aa and
    uint32(@h01+0x0132) == 0x315e2145 and
    uint32(@h01+0x0141) == 0x0be057b7 and
    uint32(@h01+0x02e9) == 0x56a2b5f0 and
    uint32(@h01+0x02fd) == 0xe553a458 and
    uint32(@h01+0x0318) == 0xe2899612
}


rule Cobaltbaltstrike_RAW_Payload_https_stager_x64
{
  meta:
    author = "Avast Threat Intel Team"
    description = "Detects CobaltStrike payloads"
    reference = "https://github.com/avast/ioc"
    id = "5f9c7426-63be-5049-91fc-63b5c29618bd"
  strings:
    // x64 default eop
    $h01 = { FC 48 83 E4 F0 E8 C8 00 00 00 41 51 41 50 52 51 56 48 31 D2 65 48 8B 52 }
  condition:
    /*
    Payload API list:
    Offset  | Hash value  | API name
    0x00e9  | 0x0726774c  | kernel32.dll_LoadLibraryA
    0x0101  | 0xa779563a  | wininet.dll_InternetOpenA
    0x0123  | 0xc69f8957  | wininet.dll_InternetConnectA
    0x0142  | 0x3b2e55eb  | wininet.dll_HttpOpenRequestA
    0x016c  | 0x869e4675  | wininet.dll_InternetSetOptionA
    0x0186  | 0x7b18062d  | wininet.dll_HttpSendRequestA
    0x032b  | 0x56a2b5f0  | kernel32.dll_ExitProcess
    0x0347  | 0xe553a458  | kernel32.dll_VirtualAlloc
    0x0365  | 0xe2899612  | wininet.dll_InternetReadFile
    */
    uint32(@h01+0x00e9) == 0x0726774c and
    uint32(@h01+0x0101) == 0xa779563a and
    uint32(@h01+0x0123) == 0xc69f8957 and
    uint32(@h01+0x0142) == 0x3b2e55eb and
    uint32(@h01+0x016c) == 0x869e4675 and
    uint32(@h01+0x0186) == 0x7b18062d and
    uint32(@h01+0x032b) == 0x56a2b5f0 and
    uint32(@h01+0x0347) == 0xe553a458 and
    uint32(@h01+0x0365) == 0xe2899612
}

rule Cobaltbaltstrike_RAW_Payload_dns_stager_x86_UTF16
{
  meta:
    author = "Avast Threat Intel Team"
    description = "Detects CobaltStrike payloads"
    reference = "https://github.com/avast/ioc"
    id = "d148ca33-b233-519d-8ba4-d389de721d15"
  strings:
    // x86 default eop utf-16
    $h01 = { FC 00 E8 00 89 00 00 00 00 00 00 00 60 00 89 00 E5 00 31 00 D2 00 64 00 8B 00 52 00 30 00 8B 00 52 00 0C 00 8B 00 52 00 14 00 8B 00 72 00 28 }
  condition:
    uint32(@h01+0x0149) == 0xe5005300 and
    uint32(@h01+0x017d) == 0x07002600 and
    uint32(@h01+0x0261) == 0xc9009c00 and
    uint32(@h01+0x0333) == 0x5600a200 and
    uint32(@h01+0x034b) == 0xe0003500 and
    uint32(@h01+0x03cb) == 0xcc008e00
}

rule Cobaltbaltstrike_RAW_Payload_smb_stager_x86_UTF16
{
  meta:
    author = "Avast Threat Intel Team"
    description = "Detects CobaltStrike payloads"
    reference = "https://github.com/avast/ioc"
    id = "d88e050f-9e6c-5349-b809-ad7dc25a79b9"
  strings:
    // x86 default eop utf-16
    $h01 = { FC 00 E8 00 89 00 00 00 00 00 00 00 60 00 89 00 E5 00 31 00 D2 00 64 00 8B 00 52 00 30 00 8B 00 52 00 0C 00 8B 00 52 00 14 00 8B 00 72 00 28 }
  condition:
    uint32(@h01+0x0145) == 0xe5005300 and
    uint32(@h01+0x018b) == 0xd400df00 and
    uint32(@h01+0x01a7) == 0xe2007d00 and
    uint32(@h01+0x01f3) == 0xbb005f00 and
    uint32(@h01+0x021d) == 0xbb005f00 and
    uint32(@h01+0x0265) == 0xfc00dd00 and
    uint32(@h01+0x0275) == 0x52008700 and
    uint32(@h01+0x0299) == 0x5600a200
}

rule Cobaltbaltstrike_RAW_Payload_TCP_Bind_x86_UTF16
{
  meta:
    author = "Avast Threat Intel Team"
    description = "Detects CobaltStrike payloads"
    reference = "https://github.com/avast/ioc"
    id = "7f17985d-b245-5e95-9b35-af669aafc263"
  strings:
    // x86 default eop utf-16
    $h01 = { FC 00 E8 00 89 00 00 00 00 00 00 00 60 00 89 00 E5 00 31 00 D2 00 64 00 8B 00 52 00 30 00 8B 00 52 00 0C 00 8B 00 52 00 14 00 8B 00 72 00 28 }
  condition:
    uint32(@h01+0x013b) == 0x07002600 and
    uint32(@h01+0x015b) == 0x00006b00 and
    uint32(@h01+0x0179) == 0xe000df00 and
    uint32(@h01+0x01ad) == 0x67003700 and
    uint32(@h01+0x01bf) == 0xff003800 and
    uint32(@h01+0x01d3) == 0xe1003b00 and
    uint32(@h01+0x01e5) == 0x61004d00 and
    uint32(@h01+0x01f7) == 0x5600a200 and
    uint32(@h01+0x0211) == 0x5f00c800 and
    uint32(@h01+0x0237) == 0xe5005300 and
    uint32(@h01+0x0253) == 0x5f00c800 and
    uint32(@h01+0x027d) == 0x61004d00
}

rule Cobaltbaltstrike_RAW_Payload_TCP_Bind_x64_UTF16
{
  meta:
    author = "Avast Threat Intel Team"
    description = "Detects CobaltStrike payloads"
    reference = "https://github.com/avast/ioc"
    id = "bd52fb44-379a-5c82-9c7c-b10c8080b53f"
  strings:
    // x64 default eop utf16
    $h01 = { FC 00 48 00 83 00 E4 00 F0 00 E8 00 C8 00 00 00 00 00 00 00 41 00 51 00 41 00 50 00 52 00 51 00 56 00 48 00 31 00 D2 00 65 00 48 00 8B 00 52 }
  condition:
    uint32(@h01+0x0203) == 0x07002600 and
    uint32(@h01+0x0225) == 0x00006b00 and
    uint32(@h01+0x025d) == 0xe000df00 and
    uint32(@h01+0x0287) == 0x67003700 and
    uint32(@h01+0x02a3) == 0xff003800 and
    uint32(@h01+0x02c5) == 0xe1003b00 and
    uint32(@h01+0x02e1) == 0x61004d00 and
    uint32(@h01+0x0333) == 0x5f00c800 and
    uint32(@h01+0x0373) == 0xe5005300 and
    uint32(@h01+0x03a7) == 0x5f00c800 and
    uint32(@h01+0x03df) == 0x61004d00
}

rule Cobaltbaltstrike_RAW_Payload_TCP_Reverse_x86_UTF16
{
  meta:
    author = "Avast Threat Intel Team"
    description = "Detects CobaltStrike payloads"
    reference = "https://github.com/avast/ioc"
    id = "321c1f3f-b7fc-5408-b460-6aa4423d381c"
  strings:
    // x86 default eop utf-16
    $h01 = { FC 00 E8 00 89 00 00 00 00 00 00 00 60 00 89 00 E5 00 31 00 D2 00 64 00 8B 00 52 00 30 00 8B 00 52 00 0C 00 8B 00 52 00 14 00 8B 00 72 00 28 }
  condition:
    uint32(@h01+0x013b) == 0x07002600 and
    uint32(@h01+0x015b) == 0x00006b00 and
    uint32(@h01+0x0179) == 0xe000df00 and
    uint32(@h01+0x01ad) == 0x61007400 and
    uint32(@h01+0x01cd) == 0x5600a200 and
    uint32(@h01+0x01e7) == 0x5f00c800 and
    uint32(@h01+0x020d) == 0xe5005300 and
    uint32(@h01+0x0229) == 0x5f00c800
}

rule Cobaltbaltstrike_RAW_Payload_TCP_Reverse_x64_UTF16
{
  meta:
    author = "Avast Threat Intel Team"
    description = "Detects CobaltStrike payloads"
    reference = "https://github.com/avast/ioc"
    id = "1cc2494c-1f39-5a72-93af-c267eaf768fe"
  strings:
    // x64 default eop utf16
    $h01 = { FC 00 48 00 83 00 E4 00 F0 00 E8 00 C8 00 00 00 00 00 00 00 41 00 51 00 41 00 50 00 52 00 51 00 56 00 48 00 31 00 D2 00 65 00 48 00 8B 00 52 }
  condition:
    uint32(@h01+0x0203) == 0x07002600 and
    uint32(@h01+0x0225) == 0x00006b00 and
    uint32(@h01+0x025d) == 0xe000df00 and
    uint32(@h01+0x0287) == 0x61007400 and
    uint32(@h01+0x02d9) == 0x5f00c800 and
    uint32(@h01+0x0319) == 0xe5005300 and
    uint32(@h01+0x034d) == 0x5f00c800 and
    uint32(@h01+0x0385) == 0x61004d00
}

rule Cobaltbaltstrike_RAW_Payload_http_stager_x86_UTF16
{
  meta:
    author = "Avast Threat Intel Team"
    description = "Detects CobaltStrike payloads"
    reference = "https://github.com/avast/ioc"
    id = "c1602e85-5b42-5005-a6d1-7140cb57a3c7"
  strings:
    // x86 default eop utf-16
    $h01 = { FC 00 E8 00 89 00 00 00 00 00 00 00 60 00 89 00 E5 00 31 00 D2 00 64 00 8B 00 52 00 30 00 8B 00 52 00 0C 00 8B 00 52 00 14 00 8B 00 72 00 28 }
  condition:
    uint32(@h01+0x013b) == 0x07002600 and
    uint32(@h01+0x0157) == 0xa7007900 and
    uint32(@h01+0x018f) == 0xc6009f00 and
    uint32(@h01+0x01bf) == 0x3b002e00 and
    uint32(@h01+0x01e7) == 0x7b001800 and
    uint32(@h01+0x0219) == 0x5d00e200 and
    uint32(@h01+0x022b) == 0x31005e00 and
    uint32(@h01+0x0249) == 0x0b00e000 and
    uint32(@h01+0x058b) == 0x5600a200 and
    uint32(@h01+0x05b3) == 0xe5005300 and
    uint32(@h01+0x05e9) == 0xe2008900
}

rule Cobaltbaltstrike_RAW_Payload_http_stager_x64_UTF16
{
  meta:
    author = "Avast Threat Intel Team"
    description = "Detects CobaltStrike payloads"
    reference = "https://github.com/avast/ioc"
    id = "78672e3b-6f76-573a-8a9a-610334baa389"
  strings:
    // x64 default eop utf16
    $h01 = { FC 00 48 00 83 00 E4 00 F0 00 E8 00 C8 00 00 00 00 00 00 00 41 00 51 00 41 00 50 00 52 00 51 00 56 00 48 00 31 00 D2 00 65 00 48 00 8B 00 52 }
  condition:
    uint32(@h01+0x01d5) == 0x07002600 and
    uint32(@h01+0x0205) == 0xa7007900 and
    uint32(@h01+0x0243) == 0xc6009f00 and
    uint32(@h01+0x0281) == 0x3b002e00 and
    uint32(@h01+0x02c9) == 0x7b001800 and
    uint32(@h01+0x0613) == 0x5600a200 and
    uint32(@h01+0x064b) == 0xe5005300 and
    uint32(@h01+0x0687) == 0xe2008900
}

rule Cobaltbaltstrike_RAW_Payload_https_stager_x86_UTF16
{
  meta:
    author = "Avast Threat Intel Team"
    description = "Detects CobaltStrike payloads"
    reference = "https://github.com/avast/ioc"
    id = "dcd3e5c8-7626-5a78-9f90-7a8e67311d90"
  strings:
    // x86 default eop utf-16
    $h01 = { FC 00 E8 00 89 00 00 00 00 00 00 00 60 00 89 00 E5 00 31 00 D2 00 64 00 8B 00 52 00 30 00 8B 00 52 00 0C 00 8B 00 52 00 14 00 8B 00 72 00 28 }
  condition:
    uint32(@h01+0x013b) == 0x07002600 and
    uint32(@h01+0x0161) == 0xa7007900 and
    uint32(@h01+0x0199) == 0xc6009f00 and
    uint32(@h01+0x01d1) == 0x3b002e00 and
    uint32(@h01+0x0203) == 0x86009e00 and
    uint32(@h01+0x0223) == 0x7b001800 and
    uint32(@h01+0x0255) == 0x5d00e200 and
    uint32(@h01+0x0267) == 0x31005e00 and
    uint32(@h01+0x0285) == 0x0b00e000 and
    uint32(@h01+0x05d5) == 0x5600a200 and
    uint32(@h01+0x05fd) == 0xe5005300 and
    uint32(@h01+0x0633) == 0xe2008900
}

rule Cobaltbaltstrike_RAW_Payload_https_stager_x64_UTF16
{
  meta:
    author = "Avast Threat Intel Team"
    description = "Detects CobaltStrike payloads"
    reference = "https://github.com/avast/ioc"
    id = "aa93dd56-9589-5958-9711-ca2f9c763665"
  strings:
    // x64 default eop utf-16
    $h01 = { FC 00 48 00 83 00 E4 00 F0 00 E8 00 C8 00 00 00 00 00 00 00 41 00 51 00 41 00 50 00 52 00 51 00 56 00 48 00 31 00 D2 00 65 00 48 00 8B 00 52 }
  condition:
    uint32(@h01+0x01d5) == 0x07002600 and
    uint32(@h01+0x0205) == 0xa7007900 and
    uint32(@h01+0x0249) == 0xc6009f00 and
    uint32(@h01+0x0287) == 0x3b002e00 and
    uint32(@h01+0x02db) == 0x86009e00 and
    uint32(@h01+0x030f) == 0x7b001800 and
    uint32(@h01+0x0659) == 0x5600a200 and
    uint32(@h01+0x0691) == 0xe5005300 and
    uint32(@h01+0x06cd) == 0xe2008900
}

rule Cobaltbaltstrike_Payload_Encoded
{
  meta:
    author = "Avast Threat Intel Team"
    description = "Detects CobaltStrike payloads"
    reference = "https://github.com/avast/ioc"
    id = "b5176740-2dda-5e5d-8c0f-47a27846753d"
  strings:
    // x86 array
    $s01 = "0xfc, 0xe8, 0x89, 0x00, 0x00, 0x00, 0x60, 0x89, 0xe5, 0x31, 0xd2, 0x64, 0x8b, 0x52, 0x30, 0x8b" ascii wide nocase
    $s02 = "0xfc,0xe8,0x89,0x00,0x00,0x00,0x60,0x89,0xe5,0x31,0xd2,0x64,0x8b,0x52,0x30,0x8b" ascii wide nocase
    // x64 array
    $s03 = "0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc8, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51" ascii wide nocase
    $s04 = "0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc8,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51" ascii wide nocase
    // x86 hex
    $s05 = "fce8890000006089e531d2648b52308b" ascii wide nocase
    $s06 = "fc e8 89 00 00 00 60 89 e5 31 d2 64 8b 52 30 8b" ascii wide nocase
    // x64 hex
    $s07 = "fc4883e4f0e8c8000000415141505251" ascii wide nocase
    $s08 = "fc 48 83 e4 f0 e8 c8 00 00 00 41 51 41 50 52 51" ascii wide nocase
    // x86 base64
    $s09 = "/OiJAAAAYInlMdJki1Iwi1IMi1IUi3IoD7dKJjH/McCsPGF8Aiwgwc8NAcfi8FJX" ascii wide
    // x64 base64
    $s10 = "/EiD5PDoyAAAAEFRQVBSUVZIMdJlSItSYEiLUhhIi1IgSItyUEgPt0pKTTHJSDHA" ascii wide
    // x86 base64 + xor 0x23
    $s11 = "38uqIyMjQ6rGEvFHqHETqHEvqHE3qFELLJRpBRLcEuOPH0JfIQ8D4uwuIuTB03F0" ascii wide
    // x64 base64 + xor 0x23
    $s12 = "32ugx9PL6yMjI2JyYnNxcnVrEvFGa6hxQ2uocTtrqHEDa6hRc2sslGlpbhLqaxLj" ascii wide
    // x86 base64 utf16
    $s13 = "/ADoAIkAAAAAAAAAYACJAOUAMQDSAGQAiwBSADAAiwBSAAwAiwBSABQAiwByACg" ascii wide
    // x64 base64 utf16
    $s14 = "/ABIAIMA5ADwAOgAyAAAAAAAAABBAFEAQQBQAFIAUQBWAEgAMQDSAGUASACLAFI" ascii wide
    // x86 base64 + xor 0x23 utf16
    $s15 = "3yPLI6ojIyMjIyMjQyOqI8YjEiPxI0cjqCNxIxMjqCNxIy8jqCNxIzcjqCNRIwsj" ascii wide
    // x64 base64 + xor 0x23 utf16
    $s16 = "3yNrI6AjxyPTI8sj6yMjIyMjIyNiI3IjYiNzI3EjciN1I2sjEiPxI0YjayOoI3Ej" ascii wide
    // x86 vba
    $s17 = "Array(-4,-24,-119,0,0,0,96,-119,-27,49,-46,100,-117,82,48,-117" ascii wide
    $s18 = "Array(-4, -24, -119, 0, 0, 0, 96, -119, -27, 49, -46, 100, -117, 82, 48, -117" ascii wide
    // x64 vba
    $s19 = "Array(-4,72,-125,-28,-16,-24,-56,0,0,0,65,81,65,80,82,81" ascii wide
    $s20 = "Array(-4, 72, -125, -28, -16, -24, -56, 0, 0, 0, 65, 81, 65, 80, 82, 81" ascii wide
    // x86 vbs
    $s21 = "Chr(-4)&Chr(-24)&Chr(-119)&Chr(0)&Chr(0)&Chr(0)&Chr(96)&Chr(-119)&Chr(-27)&\"1\"&Chr(-46)&\"d\"&Chr(-117)&\"R0\"&Chr(-117)" ascii wide
    // x64 vbs
    $s22 = "Chr(-4)&\"H\"&Chr(-125)&Chr(-28)&Chr(-16)&Chr(-24)&Chr(-56)&Chr(0)&Chr(0)&Chr(0)&\"AQAPRQVH" ascii wide
    // x86 veil
    $s23 = "\\xfc\\xe8\\x89\\x00\\x00\\x00\\x60\\x89\\xe5\\x31\\xd2\\x64\\x8b\\x52\\x30\\x8b" ascii wide nocase
    // x64 veil
    $s24 = "\\xfc\\x48\\x83\\xe4\\xf0\\xe8\\xc8\\x00\\x00\\x00\\x41\\x51\\x41\\x50\\x52\\x51" ascii wide nocase

  condition:
        any of them
}

rule Cobaltbaltstrike_strike_Payload_XORed
{
  meta:
    author = "Avast Threat Intel Team"
    description = "Detects CobaltStrike payloads"
    reference = "https://github.com/avast/ioc"
    id = "0e075644-e278-5c5b-bdcc-dc2d6a32ce73"
  strings:
    $h01 = { 10 ?? 00 00 ?? ?? ?? 00 ?? ?? ?? ?? 61 61 61 61 }
  condition:
    //x86 payload
    uint32be(@h01+8) ^ uint32be(@h01+16) == 0xFCE88900 or
    //x64 payload
    uint32be(@h01+8) ^ uint32be(@h01+16) == 0xFC4883E4 or
    //x86 beacon
    uint32be(@h01+8) ^ uint32be(@h01+16) == 0x4D5AE800 or
    //x64 beacon
    uint32be(@h01+8) ^ uint32be(@h01+16) == 0x4D5A4152 or
    //NOP slide
    uint32be(@h01+8) ^ uint32be(@h01+16) == 0x90909090
}

rule Cobaltbaltstrike_Beacon_x86
{
  meta:
    author = "Avast Threat Intel Team"
    description = "Detects CobaltStrike payloads"
    reference = "https://github.com/avast/ioc"
    id = "6ffaafe6-2758-53e4-b5b8-6d8350baf428"
  strings:
    // x86 default MZ header
    $h01 = { 4D 5A E8 00 00 00 00 5B 89 DF 52 45 55 89 E5 81 C3 ?? ?? ?? ?? FF D3 68 }
    // decoded config blob
    $h11 = { 00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02 ?? ?? 00 }
    // xored config blob v3
    $h12 = { 69 68 69 68 69 6B ?? ?? 69 6B 69 68 69 6B ?? ?? 69 }
    // xored config blob v4
    $h13 = { 2E 2F 2E 2F 2E 2C ?? ?? 2E 2C 2E 2F 2E 2C ?? ?? 2E }
  condition:
    $h01 and
    any of ($h1*)
}

rule Cobaltbaltstrike_Beacon_x64
{
  meta:
    author = "Avast Threat Intel Team"
    description = "Detects CobaltStrike payloads"
    reference = "https://github.com/avast/ioc"
    id = "5d6d86ec-9e05-5596-b623-30f44c6f44db"
  strings:
    // x64 default MZ header
    $h01 = { 4D 5A 41 52 55 48 89 E5 48 81 EC 20 00 00 00 48 8D 1D EA FF FF FF 48 89 }
    // decoded config blob
    $h11 = { 00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02 ?? ?? 00 }
    // xored config blob v3
    $h12 = { 69 68 69 68 69 6B ?? ?? 69 6B 69 68 69 6B ?? ?? 69 }
    // xored config blob v4
    $h13 = { 2E 2F 2E 2F 2E 2C ?? ?? 2E 2C 2E 2F 2E 2C ?? ?? 2E }
  condition:
    $h01 and
    any of ($h1*)
}

rule Cobaltbaltstrike_Beacon_Encoded
{
  meta:
    author = "Avast Threat Intel Team"
    description = "Detects CobaltStrike payloads"
    reference = "https://github.com/avast/ioc"
    id = "497e2a32-015a-5786-a6fa-de7084bfc389"
  strings:
    // x86 array
    $s01 = "0x4d, 0x5a, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x5b, 0x89, 0xdf, 0x52, 0x45, 0x55, 0x89, 0xe5, 0x81" ascii wide nocase
    $s02 = "0x4d,0x5a,0xe8,0x00,0x00,0x00,0x00,0x5b,0x89,0xdf,0x52,0x45,0x55,0x89,0xe5,0x81" ascii wide nocase
    // x64 array
    $s03 = "0x4d, 0x5a, 0x41, 0x52, 0x55, 0x48, 0x89, 0xe5, 0x48, 0x81, 0xec, 0x20, 0x00, 0x00, 0x00, 0x48" ascii wide nocase
    $s04 = "0x4d,0x5a,0x41,0x52,0x55,0x48,0x89,0xe5,0x48,0x81,0xec,0x20,0x00,0x00,0x00,0x48" ascii wide nocase
    // x86 hex
    $s05 = "4d5ae8000000005b89df52455589e581" ascii wide nocase
    $s06 = "4d 5a e8 00 00 00 00 5b 89 df 52 45 55 89 e5 81" ascii wide nocase
    // x64 hex
    $s07 = "4d5a4152554889e54881ec2000000048" ascii wide nocase
    $s08 = "4d 5a 41 52 55 48 89 e5 48 81 ec 20 00 00 00 48" ascii wide nocase
    // x86 base64
    $s09 = "TVroAAAAAFuJ31JFVYnlg" ascii wide
    // x64 base64
    $s10 = "TVpBUlVIieVIgewgAAAAS" ascii wide
    // x86 base64 + xor 0x23
    $s11 = "bnnLIyMjI3iq/HFmdqrGo" ascii wide
    // x64 base64 + xor 0x23
    $s12 = "bnlicXZrqsZros8DIyMja" ascii wide
    // x86 base64 utf16
    $s13 = "TQBaAOgAAAAAAAAAAABbAIkA3wBSAEUAVQCJAOUAg" ascii wide
    // x64 base64 utf16
    $s14 = "TQBaAEEAUgBVAEgAiQDlAEgAgQDsACAAAAAAAAAAS" ascii wide
    // x86 base64 + xor 0x23 utf16
    $s15 = "biN5I2IjcSN2I2sjqiPGI2sjoiPPIwMjIyMjIyMja" ascii wide
    // x64 base64 + xor 0x23 utf16
    $s16 = "biN5I8sjIyMjIyMjIyN4I6oj/CNxI2YjdiOqI8Yjo" ascii wide
    // x86 vba
    $s17 = "Array(77,90,-24,0,0,0,0,91,-119,-33,82,69,85,-119,-27,-127" ascii wide
    $s18 = "Array(77, 90, -24, 0, 0, 0, 0, 91, -119, -33, 82, 69, 85, -119, -27, -127" ascii wide
    // x64 vba
    $s19 = "Array(77,90,65,82,85,72,-119,-27,72,-127,-20,32,0,0,0,72" ascii wide
    $s20 = "Array(77, 90, 65, 82, 85, 72, -119, -27, 72, -127, -20, 32, 0, 0, 0, 72" ascii wide
    // x86 vbs
    $s21 = "MZ\"&Chr(-27)&Chr(0)&Chr(0)&Chr(0)&Chr(0)&Chr(91)&Chr(-119)&Chr(-33)&\"REU\"&Chr(-119)&Chr(-27)&Chr(-127)" ascii wide
    // x64 vbs
    $s22 = "MZARUH\"&Chr(-119)&Chr(-27)&\"H\"&Chr(-127)&Chr(-20)&Chr(32)&Chr(0)&Chr(0)&Chr(0)&\"H" ascii wide
    // x86 veil
    $s23 = "\\x4d\\x5a\\xe8\\x00\\x00\\x00\\x00\\x5b\\x89\\xdf\\x52\\x45\\x55\\x89\\xe5\\x81" ascii wide nocase
    // x64 veil
    $s24 = "\\x4d\\x5a\\x41\\x52\\x55\\x48\\x89\\xe5\\x48\\x81\\xec\\x20\\x00\\x00\\x00\\x48" ascii wide nocase
  condition:
        any of them
}

rule Cobaltbaltstrike_Beacon_XORed_x86
{
  meta:
    author = "Avast Threat Intel Team"
    description = "Detects CobaltStrike payloads"
    reference = "https://github.com/avast/ioc"
    id = "d93c20e6-3e01-5132-88a0-63ace507cae9"
  strings:
    // x86 xor decrypt loop
        // 52 bytes variant
        $h01 = { FC E8??000000 [0-32] EB27 ?? 8B?? 83??04 8B?? 31?? 83??04 ?? 8B?? 31?? 89?? 31?? 83??04 83??04 31?? 39?? 7402 EBEA ?? FF?? E8D4FFFFFF }
        // 56 bytes variant
        $h02 = { FC E8??000000 [0-32] EB2B ?? 8B??00 83C504 8B??00 31?? 83C504 55 8B??00 31?? 89??00 31?? 83C504 83??04 31?? 39?? 7402 EBE8 ?? FF?? E8D0FFFFFF }
    // end of xor decrypt loop
        $h11 = { 7402 EB(E8|EA) ?? FF?? E8(D0|D4)FFFFFF }
  condition:
        any of ($h0*) and (
            uint32be(@h11+12) ^ uint32be(@h11+20) == 0x4D5AE800 or
            uint32be(@h11+12) ^ uint32be(@h11+20) == 0x904D5AE8 or
            uint32be(@h11+12) ^ uint32be(@h11+20) == 0x90904D5A or
            uint32be(@h11+12) ^ uint32be(@h11+20) == 0x9090904D or
            uint32be(@h11+12) ^ uint32be(@h11+20) == 0x90909090
        )
}

rule Cobaltbaltstrike_Beacon_XORed_x64
{
  meta:
    author = "Avast Threat Intel Team"
    description = "Detects CobaltStrike payloads"
    reference = "https://github.com/avast/ioc"
    id = "15be610a-7552-5473-8da2-639220313783"
  strings:
        // x64 xor decrypt loop
    $h01 = { FC 4883E4F0 EB33 5D 8B4500 4883C504 8B4D00 31C1 4883C504 55 8B5500 31C2 895500 31D0 4883C504 83E904 31D2 39D1 7402 EBE7 58 FC 4883E4F0 FFD0 E8C8FFFFFF }
    // end of xor decrypt loop
        $h11 = { FC 4883E4F0 FFD0 E8C8FFFFFF }
  condition:
        $h01 and (
            uint32be(@h11+12) ^ uint32be(@h11+20) == 0x4D5A4152 or
            uint32be(@h11+12) ^ uint32be(@h11+20) == 0x904D5A41 or
            uint32be(@h11+12) ^ uint32be(@h11+20) == 0x90904D5A or
            uint32be(@h11+12) ^ uint32be(@h11+20) == 0x9090904D or
            uint32be(@h11+12) ^ uint32be(@h11+20) == 0x90909090
        )
}
