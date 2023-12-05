
rule APT_NK_Lazarus_RC4_Loop {
   meta: 
      author = "f-secure "
      description = "Detects RC4 loop in Lazarus Group implant" 
      date = "2020-06-10"
      reference = "https://labs.f-secure.com/publications/ti-report-lazarus-group-cryptocurrency-vertical"
      id = "a9503795-b4b8-505e-a1bf-df64ec8c1c32"
   strings:
      $str_rc4_loop = { 41 FE 8? 00 01 00 00 45 0F B6 ?? 00 01 00 00 48 
                        FF C? 43 0F B6 0? ?? 41 00 8? 01 01 00 00 41 0F 
                        B6 ?? 01 01 00 00 }
   condition:
      int16(0) == 0x5a4d and filesize < 3000KB and $str_rc4_loop
}

rule APT_NK_Lazarus_Network_Backdoor_Unpacked {
   meta:
      author = "f-secure"
      description = "Detects unpacked variant of Lazarus Group network backdoor" 
      date = "2020-06-10"      
      reference = "https://labs.f-secure.com/publications/ti-report-lazarus-group-cryptocurrency-vertical"
      id = "8eda9e74-1a19-5510-82d8-cd2eb324629c"
   strings:
      $str_netsh_1 = "netsh firewall add portopening TCP %d" ascii wide nocase 
      $str_netsh_2 = "netsh firewall delete portopening TCP %d" ascii wide nocase 
      $str_mask_1 = "cmd.exe /c \"%s >> %s 2>&1\"" ascii wide
      $str_mask_2 = "cmd.exe /c \"%s 2>> %s\"" ascii wide 
      $str_mask_3 = "%s\\%s\\%s" ascii wide
      $str_other_1 = "perflog.dat" ascii wide nocase 
      $str_other_2 = "perflog.evt" ascii wide nocase 
      $str_other_3 = "cbstc.log" ascii wide nocase 
      $str_other_4 = "LdrGetProcedureAddress" ascii 
      $str_other_5 = "NtProtectVirtualMemory" ascii
   condition:
      int16(0) == 0x5a4d
      and filesize < 3000KB
      and 1 of ($str_netsh*)
      and 1 of ($str_mask*)
      and 1 of ($str_other*)
}

