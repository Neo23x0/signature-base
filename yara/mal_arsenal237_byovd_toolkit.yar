/*
   Yara Rule Set
   Identifier: Arsenal-237 BYOVD Toolkit (BdApiUtil64.sys, killer.dll, lpe.exe, rootkit.dll)
   Author: The Hunters Ledger
   Source: https://pixelatedcontinuum.github.io/Threat-Intel-Reports/
   License: CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/
*/

rule Arsenal237_BdApiUtil_Signature {
   meta:
      description = "Detects BdApiUtil64.sys by Baidu signature strings and PDB path - BYOVD with legitimate expired certificate"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/arsenal-237-BdApiUtil64-sys/"
      date = "2026-01-26"
      family = "Arsenal-237"
      id = "4664f9f5-adfc-578e-a849-4d8bb31d97f2"
   strings:
      $pdb = "D:\\jenkins\\workspace\\bav_5.0_workspace\\BavOutput\\Pdb\\Release\\BdApiUtil64.pdb" ascii wide
      $signer = "Baidu Online Network Technology" ascii wide
      $product = "Baidu Antivirus" ascii wide
      $device = "\\Device\\BdApiUtil" ascii wide
      $service = "Bprotect" ascii wide
      $callback = "bdProtectExpCallBack" ascii wide
   condition:
      uint16(0) == 0x5A4D and
      uint32(uint32(0x3C)) == 0x00004550 and
      (2 of ($*))
}

rule Arsenal237_BdApiUtil_IOCTL_Abuse {
   meta:
      description = "Detects malware using BdApiUtil64.sys IOCTL codes for process termination and SSDT bypass"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/arsenal-237-BdApiUtil64-sys/"
      date = "2026-01-26"
      family = "Arsenal-237"
      id = "ade3b9f5-c841-5cf8-8266-a95ea8f4956d"
   strings:
      $ioctl1 = { B4 24 00 80 }
      $ioctl2 = { B8 24 00 80 }
      $ioctl3 = { 24 23 00 80 }
      $ioctl4 = { 48 26 00 80 }
      $ioctl5 = { 4C 26 00 80 }
      $api = "DeviceIoControl" ascii wide
      $device = "\\\\.\\BdApiUtil" ascii wide
   condition:
      uint16(0) == 0x5A4D and
      $api and $device and
      2 of ($ioctl*)
}

rule Arsenal237_BdApiUtil_SSDT_Bypass {
   meta:
      description = "Detects SSDT bypass implementation using KeServiceDescriptorTable resolution via BdApiUtil64.sys"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/arsenal-237-BdApiUtil64-sys/"
      date = "2026-01-26"
      family = "Arsenal-237"
      id = "cd77a3e2-7c9a-5c73-8433-bdc0cf40783c"
   strings:
      $ssdt_string = "KeServiceDescriptorTable" ascii wide
      $api1 = "MmGetSystemRoutineAddress" ascii wide
      $api2 = "RtlInitUnicodeString" ascii wide
      $hook_check = { 80 3? B8 }
      $ssdt_lookup = { 8B ?? ?? C1 E? 02 }
   condition:
      uint16(0) == 0x5A4D and
      $ssdt_string and
      all of ($api*) and
      1 of ($hook_check, $ssdt_lookup)
}

rule Arsenal237_BdApiUtil_Kernel_Termination {
   meta:
      description = "Detects kernel-mode process termination targeting security products via BdApiUtil64.sys"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/arsenal-237-BdApiUtil64-sys/"
      date = "2026-01-26"
      family = "Arsenal-237"
      id = "727bfa59-0321-5854-a6d1-b447cacc81f8"
   strings:
      $api1 = "PsLookupProcessByProcessId" ascii
      $api2 = "ZwTerminateProcess" ascii
      $api3 = "ObOpenObjectByPointer" ascii
      $api4 = "ObDereferenceObject" ascii
      $target1 = "MsMpEng.exe" ascii wide nocase
      $target2 = "CSFalconService.exe" ascii wide nocase
      $target3 = "ekrn.exe" ascii wide nocase
      $target4 = "avp.exe" ascii wide nocase
   condition:
      uint16(0) == 0x5A4D and
      3 of ($api*) and
      2 of ($target*)
}

rule Arsenal237_Killer_DLL_BYOVD_Comprehensive {
   meta:
      description = "Detects Arsenal-237 killer.dll BYOVD defense evasion module with embedded BdApiUtil64.sys and ProcExpDriver.sys for security product termination"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/arsenal-237-killer-dll/"
      date = "2026-01-25"
      hash1 = "10eb1fbb2be3a09eefb3d97112e42bb06cf029e6cac2a9fb891b8b89a25c788d"
      family = "Arsenal-237"
      id = "e2daec7c-79e6-5f1f-bf86-ae557249ae73"
   strings:
      $baidu_driver1 = "BdApiUtil64.sys" ascii wide nocase
      $baidu_driver2 = "Baidu Antivirus BdApi Driver" ascii wide
      $baidu_company = "Baidu, Inc." ascii wide
      $baidu_device = "\\\\.\\BdApiUtil" ascii wide
      $procexp_driver1 = "ProcExpDriver.sys" ascii wide nocase
      $procexp_driver2 = "PROCEXP152" ascii wide
      $procexp_company = "Sysinternals - www.sysinternals.com" ascii wide
      $procexp_device = "\\\\.\\PROCEXP152" ascii wide
      $ioctl_baidu = { B4 24 00 80 }
      $ioctl_procexp = { 3C 00 35 83 }
      $target1 = "MsMpEng.exe" ascii wide nocase
      $target2 = "ekrn.exe" ascii wide nocase
      $target3 = "avp.exe" ascii wide nocase
      $target4 = "MBAMService.exe" ascii wide nocase
      $target5 = "bdservicehost.exe" ascii wide nocase
      $svc1 = "CreateServiceW" ascii wide
      $svc2 = "StartServiceW" ascii wide
      $svc3 = "DeleteService" ascii wide
      $svc4 = "NtUnloadDriver" ascii wide
      $rust1 = "rustc" ascii
      $rust2 = "/rustc/" ascii
      $c2_ip = "109.230.231.37" ascii wide
      $export_func = "get_hostfxr_path" ascii
      $mz = { 4D 5A }
   condition:
      uint16(0) == 0x5A4D and
      (
      hash.sha256(0, filesize) == "10eb1fbb2be3a09eefb3d97112e42bb06cf029e6cac2a9fb891b8b89a25c788d" or
      (
      (#mz >= 2) and
      (2 of ($baidu_*)) and
      (2 of ($procexp_*)) and
      (1 of ($ioctl_*))
      ) or
      (
      (3 of ($target*)) and
      (2 of ($svc*)) and
      (1 of ($ioctl_*)) and
      (1 of ($baidu_*, $procexp_*))
      ) or
      (
      ($c2_ip) and
      ($export_func) and
      (1 of ($rust*)) and
      (2 of ($target*))
      )
      )
}

rule Arsenal237_Embedded_Vulnerable_Driver {
   meta:
      description = "Detects embedded BdApiUtil64.sys or ProcExpDriver.sys within files indicating BYOVD payload staging"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/arsenal-237-killer-dll/"
      date = "2026-01-25"
      family = "Arsenal-237"
      id = "6a4f6f6d-a38d-52ed-a339-fae826652b26"
   strings:
      $baidu_full1 = "\\SystemRoot\\System32\\Drivers\\BdApiUtil64.sys" ascii wide nocase
      $baidu_full2 = "Baidu Antivirus BdApi Driver" ascii wide
      $baidu_version = "5.0.3.84333" ascii wide
      $procexp_full1 = "\\SystemRoot\\System32\\Drivers\\PROCEXP152.SYS" ascii wide nocase
      $procexp_full2 = "Process Explorer" ascii wide
      $procexp_version = "17.0.7" ascii wide
      $device_baidu = "\\\\.\\BdApiUtil" ascii wide
      $device_procexp = "\\\\.\\PROCEXP152" ascii wide
      $mz = { 4D 5A }
   condition:
      #mz >= 2 and
      (
      (2 of ($baidu_*)) or
      (2 of ($procexp_*)) or
      (1 of ($device_*) and #mz >= 2)
      )
}

rule Arsenal237_BYOVD_Service_Creation {
   meta:
      description = "Detects BYOVD service creation patterns for kernel driver deployment (memory scanning use case)"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/arsenal-237-killer-dll/"
      date = "2026-01-25"
      family = "Arsenal-237"
      id = "729b1f2b-6e8c-51f8-9feb-4225ab8b5f14"
   strings:
      $api1 = "OpenSCManagerW" ascii wide
      $api2 = "CreateServiceW" ascii wide
      $api3 = "StartServiceW" ascii wide
      $api4 = "ControlService" ascii wide
      $api5 = "DeleteService" ascii wide
      $kernel_driver = "SERVICE_KERNEL_DRIVER" ascii wide
      $driver_ext = ".sys" ascii wide nocase
      $temp1 = "\\AppData\\Local\\Temp\\" ascii wide nocase
      $temp2 = "\\Windows\\Temp\\" ascii wide nocase
   condition:
      uint16(0) == 0x5A4D and
      4 of ($api*) and
      $kernel_driver and
      1 of ($temp*)
}

rule Arsenal237_LPE_Token_Manipulation {
   meta:
      description = "Detects Arsenal-237 lpe.exe token impersonation API pattern targeting SYSTEM-level processes"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/arsenal-237-lpe-exe/"
      date = "2026-01-25"
      family = "Arsenal-237"
      id = "b3e63cd7-eb13-5f0d-ac24-a89c0c56aa01"
   strings:
      $api1 = "CreateToolhelp32Snapshot" ascii wide
      $api2 = "OpenProcessToken" ascii wide
      $api3 = "DuplicateTokenEx" ascii wide
      $api4 = "ImpersonateLoggedOnUser" ascii wide
      $api5 = "Process32FirstW" ascii wide
      $api6 = "Process32NextW" ascii wide
      $process1 = "winlogon.exe" ascii wide nocase
      $process2 = "lsass.exe" ascii wide nocase
      $process3 = "services.exe" ascii wide nocase
      $process4 = "csrss.exe" ascii wide nocase
   condition:
      uint16(0) == 0x5A4D and
      all of ($api*) and
      2 of ($process*)
}

rule Arsenal237_LPE_UAC_Bypass {
   meta:
      description = "Detects Arsenal-237 lpe.exe UAC bypass via fodhelper.exe registry hijack"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/arsenal-237-lpe-exe/"
      date = "2026-01-25"
      family = "Arsenal-237"
      id = "ec1c0013-93e9-5955-b94e-1cc409fe54d9"
   strings:
      $reg1 = "HKCU\\\\Software\\\\Classes\\\\ms-settings\\\\Shell\\\\Open\\\\command" ascii wide nocase
      $reg2 = "DelegateExecute" ascii wide
      $reg3 = "reg add" ascii wide nocase
      $reg4 = "fodhelper.exe" ascii wide nocase
      $reg5 = "reg delete" ascii wide nocase
   condition:
      uint16(0) == 0x5A4D and
      all of ($reg*)
}

rule Arsenal237_LPE_Named_Pipe {
   meta:
      description = "Detects Arsenal-237 lpe.exe named pipe impersonation via Print Spooler exploitation"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/arsenal-237-lpe-exe/"
      date = "2026-01-25"
      family = "Arsenal-237"
      id = "558d33dd-996c-546c-9519-c849dd4d05d9"
   strings:
      $pipe1 = "CreateNamedPipeW" ascii wide
      $pipe2 = "ImpersonateNamedPipeClient" ascii wide
      $pipe3 = "ConnectNamedPipe" ascii wide
      $pipe4 = "\\\\\\\\.\\\\pipe\\\\" ascii wide
      $pipe5 = "spoolss" ascii wide nocase
      $ps = "powershell" ascii wide nocase
      $ps_pipe = "NamedPipeClientStream" ascii wide
   condition:
      uint16(0) == 0x5A4D and
      (all of ($pipe*) or ($ps and $ps_pipe))
}

rule Arsenal237_LPE_Schtasks {
   meta:
      description = "Detects Arsenal-237 lpe.exe scheduled task escalation using schtasks.exe with SYSTEM context"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/arsenal-237-lpe-exe/"
      date = "2026-01-25"
      family = "Arsenal-237"
      id = "89cb74a1-93b5-5838-90e5-802877519e40"
   strings:
      $schtasks1 = "schtasks" ascii wide nocase
      $schtasks2 = "/create" ascii wide nocase
      $schtasks3 = "/tn" ascii wide nocase
      $schtasks4 = "/ru SYSTEM" ascii wide nocase
      $schtasks5 = "/delete" ascii wide nocase
   condition:
      uint16(0) == 0x5A4D and
      all of ($schtasks*)
}

rule Arsenal237_Rootkit_DLL_Comprehensive {
   meta:
      description = "Detects Arsenal-237 rootkit.dll Rust-compiled defense evasion framework targeting 20+ security products via BYOVD"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/arsenal-237-rootkit-dll/"
      date = "2026-01-27"
      hash1 = "e71240f26af1052172b5864cdddb78fcb990d7a96d53b7d22d19f5dfccdf9012"
      hash2 = "483feeb4e391ae64a7d54637ea71d43a17d83c71"
      hash3 = "674795d4d4ec09372904704633ea0d86"
      family = "Arsenal-237"
      id = "01bb7447-f2bd-5538-a989-582b4762f581"
   strings:
      $rust_panic = "panicked at" ascii
      $rust_runtime = "std::panicking::rust_panic" ascii
      $rust_thread = "std::thread::Builder" ascii
      $baidu_driver_1 = "BdApiUtil64.sys" wide ascii
      $baidu_driver_2 = "Baidu" wide ascii nocase
      $defender_1 = "MsMpEng.exe" wide ascii nocase
      $defender_2 = "MpCmdRun.exe" wide ascii nocase
      $defender_3 = "SecurityHealthService.exe" wide ascii nocase
      $defender_4 = "WdNisDrv.sys" wide ascii nocase
      $defender_5 = "WdFilter.sys" wide ascii nocase
      $crowdstrike_1 = "CSFalconService.exe" wide ascii nocase
      $crowdstrike_2 = "CSFalconContainer.exe" wide ascii nocase
      $crowdstrike_3 = "csagent.sys" wide ascii nocase
      $av_eset = "ekrn.exe" wide ascii nocase
      $av_kaspersky = "avp.exe" wide ascii nocase
      $av_malwarebytes = "MBAMService.exe" wide ascii nocase
      $av_symantec = "ccSvcHst.exe" wide ascii nocase
      $av_webroot = "WRSA.exe" wide ascii nocase
      $av_sophos = "SophosHealth.exe" wide ascii nocase
      $av_cylance = "CylanceSvc.exe" wide ascii nocase
      $av_sentinel = "SentinelAgent.exe" wide ascii nocase
      $analysis_1 = "procexp.exe" wide ascii nocase
      $analysis_2 = "procmon.exe" wide ascii nocase
      $analysis_3 = "Wireshark.exe" wide ascii nocase
      $analysis_4 = "x64dbg.exe" wide ascii nocase
      $analysis_5 = "volatility.exe" wide ascii nocase
      $func_dispatcher = { 48 83 EC 28 48 8B ?? 48 8B ?? 48 8B ?? 48 85 ?? 74 ?? FF D? }
      $func_thread_create = { 48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC 20 48 8B D9 }
      $api_terminate = "ZwTerminateProcess" ascii
      $api_openprocess = "OpenProcess" ascii
      $api_createthread = "CreateThread" ascii
      $api_loaddriver = "ZwLoadDriver" ascii
   condition:
      uint16(0) == 0x5A4D and
      filesize < 500KB and
      (
      (2 of ($rust_*) and 1 of ($baidu_*)) or
      (6 of ($defender_*, $crowdstrike_*, $av_*)) or
      (3 of ($analysis_*)) or
      (1 of ($func_*) and 2 of ($api_*)) or
      (1 of ($rust_*) and 3 of ($defender_*, $crowdstrike_*, $av_*) and 1 of ($func_*))
      )
}
