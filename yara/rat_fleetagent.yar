/*
   Yara Rule Set
   Identifier: FleetAgent RAT Family (FUD and Advanced variants)
   Author: The Hunters Ledger
   Source: https://pixelatedcontinuum.github.io/Threat-Intel-Reports/
   License: CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/
*/

import "hash"

rule FleetAgentFUD_WebSocket_C2_Pattern {
   meta:
      description = "Detects FleetAgentFUD.exe WebSocket C2 implementation via protocol strings and message type indicators"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/fleetagentfud-exe/"
      date = "2026-01-12"
      family = "FleetAgentFUD"
      id = "b79dd451-00ab-5124-9384-ccf64b8fdc18"
   strings:
      $ws1 = "Connection: Upgrade" ascii wide
      $ws2 = "Sec-WebSocket-Key: " ascii wide
      $ws3 = "Sec-WebSocket-Version: 13" ascii wide
      $ws4 = "X-Agent-Secret: " ascii wide
      $msg1 = "\"type\":\"register\"" ascii wide nocase
      $msg2 = "\"type\":\"heartbeat\"" ascii wide nocase
      $msg3 = "machine_id" ascii wide
      $msg4 = "hostname" ascii wide
      $msg5 = "os_version" ascii wide
      $msg6 = "agent_ver" ascii wide
      $cmd1 = "cmd_type" ascii wide
      $cmd2 = "command_id" ascii wide
      $cmd3 = "powershell" ascii wide
      $cmd4 = "sysinfo" ascii wide
      $cmd5 = "clipboard" ascii wide
      $api1 = "System.Net.Sockets" ascii
      $api2 = "TcpClient" ascii
      $api3 = "NetworkStream" ascii
   condition:
      uint16(0) == 0x5A4D and
      filesize < 50KB and
      (
      (3 of ($ws*) and 3 of ($msg*)) or
      (2 of ($ws*) and 3 of ($cmd*)) or
      (all of ($ws*) and any of ($api*))
      )
}

rule FleetAgentFUD_PowerShell_Bypass {
   meta:
      description = "Detects FleetAgentFUD.exe PowerShell execution policy bypass string for clipboard theft and remote command execution"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/fleetagentfud-exe/"
      date = "2026-01-12"
      family = "FleetAgentFUD"
      id = "03b22454-8bce-562b-9c3b-019f9ae1b964"
   strings:
      $ps1 = "-NoP -NonI -W Hidden -Exec Bypass -C " ascii wide
      $ps2 = "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass" ascii wide
      $ps3 = "powershell" ascii wide nocase
      $ps4 = "Get-Clipboard" ascii wide
      $ps5 = "-Exec Bypass" ascii wide
      $ps6 = "-ExecutionPolicy Bypass" ascii wide
      $ps7 = "-W Hidden" ascii wide
   condition:
      uint16(0) == 0x5A4D and
      filesize < 100KB and
      (
      $ps1 or
      $ps2 or
      ($ps3 and ($ps5 or $ps6) and $ps7) or
      ($ps3 and $ps4 and ($ps5 or $ps6 or $ps7))
      )
}

rule FleetAgent_Family_General {
   meta:
      description = "Detects FleetAgent malware family characteristics common to FUD and Advanced variants"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/fleetagentfud-exe/"
      date = "2026-01-12"
      family = "FleetAgent"
      id = "fafd5b4a-f551-5184-9fbc-e91c369bf3aa"
   strings:
      $name1 = "FleetAgent" ascii wide fullword
      $name2 = "FleetAgentFUD" ascii wide fullword
      $name3 = "FleetAgentAdvanced" ascii wide fullword
      $ms_masquerade = "Microsoft.NET.Runtime" ascii wide
      $ver1 = "agent_ver" ascii wide fullword
      $ver2 = "3.0.0" ascii wide
      $cfg1 = "machine_id" ascii wide fullword
      $cfg2 = "hostname" ascii wide fullword
      $api1 = "VirtualProtect" ascii fullword
      $api2 = "ToBase64String" ascii fullword
      $api3 = "GetProcAddress" ascii fullword
   condition:
      uint16(0) == 0x5A4D and
      filesize < 500KB and
      (
         any of ($name1, $name2, $name3) or
         ($ver1 and $ver2 and 2 of ($cfg*)) or
         ($ms_masquerade and $ver1 and 2 of ($api*))
      )
}

rule FleetAgentAdvanced_Dropper_Core {
   meta:
      description = "Detects FleetAgentAdvanced.exe dropper with quad-persistence architecture and .NET process injection targeting AppData"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/fleetagentadvanced-exe/"
      date = "2026-01-12"
      hash1 = "172258e53b9506a7671deab25d2ad360cd833a4942609f1a4836d305ffe4578b"
      family = "FleetAgentAdvanced"
      id = "cc03bf1b-d12c-5616-94bd-67e037193ea3"
   strings:
      $func1 = "DropEmbeddedAgent" ascii wide
      $func2 = "SetPersistence" ascii wide
      $func3 = "CreateShortcut" ascii wide
      $func4 = "StartWatchdog" ascii wide
      $func5 = "RunWatchdog" ascii wide
      $func6 = "InjectIntoProcess" ascii wide
      $config1 = "EMBEDDED_AGENT" ascii wide
      $config2 = "INSTALL_NAME" ascii wide
      $config3 = "WATCHDOG_MUTEX" ascii wide
      $config4 = "AGENT_SECRET" ascii wide
      $persist1 = "RuntimeOptimization.exe" ascii wide
      $persist2 = "Microsoft .NET Runtime Optimization" ascii wide
      $persist3 = "Microsoft\\CLR" ascii wide
      $api1 = "VirtualAllocEx" ascii
      $api2 = "WriteProcessMemory" ascii
      $api3 = "CreateRemoteThread" ascii
      $api4 = "NtUnmapViewOfSection" ascii
   condition:
      uint16(0) == 0x5A4D and
      filesize < 500KB and
      (
      3 of ($func*) or
      (2 of ($config*) and any of ($persist*)) or
      (any of ($api*) and any of ($persist*)) or
      hash.sha256(0, filesize) == "172258e53b9506a7671deab25d2ad360cd833a4942609f1a4836d305ffe4578b"
      )
}

rule FleetAgentAdvanced_Quad_Persistence_Pattern {
   meta:
      description = "Detects .NET droppers with quad-persistence architecture: registry run key, startup LNK, scheduled task, and Microsoft masquerading"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/fleetagentadvanced-exe/"
      date = "2026-01-12"
      family = "FleetAgentAdvanced"
      id = "7febd710-72a2-5cf3-b2fb-f693e25527c3"
   strings:
      $reg_run = "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run" ascii wide
      $startup_folder = "\\\\Start Menu\\\\Programs\\\\Startup" ascii wide
      $schtasks = "schtasks" ascii wide nocase
      $lnk_file = ".lnk" ascii wide
      $ms_mask1 = "Microsoft" ascii wide
      $ms_mask2 = ".NET" ascii wide
      $ms_mask3 = "Runtime" ascii wide
      $ms_mask4 = "Optimization" ascii wide
   condition:
      uint16(0) == 0x5A4D and
      for any i in (0..filesize-4): (uint32(i) == 0x424A5342) and
      all of ($reg_run, $startup_folder, $schtasks, $lnk_file) and
      3 of ($ms_mask*)
}
