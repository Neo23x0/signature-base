/*
   Yara Rule Set
   Identifier: XWorm RAT (v2.x and v5.x variants)
   Author: The Hunters Ledger
   Source: https://pixelatedcontinuum.github.io/Threat-Intel-Reports/
   License: CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/
*/

rule XWorm_V5_Core_Detection {
   meta:
      description = "Detects XWorm RAT v5.x based on .NET framework imports, WebSocket C2 communication pattern, and multi-stage persistence mechanisms"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/agent-xworm-exe/"
      date = "2026-01-12"
      family = "XWorm"
      malware_type = "RAT"
      id = "0dd2b93b-5092-584a-8c56-905d92241f68"
   strings:
      $dotnet_ws = "System.Net.WebSockets" ascii wide
      $dotnet_crypto = "System.Security.Cryptography" ascii wide
      $dotnet_diag = "System.Diagnostics.Process" ascii wide
      $mscorlib = "mscorlib" ascii wide
      $xworm_mutex = "XWorm_Mutex" ascii wide nocase
      $xworm_version = "XWorm" ascii wide
      $heartbeat = "Heartbeat" ascii wide nocase
      $reconnect = "Reconnect" ascii wide nocase
      $send_async = "SendAsync" ascii wide
      $recv_async = "ReceiveAsync" ascii wide
      $websocket_state = "WebSocketState" ascii wide
      $hide_window = "ShowWindow" ascii wide
      $get_console = "GetConsoleWindow" ascii wide
      $b64 = "ToBase64String" ascii wide
      $md5_hash = "ComputeHash" ascii wide
   condition:
      uint16(0) == 0x5A4D and
      filesize < 500KB and
      $mscorlib and
      (
      ($xworm_mutex or $xworm_version) and $dotnet_ws and $heartbeat
      ) or
      (
      2 of ($dotnet_ws, $dotnet_crypto, $dotnet_diag) and
      3 of ($send_async, $recv_async, $websocket_state, $heartbeat, $reconnect) and
      1 of ($hide_window, $get_console) and
      1 of ($b64, $md5_hash)
      )
}

rule XWorm_V5_Persistence_Mechanisms {
   meta:
      description = "Detects XWorm RAT v5.x multi-stage persistence using scheduled tasks, registry run keys, and startup folder mechanisms"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/agent-xworm-exe/"
      date = "2026-01-12"
      family = "XWorm"
      malware_type = "RAT"
      id = "92a47e83-5b7b-5de7-a7b0-a3b382c11e43"
   strings:
      $schtask = "schtasks" ascii wide nocase
      $reg_run = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
      $startup = "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" ascii wide nocase
      $copy_self = "CopyFile" ascii wide
      $appdata = "\\AppData\\Roaming\\" ascii wide nocase
      $ps_bypass = "powershell" ascii wide nocase
      $execution_pol = "ExecutionPolicy" ascii wide nocase
      $bypass = "Bypass" ascii wide
   condition:
      uint16(0) == 0x5A4D and
      filesize < 500KB and
      2 of ($schtask, $reg_run, $startup) and
      ($appdata or $copy_self) and
      ($ps_bypass or ($execution_pol and $bypass))
}

rule XWorm_V5_Surveillance_Capabilities {
   meta:
      description = "Detects XWorm RAT v5.x surveillance capabilities including keylogging, clipboard monitoring, screenshot capture, and audio recording"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/agent-xworm-exe/"
      date = "2026-01-12"
      family = "XWorm"
      malware_type = "RAT"
      id = "aa62a397-84de-5365-b2b0-7af36892f71a"
   strings:
      $keylog = "GetAsyncKeyState" ascii wide
      $clipboard = "GetClipboardData" ascii wide
      $screenshot = "BitBlt" ascii wide
      $audio = "waveInOpen" ascii wide
      $webcam = "VideoCapture" ascii wide nocase
      $desktop = "GetDesktopWindow" ascii wide
      $screen_dc = "GetDC" ascii wide
   condition:
      uint16(0) == 0x5A4D and
      filesize < 500KB and
      3 of them
}

rule XWorm_RAT_V2_Family {
   meta:
      description = "Detects XWorm RAT v2.x family based on .NET WebSocket C2, AgentSec authentication secret pattern, and MD5 fingerprinting"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/agent-xworm-v2-exe/"
      date = "2026-01-12"
      family = "XWorm"
      malware_type = "RAT"
      id = "562e9937-a646-53b9-8ea2-650ff3b5bdc0"
   strings:
      $dotnet1 = "System.Net.WebSockets" ascii wide
      $dotnet2 = "System.Diagnostics.Process" ascii wide
      $dotnet3 = "System.Security.Cryptography" ascii wide
      $dotnet4 = "mscorlib" ascii wide
      $version_pattern = /2\.[0-9]\.[0-9]/ ascii wide
      $websocket = "WebSocket" ascii wide nocase
      $agent_sec = "AgentSec_" ascii wide
      $ps1 = "Get-Process" ascii wide nocase
      $ps2 = "Get-Service" ascii wide nocase
      $ps3 = "Win32_ComputerSystem" ascii wide
      $stealth1 = "ShowWindow" ascii wide
      $stealth2 = "GetConsoleWindow" ascii wide
      $encode = "ToBase64String" ascii wide
      $md5 = "MD5" ascii wide
      $hash_compute = "ComputeHash" ascii wide
   condition:
      uint16(0) == 0x5A4D and
      filesize < 500KB and
      (
      ($dotnet1 and $websocket and $agent_sec and $version_pattern) or
      (2 of ($dotnet1, $dotnet2, $dotnet3, $dotnet4) and 2 of ($ps1, $ps2, $ps3) and 1 of ($stealth1, $stealth2) and $encode) or
      ($md5 and $hash_compute and $websocket and 1 of ($ps1, $ps2, $ps3))
      )
}

rule XWorm_PowerShell_Recon {
   meta:
      description = "Detects XWorm v2.x embedded PowerShell reconnaissance command templates targeting process, service, and system information"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/agent-xworm-v2-exe/"
      date = "2026-01-12"
      family = "XWorm"
      malware_type = "RAT"
      id = "e83a762c-9592-5acf-82bb-874a6d9eb902"
   strings:
      $ps1 = "-NoP -C Get-Process|Sort CPU" ascii wide
      $ps2 = "-NoP -C Get-Service|?{$_.Status -eq" ascii wide
      $ps3 = "-NoP -C Get-WmiObject Win32_ComputerSystem" ascii wide
      $ps4 = "PartOfDomain,Domain,DomainRole" ascii wide
      $ps5 = "Select -First 20 Name,Id,CPU,WS" ascii wide
   condition:
      uint16(0) == 0x5A4D and
      3 of them
}

rule XWorm_AgentSec_Authentication {
   meta:
      description = "Detects XWorm AgentSec authentication secret naming convention used for C2 handshake authentication"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/agent-xworm-v2-exe/"
      date = "2026-01-12"
      family = "XWorm"
      malware_type = "RAT"
      id = "f01c77e9-a0ec-5671-b3f4-4d7ac2ff3117"
   strings:
      $pattern1 = /AgentSec_[0-9A-Za-z]{40,50}/ ascii wide
   condition:
      uint16(0) == 0x5A4D and
      $pattern1
}

rule XWorm_WebSocket_C2 {
   meta:
      description = "Detects .NET executables with XWorm WebSocket C2 communication pattern including heartbeat and reconnect logic"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/agent-xworm-v2-exe/"
      date = "2026-01-12"
      family = "XWorm"
      malware_type = "RAT"
      id = "a624d17c-50bd-5842-805a-750b55328d5d"
   strings:
      $ws1 = "System.Net.WebSockets" ascii wide
      $ws2 = "WebSocketState" ascii wide
      $ws3 = "SendAsync" ascii wide
      $ws4 = "ReceiveAsync" ascii wide
      $c2_1 = "Heartbeat" ascii wide nocase
      $c2_2 = "Reconnect" ascii wide nocase
      $c2_3 = "Frame" ascii wide
      $dotnet = "mscorlib" ascii wide
   condition:
      uint16(0) == 0x5A4D and
      filesize < 200KB and
      $dotnet and
      3 of ($ws1, $ws2, $ws3, $ws4) and
      2 of ($c2_1, $c2_2, $c2_3)
}
