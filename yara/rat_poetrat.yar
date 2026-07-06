/*
   Yara Rule Set
   Identifier: PoetRAT (Golang RAT with Windows Defender masquerading)
   Author: The Hunters Ledger
   Source: https://pixelatedcontinuum.github.io/Threat-Intel-Reports/
   License: CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/
*/

rule Agent_exe_PoetRAT_Comprehensive {
   meta:
      description = "Detects agent.exe PoetRAT Golang-compiled malware masquerading as Windows Defender with keylogging and encrypted C2"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/agent-exe/"
      date = "2026-01-12"
      hash1 = "e7f9a29dde307afff4191dbc14a974405f287b10f359a39305dccdc0ee949385"
      hash2 = "4e856041018242c62b3848d63b94c3763beda01648d3139060700c11e9334ad1"
      family = "PoetRAT"
      id = "6428c8b8-e1b8-57b4-a240-04836add976d"
   strings:
      $str_windefendersvc = "WinDefenderSvc.exe" ascii wide nocase
      $str_defender_update = "WindowsDefenderUpdate" ascii wide nocase
      $str_marker = ".wd_installed" ascii wide
      $golang_runtime1 = "runtime.main" ascii
      $golang_runtime2 = "runtime.goexit" ascii
      $golang_runtime3 = "go.buildid" ascii
      $golang_runtime4 = "runtime.morestack" ascii
      $antidebug1 = "NtQueryInformationProcess" ascii wide
      $antidebug2 = "SetConsoleCtrlHandler" ascii wide
      $antidebug3 = "IsDebuggerPresent" ascii wide
      $crypto1 = "crypto/aes" ascii
      $crypto2 = "crypto/rsa" ascii
      $crypto3 = "crypto/sha" ascii
      $crypto4 = "chacha20" ascii nocase
      $crypto5 = "golang.org/x/crypto" ascii
      $net1 = "net.Listen" ascii
      $net2 = "net.Dial" ascii
      $net3 = "TCPConn" ascii
      $net4 = "net/http" ascii
      $reg1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
      $surv1 = "GetAsyncKeyState" ascii wide
      $surv2 = "SetWindowsHookEx" ascii wide
      $surv3 = "GetForegroundWindow" ascii wide
   condition:
      uint16(0) == 0x5A4D and
      (
      (
      (2 of ($str_*)) and
      (2 of ($golang_*)) and
      (1 of ($antidebug*)) and
      (1 of ($crypto*))
      ) or
      (
      (3 of ($golang_*)) and
      (2 of ($crypto*)) and
      (1 of ($str_*)) and
      (1 of ($net*)) and
      (1 of ($surv*)) and
      $reg1
      )
      )
}

rule PoetRAT_Persistence_Component {
   meta:
      description = "Detects PoetRAT persistence components including WinDefenderSvc.exe masquerading and startup folder placement"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/agent-exe/"
      date = "2026-01-12"
      hash1 = "4e856041018242c62b3848d63b94c3763beda01648d3139060700c11e9334ad1"
      family = "PoetRAT"
      id = "188018a9-6d37-5938-bfb2-5b3a63e1f029"
   strings:
      $defender_svc = "WinDefenderSvc.exe" ascii wide nocase
      $defender_update = "WindowsDefenderUpdate" ascii wide nocase
      $startup_path = "Start Menu\\Programs\\Startup" ascii wide nocase
      $marker_file = ".wd_installed" ascii wide
      $go1 = "Go build ID:" ascii
      $go2 = "runtime.main" ascii
      $go3 = "runtime.goexit" ascii
   condition:
      uint16(0) == 0x5A4D and
      (
      ($defender_svc and $defender_update) or
      ($defender_svc and $startup_path) or
      ($marker_file and any of ($go*))
      )
}

rule Golang_RAT_Generic_Detection {
   meta:
      description = "Generic Golang-compiled RAT detection based on runtime artifacts, surveillance capabilities, and encrypted C2 communications"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/agent-exe/"
      date = "2026-01-12"
      family = "GolangRAT"
      id = "725f0479-29ac-5b18-8c00-bd2855008088"
   strings:
      $go_runtime1 = "runtime.main" ascii
      $go_runtime2 = "runtime.goexit" ascii
      $go_runtime3 = "runtime.morestack" ascii
      $go_runtime4 = "go.buildid" ascii
      $cap_keylog = "GetAsyncKeyState" ascii wide
      $cap_keylog2 = "SetWindowsHookEx" ascii wide
      $cap_rdp = "TermService" ascii wide nocase
      $cap_ps = "powershell" ascii wide nocase
      $cap_service = "CreateService" ascii wide
      $crypto_aes = "crypto/aes" ascii
      $crypto_tls = "crypto/tls" ascii
      $crypto_modern = "chacha20" ascii nocase
      $net_tcp = "net.Dial" ascii
      $net_http = "net/http" ascii
      $net_listen = "net.Listen" ascii
   condition:
      uint16(0) == 0x5A4D and
      (2 of ($go_runtime*)) and
      (2 of ($cap_*)) and
      (1 of ($crypto_*)) and
      (1 of ($net_*))
}
