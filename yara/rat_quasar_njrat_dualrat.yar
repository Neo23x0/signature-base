/*
   Yara Rule Set
   Identifier: Dual-RAT Campaign (Quasar + NjRAT/XWorm)
   Author: The Hunters Ledger
   Source: https://pixelatedcontinuum.github.io/Threat-Intel-Reports/
   License: CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/
*/

rule Quasar_RAT_Core_Detection {
   meta:
      description = "Detects Quasar RAT in the dual-RAT campaign by campaign C2 IP or multi-category behavioral indicators — requires multiple categories together to avoid FP on legitimate tools that use any one of these APIs (WriteProcessMemory, CreateRemoteThread, etc. are widely used)"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/dual-rat-analysis/"
      date = "2025-12-06"
      family = "QuasarRAT"
      id = "e5642197-5e01-5aa7-ac85-5a645a92e85c"
   strings:
      $inject1 = "inject_thread" fullword
      $inject2 = "WriteProcessMemory" fullword
      $inject3 = "CreateRemoteThread" fullword
      $vm_detect1 = "VirtualBox"
      $vm_detect2 = "VMware"
      $vm_detect3 = "QEMU"
      $debug_detect1 = "Debugger"
      $debug_detect2 = "IsDebuggerPresent" fullword
      $c2_1 = "185.208.159.182"
      $c2_2 = "ipwho.is"
      $c2_3 = "api.ipify.org"
      $persist1 = "RuntimeBroker"
      $persist2 = "schtasks"
      $persist3 = "ONLOGON"
      $surv1 = "keylogger" fullword
      $surv2 = "screenshot" fullword
      $surv3 = "webcam" fullword
      $surv4 = "clipboard" fullword
   condition:
      uint16(0) == 0x5A4D and
      filesize < 5MB and
      (
         $c2_1 or
         (2 of ($inject*) and 2 of ($surv*)) or
         (all of ($vm_detect*) and any of ($debug_detect*) and 2 of ($surv*)) or
         (2 of ($persist*) and 3 of ($surv*) and 1 of ($inject*))
      )
}

rule Quasar_RAT_MarkOfWeb_Removal {
   meta:
      description = "Detects Quasar RAT Zone.Identifier stream removal for anti-forensic indicator removal"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/dual-rat-analysis/"
      date = "2025-12-06"
      hash1 = "2c4387ce18be279ea735ec4f0092698534921030aaa69949ae880e41a5c73766"
      family = "QuasarRAT"
      id = "a2e913d8-0983-5d36-8bba-d9ddde38b68f"
   strings:
      $zone_stream = ":Zone.Identifier"
      $delete_api = "DeleteFile"
   condition:
      uint16(0) == 0x5A4D and
      all of them
}

rule NjRAT_XWorm_Core_Detection {
   meta:
      description = "Detects NjRAT/XWorm via NjRAT-specific config field names (the misspelled 'Groub' and 'USBNM' are NjRAT internal identifiers — high-confidence anchors) or Pastebin dead-drop C2 combined with config indicators. Avoids FPs on every VB.NET binary."
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/dual-rat-analysis/"
      date = "2025-12-06"
      hash1 = "950aadba6993619858294599b3458d5d2221f10fe72b3db3e49883d496a705bb"
      family = "NjRAT"
      id = "86a672cb-1ac0-5927-aeee-b8c0a19ce9a7"
   strings:
      $vb_net1 = "Microsoft.VisualBasic"
      $vb_net2 = "System.Windows.Forms"
      $config_specific1 = "Groub" fullword ascii wide
      $config_specific2 = "USBNM" fullword ascii wide
      $config_specific3 = "PasteUrl" fullword ascii wide
      $config_generic1 = "InstallDir" fullword
      $config_generic2 = "Mutex" fullword
      $pastebin1 = "pastebin.com"
      $pastebin2 = "raw/"
      $pastebin3 = "iPhone Safari"
      $persist1 = "conhost" fullword
      $persist2 = "minute /mo 1"
      $persist3 = "Startup"
      $persist4 = "schtasks /create"
      $critical1 = "RtlSetProcessIsCritical" fullword
      $critical2 = "BSOD"
      $surv1 = "capCreateCaptureWindowA" fullword
      $surv2 = "webcam" fullword
      $surv3 = "microphone" fullword
      $surv4 = "keylogger" fullword
   condition:
      uint16(0) == 0x5A4D and
      filesize < 500KB and
      (
         hash.sha256(0, filesize) == "950aadba6993619858294599b3458d5d2221f10fe72b3db3e49883d496a705bb" or
         1 of ($config_specific*) or
         (any of ($pastebin*) and 2 of ($config_generic*, $persist*, $critical*)) or
         ($critical1 and 2 of ($surv*) and 1 of ($persist*))
      )
}

rule NjRAT_XWorm_Triple_Persistence {
   meta:
      description = "Detects NjRAT/XWorm triple persistence mechanism via conhost-named scheduled task, run key, and startup LNK"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/dual-rat-analysis/"
      date = "2025-12-06"
      family = "NjRAT"
      id = "85fbe6d2-865b-5f69-81dd-f0db8bf50511"
   strings:
      $task_name = "conhost"
      $task_freq = "minute /mo 1"
      $reg_key = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
      $startup = "Startup\\conhost.lnk"
      $schtasks = "schtasks /create"
   condition:
      uint16(0) == 0x5A4D and
      all of them
}
