
rule EXPL_SignDrop_CLFS_LPE_Nov26 {
   meta:
      description = "Detects SignDrop (SigDrop.exe), a Windows local privilege escalation exploit by Nightmare-Eclipse (MSNightmare) that abuses the CLFS authentication mitigation. It coerces Microsoft Defender via the signature update RPC into creating a CLFS authentication file (.cnpf) as SYSTEM, redirected to C:\\Program Files\\Common Files\\microsoft shared\\ink\\hid.dll, and then gets that DLL loaded on the UAC secure desktop."
      author = "Florian Roth"
      date = "2026-11-13"
      reference = "https://github.com/MSNightmare/SignDrop"
      score = 80
      id = "2d03e489-db2c-5688-8f41-87b03f9ae4ca"
   strings:
      $x1 = "\\??\\%TEMP%\\SigDrop_" wide
      $x2 = "\\BaseNamedObjects\\Restricted\\mpasbase.vdm" wide
      $x3 = "\\CLFS%ws\\%ws" wide
      $x4 = "Failed to create CLFS containers, error : %d" ascii
      $x5 = "Failed to create clfs log file, error : 0x%0.8X" ascii

      $s1 = "%ws.cnpf" wide
      $s2 = "\\\\.\\GlobalRoot\\BaseNamedObjects\\Restricted\\" wide
      $s3 = "\\Common Files\\microsoft shared\\ink\\hid.dll" wide
      $s4 = "IMpService77BDAF73-B396-481F-9042-AD358843EC24" wide
      $s5 = "MpEngine.dll" wide fullword
      $s6 = "Failed to create bait file, error : 0x%0.8X" ascii
      $s7 = "This machine is not vulnerable." ascii
      $s8 = "\\Program Files\\Common Files\\microsoft shared\\ink" wide
   condition:
      uint16(0) == 0x5a4d
      and filesize < 10MB
      and (
         1 of ($x*)
         or 4 of ($s*)
      )
}

rule EXPL_SignDrop_Payload_DLL_Nov26 {
   meta:
      description = "Detects the hid.dll payload of the SignDrop CLFS privilege escalation exploit, which gets loaded as SYSTEM on the UAC secure desktop, switches to the user's default desktop, starts conhost.exe as SYSTEM and terminates consent.exe. Also matches SignDrop executables that embed the payload as a resource."
      author = "Florian Roth"
      date = "2026-11-13"
      reference = "https://github.com/MSNightmare/SignDrop"
      hash = "c799634115525db95295f18e339a143a0fd1c6ba3a249269b5d00db97b35418d"
      score = 80
      id = "83685599-e0f1-5e92-b595-fd586682e4ac"
   strings:
      $x1 = "\\source\\repos\\hid\\x64\\Release\\hid.pdb" ascii

      $s1 = "WinSta0\\Default" wide fullword
      $s2 = "C:\\Windows\\System32\\conhost.exe" wide fullword
      $s3 = "consent.exe" wide fullword

      // OpenDesktopW(L"Default", 0, FALSE, GENERIC_ALL)
      $op1 = {
         41 B9 00 00 00 10     // mov     r9d, 10000000h; dwDesiredAccess = GENERIC_ALL
         48 8D 0D ?? ?? ?? ??  // lea     rcx, aDefault; lpszDesktop
         45 33 C0              // xor     r8d, r8d; fInherit
         33 D2                 // xor     edx, edx; dwFlags
         FF 15                 // call    cs:__imp_OpenDesktopW
      }
      // CreateProcessW() with CREATE_BREAKAWAY_FROM_JOB | CREATE_NEW_PROCESS_GROUP | CREATE_NEW_CONSOLE
      $op2 = {
         C7 44 24 28 10 02 00 01  // mov     dword ptr [rsp+28h], 1000210h; dwCreationFlags
         89 44 24 20              // mov     [rsp+20h], eax; bInheritHandles = FALSE
      }
      // OpenProcess(PROCESS_TERMINATE, FALSE, pid) followed by TerminateProcess(h, 0)
      $op3 = {
         44 8B 84 24 ?? ?? 00 00  // mov     r8d, [rsp+...]; dwProcessId = th32ProcessID
         33 D2                    // xor     edx, edx; bInheritHandle
         B9 01 00 00 00           // mov     ecx, 1; dwDesiredAccess = PROCESS_TERMINATE
         FF 15 ?? ?? ?? ??        // call    cs:__imp_OpenProcess
         48 8B C8                 // mov     rcx, rax; hProcess
         33 D2                    // xor     edx, edx; uExitCode
         48 8B D8                 // mov     rbx, rax
         FF 15                    // call    cs:__imp_TerminateProcess
      }
   condition:
      uint16(0) == 0x5a4d
      and filesize < 10MB
      and (
         $x1 and 1 of ($s*)
         or all of ($s*) and 1 of ($op*)
      )
}

rule SUSP_CLFS_Auth_File_Redirect_Exploit_Nov26 {
   meta:
      description = "Detects executables that combine direct access to the CLFS device namespace, CLFS authentication file (.cnpf) references and object manager symbolic link creation, a combination used by exploits like SignDrop to redirect CLFS authentication file creation to an attacker-chosen path."
      author = "Florian Roth"
      date = "2026-11-13"
      reference = "https://github.com/MSNightmare/SignDrop"
      score = 65
      id = "c6e236f7-a823-530e-a96c-847c2bbd8aa8"
   strings:
      $clfs1 = "\\CLFS\\" ascii wide
      $clfs2 = "\\CLFS%" ascii wide

      $cnpf = ".cnpf" ascii wide

      $sym1 = "NtCreateSymbolicLinkObject" ascii

      $ns1 = "\\BaseNamedObjects\\Restricted" ascii wide
      $ns2 = "\\RPC Control\\" ascii wide
      $ns3 = "\\GlobalRoot\\" ascii wide nocase
   condition:
      uint16(0) == 0x5a4d
      and filesize < 20MB
      and 1 of ($clfs*)
      and $cnpf
      and $sym1
      and 1 of ($ns*)
}
