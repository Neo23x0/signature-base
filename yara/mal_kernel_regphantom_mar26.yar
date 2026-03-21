rule MAL_Kernel_RegPhantom_Mar26 {
   meta:
      description = "Detects RegPhantom, a kernel-mode rootkit that allow attacker to inject arbitrary code from unprivileged user-mode into kernel-mode and execute it."
      author = "Pezier Pierre-Henri (Nextron Systems)"
      date = "2026-03-19"
      reference = "Internal Research"
      hash = "006e08f1b8cad821f7849c282dc11d317e76ce66a5bcd84053dd5e7752e0606f"
      score = 80
   strings:
      $s1 = "CmRegisterCallback" fullword
      $s2 = "PsSetCreateThreadNotifyRoutine" fullword

      $o1 = {
         // xor decrypt
         48 8b 09     // mov     rcx, [rcx]
         0f b6 14 08  // movzx   edx, byte ptr [rax+rcx]
         4c 31 c2     // xor     rdx, r8
         88 14 08     // mov     [rax+rcx], dl
      }
      $o2 = {
         // Command selector
         c6 01 01     // mov     byte ptr [rcx], 1
         48 83 38 77  // cmp     qword ptr [rax], 77h
         0f 94 c0     // setz    al
         24 01        // and     al, 1
      }
   condition:
      uint16(0) == 0x5a4d
      and all of them
}

