rule apt_nix_elf_derusbi {
   meta:
      description = "Detects Derusbi Backdoor ELF"
      author = "Fidelis Cybersecurity"
      date = "2016/02/29"
      reference = "https://github.com/fideliscyber/indicators/tree/master/FTA-1021"
   strings:
      $s1 = "LxMain"
      $s2 = "execve"
      $s3 = "kill"
      $s4 = "cp -a %s %s"
      $s5 = "%s &"
      $s6 = "dbus-daemon"
      $s7 = "--noprofile"
      $s8 = "--norc"
      $s9 = "TERM=vt100"
      $s10 = "/proc/%u/cmdline"
      $s11 = "loadso"
      $s12 = "/proc/self/exe"
      $s13 = "Proxy-Connection: Keep-Alive"
      $s14 = "Connection: Keep-Alive"
      $s15 = "CONNECT %s"
      $s16 = "HOST: %s:%d"
      $s17 = "User-Agent: Mozilla/4.0"
      $s18 = "Proxy-Authorization: Basic %s"
      $s19 = "Server: Apache"
      $s20 = "Proxy-Authenticate"
      $s21 = "gettimeofday"
      $s22 = "pthread_create"
      $s23 = "pthread_join"
      $s24 = "pthread_mutex_init"
      $s25 = "pthread_mutex_destroy"
      $s26 = "pthread_mutex_lock"
      $s27 = "getsockopt"
      $s28 = "socket"
      $s29 = "setsockopt"
      $s30 = "select"
      $s31 = "bind"
      $s32 = "shutdown"
      $s33 = "listen"
      $s34 = "opendir"
      $s35 = "readdir"
      $s36 = "closedir"
      $s37 = "rename"
   condition:
      uint32(0) == 0x4464c457f and all of them
}

rule apt_nix_elf_derusbi_kernelModule
{
   meta:
      description = "Detects Derusbi Backdoor ELF Kernel Module"
      author = "Fidelis Cybersecurity"
      date = "2016/02/29"
      reference = "https://github.com/fideliscyber/indicators/tree/master/FTA-1021"
   strings:
      $s1 = "__this_module"
      $s2 = "init_module"
      $s3 = "unhide_pid"
      $s4 = "is_hidden_pid"
      $s5 = "clear_hidden_pid"
      $s6 = "hide_pid"
      $s7 = "license"
      $s8 = "description"
      $s9 = "srcversion="
      $s10 = "depends="
      $s12 = "vermagic="
      $s13 = "current_task"
      $s14 = "sock_release"
      $s15 = "module_layout"
      $s16 = "init_uts_ns"
      $s17 = "init_net"
      $s18 = "init_task"
      $s19 = "filp_open"
      $s20 = "__netlink_kernel_create"
      $s21 = "kfree_skb"
   condition:
      uint32(0) == 0x4464c457f and all of them
}

rule apt_nix_elf_Derusbi_Linux_SharedMemCreation {
   meta:
      description = "Detects Derusbi Backdoor ELF Shared Memory Creation"
      author = "Fidelis Cybersecurity"
      date = "2016/02/29"
      reference = "https://github.com/fideliscyber/indicators/tree/master/FTA-1021"
   strings:
      $byte1 = { B6 03 00 00 ?? 40 00 00 00 ?? 0D 5F 01 82 }
   condition:
      uint32(0) == 0x464C457F and any of them
}

rule apt_nix_elf_Derusbi_Linux_Strings {
   meta:
      description = "Detects Derusbi Backdoor ELF Strings"
      author = "Fidelis Cybersecurity"
      date = "2016/02/29"
      reference = "https://github.com/fideliscyber/indicators/tree/master/FTA-1021"
   strings:
      $a1 = "loadso" wide ascii fullword
      $a2 = "\nuname -a\n\n" wide ascii
      $a3 = "/dev/shm/.x11.id" wide ascii
      $a4 = "LxMain64" wide ascii nocase
      $a5 = "# \\u@\\h:\\w \\$ " wide ascii
      $b1 = "0123456789abcdefghijklmnopqrstuvwxyz" wide
      $b2 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" wide
      $b3 = "ret %d" wide fullword
      $b4 = "uname -a\n\n" wide ascii
      $b5 = "/proc/%u/cmdline" wide ascii
      $b6 = "/proc/self/exe" wide ascii
      $b7 = "cp -a %s %s" wide ascii
      $c1 = "/dev/pts/4" wide ascii fullword
      $c2 = "/tmp/1408.log" wide ascii fullword
   condition:
      uint32(0) == 0x464C457F and
      (
         (1 of ($a*) and 4 of ($b*) ) or
         (1 of ($a*) and 1 of ($c*)) or
         2 of ($a*) or
         all of ($b*)
      )
}

rule apt_win_exe_trojan_derusbi {
   meta:
      description = "Detects Derusbi Backdoor Win32"
      author = "Fidelis Cybersecurity"
      date = "2016/02/29"
      reference = "https://github.com/fideliscyber/indicators/tree/master/FTA-1021"
   strings:
      $sa_1 = "USB" wide ascii
      $sa_2 = "RAM" wide ascii
      $sa_3 = "SHARE" wide ascii
      $sa_4 = "HOST: %s:%d"
      $sa_5 = "POST"
      $sa_6 = "User-Agent: Mozilla"
      $sa_7 = "Proxy-Connection: Keep-Alive"
      $sa_8 = "Connection: Keep-Alive"
      $sa_9 = "Server: Apache"
      $sa_10 = "HTTP/1.1"
      $sa_11 = "ImagePath"
      $sa_12 = "ZwUnloadDriver"
      $sa_13 = "ZwLoadDriver"
      $sa_14 = "ServiceMain"
      $sa_15 = "regsvr32.exe"
      $sa_16 = "/s /u" wide ascii
      $sa_17 = "rand"
      $sa_18 = "_time64"
      $sa_19 = "DllRegisterServer"
      $sa_20 = "DllUnregisterServer"
      $sa_21 = { 8b [5] 8b ?? d3 ?? 83 ?? 08 30 [5] 40 3b [5] 72 } // Decode Driver

      $sb_1 = "PCC_CMD_PACKET"
      $sb_2 = "PCC_CMD"
      $sb_3 = "PCC_BASEMOD"
      $sb_4 = "PCC_PROXY"
      $sb_5 = "PCC_SYS"
      $sb_6 = "PCC_PROCESS"
      $sb_7 = "PCC_FILE"
      $sb_8 = "PCC_SOCK"

      $sc_1 = "bcdedit -set testsigning" wide ascii
      $sc_2 = "update.microsoft.com" wide ascii
      $sc_3 = "_crt_debugger_hook" wide ascii
      $sc_4 = "ue8G5" wide ascii

      $sd_1 = "NET" wide ascii
      $sd_2 = "\\\\.\\pipe\\%s" wide ascii
      $sd_3 = ".dat" wide ascii
      $sd_4 = "CONNECT %s:%d" wide ascii
      $sd_5 = "\\Device\\" wide ascii

      $se_1 = "-%s-%04d" wide ascii
      $se_2 = "-%04d" wide ascii
      $se_3 = "FAL" wide ascii
      $se_4 = "OK" wide ascii
      $se_5 = "2.03" wide ascii
      $se_6 = "XXXXXXXXXXXXXXX" wide ascii

   condition:
      uint16(0) == 0x5A4D and (
         all of ($sa_*) or
         (
            (13 of ($sa_*)) and (
               (5 of ($sb_*)) or
               (3 of ($sc_*)) or
               (all of ($sd_*)) or
               ( 1 of ($sc_*) and all of ($se_*) )
            )
         )
      )
}
