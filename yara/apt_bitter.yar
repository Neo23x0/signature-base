
rule EXT_APT_Bitter_Win32k_0day_Feb21 {
   meta:
      description = "Detects code that exploits a Windows 0day exploited by Bitter APT group"
      author = "dbappsecurity_lieying_lab"
      date = "2021-01-01"
      reference = "https://ti.dbappsecurity.com.cn/blog/index.php/2021/02/10/windows-kernel-zero-day-exploit-is-used-by-bitter-apt-in-targeted-attack/"
      id = "b1892b52-4b94-5571-ad63-8750a321f1f2"
   strings:
      $s1 = "NtUserConsoleControl" ascii wide
      $s2 = "NtCallbackReturn" ascii wide
      $s3 = "CreateWindowEx" ascii wide
      $s4 = "SetWindowLong" ascii wide

      $a1 = {48 C1 E8 02 48 C1 E9 02 C7 04 8A}
      $a2 = {66 0F 1F 44 00 00 80 3C 01 E8 74 22 FF C2 48 FF C1}
      $a3 = {48 63 05 CC 69 05 00 8B 0D C2 69 05 00 48 C1 E0 20 48 03 C1}

   condition:
      uint16(0) == 0x5a4d and all of ($s*) and 1 of ($a*)
}
