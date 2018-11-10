
rule PowerShell_Suite_Hacktools_Gen_Strings {
   meta:
      description = "Detects strings from scripts in the PowerShell-Suite repo"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/FuzzySecurity/PowerShell-Suite"
      date = "2017-12-27"
      hash1 = "79071ba5a984ee05903d566130467483c197cbc2537f25c1e3d7ae4772211fe0"
      hash2 = "db31367410d0a9ffc9ed37f423a4b082639591be7f46aca91f5be261b23212d5"
      hash3 = "4f51e7676a4d54c1962760ca0ac81beb28008451511af96652c31f4f40e8eb8e"
      hash4 = "17ac9bb0c46838c65303f42a4a346fcba838ebd5833b875e81dd65c82701d8a8"
      hash5 = "fa33aef619e620a88ecccb990e71c1e11ce2445f799979d23be2d1ad4321b6c6"
      hash6 = "5542bd89005819bc4eef8dfc8a158183e5fd7a1438c84da35102588f5813a225"
      hash7 = "c6a99faeba098eb411f0a9fcb772abac2af438fc155131ebfc93a00e3dcfad50"
      hash8 = "a8e06ecf5a8c25619ce85f8a23f2416832cabb5592547609cfea8bd7fcfcc93d"
      hash9 = "6aa5abf58904d347d441ac8852bd64b2bad3b5b03b518bdd06510931a6564d08"
      hash10 = "5608f25930f99d78804be8c9c39bd33f4f8d14360dd1e4cc88139aa34c27376d"
      hash11 = "68b6c0b5479ecede3050a2f44f8bb8783a22beeef4a258c4ff00974f5909b714"
      hash12 = "da25010a22460bbaabff0f7004204aae7d830348e8a4543177b1f3383b2c3100"
   strings:
      $ = "[!] NtCreateThreadEx failed.." fullword ascii
      $ = "[?] Executing mmc.." ascii
      $ = "[!] This method is only supported on 64-bit!" fullword ascii
      $ = "$LNK = [ShellLink.Shortcut]::FromByteArray($LNKHeader.GetBytes())" fullword ascii
      $ = "$CallResult = [UACTokenMagic]::TerminateProcess($ShellExecuteInfo.hProcess, 1)" fullword ascii
      $ = "[!] Unable to open process (as Administrator), this may require SYSTEM access." fullword ascii
      $ = "[!] Error, NTSTATUS Value: " ascii
      $ = "[!] UAC artifact: " ascii
      $ = "[>] Process dump success!" ascii
      $ = "[!] Process dump failed!" ascii
      $ = "[+] Eidolon entry point:" fullword ascii
      $ = "Wait for shellcode to run" fullword ascii
      $ = "$Command = Read-Host \"`nSMB shell\"" fullword ascii
      $ = "Use Netapi32::NetSessionEnum to enumerate active sessions on domain joined machines." fullword ascii
      $ = "Invoke-CreateProcess -Binary C:\\Windows\\System32\\" ascii
      $ = "[?] Thread belongs to: " ascii
      $ = "[?] Operating system core count: " ascii
      $ = "[>] Calling Advapi32::LookupPrivilegeValue --> SeDebugPrivilege" fullword ascii
      $ = "Calling Advapi32::OpenProcessToken --> LSASS" ascii
      $ = "[!] Mmm, something went wrong! GetLastError returned:" ascii
      $ = "if (($FileBytes[0..1] | % {[Char]$_}) -join '' -cne 'MZ')" fullword ascii
   condition:
      filesize < 100KB and 1 of them
}

rule PowerShell_Suite_Eidolon {
   meta:
      description = "Detects PowerShell Suite Eidolon script - file Start-Eidolon.ps1"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/FuzzySecurity/PowerShell-Suite"
      date = "2017-12-27"
      hash1 = "db31367410d0a9ffc9ed37f423a4b082639591be7f46aca91f5be261b23212d5"
   strings:
      $ = "[+] Eidolon entry point:" ascii
      $ = "C:\\PS> Start-Eidolon -Target C:\\Some\\File.Path -Mimikatz -Verbose" fullword ascii
      $ = "[Int16]$PEArch = '0x{0}' -f ((($PayloadBytes[($OptOffset+1)..($OptOffset)]) | % {$_.ToString('X2')}) -join '')" fullword ascii
   condition:
      uint16(0) == 0x7566 and filesize < 13000KB and 1 of them
}
