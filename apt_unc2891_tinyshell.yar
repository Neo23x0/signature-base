rule APT_UNC2891_TinyShell_Backdoor {
  meta:
    author = "Mandiant"
    description = "Detects Tiny SHell - An open-source UNIX backdoor"
    date = "2022-03-17"
    reference = "https://www.mandiant.com/resources/blog/unc2891-overview"
    score = 80
    hash1 = "1f889871263bd6cdad8f3d4d5fc58b4a32669b944d3ed0860730374bb87d730a"

  strings:
    $sb1 = { C6 00 48 C6 4? ?? 49 C6 4? ?? 49 C6 4? ?? 4C C6 4? ?? 53 C6 4? ?? 45 C6 4? ?? 54 C6 4? ?? 3D C6 4? ?? 46 C6 4? ?? 00 }
    $sb2 = { C6 00 54 C6 4? ?? 4D C6 4? ?? 45 C6 4? ?? 3D C6 4? ?? 52 }
    $ss1 = "fork" ascii fullword wide
    $ss2 = "socket" ascii fullword wide
    $ss3 = "bind" ascii fullword wide
    $ss4 = "listen" ascii fullword wide
    $ss5 = "accept" ascii fullword wide
    $ss6 = "alarm" ascii fullword wide
    $ss7 = "shutdown" ascii fullword wide
    $ss8 = "creat" ascii fullword wide
    $ss9 = "write" ascii fullword wide
    $ss10 = "open" ascii fullword wide
    $ss11 = "read" ascii fullword wide
    $ss12 = "execl" ascii fullword wide
    $ss13 = "gethostbyname" ascii fullword wide
    $ss14 = "connect" ascii fullword wide

  condition:
    uint32(0) == 0x464c457f and 1 of ($sb*) and 10 of ($ss*)
}
