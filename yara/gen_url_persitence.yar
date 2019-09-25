rule Methodology_Suspicious_Shortcut_Local_URL
{
  meta:
    author = "@itsreallynick (Nick Carr), @QW5kcmV3 (Andrew Thompson)"
    description = "Detects local script usage for .URL persistence"
    reference = "https://twitter.com/cglyer/status/1176184798248919044"
  strings:
    $file = "URL=file:///" nocase
    $url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
    $url_explicit = "[InternetShortcut]" nocase
  condition:
    $file and any of ($url*)
    // if you just want the .url files, feel free to further anchor & uses distances or append (uint16(0) != 0x5A4D and uint32(uint32(0x3C)) != 0x00004550)
}

rule Methodology_Suspicious_Shortcut_SMB_URL
{
  meta:
    author = "@itsreallynick (Nick Carr), @QW5kcmV3 (Andrew Thompson)"
    description = "Detects remote SMB path for .URL persistence"
    reference = "https://twitter.com/cglyer/status/1176184798248919044"
    sample = "e0bef7497fcb284edb0c65b59d511830"
  strings:
    $file = /URL=file:\/\/[a-z0-9]/ nocase
    $url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
    $url_explicit = "[InternetShortcut]" nocase
  condition:
    $file and any of ($url*)
    // if you just want the .url files, feel free to further anchor & uses distances or append (uint16(0) != 0x5A4D and uint32(uint32(0x3C)) != 0x00004550)
}

rule Methodology_Suspicious_Shortcut_IconRemote_HTTP
{
  meta:
    author = "@itsreallynick (Nick Carr)"
    description = "Detects .URL persistence file"
    reference = "https://twitter.com/ItsReallyNick/status/1176241449148588032"
  strings:
    $icon = "IconFile=http" nocase
    $url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
    $url_explicit = "[InternetShortcut]" nocase
  condition:
    $icon and any of ($url*)
    //and uint16(0) != 0x5A4D and uint32(uint32(0x3C)) != 0x00004550
}

rule Methodology_Suspicious_Shortcut_IconRemote_SMB
{
  meta:
    author = "@itsreallynick (Nick Carr)"
    description = "Detects .URL persistence file"
    reference = "https://twitter.com/ItsReallyNick/status/1176241449148588032"
  strings:
    $icon = "IconFile=file://" nocase
    $url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
    $url_explicit = "[InternetShortcut]" nocase
  condition:
    $icon and any of ($url*)
    //and (uint16(0) != 0x5A4D and uint32(uint32(0x3C)) != 0x00004550)
}

rule Methodology_Suspicious_Shortcut_WebDAV
{
  meta:
    author = "@itsreallynick (Nick Carr)"
    description = "Detects .URL persistence file"
    reference = "https://twitter.com/cglyer/status/1176243536754282497"
  strings:
    $file1 = /URL=\/\/[A-Za-z0-9]/
    $file2 = /IconFile=\/\/[A-Za-z0-9]/
    $url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
    $url_explicit = "[InternetShortcut]" nocase
  condition:
    any of ($url*) and any of ($file*)
    and uint16(0) != 0x5A4D and uint32(uint32(0x3C)) != 0x00004550 and uint32(0) != 0x464c457f and uint32(0) != 0xBEBAFECA and uint32(0) != 0xFEEDFACE and uint32(0) != 0xFEEDFACF and uint32(0) != 0xCEFAEDFE
}
