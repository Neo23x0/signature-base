
rule Methodology_Suspicious_Shortcut_Local_URL
{
  meta:
    author = "@itsreallynick (Nick Carr), @QW5kcmV3 (Andrew Thompson)"
    description = "Detects local script usage for .URL persistence"
    reference = "https://twitter.com/cglyer/status/1176184798248919044"
    score = 50
    date = "27.09.2019"
    id = "438d9323-cb6a-5f5d-af71-76692b93436a"
  strings:
    $file = "URL=file:///" nocase
    $url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
    $url_explicit = "[InternetShortcut]" nocase
  condition:
    $file and any of ($url*)
    and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32(0) != 0xBEBAFECA and uint32(0) != 0xFEEDFACE and uint32(0) != 0xFEEDFACF and uint32(0) != 0xCEFAEDFE
    and filesize < 30KB
}

rule Methodology_Suspicious_Shortcut_SMB_URL
{
  meta:
    author = "@itsreallynick (Nick Carr), @QW5kcmV3 (Andrew Thompson)"
    description = "Detects remote SMB path for .URL persistence"
    reference = "https://twitter.com/cglyer/status/1176184798248919044"
    sample = "e0bef7497fcb284edb0c65b59d511830"
    score = 50
    date = "27.09.2019"
    id = "e23609a1-9b18-5a56-92ee-c7f84c966865"
  strings:
    $file = /URL=file:\/\/[a-z0-9]/ nocase
    $url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
    $url_explicit = "[InternetShortcut]" nocase
  condition:
    $file and any of ($url*)
    and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32(0) != 0xBEBAFECA and uint32(0) != 0xFEEDFACE and uint32(0) != 0xFEEDFACF and uint32(0) != 0xCEFAEDFE
    and filesize < 30KB
}

/* many FPs
rule Methodology_Suspicious_Shortcut_IconRemote_HTTP
{
  meta:
    author = "@itsreallynick (Nick Carr)"
    description = "Detects possible shortcut usage for .URL persistence"
    reference = "https://twitter.com/cglyer/status/1176184798248919044"
    score = 40
    date = "27.09.2019"
  strings:
    $icon = /IconFile\s*=\s*http/ nocase
    $url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
    $url_explicit = "[InternetShortcut]" nocase
  condition:
    $icon and any of ($url*)
    and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32(0) != 0xBEBAFECA and uint32(0) != 0xFEEDFACE and uint32(0) != 0xFEEDFACF and uint32(0) != 0xCEFAEDFE
    and filesize < 30KB
}
*/

rule Methodology_Suspicious_Shortcut_IconRemote_SMBorLocal
{
  meta:
    author = "@itsreallynick (Nick Carr)"
    description = "This is the syntax used for NTLM hash stealing via Responder - https://www.securify.nl/nl/blog/SFY20180501/living-off-the-land_-stealing-netntlm-hashes.html"
    reference = "https://twitter.com/ItsReallyNick/status/1176241449148588032"
    score = 50
    date = "27.09.2019"
    id = "9362ce46-265c-5215-bee1-3d784d0cb928"
  strings:
    $icon = "IconFile=file://" nocase
    $url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
    $url_explicit = "[InternetShortcut]" nocase
  condition:
    $icon and any of ($url*)
    and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32(0) != 0xBEBAFECA and uint32(0) != 0xFEEDFACE and uint32(0) != 0xFEEDFACF and uint32(0) != 0xCEFAEDFE
    and filesize < 30KB
}

rule Methodology_Shortcut_HotKey
{
  meta:
    author = "@itsreallynick (Nick Carr)"
    description = "Detects possible shortcut usage for .URL persistence"
    reference = "https://twitter.com/cglyer/status/1176184798248919044"
    score = 50
    date = "27.09.2019"
    id = "0ce377c4-db9b-59fa-987b-a77eaf408765"
  strings:
    $hotkey = /[\x0a\x0d]HotKey=[1-9]/ nocase
    $url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
    $url_explicit = "[InternetShortcut]" nocase
  condition:
    $hotkey and any of ($url*)
    and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32(0) != 0xBEBAFECA and uint32(0) != 0xFEEDFACE and uint32(0) != 0xFEEDFACF and uint32(0) != 0xCEFAEDFE
    and filesize < 30KB
}

rule Methodology_Suspicious_Shortcut_BaseURLSyntax
{
  meta:
    author = "@itsreallynick (Nick Carr)"
    description = "Detects possible shortcut usage for .URL persistence"
    reference = "https://twitter.com/cglyer/status/1176184798248919044"
    score = 50
    date = "27.09.2019"
    id = "cab7b573-d197-5afc-95a9-ef05a07c2b7a"
  strings:
    $baseurl1 = "BASEURL=file://" nocase
    $baseurl2 = "[DEFAULT]" nocase
    $url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
    $url_explicit = "[InternetShortcut]" nocase
  condition:
    all of ($baseurl*) and any of ($url*)
    and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32(0) != 0xBEBAFECA and uint32(0) != 0xFEEDFACE and uint32(0) != 0xFEEDFACF and uint32(0) != 0xCEFAEDFE
    and filesize < 30KB
}

rule Methodology_Contains_Shortcut_OtherURIhandlers
{
  meta:
    author = "@itsreallynick (Nick Carr)"
    description = "Noisy rule for .URL shortcuts containing unique URI handlers"
    description = "Detects possible shortcut usage for .URL persistence"
    reference = "https://twitter.com/cglyer/status/1176184798248919044"
    score = 35
    date = "27.09.2019"
    id = "1c0750d2-2177-5e2c-908b-4226ae099981"
  strings:
    $file = "URL="
    $filenegate = /[\x0a\x0d](Base|)URL\s*=\s*(https?|file):\/\// nocase
    $url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
    $url_explicit = "[InternetShortcut]" nocase
  condition:
    $file and any of ($url*) and not $filenegate
    and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32(0) != 0xBEBAFECA and uint32(0) != 0xFEEDFACE and uint32(0) != 0xFEEDFACF and uint32(0) != 0xCEFAEDFE
    and filesize < 30KB
}

/*
rule Methodology_Suspicious_Shortcut_IconShenanigans_dotDL
{
  meta:
    author = "@itsreallynick (Nick Carr)"
    reference = "https://twitter.com/ItsReallyNick/status/1176229087196696577"
    description = "Detects possible shortcut usage for .URL persistence"
    reference = "https://twitter.com/cglyer/status/1176184798248919044"
    score = 50
    date = "27.09.2019"
  strings:
    $icon = /[\x0a\x0d]IconFile=[^\x0d]*\.dl\x0d/ nocase ascii wide
    $url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
    $url_explicit = "[InternetShortcut]" nocase
  condition:
    any of ($url*) and $icon
    and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32(0) != 0xBEBAFECA and uint32(0) != 0xFEEDFACE and uint32(0) != 0xFEEDFACF and uint32(0) != 0xCEFAEDFE
    and filesize < 30KB
}
*/

rule Methodology_Suspicious_Shortcut_IconNotFromExeOrDLLOrICO
{
  meta:
    author = "@itsreallynick (Nick Carr)"
    reference = "https://twitter.com/ItsReallyNick/status/1176229087196696577"
    description = "Detects possible shortcut usage for .URL persistence"
    score = 50
    date = "27.09.2019"
    id = "82d0483f-48ee-5d0c-ba7d-73d9e9455423"
  strings:
    $icon = "IconFile="
    $icon_negate = /[\x0a\x0d]IconFile=[^\x0d]*\.(dll|exe|ico)\x0d/ nocase
    $url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
    $url_explicit = "[InternetShortcut]" nocase
  condition:
    any of ($url*) and $icon and not $icon_negate
    and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32(0) != 0xBEBAFECA and uint32(0) != 0xFEEDFACE and uint32(0) != 0xFEEDFACF and uint32(0) != 0xCEFAEDFE
    and filesize < 30KB
}

rule Methodology_Suspicious_Shortcut_Evasion
{
  meta:
    author = "@itsreallynick (Nick Carr)"
    description = "Non-standard .URLs and evasion"
    reference = "https://twitter.com/DissectMalware/status/1176736510856634368"
    score = 50
    date = "27.09.2019"
    id = "36df4252-2575-5efa-88ce-17e68a349306"
  strings:
    $URI = /[\x0a\x0d](IconFile|(Base|)URL)[^\x0d=]+/ nocase
    $filetype_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
    $filetype_explicit = "[InternetShortcut]" nocase
  condition:
    any of ($filetype*) and $URI //and $URInegate
    and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32(0) != 0xBEBAFECA and uint32(0) != 0xFEEDFACE and uint32(0) != 0xFEEDFACF and uint32(0) != 0xCEFAEDFE
    and filesize < 30KB
}

// the below rule hasn't been seen, but I still want to explore whether this format can be abused to launch commands in unstructured .URL space
rule Methodology_Suspicious_Shortcut_LOLcommand
{
  meta:
    author = "@itsreallynick (Nick Carr)"
    reference = "https://twitter.com/ItsReallyNick/status/1176601500069576704"
    description = "Detects possible shortcut usage for .URL persistence"
    score = 50
    date = "27.09.2019"
    modified = "2021-02-14"
    id = "061e7919-17f1-5774-ad7d-fc964dc9a947"
  strings:
    $file1 = /[\x0a\x0d](IconFile|(Base|)URL)\s*=[^\x0d]*(powershell|cmd|certutil|mshta|wscript|cscript|rundll32|wmic|regsvr32|msbuild)(\.exe|)[^\x0d]{2,50}\x0d/ nocase
    $url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
    $url_explicit = "[InternetShortcut]" nocase
  condition:
    any of ($url*) and any of ($file*)
    and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32(0) != 0xBEBAFECA and uint32(0) != 0xFEEDFACE and uint32(0) != 0xFEEDFACF and uint32(0) != 0xCEFAEDFE
    and filesize < 30KB
}

// NONE of the following rules have been seen itw, but they are searching for unique (possible?) .URL syntax - leaving here for transparency
rule Methodology_Suspicious_Shortcut_WebDAV
{
  meta:
    author = "@itsreallynick (Nick Carr)"
    reference = "https://twitter.com/cglyer/status/1176243536754282497"
    description = "Detects possible shortcut usage for .URL persistence"
    score = 50
    date = "27.09.2019"
    id = "cd660b84-d7c6-52fc-9e1d-76450e5262b1"
  strings:
    $file1 = /[\x0a\x0d](IconFile|(Base|)URL)\s*=\s*\/\/[A-Za-z0-9]/
    $url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
    $url_explicit = "[InternetShortcut]" nocase
  condition:
    any of ($url*) and any of ($file*)
    and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32(0) != 0xBEBAFECA and uint32(0) != 0xFEEDFACE and uint32(0) != 0xFEEDFACF and uint32(0) != 0xCEFAEDFE
    and filesize < 30KB
}

rule Methodology_Suspicious_Shortcut_ScriptURL
{
  meta:
    author = "@itsreallynick (Nick Carr)"
    description = "Detects possible shortcut usage for .URL persistence"
    reference = "https://twitter.com/cglyer/status/1176184798248919044"
    score = 50
    date = "27.09.2019"
    id = "2f55f8a9-4e4b-5480-9042-da6bb66b2e06"
  strings:
    $file1 = /[\x0a\x0d](IconFile|(Base|)URL)\s*=[^\x0d]*script:/ nocase
//    $file2 = /IconFile=script:/ nocase
    $url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
    $url_explicit = "[InternetShortcut]" nocase
  condition:
    any of ($url*) and any of ($file*)
    and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32(0) != 0xBEBAFECA and uint32(0) != 0xFEEDFACE and uint32(0) != 0xFEEDFACF and uint32(0) != 0xCEFAEDFE
    and filesize < 30KB
}

rule Methodology_Suspicious_Shortcut_WorkingDirRemote_HTTP
{
  meta:
    author = "@itsreallynick (Nick Carr)"
    description = "Detects possible shortcut usage for .URL persistence"
    reference = "https://twitter.com/cglyer/status/1176184798248919044"
    score = 50
    date = "27.09.2019"
    id = "68e54f8a-11e4-59e4-8498-59d88e70e438"
  strings:
    $icon = "WorkingDirectory=http" nocase
    $url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
    $url_explicit = "[InternetShortcut]" nocase
  condition:
    $icon and any of ($url*)
    and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32(0) != 0xBEBAFECA and uint32(0) != 0xFEEDFACE and uint32(0) != 0xFEEDFACF and uint32(0) != 0xCEFAEDFE
    and filesize < 30KB
}

rule Methodology_Suspicious_Shortcut_WorkingDirRemote_SMB
{
  meta:
    author = "@itsreallynick (Nick Carr)"
    description = "Detects possible shortcut usage for .URL persistence"
    reference = "https://twitter.com/cglyer/status/1176184798248919044"
    score = 50
    date = "27.09.2019"
    id = "26e19fe3-c25c-53b0-9b41-c04803134bc2"
  strings:
    $icon = "WorkingDirectory=file://" nocase
    $url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
    $url_explicit = "[InternetShortcut]" nocase
  condition:
    $icon and any of ($url*)
    and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32(0) != 0xBEBAFECA and uint32(0) != 0xFEEDFACE and uint32(0) != 0xFEEDFACF and uint32(0) != 0xCEFAEDFE
    and filesize < 30KB
}
