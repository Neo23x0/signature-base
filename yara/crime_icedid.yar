rule MAL_IcedID_Fake_GZIP_Bokbot_202104 {
   meta:
      author = "Thomas Barabosch, Telekom Security"
      date = "2021-04-20"
      description = "Detects fake gzip provided by CC"
      reference = "https://www.telekom.com/en/blog/group/article/let-s-set-ice-on-fire-hunting-and-detecting-icedid-infections-627240"
   strings:
      $gzip = {1f 8b 08 08 00 00 00 00 00 00 75 70 64 61 74 65}
   condition:
      $gzip at 0
}

rule MAL_IcedID_GZIP_LDR_202104 {
   meta:
      author = "Thomas Barabosch, Telekom Security"
      date = "2021-04-12"
      modified = "2023-01-27"
      description = "2021 initial Bokbot / Icedid loader for fake GZIP payloads"
      reference = "https://www.telekom.com/en/blog/group/article/let-s-set-ice-on-fire-hunting-and-detecting-icedid-infections-627240"
   strings:
      $internal_name = "loader_dll_64.dll" fullword

      $string0 = "_gat=" wide
      $string1 = "_ga=" wide
      $string2 = "_gid=" wide
      $string4 = "_io=" wide
      $string5 = "GetAdaptersInfo" fullword
      $string6 = "WINHTTP.dll" fullword
      $string7 = "DllRegisterServer" fullword
      $string8 = "PluginInit" fullword
      $string9 = "POST" wide fullword
      $string10 = "aws.amazon.com" wide fullword
   condition:
      uint16(0) == 0x5a4d and
      filesize < 5000KB and 
      ( $internal_name or all of ($s*) )
      or all of them
}

rule MAL_IcedId_Core_LDR_202104 {
   meta:
      author = "Thomas Barabosch, Telekom Security"
      date = "2021-04-13"
      description = "2021 loader for Bokbot / Icedid core (license.dat)"
      reference = "https://www.telekom.com/en/blog/group/article/let-s-set-ice-on-fire-hunting-and-detecting-icedid-infections-627240"
   strings:
      $internal_name = "sadl_64.dll" fullword

      $string0 = "GetCommandLineA" fullword
      $string1 = "LoadLibraryA" fullword
      $string2 = "ProgramData" fullword
      $string3 = "SHLWAPI.dll" fullword
      $string4 = "SHGetFolderPathA" fullword
      $string5 = "DllRegisterServer" fullword
      $string6 = "update" fullword
      $string7 = "SHELL32.dll" fullword
      $string8 = "CreateThread" fullword
   condition:
      uint16(0) == 0x5a4d and
      filesize < 5000KB and 
      ( $internal_name and 5 of them )
      or all of them
}

rule MAL_IceId_Core_202104 {
   meta:
      author = "Thomas Barabosch, Telekom Security"
      date = "2021-04-12"
      description = "2021 Bokbot / Icedid core"
      reference = "https://www.telekom.com/en/blog/group/article/let-s-set-ice-on-fire-hunting-and-detecting-icedid-infections-627240"
   strings:
      $internal_name = "fixed_loader64.dll" fullword

      $string0 = "mail_vault" wide fullword
      $string1 = "ie_reg" wide fullword
      $string2 = "outlook" wide fullword
      $string3 = "user_num" wide fullword
      $string4 = "cred" wide fullword
      $string5 = "Authorization: Basic" fullword
      $string6 = "VaultOpenVault" fullword
      $string7 = "sqlite3_free" fullword
      $string8 = "cookie.tar" fullword
      $string9 = "DllRegisterServer" fullword
      $string10 = "PT0S" wide
   condition:
      uint16(0) == 0x5a4d and
      filesize < 5000KB and 
      ( $internal_name or all of ($s*) )
      or all of them
}
