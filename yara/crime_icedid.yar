rule MAL_IcedID_Unpacked_202401 {
  meta:
      author = "0x0d4y"
      description = "This rule detects samples from the IcedID family unpacked in memory, identifying code reuse of key functions."
      date = "2024-01-09"
      score = 90
      reference = "https://0x0d4y.blog/icedid-technical-analysis/"
      sample_reference_md5 = "5692c5708c71d0916ca48662a7ea9caf"
      uuid = "53918024-6212-4ad0-8870-7f83b3b1eaf3"
      license = "CC BY 4.0"
      rule_matching_tlp = "TLP:WHITE"
      rule_sharing_tlp = "TLP:WHITE"
      malpedia_family = "win.icedid"
    strings:
    $hardware_info_collect_code_pattern = { 
        B8 00 00 00 40 0F A2 89 06 0F B6 44 24 16 89 5E 04 89 4E 08 89 56 0C FF 74 24 28 50 0F B6 44 24 1F 50 0F B6 44 24 24 50 0F B6 44 24 29 50 0F B6 44 24 2E 50 0F B6 44 24 33 50 68 ?? ?? 40 00
        }
    $ksa_prga_pattern = { 
        51 51 53 55 56 8B EA 89 4C 24 10 33 D2 57 8B 7C 24 1C 8B C2 88 04 38 40 3D 00 01 00 00 72 F5 8A CA 8B DA 8B 44 24 14 0F B6 F2 8A 14 3B 8A 04 06 02 C2 02 C8 88 4C 24 13 0F B6 C9 8A 04 39 88 04 3B 8D 46 01 88 14 39 33 D2 8A 4C 24 13 F7 F5 43 81 FB 00 01 00 00 
        }
    $xor_operation_pattern = {
        FE C3 0F B6 DB 8A 4C 1C 14 0F B6 D1 02 C2 0F B6 C0 89 44 24 10 8A 44 04 14 88 44 1C 14 8B 44 24 10 88 4C 04 14 8A 44 1C 14 02 C2 0F B6 C0 8A 44 04 14 32 04 3E 88 07 
        }
    $related_string1 = "WinHttpConnect"
    $related_string2 = "VirtualAlloc"
    $related_string3 = "WriteFile"
    $related_string4 = "CreateFileA"
    $related_string5 = "lstrcpyA"
    $related_string6 = "ProgramData"
    $related_string7 = "c:\\Users\\Public\\"
    $related_string8 = "%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.8X"
    $related_string9 = "%0.2X%0.8X%0.8X"
    condition:
        uint16(0) == 0x5a4d and
        ($hardware_info_collect_code_pattern or
        $ksa_prga_pattern or
        $xor_operation_pattern) or
        8 of ($related_string*)
}

rule MAL_IcedID_Fake_GZIP_Bokbot_202104 {
   meta:
      author = "Thomas Barabosch, Telekom Security"
      date = "2021-04-20"
      description = "Detects fake gzip provided by CC"
      reference = "https://www.telekom.com/en/blog/group/article/let-s-set-ice-on-fire-hunting-and-detecting-icedid-infections-627240"
      id = "538d84d8-aff2-571c-ba60-102f18262434"
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
      id = "fbf578e7-c318-5f67-82df-f93232362a23"
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
      id = "f096e18d-3a31-5236-b3c3-0df39b408d9a"
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
      id = "526a73da-415f-58fe-bb5f-4c3df6b2e647"
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
