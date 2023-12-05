
/* NCSC rules
   slightly modified by Florian Roth for memory usage reasons
*/

rule APT_Sandworm_CyclopsBlink_notable_strings {
   meta:
      author = "NCSC"
      description = "Detects notable strings identified within the Cyclops Blink executable"
      hash1 = "3adf9a59743bc5d8399f67cab5eb2daf28b9b863"
      hash2 = "c59bc17659daca1b1ce65b6af077f86a648ad8a8"
      reference = "https://www.ncsc.gov.uk/news/joint-advisory-shows-new-sandworm-malware-cyclops-blink-replaces-vpnfilter"
      date = "2022-02-23"
      id = "81ccf582-41f5-5fe5-8afc-e008e01289ff"
   strings:
      // Process names masqueraded by implant
      $proc_name1 = "[kworker/0:1]"
      $proc_name2 = "[kworker/1:1]"
      // DNS query over SSL, used to resolve C2 server address
      $dns_query = "POST /dns-query HTTP/1.1\x0d\x0aHost: dns.google\x0d\x0a"
      // iptables commands
      $iptables1 = "iptables -I %s -p tcp --dport %d -j ACCEPT &>/dev/null"
      $iptables2 = "iptables -D %s -p tcp --dport %d -j ACCEPT &>/dev/null"
      // Format strings used for system recon
      $sys_recon1 = "{\"ver\":\"%x\",\"mods\";["
      $sys_recon2 = "uptime: %lu mem_size: %lu mem_free: %lu"
      $sys_recon3 = "disk_size: %lu disk_free: %lu"
      $sys_recon4 = "hw: %02x:%02x:%02x:%02x:%02x:%02x"
      // Format string for filepath used to test access to device filesystem
      $testpath = "%s/214688dsf46"
      // Format string for implant configuration filepath
      $confpath = "%s/rootfs_cfg"
      // Default file download path
      $downpath = "/var/tmp/a.tmp"
   condition:
      (uint32(0) == 0x464c457f) and (8 of them)
}

rule APT_Sandworm_CyclopsBlink_module_initialisation {
   meta:
      author = "NCSC"
      description = "Detects the code bytes used to initialise the modules built into Cyclops Blink"
      hash1 = "3adf9a59743bc5d8399f67cab5eb2daf28b9b863"
      hash2 = "c59bc17659daca1b1ce65b6af077f86a648ad8a8"
      reference = "https://www.ncsc.gov.uk/news/joint-advisory-shows-new-sandworm-malware-cyclops-blink-replaces-vpnfilter"
      date = "2022-02-23"
      id = "c81b92c4-3f70-5bbd-acfa-ed1e1d33461d"
   strings:
      // Module initialisation code bytes, simply returning the module ID
      // to the caller
      $ = {94 21 FF F0 93 E1 00 08 7C 3F 0B 78 38 00 00 ?? 7C 03
      03 78 81 61 00 00 8E EB FF F8 7D 61 5B 78 4E 80 00 20}
   condition:
      (uint32(0) == 0x464c457f) and (any of them)
}

rule APT_Sandworm_CyclopsBlink_modified_install_upgrade {
   meta:
      author = "NCSC"
      description = "Detects notable strings identified within the modified install_upgrade executable, embedded within Cyclops Blink"
      hash1 = "3adf9a59743bc5d8399f67cab5eb2daf28b9b863"
      hash2 = "c59bc17659daca1b1ce65b6af077f86a648ad8a8"
      hash3 = "7d61c0dd0cd901221a9dff9df09bb90810754f10"
      hash4 = "438cd40caca70cafe5ca436b36ef7d3a6321e858"
      reference = "https://www.ncsc.gov.uk/news/joint-advisory-shows-new-sandworm-malware-cyclops-blink-replaces-vpnfilter"
      date = "2022-02-23"
      id = "4c4f7262-df74-5f6a-afc0-df1fcae4741c"
   strings:
      // Format strings used for temporary filenames
      $ = "/pending/%010lu_%06d_%03d_p1"
      $ = "/pending/sysa_code_dir/test_%d_%d_%d_%d_%d_%d"
      // Hard-coded key used to initialise HMAC calculation
      $ = "etaonrishdlcupfm"
      // Filepath used to store the patched firmware image
      $ = "/pending/WGUpgrade-dl.new"
      // Filepath of legitimate install_upgrade executable
      $ = "/pending/bin/install_upgraded"
      // Loop device IOCTL LOOP_SET_FD
      $ = {38 80 4C 00}
      // Loop device IOCTL LOOP_GET_STATUS64
      $ = {38 80 4C 05}
      // Loop device IOCTL LOOP_SET_STATUS64
      $ = {38 80 4C 04}
      // Firmware HMAC record starts with the string "HMAC"
      $ = {3C 00 48 4D 60 00 41 43 90 09 00 00}
   condition:
      (uint32(0) == 0x464c457f) and (6 of them)
}

rule APT_Sandworm_CyclopsBlink_core_command_check {
   meta:
      author = "NCSC"
      description = "Detects the code bytes used to test the command ID being sent to the core component of Cyclops Blink"
      hash1 = "3adf9a59743bc5d8399f67cab5eb2daf28b9b863"
      hash2 = "c59bc17659daca1b1ce65b6af077f86a648ad8a8"
      reference = "https://www.ncsc.gov.uk/news/joint-advisory-shows-new-sandworm-malware-cyclops-blink-replaces-vpnfilter"
      date = "2022-02-23"
      id = "46066474-7647-52fb-b40d-30ff8e285b6e"
   strings:
      // Check for command ID equals 0x7, 0xa, 0xb, 0xc or 0xd
      $cmd_check = {81 3F 00 18 88 09 00 05 54 00 06 3E 2F 80 00 (07|0A|0B|0C|0D) }
   condition:
      (uint32(0) == 0x464c457f) and (#cmd_check == 5)
}

rule APT_Sandworm_CyclopsBlink_config_identifiers {
   meta:
      author = "NCSC"
      description = "Detects the initial characters used to identify Cyclops Blink configuration data"
      hash1 = "3adf9a59743bc5d8399f67cab5eb2daf28b9b863"
      hash2 = "c59bc17659daca1b1ce65b6af077f86a648ad8a8"
      reference = "https://www.ncsc.gov.uk/news/joint-advisory-shows-new-sandworm-malware-cyclops-blink-replaces-vpnfilter"
      date = "2022-02-23"
      id = "db5b3a4a-82c2-500a-88f6-340b3392eac8"
   strings:
      // Main config parameter data starts with the string "<p: "
      //$ = "<p: " fullword  // short atom - not necessary
      // RSA public key data starts with the string "<k: "
      $ = {3C 00 3C 6B 60 00 3A 20 90 09 00 00}
      // X.509 certificate data starts with the string "<c: "
      $ = {3C 00 3C 63 60 00 3A 20 90 09 00 00}
      // RSA private key data starts with the string "<s: "
      $ = {3C 00 3C 73 60 00 3A 20 90 09 00 00}
   condition:
      (uint32(0) == 0x464c457f) and (all of them)
}

rule APT_Sandworm_CyclopsBlink_handle_mod_0xf_command {
   meta:
      author = "NCSC"
      description = "Detects the code bytes used to check module ID 0xf control flags and a format string used for file content upload"
      hash1 = "3adf9a59743bc5d8399f67cab5eb2daf28b9b863"
      hash2 = "c59bc17659daca1b1ce65b6af077f86a648ad8a8"
      reference = "https://www.ncsc.gov.uk/news/joint-advisory-shows-new-sandworm-malware-cyclops-blink-replaces-vpnfilter"
      date = "2022-02-23"
      id = "36646b7a-389d-5fd9-88a1-e43e7224763a"
   strings:
      // Tests execute flag (bit 0)
      $ = {54 00 06 3E 54 00 07 FE 54 00 06 3E 2F 80 00 00}
      // Tests add module flag (bit 1)
      $ = {54 00 06 3E 54 00 07 BC 2F 80 00 00}
      // Tests run as shellcode flag (bit 2)
      $ = {54 00 06 3E 54 00 07 7A 2F 80 00 00}
      // Tests upload flag (bit 4)
      $ = {54 00 06 3E 54 00 06 F6 2F 80 00 00}
      // Upload format string
      $ = "file:%s\n" fullword
   condition:
      (uint32(0) == 0x464c457f) and (all of them)
}

rule APT_Sandworm_CyclopsBlink_default_config_values {
   meta:
      author = "NCSC"
      description = "Detects the code bytes used to set default Cyclops Blink configuration values"
      hash1 = "3adf9a59743bc5d8399f67cab5eb2daf28b9b863"
      hash2 = "c59bc17659daca1b1ce65b6af077f86a648ad8a8"
      reference = "https://www.ncsc.gov.uk/news/joint-advisory-shows-new-sandworm-malware-cyclops-blink-replaces-vpnfilter"
      date = "2022-02-23"
      id = "04067609-1173-51f2-907f-2a236aae6c7c"
   strings:
      // Unknown config value set to 0x19
      $ = {38 00 00 19 90 09 01 A4}
      // Unknown config value set to 0x18000
      $ = {3C 00 00 01 60 00 80 00 90 09 01 A8}
      // Unknown config value set to 0x4000
      $ = {38 00 40 00 90 09 01 AC}
      // Unknown config value set to 0x10b
      $ = {38 00 01 0B 90 09 01 B0}
      // Unknown config value set to 0x2711
      $ = {38 00 27 11 90 09 01 C0}
   condition:
      (uint32(0) == 0x464c457f) and (3 of them)
}

rule APT_Sandworm_CyclopsBlink_handle_mod_0x51_command {
   meta:
      author = "NCSC"
      description = "Detects the code bytes used to check commands sent to module ID 0x51 and notable strings relating to the Cyclops Blink update process"
      hash1 = "3adf9a59743bc5d8399f67cab5eb2daf28b9b863"
      hash2 = "c59bc17659daca1b1ce65b6af077f86a648ad8a8"
      reference = "https://www.ncsc.gov.uk/news/joint-advisory-shows-new-sandworm-malware-cyclops-blink-replaces-vpnfilter"
      date = "2022-02-23"
      id = "a6800aed-27dc-5d01-b005-1eb4a62344a3"
   strings:
      // Check for module command ID equals 0x1, 0x2 or 0x3
      $cmd_check = {88 1F [2] 54 00 06 3E 2F 80 00 (01|02|03) }
      // Legitimate WatchGuard filepaths relating to device configuration
      $path1 = "/etc/wg/configd-hash.xml"
      $path2 = "/etc/wg/config.xml"
      // Mount arguments used to remount root filesystem as RW or RO
      $mnt_arg1 = "ext2"
      $mnt_arg2 = "errors=continue"
      $mnt_arg3 = {38 C0 0C 20}
      $mnt_arg4 = {38 C0 0C 21}
   condition:
      (uint32(0) == 0x464c457f) and (#cmd_check == 3) and
      ((@cmd_check[3] - @cmd_check[1]) < 0x200) and
      (all of ($path*)) and (all of ($mnt_arg*))
}
