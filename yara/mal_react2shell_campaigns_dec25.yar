rule MAL_ZinFoq_Dec25 {
   meta:
      description = "Detects ZinFoq Go-based Linux post-exploitation implant (interactive shell + file ops/exfil) seen in React2Shell intrusions"
      author = "RussianPanda"
      date = "2025-12-08"
      score = 85
      reference = "https://www.huntress.com/blog/peerblight-linux-backdoor-exploits-react2shell"
      hash = "0f0f9c339fcc267ec3d560c7168c56f607232cbeb158cb02a0818720a54e72ce"
   strings:
      $s1 = "_FlAg_UuId;;;;;;"
      $s2 = "interactive_shell"
      $s3 = "explorer_download"
   condition:
      uint32(0) == 0x464c457f and all of them
}

rule HKTL_CowTunnel_Dec25 {
   meta:
      description = "Detects CowTunnel Linux reverse-proxy tunnel (NSS wrapper + FRP client) used for outbound access/pivoting in React2Shell activity"
      author = "RussianPanda"
      date = "2025-12-08"
      score = 85
      reference = "https://www.huntress.com/blog/peerblight-linux-backdoor-exploits-react2shell"
      hash = "776850a1e6d6915e9bf35aa83554616129acd94e3a3f6673bd6ddaec530f4273"
   strings:
      $s1 = "cannot create proxy service, it should not happenned!"
      $s2 = "[nss] encrypt_data"
      $s3 = "[nss] decrypt_data"
   condition:
      uint32(0) == 0x464c457f and all of them
}

rule MAL_PeerBlight_Dec25 {
   meta:
      description = "Detects PeerBlight Linux backdoor with systemd persistence artifacts and user-mode masquerading strings, linked to React2Shell exploitation"
      author = "RussianPanda"
      date = "2025-12-07"
      score = 85
      reference = "https://www.huntress.com/blog/peerblight-linux-backdoor-exploits-react2shell"
      hash = "a605a70d031577c83c093803d11ec7c1e29d2ad530f8e95d9a729c3818c7050d"
   strings:
      $s1 = "/bin/systemd-daemon"
      $s2 = "/lib/systemd/system/systemd-agent.service"
      $s3 = "group"
      $s4 = "tag"
      $s5 = "arch"
      $s6 = "softirq"
   condition:
      uint32(0) == 0x464c457f and 5 of them
}
