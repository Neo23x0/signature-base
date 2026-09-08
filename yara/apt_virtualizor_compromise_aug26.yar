rule APT_Virtualizor_Compromise_ForensicArtifacts_Aug26 {
   meta:
      description = "Detects forensic artifacts found in a campaign against compromised hosting providers using Virtualizor software"
      author = "Florian Roth"
      date = "2026-08-31"
      reference = "https://lowendtalk.com/discussion/220625/urgent-virtualizor-compromised-31st-aug/p1"
      score = 75
   strings:
      $x1 = "AAAAC3NzaC1lZDI1NTE5AAAAIP13pPAm5jmInLQYD3XNb3HwrW4cAKDcphoT4kSKrnte"
      $x2 = "/tmp/.vz_svc_done"
      $x3 = "/tmp/widdow.jar"
      $x4 = "31.77.220.138:2025"  // Java connection

      $sa1 = "proxyuser"
      $sb1 = "193.32.127.248"
   condition:
      filesize < 5MB
      and (
         1 of ($x*)
         or all of ($s*)
      )
}

rule APT_Virtualizor_Compromise_Payload_Aug26 {
   meta:
      description = "Detects java based payload used in a campaign against compromised hosting providers using Virtualizor software"
      author = "Jonathan Peters (cod3nym)"
      date = "2026-08-31"
      reference = "https://lowendtalk.com/discussion/220625/urgent-virtualizor-compromised-31st-aug/p1"
      hash = "b81a4e1fab9fc4e404d57224fe71e2c143aa93942bd46998789bdc944a7870c7"
      score = 80
   strings:
      $s1 = "net/ikvm/clientvds/stresser/methods/impl/l4/minecraft/protocollib/" ascii
      $s2 = "oshi/util/VirtualizationDetector" ascii
      $s3 = "META-INF/proguard/base.proUT" ascii
   condition:
      uint16(0) == 0x4b50
      and filesize < 20MB
      and all of them
}
