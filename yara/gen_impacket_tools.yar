
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-04-07
   Identifier: Compiled Impacket Tools
*/

/* Rule Set ----------------------------------------------------------------- */

rule Impacket_Tools_tracer {
   meta:
      description = "Compiled Impacket Tools"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "e300339058a885475f5952fb4e9faaa09bb6eac26757443017b281c46b03108b"
   strings:
      $s1 = "btk85.dll" fullword ascii
      $s2 = "btcl85.dll" fullword ascii
      $s3 = "xtk\\unsupported.tcl" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 21000KB and all of them )
}

rule Impacket_Tools_wmiexec {
   meta:
      description = "Compiled Impacket Tools"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "19544863758341fe7276c59d85f4aa17094045621ca9c98f8a9e7307c290bad4"
   strings:
      $s1 = "bwmiexec.exe.manifest" fullword ascii
      $s2 = "swmiexec" fullword ascii
      $s3 = "\\yzHPlU=QA" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and 2 of them )
}

rule Impacket_Tools_sniffer {
   meta:
      description = "Compiled Impacket Tools"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "efff15e1815fb3c156678417d6037ddf4b711a3122c9b5bc2ca8dc97165d3769"
   strings:
      $s1 = "ssniffer" fullword ascii
      $s2 = "impacket.dhcp(" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 15000KB and all of them )
}

rule Impacket_Tools_mmcexec {
   meta:
      description = "Compiled Impacket Tools"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "263a1655a94b7920531e123a8c9737428f2988bf58156c62408e192d4b2a63fc"
   strings:
      $s1 = "smmcexec" fullword ascii
      $s2 = "\\yzHPlU=QA" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 16000KB and all of them )
}

rule Impacket_Tools_ifmap {
   meta:
      description = "Compiled Impacket Tools"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "20a1f11788e6cc98a76dca2db4691963c054fc12a4d608ac41739b98f84b3613"
   strings:
      $s1 = "bifmap.exe.manifest" fullword ascii
      $s2 = "impacket.dcerpc.v5.epm(" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 15000KB and all of them )
}

rule karmaSMB {
   meta:
      description = "Compiled Impacket Tools"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "d256d1e05695d62a86d9e76830fcbb856ba7bd578165a561edd43b9f7fdb18a3"
   strings:
      $s1 = "bkarmaSMB.exe.manifest" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and all of them )
}

rule samrdump {
   meta:
      description = "Compiled Impacket Tools"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "4c2921702d18e0874b57638433474e54719ee6dfa39d323839d216952c5c834a"
   strings:
      $s2 = "bsamrdump.exe.manifest" fullword ascii
      $s3 = "ssamrdump" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and all of them )
}

rule Impacket_Tools_rpcdump {
   meta:
      description = "Compiled Impacket Tools"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "21d85b36197db47b94b0f4995d07b040a0455ebbe6d413bc33d926ee4e0315d9"
   strings:
      $s1 = "srpcdump" fullword ascii
      $s2 = "impacket.dcerpc.v5.epm(" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and all of them )
}

rule Impacket_Tools_secretsdump {
   meta:
      description = "Compiled Impacket Tools"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "47afa5fd954190df825924c55112e65fd8ed0f7e1d6fd403ede5209623534d7d"
   strings:
      $s1 = "ssecretsdump" fullword ascii
      $s2 = "impacket.ese(" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and all of them )
}

rule Impacket_Tools_esentutl {
   meta:
      description = "Compiled Impacket Tools"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "70d854953d3ebb2c252783a4a103ba0e596d6ab447f238af777fb37d2b64c0cd"
   strings:
      $s1 = "impacket.ese(" fullword ascii
      $s2 = "sesentutl" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 11000KB and all of them )
}

rule Impacket_Tools_opdump {
   meta:
      description = "Compiled Impacket Tools"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "e2205539f29972d4e2a83eabf92af18dd406c9be97f70661c336ddf5eb496742"
   strings:
      $s2 = "bopdump.exe.manifest" fullword ascii
      $s3 = "sopdump" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and all of them )
}

rule Impacket_Tools_sniff {
   meta:
      description = "Compiled Impacket Tools"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "8ab2b60aadf97e921e3a9df5cf1c135fbc851cb66d09b1043eaaa1dc01b9a699"
   strings:
      $s1 = "ssniff" fullword ascii
      $s2 = "impacket.eap(" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 15000KB and all of them )
}

rule Impacket_Tools_smbexec {
   meta:
      description = "Compiled Impacket Tools"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "7d715217e23a471d42d95c624179fe7de085af5670171d212b7b798ed9bf07c2"
   strings:
      $s1 = "logging.config(" fullword ascii
      $s2 = "ssmbexec" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and all of them )
}

rule Impacket_Tools_goldenPac {
   meta:
      description = "Compiled Impacket Tools"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "4f7fad0676d3c3d2d89e8d4e74b6ec40af731b1ddf5499a0b81fc3b1cd797ee3"
   strings:
      $s1 = "impacket.examples.serviceinstall(" fullword ascii
      $s2 = "bgoldenPac.exe" fullword ascii
      $s3 = "json.scanner(" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and all of them )
}

rule Impacket_Tools_netview {
   meta:
      description = "Compiled Impacket Tools"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "ab909f8082c2d04f73d8be8f4c2640a5582294306dffdcc85e83a39d20c49ed6"
   strings:
      $s1 = "impacket.dcerpc.v5.wkst(" fullword ascii
      $s2 = "dummy_threading(" fullword ascii
      $s3 = "snetview" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and all of them )
}

rule Impacket_Tools_smbtorture {
   meta:
      description = "Compiled Impacket Tools"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "d2856e98011541883e5b335cb46b713b1a6b2c414966a9de122ee7fb226aa7f7"
   strings:
      $s1 = "impacket" fullword ascii
      $s2 = "ssmbtorture" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and all of them )
}

rule Impacket_Tools_mimikatz {
   meta:
      description = "Compiled Impacket Tools"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "2d8d500bcb3ffd22ddd8bd68b5b2ce935c958304f03729442a20a28b2c0328c1"
   strings:
      $s1 = "impacket" fullword ascii
      $s2 = "smimikatz" fullword ascii
      $s3 = "otwsdlc" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and all of them )
}

rule Impacket_Tools_smbrelayx {
   meta:
      description = "Compiled Impacket Tools"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "9706eb99e48e445ac4240b5acb2efd49468a800913e70e40b25c2bf80d6be35f"
   strings:
      $s1 = "impacket.examples.secretsdump" fullword ascii
      $s2 = "impacket.examples.serviceinstall" fullword ascii
      $s3 = "impacket.smbserver(" fullword ascii
      $s4 = "SimpleHTTPServer(" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 18000KB and 3 of them )
}

rule Impacket_Tools_wmipersist {
   meta:
      description = "Compiled Impacket Tools"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "2527fff1a3c780f6a757f13a8912278a417aea84295af1abfa4666572bbbf086"
   strings:
      $s1 = "swmipersist" fullword ascii
      $s2 = "\\yzHPlU=QA" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and all of them )
}

rule Impacket_Tools_lookupsid {
   meta:
      description = "Compiled Impacket Tools"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "47756725d7a752d3d3cfccfb02e7df4fa0769b72e008ae5c85c018be4cf35cc1"
   strings:
      $s1 = "slookupsid" fullword ascii
      $s2 = "impacket.dcerpc" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 15000KB and all of them )
}

rule Impacket_Tools_wmiquery {
   meta:
      description = "Compiled Impacket Tools"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "202a1d149be35d96e491b0b65516f631f3486215f78526160cf262d8ae179094"
   strings:
      $s1 = "swmiquery" fullword ascii
      $s2 = "\\yzHPlU=QA" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and all of them )
}

rule Impacket_Tools_atexec {
   meta:
      description = "Compiled Impacket Tools"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "337bd5858aba0380e16ee9a9d8f0b3f5bfc10056ced4e75901207166689fbedc"
   strings:
      $s1 = "batexec.exe.manifest" fullword ascii
      $s2 = "satexec" fullword ascii
      $s3 = "impacket.dcerpc" fullword ascii
      $s4 = "# CSZq" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 15000KB and 3 of them )
}

rule Impacket_Tools_psexec {
   meta:
      description = "Compiled Impacket Tools"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "27bb10569a872367ba1cfca3cf1c9b428422c82af7ab4c2728f501406461c364"
   strings:
      $s1 = "impacket.examples.serviceinstall(" fullword ascii
      $s2 = "spsexec" fullword ascii
      $s3 = "impacket.examples.remcomsvc(" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and 2 of them )
}

rule Impacket_Tools_Generic_1 {
   meta:
      description = "Compiled Impacket Tools"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      super_rule = 1
      hash1 = "4f7fad0676d3c3d2d89e8d4e74b6ec40af731b1ddf5499a0b81fc3b1cd797ee3"
      hash2 = "d256d1e05695d62a86d9e76830fcbb856ba7bd578165a561edd43b9f7fdb18a3"
      hash3 = "2d8d500bcb3ffd22ddd8bd68b5b2ce935c958304f03729442a20a28b2c0328c1"
      hash4 = "ab909f8082c2d04f73d8be8f4c2640a5582294306dffdcc85e83a39d20c49ed6"
      hash5 = "e2205539f29972d4e2a83eabf92af18dd406c9be97f70661c336ddf5eb496742"
      hash6 = "27bb10569a872367ba1cfca3cf1c9b428422c82af7ab4c2728f501406461c364"
      hash7 = "dc85a3944fcb8cc0991be100859c4e1bf84062f7428c4dc27c71e08d88383c98"
      hash8 = "0f7f0d8afb230c31fe6cf349c4012b430fc3d6722289938f7e33ea15b2996e1b"
      hash9 = "21d85b36197db47b94b0f4995d07b040a0455ebbe6d413bc33d926ee4e0315d9"
      hash10 = "4c2921702d18e0874b57638433474e54719ee6dfa39d323839d216952c5c834a"
      hash11 = "47afa5fd954190df825924c55112e65fd8ed0f7e1d6fd403ede5209623534d7d"
      hash12 = "7d715217e23a471d42d95c624179fe7de085af5670171d212b7b798ed9bf07c2"
      hash13 = "9706eb99e48e445ac4240b5acb2efd49468a800913e70e40b25c2bf80d6be35f"
      hash14 = "d2856e98011541883e5b335cb46b713b1a6b2c414966a9de122ee7fb226aa7f7"
      hash15 = "8ab2b60aadf97e921e3a9df5cf1c135fbc851cb66d09b1043eaaa1dc01b9a699"
      hash16 = "efff15e1815fb3c156678417d6037ddf4b711a3122c9b5bc2ca8dc97165d3769"
      hash17 = "e300339058a885475f5952fb4e9faaa09bb6eac26757443017b281c46b03108b"
      hash18 = "19544863758341fe7276c59d85f4aa17094045621ca9c98f8a9e7307c290bad4"
      hash19 = "2527fff1a3c780f6a757f13a8912278a417aea84295af1abfa4666572bbbf086"
      hash20 = "202a1d149be35d96e491b0b65516f631f3486215f78526160cf262d8ae179094"
   strings:
      $s1 = "bpywintypes27.dll" fullword ascii
      $s2 = "hZFtPC" fullword ascii
      $s3 = "impacket" ascii 
   condition:
      ( uint16(0) == 0x5a4d and filesize < 21000KB and all of ($s*) ) or ( all of them )
}
