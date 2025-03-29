
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-04-07
   Identifier: Compiled Impacket Tools
*/

/* Rule Set ----------------------------------------------------------------- */

/* already covered by : Impacket_Tools_Generic_1
rule Impacket_Tools_tracer {
   meta:
      description = "Compiled Impacket Tools"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      modified = "2021-07-15"
      hash1 = "e300339058a885475f5952fb4e9faaa09bb6eac26757443017b281c46b03108b"
   strings:
      $s1 = "btk85.dll" fullword ascii
      $s2 = "btcl85.dll" fullword ascii
      $s3 = "xtk\\unsupported.tcl" fullword ascii

      $fp1 = "Linden Research Inc" wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 21000KB and all of ($s*) )
      and not 1 of ($fp*)
}
*/

rule Impacket_Tools_wmiexec {
   meta:
      description = "Compiled Impacket Tools"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "19544863758341fe7276c59d85f4aa17094045621ca9c98f8a9e7307c290bad4"
      id = "3c2c7edf-da71-53dc-9ddf-dfbf10838a27"
   strings:
      $s1 = "bwmiexec.exe.manifest" fullword ascii
      $s2 = "swmiexec" fullword ascii
      $s3 = "\\yzHPlU=QA" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and 2 of them )
}

rule Impacket_Tools_sniffer {
   meta:
      description = "Compiled Impacket Tools"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "efff15e1815fb3c156678417d6037ddf4b711a3122c9b5bc2ca8dc97165d3769"
      id = "07051edc-91a8-59d6-87bf-dba98ef28588"
   strings:
      $s1 = "ssniffer" fullword ascii
      $s2 = "impacket.dhcp(" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 15000KB and all of them )
}

rule Impacket_Tools_mmcexec {
   meta:
      description = "Compiled Impacket Tools"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "263a1655a94b7920531e123a8c9737428f2988bf58156c62408e192d4b2a63fc"
      id = "cca2082f-72a4-50c8-80b8-a9bed430dc4e"
   strings:
      $s1 = "smmcexec" fullword ascii
      $s2 = "\\yzHPlU=QA" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 16000KB and all of them )
}

rule Impacket_Tools_ifmap {
   meta:
      description = "Compiled Impacket Tools"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "20a1f11788e6cc98a76dca2db4691963c054fc12a4d608ac41739b98f84b3613"
      id = "e5461916-ec2b-5f65-b938-267483f50bb2"
   strings:
      $s1 = "bifmap.exe.manifest" fullword ascii
      $s2 = "impacket.dcerpc.v5.epm(" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 15000KB and all of them )
}

rule karmaSMB {
   meta:
      description = "Compiled Impacket Tools"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "d256d1e05695d62a86d9e76830fcbb856ba7bd578165a561edd43b9f7fdb18a3"
      id = "32c810c7-02e7-5203-b2ed-4e930b318cc0"
   strings:
      $s1 = "bkarmaSMB.exe.manifest" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and all of them )
}

rule samrdump {
   meta:
      description = "Compiled Impacket Tools"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "4c2921702d18e0874b57638433474e54719ee6dfa39d323839d216952c5c834a"
      id = "cd274719-c8cc-5882-8d75-192ad822c6b3"
   strings:
      $s2 = "bsamrdump.exe.manifest" fullword ascii
      $s3 = "ssamrdump" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and all of them )
}

rule Impacket_Tools_rpcdump {
   meta:
      description = "Compiled Impacket Tools"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "21d85b36197db47b94b0f4995d07b040a0455ebbe6d413bc33d926ee4e0315d9"
      id = "3f998aa6-c260-5fef-99ef-e8b4770c68c6"
   strings:
      $s1 = "srpcdump" fullword ascii
      $s2 = "impacket.dcerpc.v5.epm(" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and all of them )
}

rule Impacket_Tools_secretsdump {
   meta:
      description = "Compiled Impacket Tools"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "47afa5fd954190df825924c55112e65fd8ed0f7e1d6fd403ede5209623534d7d"
      id = "c944d051-ea24-5595-abef-59e326ad56de"
   strings:
      $s1 = "ssecretsdump" fullword ascii
      $s2 = "impacket.ese(" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and all of them )
}

rule Impacket_Tools_esentutl {
   meta:
      description = "Compiled Impacket Tools"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "70d854953d3ebb2c252783a4a103ba0e596d6ab447f238af777fb37d2b64c0cd"
      id = "1965e2b3-54be-553a-83d6-a0d4919414dd"
   strings:
      $s1 = "impacket.ese(" ascii
      $s2 = "sesentutl" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 11000KB and all of them )
}

rule Impacket_Tools_opdump {
   meta:
      description = "Compiled Impacket Tools"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "e2205539f29972d4e2a83eabf92af18dd406c9be97f70661c336ddf5eb496742"
      id = "1bb0e747-e9b7-5a54-8052-428351be8d0d"
   strings:
      $s2 = "bopdump.exe.manifest" fullword ascii
      $s3 = "sopdump" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and all of them )
}

rule Impacket_Tools_sniff {
   meta:
      description = "Compiled Impacket Tools"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "8ab2b60aadf97e921e3a9df5cf1c135fbc851cb66d09b1043eaaa1dc01b9a699"
      id = "07051edc-91a8-59d6-87bf-dba98ef28588"
   strings:
      $s1 = "ssniff" fullword ascii
      $s2 = "impacket.eap(" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 15000KB and all of them )
}

rule Impacket_Tools_smbexec {
   meta:
      description = "Compiled Impacket Tools"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "7d715217e23a471d42d95c624179fe7de085af5670171d212b7b798ed9bf07c2"
      id = "02208817-2eab-54e2-90cf-44dbf5474607"
   strings:
      $s1 = "logging.config(" ascii
      $s2 = "ssmbexec" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and all of them )
}

rule Impacket_Tools_goldenPac {
   meta:
      description = "Compiled Impacket Tools"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "4f7fad0676d3c3d2d89e8d4e74b6ec40af731b1ddf5499a0b81fc3b1cd797ee3"
      id = "9894d16c-83fa-5e1d-9ca6-572deeec006a"
   strings:
      $s1 = "impacket.examples.serviceinstall(" ascii
      $s2 = "bgoldenPac.exe" fullword ascii
      $s3 = "json.scanner(" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and all of them )
}

rule Impacket_Tools_netview {
   meta:
      description = "Compiled Impacket Tools"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "ab909f8082c2d04f73d8be8f4c2640a5582294306dffdcc85e83a39d20c49ed6"
      id = "1b9238d2-b9b1-5633-8481-05a3a97af5a6"
   strings:
      $s1 = "impacket.dcerpc.v5.wkst(" ascii
      $s2 = "dummy_threading(" ascii
      $s3 = "snetview" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and all of them )
}

rule Impacket_Tools_smbtorture {
   meta:
      description = "Compiled Impacket Tools"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "d2856e98011541883e5b335cb46b713b1a6b2c414966a9de122ee7fb226aa7f7"
      id = "4f9b55e2-93ce-5d08-a228-73233fb0a2c6"
   strings:
      $s1 = "impacket" fullword ascii
      $s2 = "ssmbtorture" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and all of them )
}

rule Impacket_Tools_mimikatz {
   meta:
      description = "Compiled Impacket Tools"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "2d8d500bcb3ffd22ddd8bd68b5b2ce935c958304f03729442a20a28b2c0328c1"
      id = "0b1f5ad0-7070-58d5-946f-157dcb9627ab"
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
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "9706eb99e48e445ac4240b5acb2efd49468a800913e70e40b25c2bf80d6be35f"
      id = "84abf3cf-841c-592d-a9d1-71d5e76eb43f"
   strings:
      $s1 = "impacket.examples.secretsdump" fullword ascii
      $s2 = "impacket.examples.serviceinstall" fullword ascii
      $s3 = "impacket.smbserver(" ascii
      $s4 = "SimpleHTTPServer(" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 18000KB and 3 of them )
}

rule Impacket_Tools_wmipersist {
   meta:
      description = "Compiled Impacket Tools"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "2527fff1a3c780f6a757f13a8912278a417aea84295af1abfa4666572bbbf086"
      id = "29bda652-28f0-5ab6-9bc2-411f20ab0dda"
   strings:
      $s1 = "swmipersist" fullword ascii
      $s2 = "\\yzHPlU=QA" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and all of them )
}

rule Impacket_Tools_lookupsid {
   meta:
      description = "Compiled Impacket Tools"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "47756725d7a752d3d3cfccfb02e7df4fa0769b72e008ae5c85c018be4cf35cc1"
      id = "27f13397-b044-54b4-b5e8-c5f7ed374f59"
   strings:
      $s1 = "slookupsid" fullword ascii
      $s2 = "impacket.dcerpc" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 15000KB and all of them )
}

rule Impacket_Tools_wmiquery {
   meta:
      description = "Compiled Impacket Tools"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "202a1d149be35d96e491b0b65516f631f3486215f78526160cf262d8ae179094"
      id = "e8bdf27a-9763-5947-854f-162f74ff53be"
   strings:
      $s1 = "swmiquery" fullword ascii
      $s2 = "\\yzHPlU=QA" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and all of them )
}

rule Impacket_Tools_atexec {
   meta:
      description = "Compiled Impacket Tools"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "337bd5858aba0380e16ee9a9d8f0b3f5bfc10056ced4e75901207166689fbedc"
      id = "4f02e304-69d4-5952-80be-793379bccac0"
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
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "27bb10569a872367ba1cfca3cf1c9b428422c82af7ab4c2728f501406461c364"
      id = "5e8d0964-7e6a-5ff6-b9db-e37f997c3e05"
   strings:
      $s1 = "impacket.examples.serviceinstall(" ascii
      $s2 = "spsexec" fullword ascii
      $s3 = "impacket.examples.remcomsvc(" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and 2 of them )
}

rule Impacket_Tools_Generic_1 {
   meta:
      description = "Compiled Impacket Tools"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
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
      id = "d2ce6426-d165-5569-a992-268f05622653"
   strings:
      $s1 = "bpywintypes27.dll" fullword ascii
      $s2 = "hZFtPC" fullword ascii
      $s3 = "impacket" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 21000KB and all of ($s*) ) or ( all of them )
}

rule Impacket_Lateral_Movement {
   meta:
      description = "Detects Impacket Network Aktivity for Lateral Movement"
      author = "Markus Neis"
      reference = "https://github.com/CoreSecurity/impacket"
      date = "2018-03-22"
      score = 60
      id = "44db234c-ac81-5d21-bc2a-8cfd88807c0d"
   strings:
      $s1 = "impacket.dcerpc.v5.transport(" ascii
      $s2 = "impacket.smbconnection(" ascii
      $s3 = "impacket.dcerpc.v5.ndr(" ascii
      $s4 = "impacket.spnego(" ascii
      $s5 = "impacket.smb(" ascii
      $s6 = "impacket.ntlm(" ascii
      $s7 = "impacket.nmb(" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 14000KB and 2 of them
}
