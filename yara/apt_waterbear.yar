/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-06-23
   Identifier: Waterbear
   Reference: https://goo.gl/L9g9eR
*/

/* Rule Set ----------------------------------------------------------------- */

rule Waterbear_1_Jun17 {
   meta:
      description = "Detects malware from Operation Waterbear"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/L9g9eR"
      date = "2017-06-23"
      hash1 = "dd3676f478ee6f814077a12302d38426760b0701bb629f413f7bf2ec71319db5"
   strings:
      $s1 = "\\Release\\svc.pdb" ascii
      $s2 = "svc.dll" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and all of them )
}

rule Waterbear_2_Jun17 {
   meta:
      description = "Detects malware from Operation Waterbear"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/L9g9eR"
      date = "2017-06-23"
      hash1 = "dcb5c350af76c590002a8ea00b01d862b4d89cccbec3908bfe92fdf25eaa6ea4"
   strings:
      $s1 = "downloading movie" fullword ascii
      $s2 = "name=\"test.exe\"/>" fullword ascii
      $s3 = "<description>Test Application</description>" fullword ascii
      $s4 = "UI look 2003" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and all of them )
}

rule Waterbear_4_Jun17 {
   meta:
      description = "Detects malware from Operation Waterbear"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/L9g9eR"
      date = "2017-06-23"
      hash1 = "2e9cb7cadb3478edc9ef714ca4ddebb45e99d35386480e12792950f8a7a766e1"
   strings:
      $x1 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1;)" fullword ascii

      $s1 = "Wininet.dll InternetOpenA InternetConnectA HttpOpenRequestA HttpSendRequestA HttpQueryInfoA InternetReadFile InternetCloseHandle" fullword ascii
      $s2 = "read from pipe:%s" fullword ascii
      $s3 = "delete pipe" fullword ascii
      $s4 = "cmdcommand:%s" fullword ascii
      $s5 = "%s /c del %s" fullword ascii
      $s6 = "10.0.0.250" fullword ascii
      $s7 = "Vista/2008" fullword ascii
      $s8 = "%02X%02X%02X%02X%02X%02X%04X" fullword ascii
      $s9 = "UNKOWN" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 3 of them )
}

rule Waterbear_5_Jun17 {
   meta:
      description = "Detects malware from Operation Waterbear"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/L9g9eR"
      date = "2017-06-23"
      hash1 = "d3678cd9744b3aedeba23a03a178be5b82d5f8059a86f816007789a9dd06dc7d"
   strings:
      $a1 = "ICESWORD" fullword ascii
      $a2 = "klog.dat" fullword ascii

      $s1 = "\\cswbse.dll" fullword ascii
      $s2 = "WIRESHARK" fullword ascii
      $s3 = "default_zz|" fullword ascii
      $s4 = "%c4%u-%.2u-%.2u %.2u:%.2u" fullword ascii
      $s5 = "1111%c%s" fullword ascii
   condition:
      ( uint16(0) == 0x3d53 and filesize < 100KB and ( all of ($a*) or 3 of them ) )
}

rule Waterbear_6_Jun17 {
   meta:
      description = "Detects malware from Operation Waterbear"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/L9g9eR"
      date = "2017-06-23"
      hash1 = "409cd490feb40d08eb33808b78d52c00e1722eee163b60635df6c6fe2c43c230"
   strings:
      $s1 = "svcdll.dll" fullword ascii
      $s2 = "log.log" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 60KB and all of them )
}

rule Waterbear_7_Jun17 {
   meta:
      description = "Detects malware from Operation Waterbear"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/L9g9eR"
      date = "2017-06-23"
      hash1 = "6891aa78524e442f4dda66dff51db9798e1f92e6fefcdf21eb870b05b0293134"
   strings:
      $s1 = "Bluthmon.exe" fullword wide
      $s2 = "Motomon.exe" fullword wide
      $s3 = "%d.%s%d%d%d" fullword ascii
      $s4 = "mywishes.hlp" fullword ascii
      $s5 = "filemon.rtf" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 80KB and all of them )
}

rule Waterbear_8_Jun17 {
   meta:
      description = "Detects malware from Operation Waterbear"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/L9g9eR"
      date = "2017-06-23"
      hash1 = "bd06f6117a0abf1442826179f6f5e1932047b4a6c14add9149e8288ab4a902c3"
      hash1 = "5dba8ddf05cb204ef320a72a0c031e55285202570d7883f2ff65135ec35b3dd0"
   strings:
      $s1 = "Update.dll" fullword ascii
      $s2 = "ADVPACK32.DLL" fullword wide
      $s3 = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\" fullword ascii
      $s4 = "\\drivers\\sftst.sys" fullword ascii
      $s5 = "\\\\.\\SFilter" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 40KB and all of them )
}

rule Waterbear_9_Jun17 {
   meta:
      description = "Detects malware from Operation Waterbear"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/L9g9eR"
      date = "2017-06-23"
      hash1 = "fc74d2434d48b316c9368d3f90fea19d76a20c09847421d1469268a32f59664c"
   strings:
      $s1 = "ADVPACK32.DLL" fullword wide
      $s2 = "ADVPACK32" fullword wide

      $a1 = "U2_Dll.dll" fullword ascii

      $b1 = "ProUpdate" fullword ascii
      $b2 = "Update.dll" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 30KB and all of ($s*) and ( $a1 or all of ($b*) )
}

rule Waterbear_10_Jun17 {
   meta:
      description = "Detects malware from Operation Waterbear"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/L9g9eR"
      date = "2017-06-23"
      hash1 = "3b1e67e0e86d912d7bc6dee5b0f801260350e8ce831c93c3e9cfe5a39e766f41"
   strings:
      $s1 = "ADVPACK32.DLL" fullword wide
      $s5 = "ADVPACK32" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 30KB and all of them )
}


rule Waterbear_11_Jun17 {
   meta:
      description = "Detects malware from Operation Waterbear"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/L9g9eR"
      date = "2017-06-23"
      hash1 = "b046b2e2569636c2fc3683a0da8cfad25ff47bc304145be0f282a969c7397ae8"
   strings:
      $s1 = "/Pages/%u.asp" fullword wide
      $s2 = "NVIDIA Corporation." fullword wide
      $s3 = "tqxbLc|fP_{eOY{eOX{eO" fullword ascii
      $s4 = "Copyright (C) 2005" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and all of them )
}

rule Waterbear_12_Jun17 {
   meta:
      description = "Detects malware from Operation Waterbear"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/L9g9eR"
      date = "2017-06-23"
      hash1 = "15d9db2c90f56cd02be38e7088db8ec00fc603508ec888b4b85d60d970966585"
   strings:
      $s1 = "O_PROXY" fullword ascii
      $s2 = "XMODIFY" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and all of them )
}

rule Waterbear_13_Jun17 {
   meta:
      description = "Detects malware from Operation Waterbear"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/L9g9eR"
      date = "2017-06-23"
      super_rule = 1
      hash1 = "734e5972ab5ac1e9bc5470c666a55e0d2bd57c4e2ea2da11dc9bf56fb2ea6f23"
      hash2 = "8bde3f71575aa0d5f5a095d9d0ea10eceadba38be888e10d3ca3776f7b361fe7"
      hash3 = "c4b3b0a7378bfc3824d4178fd7fb29475c42ab874d69abdfb4898d0bcd4f8ce1"
   strings:
      $s1 = "%WINDIR%\\PCHealth\\HelpCtr\\Binaries\\pchsvc.dll" fullword ascii
      $s2 = "brnew.exe" fullword ascii
      $s3 = "ChangeServiceConfig failed (%d)" fullword ascii
      $s4 = "Proxy %d:%s %d" fullword ascii
      $s5 = "win9807.tmp" fullword ascii
      $s7 = "Service stopped successfully" fullword ascii
      $s8 = "current dns:%s" fullword ascii
      $s9 = "%c%u|%u|%u|%u|%u|" fullword ascii
      $s10 = "[-]send %d: " fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 4 of them )
}

rule Waterbear_14_Jun17 {
   meta:
      description = "Detects malware from Operation Waterbear"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/L9g9eR"
      date = "2017-06-23"
      hash1 = "00a1068645dbe982a9aa95e7b8202a588989cd37de2fa1b344abbc0102c27d05"
      hash2 = "53330a80b3c4f74f3f10a8621dbef4cd2427723e8b98c5b7aed58229d0c292ba"
      hash3 = "bdcb23a82ac4eb1bc9254d77d92b6f294d45501aaea678a3d21c8b188e31e68b"
   strings:
      $s1 = "my.com/msg/util/sgthash" fullword ascii
      $s2 = "C:\\recycled" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and all of them )
}
