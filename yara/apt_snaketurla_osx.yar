/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-05-04
   Identifier: Snake / Turla
   Reference: https://goo.gl/QaOh4V
*/

/* Rule Set ----------------------------------------------------------------- */

rule SnakeTurla_Malware_May17_1 {
   meta:
      description = "Detects Snake / Turla Sample"
      author = "Florian Roth"
      reference = "https://goo.gl/QaOh4V"
      date = "2017-05-04"
      hash1 = "5b7792a16c6b7978fca389882c6aeeb2c792352076bf6a064e7b8b90eace8060"
   strings:
      $s1 = "/Users/vlad/Desktop/install/install/" fullword ascii
   condition:
      ( uint16(0) == 0xfacf and filesize < 200KB and all of them )
}

rule SnakeTurla_Malware_May17_2 {
   meta:
      description = "Detects Snake / Turla Sample"
      author = "Florian Roth"
      reference = "https://goo.gl/QaOh4V"
      date = "2017-05-04"
      hash1 = "b8ee4556dc09b28826359b98343a4e00680971a6f8c6602747bd5d723d26eaea"
   strings:
      $s1 = "b_openssl: oops - number of mutexes is 0" fullword ascii
      $s2 = "networksetup -get%sproxy Ethernet" fullword ascii
      $s3 = "012A04DECBC441e49C527B2798F54CA7LOG_NAMED_PIPE_NAME" fullword ascii
   condition:
      ( uint16(0) == 0xfacf and filesize < 6000KB and all of them )
}

rule SnakeTurla_Malware_May17_3 {
   meta:
      description = "Detects Snake / Turla Sample"
      author = "Florian Roth"
      reference = "https://goo.gl/QaOh4V"
      date = "2017-05-04"
      hash1 = "7848f7808af02ba0466f3a0687cf949c4d29a2d94b035481a3299ec519aaaa30"
   strings:
      $x1 = "Addy Symonds1" ascii
      $x2 = "com.addy.InstallAdobeFlash" ascii
   condition:
      ( uint16(0) == 0xfacf and filesize < 3000KB and all of them )
}

rule SnakeTurla_Malware_May17_4 {
   meta:
      description = "Detects Snake / Turla Sample"
      author = "Florian Roth"
      reference = "https://goo.gl/QaOh4V"
      date = "2017-05-04"
      hash1 = "d5ea79632a1a67abbf9fb1c2813b899c90a5fb9442966ed4f530e92715087ee2"
   strings:
      $s1 = "Install Adobe Flash Player.app/com.adobe.updatePK" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and filesize < 5000KB and all of them )
}

rule SnakeTurla_Installd_SH {
   meta:
      description = "Detects Snake / Turla Sample"
      author = "Florian Roth"
      reference = "https://goo.gl/QaOh4V"
      date = "2017-05-04"
   strings:
      $s1 = "PIDS=`ps cax | grep installdp" ascii
      $s2 = "${SCRIPT_DIR}/installdp ${FILE}" ascii
   condition:
      ( uint16(0) == 0x2123 and filesize < 20KB and all of them )
}

rule SnakeTurla_Install_SH {
   meta:
      description = "Detects Snake / Turla Sample"
      author = "Florian Roth"
      reference = "https://goo.gl/QaOh4V"
      date = "2017-05-04"
   strings:
      $s1 = "${TARGET_PATH}/installd.sh" ascii
      $s2 = "$TARGET_PATH2/com.adobe.update.plist" ascii
   condition:
   ( uint16(0) == 0x2123 and filesize < 20KB and all of them )
}
