import "pe"

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-10-18
   Identifier: HKDoor
   Reference: https://www.cylance.com/en_us/blog/threat-spotlight-opening-hackers-door.html
*/

rule hkdoor_backdoor_dll {
   meta:
      description = "Hacker's Door Backdoor DLL"
      author = "Cylance Inc."
      reference = "https://www.cylance.com/en_us/blog/threat-spotlight-opening-hackers-door.html"
   strings:
      $s1 = "The version of personal hacker's door server is" fullword ascii
      $s2 = "The connect back interval is %d (minutes)" fullword ascii
      $s3 = "I'mhackeryythac1977" fullword ascii
      $s4 = "Welcome to http://www.yythac.com" fullword ascii
      $s5 = "SeLoadDriverPrivilege" fullword ascii
   condition:
      uint16(0) == 0x5a4d and
      filesize < 400KB and
      ( 3 of ($s*) ) and
      pe.characteristics & pe.DLL and
      pe.imports("ws2_32.dll", "WSAStartup") and
      pe.imports("ws2_32.dll", "sendto")
}

rule hkdoor_backdoor {
   meta:
      description = "Hacker's Door Backdoor"
      author = "Cylance Inc."
      reference = "https://www.cylance.com/en_us/blog/threat-spotlight-opening-hackers-door.html"
   strings:
      $s1 = "http://www.yythac.com" fullword ascii
      $s2 = "Example:%s 192.168.1.100 139 -p yyt_hac -t 1" fullword ascii
      $s3 = "password-----------The hacker's door's password" fullword ascii
      $s4 = "It is the client of hacker's door %d.%d public version" fullword ascii
      $s5 = "hkdoordll.dll" fullword ascii
      $s6 = "http://www.yythac.com/images/mm.jpg" fullword ascii
      $s7 = "I'mhackeryythac1977" fullword ascii
      $s8 = "yythac.yeah.net" fullword ascii
   condition:
      uint16(0) == 0x5a4d and
      filesize < 400KB and
      ( 4 of ($s*) )
}

rule hkdoor_dropper {
   meta:
      description = "Hacker's Door Dropper"
      author = "Cylance Inc."
      reference = "https://www.cylance.com/en_us/blog/threat-spotlight-opening-hackers-door.html"
   strings:
      $s1 = "The version of personal hacker's door server is" fullword ascii
      $s2 = "The connect back interval is %d (minutes)" fullword ascii
      $s3 = "I'mhackeryythac1977" fullword ascii
      $s4 = "Welcome to http://www.yythac.com" fullword ascii
      $s5 = "SeLoadDriverPrivilege" fullword ascii
      $s6 = "\\drivers\\ntfs.sys" fullword ascii
      $s7 = "kifes" fullword ascii
   condition:
      uint16(0) == 0x5a4d and
      filesize < 1000KB and
      ( 4 of ($s*) ) and
      pe.number_of_resources > 0 and
      for any i in (0..pe.number_of_resources - 1):
         (pe.resources[i].type_string == "B\x00I\x00N\x00" and
         uint16(pe.resources[i].offset) == 0x5A4D) and
      pe.imports("KERNEL32.dll", "FindResourceW") and
      pe.imports("KERNEL32.dll", "LoadResource")
}

rule hkdoor_driver {
   meta:
      description = "Hacker's Door Driver"
   strings:
      $s1 = "ipfltdrv.sys" fullword ascii
      $s2 = "Patch Success." fullword ascii
      $s3 = "\\DosDevices\\kifes" fullword ascii
      $s4 = "\\Device\\kifes" fullword ascii
      $s5 = {75 28 22 36 30 5b 4a 77 7b 58 4d 6c 3f 73 63 5e 38 47 7c 7d 7a 40 3a 41 2a 45 4e 44 79 64 67 6d 65 74 21 39 23 3c 20 49 43 69 4c 3b 31 57 2f 55 3e 26 59 62 61 54 53 5a 2d 25 78 35 5c 76 3d 34 27 6b 5f 72 2c 32 4f 2b 71 66 42 33 37 56 52 60 5d 29 4b 51 2e 6f 50 68 6e 6a 24 48 7e 46 70}
   condition:
      uint16(0) == 0x5a4d and
      pe.subsystem == pe.SUBSYSTEM_NATIVE and
      ( 4 of ($s*) )
}