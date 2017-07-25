/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-07-23
   Identifier: Operation Wilted Tulip
   Reference: http://www.clearskysec.com/tulip
*/

import "pe"

/* Rule Set ----------------------------------------------------------------- */

rule WiltedTulip_Tools_back {
   meta:
      description = "Detects Chrome password dumper used in Operation Wilted Tulip"
      author = "Florian Roth"
      reference = "http://www.clearskysec.com/tulip"
      date = "2017-07-23"
      hash1 = "b7faeaa6163e05ad33b310a8fdc696ccf1660c425fa2a962c3909eada5f2c265"
   strings:
      $x1 = "%s.exe -f \"C:\\Users\\Admin\\Google\\Chrome\\TestProfile\" -o \"c:\\passlist.txt\"" fullword ascii
      $x2 = "\\ChromePasswordDump\\Release\\FireMaster.pdb" fullword ascii
      $x3 = "//Dump Chrome Passwords to a Output file \"c:\\passlist.txt\"" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and 1 of them )
}

rule WiltedTulip_Tools_clrlg {
   meta:
      description = "Detects Windows eventlog cleaner used in Operation Wilted Tulip - file clrlg.bat"
      author = "Florian Roth"
      reference = "http://www.clearskysec.com/tulip"
      date = "2017-07-23"
      hash1 = "b33fd3420bffa92cadbe90497b3036b5816f2157100bf1d9a3b6c946108148bf"
   strings:
      $s1 = "('wevtutil.exe el') DO (call :do_clear" fullword ascii
      $s2 = "wevtutil.exe cl %1" fullword ascii
   condition:
      filesize < 1KB and 1 of them
}

rule WiltedTulip_powershell {
   meta:
      description = "Detects powershell script used in Operation Wilted Tulip"
      author = "Florian Roth"
      reference = "http://www.clearskysec.com/tulip"
      date = "2017-07-23"
      hash1 = "e5ee1f45cbfdb54b02180e158c3c1f080d89bce6a7d1fe99dd0ff09d47a36787"
   strings:
      $x1 = "powershell.exe -nop -w hidden -c if([IntPtr]::Size -eq 4){$b='powershell.exe'}else{$b=$env:windir+" ascii
   condition:
      1 of them
}

rule WiltedTulip_vminst {
   meta:
      description = "Detects malware used in Operation Wilted Tulip"
      author = "Florian Roth"
      reference = "http://www.clearskysec.com/tulip"
      date = "2017-07-23"
      hash1 = "930118fdf1e6fbffff579e65e1810c8d91d4067cbbce798c5401cf05d7b4c911"
   strings:
      $x1 = "\\C++\\Trojan\\Target\\" ascii

      $s1 = "%s\\system32\\rundll32.exe" fullword wide
      $s2 = "$C:\\Windows\\temp\\l.tmp" fullword wide
      $s3 = "%s\\svchost.exe" fullword wide
      $s4 = "args[10] is %S and command is %S" fullword ascii
      $s5 = "LOGON USER FAILD " fullword ascii
      $s6 = "vminst.tmp" fullword wide
      $s7 = "operator co_await" fullword ascii
      $s8 = "?ReflectiveLoader@@YGKPAX@Z" fullword ascii
      $s9 = "%s -k %s" fullword wide
      $s10 = "ERROR in %S/%d" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and (
         ( 1 of ($x*) or 5 of ($s*) ) or
         pe.exports("?ReflectiveLoader@@YGKPAX@Z")
      )
}

rule WiltedTulip_Windows_UM_Task {
   meta:
      description = "Detects a Windows scheduled task as used in Operation Wilted Tulip"
      author = "Florian Roth"
      reference = "http://www.clearskysec.com/tulip"
      date = "2017-07-23"
      hash1 = "4c2fc21a4aab7686877ddd35d74a917f6156e48117920d45a3d2f21fb74fedd3"
   strings:
      $r1 = "<Command>C:\\Windows\\syswow64\\rundll32.exe</Command>" fullword wide
      $p1 = "<Arguments>\"C:\\Users\\public\\" wide
      $c1 = "svchost64.swp\",checkUpdate" wide ascii
      $c2 = "svchost64.swp,checkUpdate" wide ascii
   condition:
      ( $r1 and $p1 ) or
      1 of ($c*)
}

rule WiltedTulip_WindowsTask {
   meta:
      description = "Detects hack tool used in Operation Wilted Tulip - Windows Tasks"
      author = "Florian Roth"
      reference = "http://www.clearskysec.com/tulip"
      date = "2017-07-23"
      hash1 = "c3cbe88b82cd0ea46868fb4f2e8ed226f3419fc6d4d6b5f7561e70f4cd33822c"
      hash2 = "340cbbffbb7685133fc318fa20e4620ddf15e56c0e65d4cf1b2d606790d4425d"
      hash3 = "b6f515b3f713b70b808fc6578232901ffdeadeb419c9c4219fbfba417bba9f01"
      hash4 = "5046e7c28f5f2781ed7a63b0871f4a2b3065b70d62de7254491339e8fe2fa14a"
      hash5 = "984c7e1f76c21daf214b3f7e131ceb60c14abf1b0f4066eae563e9c184372a34"
   strings:
      $x1 = "<Command>C:\\Windows\\svchost.exe</Command>" fullword wide
      $x2 = "<Arguments>-nop -w hidden -encodedcommand" wide
      $x3 = "-encodedcommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgA"
   condition:
      1 of them
}

rule WiltedTulip_tdtess {
   meta:
      description = "Detects malicious service used in Operation Wilted Tulip"
      author = "Florian Roth"
      reference = "http://www.clearskysec.com/tulip"
      date = "2017-07-23"
      hash1 = "3fd28b9d1f26bd0cee16a167184c9f4a22fd829454fd89349f2962548f70dc34"
   strings:
      $x1 = "d2lubG9naW4k" fullword wide /* base64 encoded string 'winlogin$' */
      $x2 = "C:\\Users\\admin\\Documents\\visual studio 2015\\Projects\\Export\\TDTESS_ShortOne\\WinService Template\\" ascii

      $s1 = "\\WinService Template\\obj\\x64\\x64\\winlogin" ascii
      $s2 = "winlogin.exe" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and ( 1 of ($x*) or 2 of them ) )
}

rule WiltedTulip_SilverlightMSI {
   meta:
      description = "Detects powershell tool call Get_AD_Users_Logon_History used in Operation Wilted Tulip"
      author = "Florian Roth"
      reference = "http://www.clearskysec.com/tulip"
      date = "2017-07-23"
      hash1 = "c75906dbc3078ff81092f6a799c31afc79b1dece29db696b2ecf27951a86a1b2"
   strings:
      $x1 = ".\\Get_AD_Users_Logon_History.ps1 -MaxEvent" fullword ascii
      $x2 = "if ((Resolve-dnsname $_.\"IP Address\" -Type PTR -TcpOnly -DnsOnly -ErrorAction \"SilentlyContinue\").Type -eq \"PTR\")" fullword ascii
      $x3 = "$Client_Name = (Resolve-dnsname $_.\"IP Address\" -Type PTR -TcpOnly -DnsOnly).NameHost  " fullword ascii
      $x4 = "########## Find the Computer account in AD and if not found, throw an exception ###########" fullword ascii
   condition:
      ( filesize < 20KB and 1 of them )
}

rule WiltedTulip_matryoshka_Injector {
   meta:
      description = "Detects hack tool used in Operation Wilted Tulip"
      author = "Florian Roth"
      reference = "http://www.clearskysec.com/tulip"
      date = "2017-07-23"
      hash1 = "c41e97b3b22a3f0264f10af2e71e3db44e53c6633d0d690ac4d2f8f5005708ed"
      hash2 = "b93b5d6716a4f8eee450d9f374d0294d1800784bc99c6934246570e4baffe509"
   strings:
      $s1 = "Injector.dll" fullword ascii
      $s2 = "ReflectiveLoader" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and all of them ) or
      (
        pe.exports("__dec") and
        pe.exports("_check") and
        pe.exports("_dec") and
        pe.exports("start") and
        pe.exports("test")
      )
}

rule WiltedTulip_Zpp {
   meta:
      description = "Detects hack tool used in Operation Wilted Tulip"
      author = "Florian Roth"
      reference = "http://www.clearskysec.com/tulip"
      date = "2017-07-23"
      hash1 = "10ec585dc1304436821a11e35473c0710e844ba18727b302c6bd7f8ebac574bb"
      hash2 = "7d046a3ed15035ea197235980a72d133863c372cc27545af652e1b2389c23918"
      hash3 = "6d6816e0b9c24e904bc7c5fea5951d53465c478cc159ab900d975baf8a0921cf"
   strings:
      $x1 = "[ERROR] Error Main -i -s -d -gt -lt -mb" fullword wide
      $x2 = "[ERROR] Error Main -i(with.) -s -d -gt -lt -mb -o -e" fullword wide

      $s1 = "LT Time invalid" fullword wide
      $s2 = "doCompressInNetWorkDirectory" fullword ascii
      $s3 = "files remaining ,total file save = " fullword wide
      $s4 = "$ec996350-79a4-477b-87ae-2d5b9dbe20fd" fullword ascii
      $s5 = "Destinition Directory Not Found" fullword wide
      $s6 = "\\obj\\Release\\ZPP.pdb" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 30KB and ( 1 of ($x*) or 3 of them )
}

rule WiltedTulip_Netsrv_netsrvs {
   meta:
      description = "Detects sample from Operation Wilted Tulip"
      author = "Florian Roth"
      reference = "http://www.clearskysec.com/tulip"
      date = "2017-07-23"
      hash1 = "a062cb4364125427b54375d51e9e9afb0baeb09b05a600937f70c9d6d365f4e5"
      hash2 = "afa563221aac89f96c383f9f9f4ef81d82c69419f124a80b7f4a8c437d83ce77"
      hash3 = "acf24620e544f79e55fd8ae6022e040257b60b33cf474c37f2877c39fbf2308a"
      hash4 = "bff115d5fb4fd8a395d158fb18175d1d183c8869d54624c706ee48a1180b2361"
      hash5 = "07ab795eeb16421a50c36257e6e703188a0fef9ed87647e588d0cd2fcf56fe43"
   strings:
      $s1 = "Process %d Created" fullword ascii
      $s2 = "%s\\system32\\rundll32.exe" fullword wide
      $s3 = "%s\\SysWOW64\\rundll32.exe" fullword wide

      $c1 = "slbhttps" fullword ascii
      $c2 = "/slbhttps" fullword wide
      $c3 = "/slbdnsk1" fullword wide
      $c4 = "netsrv" fullword wide
      $c5 = "/slbhttps" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( all of ($s*) and 1 of ($c*) ) )
}

rule WiltedTulip_ReflectiveLoader {
   meta:
      description = "Detects reflective loader (Cobalt Strike) used in Operation Wilted Tulip"
      author = "Florian Roth"
      reference = "http://www.clearskysec.com/tulip"
      date = "2017-07-23"
      hash1 = "1097bf8f5b832b54c81c1708327a54a88ca09f7bdab4571f1a335cc26bbd7904"
      hash2 = "1f52d643e8e633026db73db55eb1848580de00a203ee46263418f02c6bdb8c7a"
      hash3 = "a159a9bfb938de686f6aced37a2f7fa62d6ff5e702586448884b70804882b32f"
      hash4 = "cf7c754ceece984e6fa0d799677f50d93133db609772c7a2226e7746e6d046f0"
      hash5 = "eee430003e7d59a431d1a60d45e823d4afb0d69262cc5e0c79f345aa37333a89"
   strings:
      $x1 = "powershell -nop -exec bypass -EncodedCommand \"%s\"" fullword ascii
      $x2 = "%d is an x86 process (can't inject x64 content)" fullword ascii
      $x3 = "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/'); %s" fullword ascii
      $x4 = "Failed to impersonate token from %d (%u)" fullword ascii
      $x5 = "Failed to impersonate logged on user %d (%u)" fullword ascii
      $x6 = "%s.4%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and 1 of them ) or
      ( 2 of them ) or
      pe.exports("_ReflectiveLoader@4")
}

rule WiltedTulip_Matryoshka_RAT {
   meta:
      description = "Detects Matryoshka RAT used in Operation Wilted Tulip"
      author = "Florian Roth"
      reference = "http://www.clearskysec.com/tulip"
      date = "2017-07-23"
      hash1 = "6f208473df0d31987a4999eeea04d24b069fdb6a8245150aa91dfdc063cd64ab"
      hash2 = "6cc1f4ecd28b833c978c8e21a20a002459b4a6c21a4fbaad637111aa9d5b1a32"
   strings:
      $s1 = "%S:\\Users\\public" fullword wide
      $s2 = "ntuser.dat.swp" fullword wide
      $s3 = "Job Save / Load Config" fullword wide
      $s4 = ".?AVPSCL_CLASS_JOB_SAVE_CONFIG@@" fullword ascii
      $s5 = "winupdate64.com" fullword ascii
      $s6 = "Job Save KeyLogger" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and 3 of them )
}
