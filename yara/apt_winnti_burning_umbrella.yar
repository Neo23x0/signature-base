/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2018-05-04
   Identifier: Burning Umbrella
   Reference: https://401trg.pw/burning-umbrella/
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule MAL_BurningUmbrella_Sample_1 {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      hash1 = "fcfe8fcf054bd8b19226d592617425e320e4a5bb4798807d6f067c39dfc6d1ff"
   strings:
      $s1 = { 40 00 00 E0 75 68 66 61 6F 68 6C 79 }
      $s2 = { 40 00 00 E0 64 6A 7A 66 63 6D 77 62 }
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and (
         pe.imphash() == "baa93d47220682c04d92f7797d9224ce" and
         $s1 in (0..1024) and
         $s2 in (0..1024)
      )
}

rule MAL_BurningUmbrella_Sample_2 {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      hash1 = "801a64a730fc8d80e17e59e93533c1455686ca778e6ba99cf6f1971a935eda4c"
   strings:
      $s1 = { 40 00 00 E0 63 68 72 6F 6D 67 75 78 }
      $s2 = { 40 00 00 E0 77 62 68 75 74 66 6F 61 }
      $s3 = "ActiveX Manager" wide
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      $s1 in (0..1024) and
      $s2 in (0..1024) and
      $s3
}

rule MAL_BurningUmbrella_Sample_3 {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      hash1 = "92efbecc24fbb5690708926b6221b241b10bdfe3dd0375d663b051283d0de30f"
   strings:
      $s1 = "HKEY_CLASSES_ROOT\\Word.Document.8\\shell\\Open\\command" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and 1 of them
}

rule MAL_BurningUmbrella_Sample_4 {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      hash1 = "a1629e8abce9d670fdb66fa1ef73ad4181706eefb8adc8a9fd257b6a21be48c6"
   strings:
      $x1 = "dumpodbc.exe" fullword ascii
      $x2 = "photo_Bundle.exe" fullword ascii
      $x3 = "Connect 2 fails : %d,%s:%d" fullword ascii
      $x4 = "Connect fails 1 : %d %s:%d" fullword ascii
      $x5 = "New IP : %s,New Port: %d" fullword ascii
      $x6 = "Micrsoft Corporation. All rights reserved." fullword wide
      $x7 = "New ConFails : %d" fullword ascii

      $s1 = "cmd /c net stop stisvc" fullword ascii
      $s2 = "cmd /c net stop spooler" fullword ascii
      $s3 = "\\temp\\s%d.dat" fullword ascii
      $s4 = "cmd /c net stop wuauserv" fullword ascii
      $s5 = "User-Agent: MyApp/0.1" fullword ascii
      $s6 = "%s->%s Fails : %d" fullword ascii
      $s7 = "Enter WorkThread,Current sock:%d" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 50KB and (
         ( pe.exports("Print32") and 2 of them ) or
         1 of ($x*) or
         4 of them
      )
}

rule MAL_BurningUmbrella_Sample_6 {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      hash1 = "49ef2b98b414c321bcdbab107b8fa71a537958fe1e05ae62aaa01fe7773c3b4b"
   strings:
      $s1 = "ExecuteFile=\"hidcon:nowait:\\\"Word\\\\r.bat\\\"\"" fullword ascii
      $s2 = "InstallPath=\"%Appdata%\\\\Microsoft\"" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and 1 of them
}

rule MAL_BurningUmbrella_Sample_7 {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      hash1 = "a4ce3a356d61fbbb067e1430b8ceedbe8965e0cfedd8fb43f1f719e2925b094a"
      hash2 = "a8bfc1e013f15bc395aa5c047f22ff2344c343c22d420804b6d2f0a67eb6db64"
      hash3 = "959612f2a9a8ce454c144d6aef10dd326b201336a85e69a604e6b3892892d7ed"
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and pe.imphash() == "f5b113d6708a3927b5cc48f2215fcaff"
}

rule MAL_BurningUmbrella_Sample_8 {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      hash1 = "73270fe9bca94fead1b5b38ddf69fae6a42e574e3150d3e3ab369f5d37d93d88"
   strings:
      $s1 = "cmd /c open %s" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and 1 of them
}

rule MAL_BurningUmbrella_Sample_10 {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      hash1 = "70992a72412c5d62d003a29c3967fcb0687189d3290ebbc8671fa630829f6694"
      hash2 = "48f0bbc3b679aac6b1a71c06f19bb182123e74df8bb0b6b04ebe99100c57a41e"
      hash3 = "5475ae24c4eeadcbd49fcd891ce64d0fe5d9738f1c10ba2ac7e6235da97d3926"
   strings:
      $s1 = "revjj.syshell.org" fullword ascii
      /* $s2 = "Kernel.dll" fullword ascii */
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and all of them
}

rule MAL_BurningUmbrella_Sample_11 {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      hash1 = "278e9d130678615d0fee4d7dd432f0dda6d52b0719649ee58cbdca097e997c3f"
   strings:
      $s1 = "Resume.app/Contents/Java/Resume.jarPK" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 700KB and 1 of them
}

rule MAL_BurningUmbrella_Sample_12 {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      hash1 = "b9aba520eeaf6511877c1eec5f7d71e0eea017312a104f30d3b8f17c89db47e8"
   strings:
      $s1 = "%SystemRoot%\\System32\\qmgr.dll" fullword ascii
      $s2 = "rundll32.exe %s,Startup" fullword ascii
      $s3 = "nvsvcs.dll" fullword wide
      $s4 = "SYSTEM\\CurrentControlSet\\services\\BITS\\Parameters" fullword ascii
      $s5 = "http://www.sginternet.net 0" fullword ascii
      $s6 = "Microsoft Corporation. All rights reserved." fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 80KB and (
         pe.exports("SvcServiceMain") and
         5 of them
      )
}

rule MAL_BurningUmbrella_Sample_13 {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      hash1 = "d31374adc0b96a8a8b56438bbbc313061fd305ecee32a12738dd965910c8890f"
      hash2 = "c74a8e6c88f8501fb066ae07753efe8d267afb006f555811083c51c7f546cb67"
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and pe.imphash() == "75f201aa8b18e1c4f826b2fe0963b84f"
}

rule MAL_BurningUmbrella_Sample_14 {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      hash1 = "388ef4b4e12a04eab451bd6393860b8d12948f2bce12e5c9022996a9167f4972"
   strings:
      $s1 = "C:\\tmp\\Google_updata.exe" fullword ascii
      /* $s2 = "Kernel.dll" fullword ascii */
   condition:
      uint16(0) == 0x5a4d and filesize < 40KB and 1 of them
}

rule MAL_BurningUmbrella_Sample_15 {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      hash1 = "be6bea22e909bd772d21647ffee6d15e208e386e8c3c95fd22816c6b94196ae8"
      hash2 = "72a8fa454f428587d210cba0e74735381cd0332f3bdcbb45eecb7e271e138501"
      hash3 = "9cc38ea106efd5c8e98c2e8faf97c818171c52fa3afa0c4c8f376430fa556066"
      hash4 = "1a4a64f01b101c16e8b5928b52231211e744e695f125e056ef7a9412da04bb91"
      hash5 = "3cd42e665e21ed4815af6f983452cbe7a4f2ac99f9ea71af4480a9ebff5aa048"
   condition:
      uint16(0) == 0x5a4d and filesize < 50KB and pe.imphash() == "cc33b1500354cf785409a3b428f7cd2a"
}

rule MAL_BurningUmbrella_Sample_16 {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      hash1 = "58bb3859e02b8483e9f84cc56fbd964486e056ef28e94dd0027d361383cc4f4a"
   strings:
      $s1 = "http://netimo.net 0" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and all of them
}

rule MAL_BurningUmbrella_Sample_17 {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      hash1 = "fa380dac35e16da01242e456f760a0e75c2ce9b68ff18cfc7cfdd16b2f4dec56"
      hash2 = "854b64155f9ceac806b49f3e352949cc292e5bc33f110d965cf81a93f78d2f07"
      hash3 = "1e462d8968e8b6e8784d7ecd1d60249b41cf600975d2a894f15433a7fdf07a0f"
      hash4 = "3cdc149e387ec4a64cce1191fc30b8588df4a2947d54127eae43955ce3d08a01"
      hash5 = "a026b11e15d4a81a449d20baf7cbd7b8602adc2644aa4bea1e55ff1f422c60e3"
   strings:
      $s1 = "syshell" fullword wide
      $s2 = "Normal.dotm" fullword ascii
      $s3 = "Microsoft Office Word" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and all of them
}

rule MAL_BurningUmbrella_Sample_18 {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      hash1 = "d8df60524deb6df4f9ddd802037a248f9fbdd532151bb00e647b233e845b1617"
      hash2 = "c55cb6b42cfabf0edf1499d383817164d1b034895e597068e019c19d787ea313"
      hash3 = "32144ba8370826e069e5f1b6745a3625d10f50a809f3f2a72c4c7644ed0cab03"
      hash4 = "ae616003d85a12393783eaff9778aba20189e423c11c852e96c29efa6ecfce81"
      hash5 = "95b6e427883f402db73234b84a84015ad7f3456801cb9bb19df4b11739ea646d"
      hash6 = "1419ba36aae1daecc7a81a2dfb96631537365a5b34247533d59a70c1c9f58da2"
      hash7 = "6a5a9b0ae10ce6a0d5e1f7d21d8ea87894d62d0cda00db005d8d0de17cae7743"
      hash8 = "74e348068f8851fec1b3de54550fe09d07fb85b7481ca6b61404823b473885bb"
      hash9 = "adb9c2fe930fae579ce87059b4b9e15c22b6498c42df01db9760f75d983b93b2"
      hash0 = "23f28b5c4e94d0ad86341c0b9054f197c63389133fcd81dd5e0cf59f774ce54b"
   strings:
      $s1 = "c:\\tmp\\tran.exe" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and (
         pe.imphash() == "11675b4db0e7df7b29b1c1ef6f88e2e1" or
         pe.imphash() == "364e1f68e2d412db34715709c68ba467" or
         pe.exports("deKernel") or
         1 of them
      )
}

rule MAL_BurningUmbrella_Sample_19 {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      hash1 = "05e2912f2a593ba16a5a094d319d96715cbecf025bf88bb0293caaf6beb8bc20"
      hash2 = "e7bbdb275773f43c8e0610ad75cfe48739e0a2414c948de66ce042016eae0b2e"
   strings:
      $s1 = "Cryption.dll" fullword ascii
      $s2 = "tran.exe" fullword ascii
      $s3 = "Kernel.dll" fullword ascii
      $s4 = "Now ready to get the file %s!" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and 3 of them
}

rule MAL_BurningUmbrella_Sample_20 {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      hash1 = "5c12379cd7ab3cb03dac354d0e850769873d45bb486c266a893c0daa452aa03c"
      hash2 = "172cd90fd9e31ba70e47f0cc76c07d53e512da4cbfd197772c179fe604b75369"
      hash3 = "1ce88e98c8b37ea68466657485f2c01010a4d4a88587ba0ae814f37680a2e7a8"
   strings:
      $s1 = "Wordpad.Document.1\\shell\\open\\command\\" fullword wide
      $s2 = "%s\\shell\\Open\\command" fullword wide
      $s3 = "expanding computer" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and (
         pe.imphash() == "bac338bfe2685483c201e15eae4352d5" or
         2 of them
      )
}

rule MAL_BurningUmbrella_Sample_21 {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      hash1 = "4b7b9c2a9d5080ccc4e9934f2fd14b9d4e8f6f500889bf9750f1d672c8724438"
   strings:
      $s1 = "c:\\windows\\ime\\setup.exe" fullword ascii
      $s2 = "ws.run \"later.bat /start\",0Cet " fullword ascii
      $s3 = "del later.bat" fullword ascii
      $s4 = "mycrs.xls" fullword ascii

      $a1 = "-el -s2 \"-d%s\" \"-p%s\" \"-sp%s\"" fullword ascii
      $a2 = "<set ws=wscript.createobject(\"wscript.shell\")" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and 2 of them
}

rule MAL_BurningUmbrella_Sample_22 {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      hash1 = "fa116cf9410f1613003ca423ad6ca92657a61b8e9eda1b05caf4f30ca650aee5"
   strings:
      $s1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\" fullword ascii
      $s3 = "Content-Disposition: form-data; name=\"txt\"; filename=\"" fullword ascii
      $s4 = "Fail To Enum Service" fullword ascii
      $s5 = "Host Power ON Time" fullword ascii
      $s6 = "%d Hours %2d Minutes %2d Seconds " fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and 4 of them
}


rule MAL_AirdViper_Sample_Apr18_1 {
   meta:
      description = "Detects Arid Viper malware sample"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-05-04"
      hash1 = "9f453f1d5088bd17c60e812289b4bb0a734b7ad2ba5a536f5fd6d6ac3b8f3397"
   strings:
      $x1 = "cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del \"%s\"" fullword ascii
      $x2 = "daenerys=%s&" ascii
      $x3 = "betriebssystem=%s&anwendung=%s&AV=%s" ascii

      $s1 = "Taskkill /IM  %s /F &  %s" fullword ascii
      $s2 = "/api/primewire/%s/requests/macKenzie/delete" fullword ascii
      $s3 = "\\TaskWindows.exe" ascii
      $s4 = "MicrosoftOneDrives.exe" fullword ascii
      $s5 = "\\SeanSansom.txt" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and (
         1 of ($x*) or
         4 of them
      )
}

/* Generic Rules ------------------------------------ */

rule MAL_Winnti_Sample_May18_1 {
   meta:
      description = "Detects malware sample from Burning Umbrella report - Generic Winnti Rule"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      hash1 = "528d9eaaac67716e6b37dd562770190318c8766fa1b2f33c0974f7d5f6725d41"
   strings:
      $s1 = "wireshark" fullword wide
      $s2 = "procexp" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and all of them
}

rule MAL_Visel_Sample_May18_1 {
   meta:
      description = "Detects Visel malware sample from Burning Umbrella report"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      hash1 = "35db8e6a2eb5cf09cd98bf5d31f6356d0deaf4951b353fc513ce98918b91439c"
   strings:
      $s2 = "print32.dll" fullword ascii
      $s3 = "c:\\a\\b.txt" fullword ascii
      $s4 = "\\temp\\s%d.dat" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and (
         pe.exports("szFile") or
         2 of them
      )
}
