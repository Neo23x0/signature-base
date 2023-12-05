/*
	Yara Rule Set
	Author: Airbus Defence and Space Cybersecurity CSIRT - Fabien Perigaud
	Date: 2015-12-09
   Reference = http://blog.airbuscybersecurity.com/post/2015/11/Newcomers-in-the-Derusbi-family
	Identifier: Derusbi Dez 2015
*/

rule derusbi_kernel
{
    meta:
        description = "Derusbi Driver version"
        date = "2015-12-09"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Fabien Perigaud"
        id = "a60ab93a-e2be-53ee-a7da-56c763bc5533"
    strings:
        $token1 = "$$$--Hello"
        $token2 = "Wrod--$$$"
        $class = ".?AVPCC_BASEMOD@@"
    condition:
        uint16(0) == 0x5A4D and $token1 and $token2 and $class
}

rule derusbi_linux
{
    meta:
        description = "Derusbi Server Linux version"
        date = "2015-12-09"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Fabien Perigaud"
        id = "2b33afb5-be87-5d41-b05e-b99d0c1d8ed9"
    strings:
        $PS1 = "PS1=RK# \\u@\\h:\\w \\$"
        $cmd = "unset LS_OPTIONS;uname -a"
        $pname = "[diskio]"
        $rkfile = "/tmp/.secure"
        $ELF = "\x7fELF"
    condition:
        $ELF at 0 and $PS1 and $cmd and $pname and $rkfile
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-12-15
	Identifier: Derusbi Dez 2015
*/

rule Derusbi_Kernel_Driver_WD_UDFS {
	meta:
		description = "Detects Derusbi Kernel Driver"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://blog.airbuscybersecurity.com/post/2015/11/Newcomers-in-the-Derusbi-family"
		date = "2015-12-15"
		score = 80
		hash1 = "1b449121300b0188ff9f6a8c399fb818d0cf53fd36cf012e6908a2665a27f016"
		hash2 = "50174311e524b97ea5cb4f3ea571dd477d1f0eee06cd3ed73af39a15f3e6484a"
		hash3 = "6cdb65dbfb2c236b6d149fd9836cb484d0608ea082cf5bd88edde31ad11a0d58"
		hash4 = "e27fb16dce7fff714f4b05f2cef53e1919a34d7ec0e595f2eaa155861a213e59"
		id = "51d80d19-f87f-5b09-ac49-08ebcb464013"
	strings:
      $x1 = "\\\\.\\pipe\\usbpcex%d" fullword wide
      $x2 = "\\\\.\\pipe\\usbpcg%d" fullword wide
      $x3 = "\\??\\pipe\\usbpcex%d" fullword wide
		$x4 = "\\??\\pipe\\usbpcg%d" fullword wide
      $x5 = "$$$--Hello" fullword ascii
      $x6 = "Wrod--$$$" fullword ascii

		$s1 = "\\Registry\\User\\%s\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" wide
		$s2 = "Update.dll" fullword ascii
		$s3 = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\WMI" wide
		$s4 = "\\Driver\\nsiproxy" wide
		$s5 = "HOST: %s" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 800KB and
      (
         2 of ($x*) or all of ($s*)
      )
}

rule Derusbi_Code_Signing_Cert {
	meta:
		description = "Detects an executable signed with a certificate also used for Derusbi Trojan - suspicious"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://blog.airbuscybersecurity.com/post/2015/11/Newcomers-in-the-Derusbi-family"
		date = "2015-12-15"
		score = 60
		id = "d123fde9-0182-5232-a716-b76e8d9830c4"
   strings:
      $s1 = "Fuqing Dawu Technology Co.,Ltd.0" fullword ascii
      $s2 = "XL Games Co.,Ltd.0" fullword ascii
      $s3 = "Wemade Entertainment co.,Ltd0" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and 1 of them
}

rule XOR_4byte_Key {
	meta:
		description = "Detects an executable encrypted with a 4 byte XOR (also used for Derusbi Trojan)"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://blog.airbuscybersecurity.com/post/2015/11/Newcomers-in-the-Derusbi-family"
		date = "2015-12-15"
		score = 60
		id = "77850332-87ce-5ed3-bb09-88e91e5bb5f6"
   strings:
      /* Op Code */
      $s1 = { 85 C9 74 0A 31 06 01 1E 83 C6 04 49 EB F2 }
      /*
      test    ecx, ecx
      jz      short loc_590170
      xor     [esi], eax
      add     [esi], ebx
      add     esi, 4
      dec     ecx
      jmp     short loc_590162
      */
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and all of them
}

rule Derusbi_Backdoor_Mar17_1 {
   meta:
      description = "Detects a variant of the Derusbi backdoor"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-03-03"
      hash1 = "f87915f21dcc527981ebb6db3d332b5b341129b4af83524f59d7178e9d2a3a32"
      id = "5c8838d6-b9c2-589e-b6a2-a8c7ad6f10cc"
   strings:
      $x1 = "%SystemRoot%\\System32\\wiaservc.dll" fullword wide
      $x2 = "c%WINDIR%\\PCHealth\\HelpCtr\\Binaries\\pchsvc.dll" fullword wide
      $x3 = "%Systemroot%\\Help\\perfc009.dat" fullword wide
      $x4 = "rundll32.exe \"%s\", R32 %s" fullword wide
      $x5 = "OfficeUt32.dll" fullword ascii
      $x6 = "\\\\.\\pipe\\usb%so" fullword wide
      $x7 = "\\\\.\\pipe\\usb%si" fullword wide
      $x8 = "\\tmp1.dat" wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and 1 of them )
}
