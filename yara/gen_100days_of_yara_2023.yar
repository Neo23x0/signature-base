import "pe"

rule SUSP_LNK_Embedded_WordDoc {
	meta:
		author = "Greg Lesnewich"
		description = "check for LNK files with indications of the Word program or an embedded doc"
		date = "2023-01-02"
		version = "1.0"
		hash = "120ca851663ef0ebef585d716c9e2ba67bd4870865160fec3b853156be1159c5"
		DaysofYARA = "2/100"

		id = "9677d41a-9d29-510c-98cd-122dc0ca9606"
	strings:
		$doc_header = {D0 CF 11 E0 A1 B1 1A E1}
		$icon_loc = "C:\\Program Files\\Microsoft Office\\Office16\\WINWORD.exe" ascii wide
	condition:
		uint32be(0x0) == 0x4C000000 and
		filesize > 10KB and
		any of them
}

rule SUSP_LNK_SmallScreenSize {
	meta:
		author = "Greg Lesnewich"
		description = "check for LNKs that have a screen buffer size and WindowSize dimensions of 1x1"
		date = "2023-01-01"
		version = "1.0"
		DaysofYARA = "1/100"

		id = "6194a76b-36d6-51d1-8d53-2e11172e29d2"
	strings:
		$dimensions = {02 00 00 A0 ?? 00 ?? ?? 01 00 01 00 01}
		// struct ConsoleDataBlock sConsoleDataBlock
		// uint32 Size
		// uint32 Signature
		// enum FillAttributes
		// enum PopupFillAttributes
		// uint16 ScreenBufferSizeX
		// uint16 ScreenBufferSizeY
		// uint16 WindowSizeX
		// uint16 WindowSizeY
	condition:
		uint32be(0x0) == 0x4c000000 and all of them
}

rule MAL_Janicab_LNK {
	meta:
		author = "Greg Lesnewich"
		description = "detect LNK files used in Janicab infection chain"
		date = "2023-01-01"
		version = "1.0"
		hash = "0c7e8427ee61672568983e51bf03e0bcf6f2e9c01d2524d82677b20264b23a3f"
		hash = "22ede766fba7551ad0b71ef568d0e5022378eadbdff55c4a02b42e63fcb3b17c"
		hash = "4920e6506ca557d486e6785cb5f7e4b0f4505709ffe8c30070909b040d3c3840"
		hash = "880607cc2da4c3213ea687dabd7707736a879cc5f2f1d4accf79821e4d24d870"
		hash = "f4610b65eba977b3d13eba5da0e38788a9e796a3e9775dd2b8e37b3085c2e1af"
		DaysofYARA = "1/100"

		id = "c21844d3-eeee-530e-a69c-b7f604616f0b"
	strings:
		$j_pdf1 = "%PDF-1.5" ascii wide
		$j_cmd = "\\Windows\\System32\\cmd.exe" ascii wide
		$j_pdf_stream = "endstream" ascii wide
		$j_pdb_obj = "endobj" ascii wide
		$dimensions = {02 00 00 A0 ?? 00 ?? ?? 01 00 01 00 01}
	condition:
		uint32be(0x0) == 0x4C000000 and $dimensions and 2 of ($j_*)
}

rule SUSP_ELF_Invalid_Version {
   meta:
      desc = "Identify ELF file that has mangled header info."
      author = "@shellcromancer"
      version = "0.1"
      score = 55
      last_modified = "2023.01.01"
      reference = "https://n0.lol/ebm/1.html"
      reference = "https://tmpout.sh/1/1.html"
      hash = "05379bbf3f46e05d385bbd853d33a13e7e5d7d50"
      id = "5bd97fdd-0912-5f9b-877c-91fff9b98dea"
   condition:
      (
         uint32(0) == 0x464c457f
         and uint8(0x6) > 1 // ELF Version is greater value than in spec.
      )
}

rule MAL_ELF_TorchTriton {
	meta:
		author = "Silas Cutler"
		description = "Detection for backdoor (TorchTriton) distributed with a nightly build of PyTorch"
		date = "2023-01-02"
		version = "1.0"
		hash = "2385b29489cd9e35f92c072780f903ae2e517ed422eae67246ae50a5cc738a0e"
		reference = "https://www.bleepingcomputer.com/news/security/pytorch-discloses-malicious-dependency-chain-compromise-over-holidays/"
		DaysofYARA = "2/100"

		id = "85e98ee7-30bf-554f-a0ac-9df263e6dfe4"
	strings:
		$error = "failed to send packet"
		$aes_key = "gIdk8tzrHLOM)mPY-R)QgG[;yRXYCZFU"
		$aes_iv = "?BVsNqL]S.Ni"
			// std::vector<std::__cxx11::basic_string<char> > splitIntoDomains(const string&, const string&, const string&)
		$func01 = "splitIntoDomains("
		$func02 = "packageForTransport"
		$func03 = "gatherFiles"
			// void sendFile(const string&, const string&, int, int, const string&)
		$func04 = "void sendFile("
		//enc Domain
		$domain = "&z-%`-(*"
	condition:
		uint32(0) == 0x464c457f and (
			(all of ($aes_*)) or
			(all of ($func*) and $error) or
			($domain and 2 of them)
			)
}

rule MAL_GOLDBACKDOOR_LNK {
	meta:
		author = "Greg Lesnewich"
		date = "2023-01-02"
		version = "1.0"
		hash = "120ca851663ef0ebef585d716c9e2ba67bd4870865160fec3b853156be1159c5"
		reference = "https://stairwell.com/wp-content/uploads/2022/04/Stairwell-threat-report-The-ink-stained-trail-of-GOLDBACKDOOR.pdf"
		DaysofYARA = "2/100"

		id = "9a80f875-4843-535c-9f2b-b04da55713b1"
	strings:
		$doc_header = {D0 CF 11 E0 A1 B1 1A E1}
		$doc_icon_loc = "C:\\Program Files\\Microsoft Office\\Office16\\WINWORD.exe" ascii wide
		$script_apionedrivecom_hex_enc_str = "6170692e6f6e6564726976652e636f6d" wide
		$script_kernel32dll_hex_enc_str = "6b65726e656c33322e646c6c" wide
		$script_GlobalAlloc_hex_enc_str = "476c6f62616c416c6c6f63" wide
		$script_VirtualProtect_hex_enc_str = "5669727475616c50726f74656374" wide
		$script_WriteByte_hex_enc_str = "577269746542797465" wide
		$script_CreateThread_hex_enc_str = "437265617465546872656164" wide
	condition:
		uint32be(0x0) == 0x4C000000 and
		1 of ($doc*) and
		2 of ($script*)
}

rule MAL_EXE_LockBit_v2
{
	meta:
		author = "Silas Cutler, modified by Florian Roth"
		description = "Detection for LockBit version 2.x from 2011"
		date = "2023-01-01"
      modified = "2023-01-06"
		version = "1.0"
      score = 80
		hash = "00260c390ffab5734208a7199df0e4229a76261c3f5b7264c4515acb8eb9c2f8"
		DaysofYARA = "1/100"

		id = "a2c27110-e63b-5f93-88a0-98c12811e8b4"
	strings:
		$s_ransom_note01 = "that is located in every encrypted folder." wide
		$s_ransom_note02 = "Would you like to earn millions of dollars?" wide

		$x_ransom_tox = "3085B89A0C515D2FB124D645906F5D3DA5CB97CEBEA975959AE4F95302A04E1D709C3C4AE9B7" wide
		$x_ransom_url = "http://lockbitapt6vx57t3eeqjofwgcglmutr3a35nygvokja5uuccip4ykyd.onion" wide

		$s_str1 = "Active:[ %d [                  Completed:[ %d" wide
		$x_str2 = "\\LockBit_Ransomware.hta" wide ascii
      $s_str2 = "Ransomware.hta" wide ascii
	condition:
		uint16(0) == 0x5A4D and ( 1 of ($x*) or 2 of them ) or 3 of them
}

rule MAL_EXE_PrestigeRansomware {
	meta:
		author = "Silas Cutler, modfied by Florian Roth"
		description = "Detection for Prestige Ransomware"
		date = "2023-01-04"
      modified = "2023-01-06"
		version = "1.0"
      score = 80
		reference = "https://www.microsoft.com/en-us/security/blog/2022/10/14/new-prestige-ransomware-impacts-organizations-in-ukraine-and-poland/"
		hash = "5fc44c7342b84f50f24758e39c8848b2f0991e8817ef5465844f5f2ff6085a57"
		DaysofYARA = "4/100"

		id = "5ac8033a-8b15-5abe-89d5-018a4fef9ab5"
	strings:
		$x_ransom_email = "Prestige.ranusomeware@Proton.me" wide
		$x_reg_ransom_note = "C:\\Windows\\System32\\reg.exe add HKCR\\enc\\shell\\open\\command /ve /t REG_SZ /d \"C:\\Windows\\Notepad.exe C:\\Users\\Public\\README\" /f" wide

		$ransom_message01 = "To decrypt all the data, you will need to purchase our decryption software." wide
		$ransom_message02 = "Contact us {}. In the letter, type your ID = {:X}." wide
		$ransom_message03 = "- Do not try to decrypt your data using third party software, it may cause permanent data loss." wide
		$ransom_message04 = "- Do not modify or rename encrypted files. You will lose them." wide
	condition:
		uint16(0) == 0x5A4D and 
			(1 of ($x*) or 2 of them or pe.imphash() == "a32bbc5df4195de63ea06feb46cd6b55")
}

rule MAL_EXE_RoyalRansomware {
	meta:
		author = "Silas Cutler, modfied by Florian Roth"
		description = "Detection for Royal Ransomware seen Dec 2022"
		date = "2023-01-03"
		version = "1.0"
		hash = "a8384c9e3689eb72fa737b570dbb53b2c3d103c62d46747a96e1e1becf14dfea"
		DaysofYARA = "3/100"

		id = "f83316f7-b8c4-5907-a38e-80535215e7ef"
	strings:
		$x_ext = ".royal_" wide
		$x_fname = "royal_dll.dll"
		$s_readme = "README.TXT" wide
		$s_cli_flag01 = "-networkonly" wide
		$s_cli_flag02 = "-localonly" wide
		$x_ransom_msg01 = "If you are reading this, it means that your system were hit by Royal ransomware."
		$x_ransom_msg02 = "Try Royal today and enter the new era of data security!"
		$x_onion_site = "http://royal2xthig3ou5hd7zsliqagy6yygk2cdelaxtni2fyad6dpmpxedid.onion/"
	condition:
		uint16(0) == 0x5A4D and 
		( 
         2 of ($x*) or
		   5 of them
		)
}

rule MAL_PY_Dimorf {
	meta:
		author = "Silas Cutler"
		description = "Detection for Dimorf ransomeware"
		date = "2023-01-03"
		version = "1.0"
		reference = "https://github.com/Ort0x36/Dimorf"

		id = "78b53433-6926-58cd-8ec0-2195af803aab"
	strings:
		$func01 = "def find_and_encrypt"
		$func02 = "def check_os"
		
		$comment01 = "checks if the user has permission on the file."
		$misc01 = "log_dimorf.log"
		$misc02 = ".dimorf"
	condition:
		all of them
}
