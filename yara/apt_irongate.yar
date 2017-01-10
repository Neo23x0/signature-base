/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-06-04
	Identifier: IronGate (FireEye)
*/

/* Rule Set ----------------------------------------------------------------- */

rule IronGate_APT_Step7ProSim_Gen {
	meta:
		description = "Detects IronGate APT Malware - Step7ProSim DLL"
		author = "Florian Roth"
		reference = "https://goo.gl/Mr6M2J"
		date = "2016-06-04"
		score = 90
		hash1 = "0539af1a0cc7f231af8f135920a990321529479f6534c3b64e571d490e1514c3"
		hash2 = "fa8400422f3161206814590768fc1a27cf6420fc5d322d52e82899ac9f49e14f"
		hash3 = "5ab1672b15de9bda84298e0bb226265af09b70a9f0b26d6dfb7bdd6cbaed192d"
	strings:
		$x1 = "\\obj\\Release\\Step7ProSim.pdb" ascii

		$s1 = "Step7ProSim.Interfaces" fullword ascii
		$s2 = "payloadExecutionTimeInMilliSeconds" fullword ascii
		$s3 = "PackagingModule.Step7ProSim.dll" fullword wide
		$s4 = "<KillProcess>b__0" fullword ascii
		$s5 = "newDllFilename" fullword ascii
		$s6 = "PackagingModule.exe" fullword wide
		$s7 = "$863d8af0-cee6-4676-96ad-13e8540f4d47" fullword ascii
		$s8 = "RunPlcSim" fullword ascii
		$s9 = "$ccc64bc5-ef95-4217-adc4-5bf0d448c272" fullword ascii
		$s10 = "InstallProxy" fullword ascii
		$s11 = "DllProxyInstaller" fullword ascii
		$s12 = "FindFileInDrive" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 50KB and ( $x1 or 3 of ($s*) ) )
		or ( 6 of them )
}

rule IronGate_PyInstaller_update_EXE {
	meta:
		description = "Detects a PyInstaller file named update.exe as mentioned in the IronGate APT"
		author = "Florian Roth"
		reference = "https://goo.gl/Mr6M2J"
		date = "2016-06-04"
		score = 60
		hash1 = "2044712ceb99972d025716f0f16aa039550e22a63000d2885f7b7cd50f6834e0"
	strings:
		$s1 = "bpython27.dll" fullword ascii
		$s5 = "%s%s.exe" fullword ascii
		$s6 = "bupdate.exe.manifest" fullword ascii
		$s9 = "bunicodedata.pyd" fullword ascii
		$s11 = "distutils.sysconfig(" fullword ascii
		$s16 = "distutils.debug(" fullword ascii
		$s18 = "supdate" fullword ascii
	condition:
		uint16(0) == 0x5a4d and all of them
}

/* Additional Rules --------------------------------------------------------- */
/* Other tools used in the APT ---------------------------------------------- */

rule Nirsoft_NetResView {
	meta:
		description = "Detects NirSoft NetResView - utility that displays the list of all network resources"
		author = "Florian Roth"
		reference = "https://goo.gl/Mr6M2J"
		date = "2016-06-04"
		score = 40
		hash1 = "83f0352c14fa62ae159ab532d85a2b481900fed50d32cc757aa3f4ccf6a13bee"
	strings:
		$s1 = "NetResView.exe" fullword wide
		$s2 = "2005 - 2013 Nir Sofer" wide
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and all of them
}

/* These only work with external variable "filename" ------------------------ */
/* as used in LOKI, THOR, SPARK --------------------------------------------- */

rule SysInterals_PipeList_NameChanged {
	meta:
		description = "Detects NirSoft PipeList"
		author = "Florian Roth"
		reference = "https://goo.gl/Mr6M2J"
		date = "2016-06-04"
		score = 90
		hash1 = "83f0352c14fa62ae159ab532d85a2b481900fed50d32cc757aa3f4ccf6a13bee"
	strings:
		$s1 = "PipeList" ascii fullword
		$s2 = "Sysinternals License" ascii fullword
	condition:
		uint16(0) == 0x5a4d and filesize < 170KB and all of them
		and not filename contains "pipelist.exe"
		and not filename contains "PipeList.exe"
}
