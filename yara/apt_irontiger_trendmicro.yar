rule IronTiger_ASPXSpy
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "ASPXSpy detection. It might be used by other fraudsters"
		reference = "http://goo.gl/T5fSJC"
	strings:
		$str2 = "IIS Spy" wide ascii
		$str3 = "protected void DGCoW(object sender,EventArgs e)" nocase wide ascii
	condition:
		any of ($str*)
}

rule IronTiger_ChangePort_Toolkit_driversinstall
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger Malware - Changeport Toolkit driverinstall"
		reference = "http://goo.gl/T5fSJC"
	strings:
		$str1 = "openmydoor" nocase wide ascii
		$str2 = "Install service error" nocase wide ascii
		$str3 = "start remove service" nocase wide ascii
		$str4 = "NdisVersion" nocase wide ascii
	condition:
		uint16(0) == 0x5a4d and (2 of ($str*))
}

rule IronTiger_ChangePort_Toolkit_ChangePortExe
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger Malware - Toolkit ChangePort"
		reference = "http://goo.gl/T5fSJC"
	strings:
		$str1 = "Unable to alloc the adapter!" nocase wide ascii
		$str2 = "Wait for master fuck" nocase wide ascii
		$str3 = "xx.exe <HOST> <PORT>" nocase wide ascii
		$str4 = "chkroot2007" nocase wide ascii
		$str5 = "Door is bind on %s" nocase wide ascii
	condition:
		uint16(0) == 0x5a4d and (2 of ($str*))
}

rule IronTiger_dllshellexc2010
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "dllshellexc2010 Exchange backdoor + remote shell"
		reference = "http://goo.gl/T5fSJC"
	strings:
		$str1 = "Microsoft.Exchange.Clients.Auth.dll" nocase ascii wide
		$str2 = "Dllshellexc2010" nocase wide ascii
		$str3 = "Users\\ljw\\Documents" nocase wide ascii
		$bla1 = "please input path" nocase wide ascii
		$bla2 = "auth.owa" nocase wide ascii
	condition:
		(uint16(0) == 0x5a4d) and ((any of ($str*)) or (all of ($bla*)))
}

rule IronTiger_dnstunnel
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "This rule detects a dns tunnel tool used in Operation Iron Tiger"
		reference = "http://goo.gl/T5fSJC"
	strings:
		$str1 = "\\DnsTunClient\\" nocase wide ascii
		$str2 = "\\t-DNSTunnel\\" nocase wide ascii
		$str3 = "xssok.blogspot" nocase wide ascii
		$str4 = "dnstunclient" nocase wide ascii
		$mistake1 = "because of error, can not analysis" nocase wide ascii
		$mistake2 = "can not deal witn the error" nocase wide ascii
		$mistake3 = "the other retun one RST" nocase wide ascii
		$mistake4 = "Coversation produce one error" nocase wide ascii
		$mistake5 = "Program try to use the have deleted the buffer" nocase wide ascii
	condition:
		(uint16(0) == 0x5a4d) and ((any of ($str*)) or (any of ($mistake*)))
}

rule IronTiger_EFH3_encoder
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger EFH3 Encoder"
		reference = "http://goo.gl/T5fSJC"
	strings:
		$str1 = "EFH3 [HEX] [SRCFILE] [DSTFILE]" nocase wide ascii
		$str2 = "123.EXE 123.EFH" nocase wide ascii
		$str3 = "ENCODER: b[i]: = " nocase wide ascii
	condition:
		uint16(0) == 0x5a4d and (any of ($str*))
}

rule IronTiger_GetPassword_x64
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger Malware - GetPassword x64"
		reference = "http://goo.gl/T5fSJC"
	strings:
		$str1 = "(LUID ERROR)" nocase wide ascii
		$str2 = "Users\\K8team\\Desktop\\GetPassword" nocase wide ascii
		$str3 = "Debug x64\\GetPassword.pdb" nocase wide ascii
		$bla1 = "Authentication Package:" nocase wide ascii
		$bla2 = "Authentication Domain:" nocase wide ascii
		$bla3 = "* Password:" nocase wide ascii
		$bla4 = "Primary User:" nocase wide ascii
	condition:
		uint16(0) == 0x5a4d and ((any of ($str*)) or (all of ($bla*)))
}

rule IronTiger_GTalk_Trojan
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger Malware - GTalk Trojan"
		reference = "http://goo.gl/T5fSJC"
	strings:
		$str1 = "gtalklite.com" nocase wide ascii
		$str2 = "computer=%s&lanip=%s&uid=%s&os=%s&data=%s" nocase wide ascii
		$str3 = "D13idmAdm" nocase wide ascii
		$str4 = "Error: PeekNamedPipe failed with %i" nocase wide ascii
	condition:
		uint16(0) == 0x5a4d and (2 of ($str*))
}

rule IronTiger_HTTP_SOCKS_Proxy_soexe
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger Toolset - HTTP SOCKS Proxy soexe"
		reference = "http://goo.gl/T5fSJC"
	strings:
		$str1 = "listen SOCKET error." nocase wide ascii
		$str2 = "WSAAsyncSelect SOCKET error." nocase wide ascii
		$str3 = "new SOCKETINFO error!" nocase wide ascii
		$str4 = "Http/1.1 403 Forbidden" nocase wide ascii
		$str5 = "Create SOCKET error." nocase wide ascii
	condition:
		uint16(0) == 0x5a4d and (3 of ($str*))
}

rule IronTiger_NBDDos_Gh0stvariant_dropper
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger Malware - NBDDos Gh0stvariant Dropper"
		reference = "http://goo.gl/T5fSJC"
	strings:
		$str1 = "This service can't be stoped." nocase wide ascii
		$str2 = "Provides support for media palyer" nocase wide ascii
		$str4 = "CreaetProcess Error" nocase wide ascii
		$bla1 = "Kill You" nocase wide ascii
		$bla2 = "%4.2f GB" nocase wide ascii
	condition:
		uint16(0) == 0x5a4d and ((any of ($str*)) or (all of ($bla*)))
}

rule IronTiger_PlugX_DosEmulator
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro - modified by Florian Roth"
		description = "Iron Tiger Malware - PlugX DosEmulator"
		reference = "http://goo.gl/T5fSJC"
	strings:
		$str1 = "Dos Emluator Ver" nocase wide ascii
		$str2 = "\\PIPE\\FASTDOS" nocase wide ascii
		$str3 = "FastDos.cpp" nocase wide ascii
		$str4 = "fail,error code = %d." nocase wide ascii
	condition:
		uint16(0) == 0x5a4d and 2 of ($str*)
}

rule IronTiger_PlugX_FastProxy
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger Malware - PlugX FastProxy"
		reference = "http://goo.gl/T5fSJC"
	strings:
		$str1 = "SAFEPROXY HTServerTimer Quit!" nocase wide ascii
		$str2 = "Useage: %s pid" nocase wide ascii
		$str3 = "%s PORT[%d] TO PORT[%d] SUCCESS!" nocase wide ascii
		$str4 = "p0: port for listener" nocase wide ascii
		$str5 = "\\users\\whg\\desktop\\plug\\" nocase wide ascii
		$str6 = "[+Y] cwnd : %3d, fligth:" nocase wide ascii
	condition:
		uint16(0) == 0x5a4d and (any of ($str*))
}

rule IronTiger_PlugX_Server
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger Malware - PlugX Server"
		reference = "http://goo.gl/T5fSJC"
	strings:
		$str1 = "\\UnitFrmManagerKeyLog.pas" nocase wide ascii
		$str2 = "\\UnitFrmManagerRegister.pas" nocase wide ascii
		$str3 = "Input Name..." nocase wide ascii
		$str4 = "New Value#" nocase wide ascii
		$str5 = "TThreadRControl.Execute SEH!!!" nocase wide ascii
		$str6 = "\\UnitFrmRControl.pas" nocase wide ascii
		$str7 = "OnSocket(event is error)!" nocase wide ascii
		$str8 = "Make 3F Version Ok!!!" nocase wide ascii
		$str9 = "PELEASE DO NOT CHANGE THE DOCAMENT" nocase wide ascii
		$str10 = "Press [Ok] Continue Run, Press [Cancel] Exit" nocase wide ascii
	condition:
		uint16(0) == 0x5a4d and (2 of ($str*))
}

rule IronTiger_ReadPWD86
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger Malware - ReadPWD86"
		reference = "http://goo.gl/T5fSJC"
	strings:
		$str1 = "Fail To Load LSASRV" nocase wide ascii
		$str2 = "Fail To Search LSASS Data" nocase wide ascii
		$str3 = "User Principal" nocase wide ascii
	condition:
		uint16(0) == 0x5a4d and (all of ($str*))
}

rule IronTiger_Ring_Gh0stvariant
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger Malware - Ring Gh0stvariant"
		reference = "http://goo.gl/T5fSJC"
	strings:
		$str1 = "RING RAT Exception" nocase wide ascii
		$str2 = "(can not update server recently)!" nocase wide ascii
		$str4 = "CreaetProcess Error" nocase wide ascii
		$bla1 = "Sucess!" nocase wide ascii
		$bla2 = "user canceled!" nocase wide ascii
	condition:
		uint16(0) == 0x5a4d and ((any of ($str*)) or (all of ($bla*)))
}

rule IronTiger_wmiexec
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger Tool - wmi.vbs detection"
		reference = "http://goo.gl/T5fSJC"
	strings:
		$str1 = "Temp Result File , Change it to where you like" nocase wide ascii
		$str2 = "wmiexec" nocase wide ascii
		$str3 = "By. Twi1ight" nocase wide ascii
		$str4 = "[both mode] ,delay TIME to read result" nocase wide ascii
		$str5 = "such as nc.exe or Trojan" nocase wide ascii
		$str6 = "+++shell mode+++" nocase wide ascii
		$str7 = "win2008 fso has no privilege to delete file" nocase wide ascii
	condition:
		2 of ($str*)
}
