/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-02-09
   Identifier: MSF Payloads
*/

/* Rule Set ----------------------------------------------------------------- */

rule Msfpayloads_msf {
   meta:
      description = "Metasploit Payloads - file msf.sh"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "320a01ec4e023fb5fbbaef963a2b57229e4f918847e5a49c7a3f631cb556e96c"
   strings:
      $s1 = "export buf=\\" fullword ascii
   condition:
      ( uint16(0) == 0x7865 and filesize < 4KB and ( 10 of ($s*) ) ) or ( all of them )
}

rule Msfpayloads_msf_2 {
   meta:
      description = "Metasploit Payloads - file msf.asp"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "e52f98466b92ee9629d564453af6f27bd3645e00a9e2da518f5a64a33ccf8eb5"
   strings:
      $s1 = "& \"\\\" & \"svchost.exe\"" fullword ascii
      $s2 = "CreateObject(\"Wscript.Shell\")" fullword ascii
      $s3 = "<% @language=\"VBScript\" %>" fullword ascii
   condition:
      all of them
}

rule Msfpayloads_msf_psh {
   meta:
      description = "Metasploit Payloads - file msf-psh.vba"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "5cc6c7f1aa75df8979be4a16e36cece40340c6e192ce527771bdd6463253e46f"
   strings:
      $s1 = "powershell.exe -nop -w hidden -e" ascii
      $s2 = "Call Shell(" fullword ascii
      $s3 = "Sub Workbook_Open()" fullword ascii
   condition:
      all of them
}

rule Msfpayloads_msf_exe {
   meta:
      description = "Metasploit Payloads - file msf-exe.vba"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "321537007ea5052a43ffa46a6976075cee6a4902af0c98b9fd711b9f572c20fd"
   strings:
      $s1 = "'* PAYLOAD DATA" fullword ascii
      $s2 = " = Shell(" ascii
      $s3 = "= Environ(\"USERPROFILE\")" fullword ascii
      $s4 = "'**************************************************************" fullword ascii
      $s5 = "ChDir (" fullword ascii
      $s6 = "'* MACRO CODE" fullword ascii
   condition:
      4 of them
}

rule Msfpayloads_msf_3 {
   meta:
      description = "Metasploit Payloads - file msf.psh"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "335cfb85e11e7fb20cddc87e743b9e777dc4ab4e18a39c2a2da1aa61efdbd054"
   strings:
      $s1 = "[DllImport(\"kernel32.dll\")] public static extern int WaitForSingleObject(" ascii
      $s2 = "public enum MemoryProtection { ExecuteReadWrite = 0x40 }" fullword ascii
      $s3 = ".func]::VirtualAlloc(0,"
      $s4 = ".func+AllocationType]::Reserve -bOr [" ascii
      $s5 = "New-Object System.CodeDom.Compiler.CompilerParameters" fullword ascii
      $s6 = "ReferencedAssemblies.AddRange(@(\"System.dll\", [PsObject].Assembly.Location))" fullword ascii
      $s7 = "public enum AllocationType { Commit = 0x1000, Reserve = 0x2000 }" fullword ascii
      $s8 = ".func]::CreateThread(0,0,$" fullword ascii
      $s9 = "public enum Time : uint { Infinite = 0xFFFFFFFF }" fullword ascii
      $s10 = "= [System.Convert]::FromBase64String(\"/" ascii
      $s11 = "{ $global:result = 3; return }" fullword ascii
   condition:
      4 of them
}

rule Msfpayloads_msf_4 {
   meta:
      description = "Metasploit Payloads - file msf.aspx"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "26b3e572ba1574164b76c6d5213ab02e4170168ae2bcd2f477f246d37dbe84ef"
   strings:
      $s1 = "= VirtualAlloc(IntPtr.Zero,(UIntPtr)" ascii
      $s2 = ".Length,MEM_COMMIT, PAGE_EXECUTE_READWRITE);" ascii
      $s3 = "[System.Runtime.InteropServices.DllImport(\"kernel32\")]" fullword ascii
      $s4 = "private static IntPtr PAGE_EXECUTE_READWRITE=(IntPtr)0x40;" fullword ascii
      $s5 = "private static extern IntPtr VirtualAlloc(IntPtr lpStartAddr,UIntPtr size,Int32 flAllocationType,IntPtr flProtect);" fullword ascii
   condition:
      4 of them
}

rule Msfpayloads_msf_exe_2 {
   meta:
      description = "Metasploit Payloads - file msf-exe.aspx"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "3a2f7a654c1100e64d8d3b4cd39165fba3b101bbcce6dd0f70dae863da338401"
   strings:
      $x1 = "= new System.Diagnostics.Process();" fullword ascii
      $x2 = ".StartInfo.UseShellExecute = true;" fullword ascii
      $x3 = ", \"svchost.exe\");" ascii
      $s4 = " = Path.GetTempPath();" ascii
   condition:
      all of them
}

rule Msfpayloads_msf_5 {
   meta:
      description = "Metasploit Payloads - file msf.msi"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "7a6c66dfc998bf5838993e40026e1f400acd018bde8d4c01ef2e2e8fba507065"
   strings:
      $s1 = "required to install Foobar 1.0." fullword ascii
      $s2 = "Copyright 2009 The Apache Software Foundation." fullword wide
      $s3 = "{50F36D89-59A8-4A40-9689-8792029113AC}" fullword ascii
   condition:
      all of them
}

rule Msfpayloads_msf_6 {
   meta:
      description = "Metasploit Payloads - file msf.vbs"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "8d6f55c6715c4a2023087c3d0d7abfa21e31a629393e4dc179d31bb25b166b3f"
   strings:
      $s1 = "= CreateObject(\"Wscript.Shell\")" fullword ascii
      $s2 = "= CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
      $s3 = ".GetSpecialFolder(2)" ascii
      $s4 = ".Write Chr(CLng(\"" ascii
      $s5 = "= \"4d5a90000300000004000000ffff00" ascii
      $s6 = "For i = 1 to Len(" ascii
      $s7  = ") Step 2" ascii
   condition:
      5 of them
}

rule Msfpayloads_msf_7 {
   meta:
      description = "Metasploit Payloads - file msf.vba"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "425beff61a01e2f60773be3fcb74bdfc7c66099fe40b9209745029b3c19b5f2f"
   strings:
      $s1 = "Private Declare PtrSafe Function CreateThread Lib \"kernel32\" (ByVal" ascii
      $s2 = "= VirtualAlloc(0, UBound(Tsw), &H1000, &H40)" fullword ascii
      $s3 = "= RtlMoveMemory(" ascii
   condition:
      all of them
}

rule Msfpayloads_msf_8 {
   meta:
      description = "Metasploit Payloads - file msf.ps1"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "519717e01f0cb3f460ef88cd70c3de8c7f00fb7c564260bd2908e97d11fde87f"
   strings:
      $s1 = "[DllImport(\"kernel32.dll\")]" fullword ascii
      $s2 = "[DllImport(\"msvcrt.dll\")]" fullword ascii
      $s3 = "-Name \"Win32\" -namespace Win32Functions -passthru" fullword ascii
      $s4 = "::VirtualAlloc(0,[Math]::Max($" ascii
      $s5 = ".Length,0x1000),0x3000,0x40)" ascii
      $s6 = "public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);" fullword ascii
      $s7 = "::memset([IntPtr]($" ascii
   condition:
      6 of them
}

rule Msfpayloads_msf_cmd {
   meta:
      description = "Metasploit Payloads - file msf-cmd.ps1"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "9f41932afc9b6b4938ee7a2559067f4df34a5c8eae73558a3959dd677cb5867f"
   strings:
      $x1 = "%COMSPEC% /b /c start /b /min powershell.exe -nop -w hidden -e" ascii
   condition:
      all of them
}

rule Msfpayloads_msf_9 {
   meta:
      description = "Metasploit Payloads - file msf.war - contents"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "e408678042642a5d341e8042f476ee7cef253871ef1c9e289acf0ee9591d1e81"
   strings:
      $s1 = "if (System.getProperty(\"os.name\").toLowerCase().indexOf(\"windows\") != -1)" fullword ascii
      $s2 = ".concat(\".exe\");" fullword ascii
      $s3 = "[0] = \"chmod\";" ascii
      $s4 = "= Runtime.getRuntime().exec(" ascii
      $s5 = ", 16) & 0xff;" ascii

      $x1 = "4d5a9000030000000" ascii
   condition:
      4 of ($s*) or $x1 at 0
}

rule Msfpayloads_msf_10 {
   meta:
      description = "Metasploit Payloads - file msf.exe"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "3cd74fa28323c0d64f45507675ac08fb09bae4dd6b7e11f2832a4fbc70bb7082"
   strings:
      $s1 = { 0c 8b 52 14 8b 72 28 0f b7 4a 26 31 ff ac 3c 61 }
      $s2 = { 01 c7 38 e0 75 f6 03 7d f8 3b 7d 24 75 e4 58 8b }
      $s3 = { 01 d0 89 44 24 24 5b 5b 61 59 5a 51 ff e0 5f 5f }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}

rule Msfpayloads_msf_svc {
   meta:
      description = "Metasploit Payloads - file msf-svc.exe"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "2b02c9c10577ee0c7590d3dadc525c494122747a628a7bf714879b8e94ae5ea1"
   strings:
      $s1 = "PAYLOAD:" fullword ascii
      $s2 = ".exehll" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 50KB and all of them )
}

rule Msfpayloads_msf_11 {
   meta:
      description = "Metasploit Payloads - file msf.hta"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "d1daf7bc41580322333a893133d103f7d67f5cd8a3e0f919471061d41cf710b6"
   strings:
      $s1 = ".ExpandEnvironmentStrings(\"%PSModulePath%\") + \"..\\powershell.exe\") Then" fullword ascii
      $s2 = "= CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
      $s3 = "= CreateObject(\"Wscript.Shell\") " fullword ascii
   condition:
      all of them
}

rule Msfpayloads_msf_ref {
   meta:
      description = "Metasploit Payloads - file msf-ref.ps1"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "4ec95724b4c2b6cb57d2c63332a1dd6d4a0101707f42e3d693c9aab19f6c9f87"
   strings:
      $s1 = "kernel32.dll WaitForSingleObject)," ascii
      $s2 = "= ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\\\')" ascii
      $s3 = "GetMethod('GetProcAddress').Invoke($null, @([System.Runtime.InteropServices.HandleRef](New-Object" ascii
      $s4 = ".DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual'," ascii
      $s5 = "= [System.Convert]::FromBase64String(" ascii
      $s6 = "[Parameter(Position = 0, Mandatory = $True)] [Type[]]" fullword ascii
      $s7 = "DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard," ascii
   condition:
      5 of them
}
