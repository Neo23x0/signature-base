/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-09-04
	Identifier: PowerShell Toolset - Cloaked
*/

/* Rule Set ----------------------------------------------------------------- */

rule ps1_toolkit_PowerUp {
	meta:
		description = "Auto-generated rule - file PowerUp.ps1"
		author = "Florian Roth"
		reference = "https://github.com/vysec/ps1-toolkit"
		date = "2016-09-04"
		score = 80
		hash1 = "fc65ec85dbcd49001e6037de9134086dd5559ac41ac4d1adf7cab319546758ad"
	strings:
		$s1 = "iex \"$Env:SystemRoot\\System32\\inetsrv\\appcmd.exe list vdir /text:vdir.name\" | % { " fullword ascii
		$s2 = "iex \"$Env:SystemRoot\\System32\\inetsrv\\appcmd.exe list apppools /text:name\" | % { " fullword ascii
		$s3 = "if ($Env:PROCESSOR_ARCHITECTURE -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBNAEQANgA0AA==')))) {" fullword ascii
		$s4 = "C:\\Windows\\System32\\InetSRV\\appcmd.exe list vdir /text:physicalpath | " fullword ascii
		$s5 = "if (Test-Path  (\"$Env:SystemRoot\\System32\\inetsrv\\appcmd.exe\"))" fullword ascii
		$s6 = "if (Test-Path  (\"$Env:SystemRoot\\System32\\InetSRV\\appcmd.exe\")) {" fullword ascii
		$s7 = "Write-Verbose \"Executing command '$Cmd'\"" fullword ascii
		$s8 = "Write-Warning \"[!] Target service" fullword ascii
	condition:
		( uint16(0) == 0xbbef and filesize < 4000KB and 1 of them ) or ( 3 of them )
}

rule ps1_toolkit_Inveigh_BruteForce {
	meta:
		description = "Auto-generated rule - file Inveigh-BruteForce.ps1"
		author = "Florian Roth"
		reference = "https://github.com/vysec/ps1-toolkit"
		date = "2016-09-04"
		score = 80
		hash1 = "a2ae1e02bcb977cd003374f551ed32218dbcba3120124e369cc150b9a63fe3b8"
	strings:
		$s1 = "Import-Module .\\Inveigh.psd1;Invoke-InveighBruteForce -SpooferTarget 192.168.1.11 " fullword ascii
		$s2 = "$(Get-Date -format 's') - Attempting to stop HTTP listener\")|Out-Null" fullword ascii
		$s3 = "Invoke-InveighBruteForce -SpooferTarget 192.168.1.11 -Hostname server1" fullword ascii
	condition:
		( uint16(0) == 0xbbef and filesize < 300KB and 1 of them ) or ( 2 of them )
}

rule ps1_toolkit_Invoke_Shellcode {
	meta:
		description = "Auto-generated rule - file Invoke-Shellcode.ps1"
		author = "Florian Roth"
		reference = "https://github.com/vysec/ps1-toolkit"
		date = "2016-09-04"
		score = 80
		hash1 = "24abe9f3f366a3d269f8681be80c99504dea51e50318d83ee42f9a4c7435999a"
	strings:
		$s1 = "Get-ProcAddress kernel32.dll WriteProcessMemory" fullword ascii
		$s2 = "Get-ProcAddress kernel32.dll OpenProcess" fullword ascii
		$s3 = "msfpayload windows/exec CMD=\"cmd /k calc\" EXITFUNC=thread C | sed '1,6d;s/[\";]//g;s/\\\\/,0/g' | tr -d '\\n' | cut -c2- " fullword ascii
		$s4 = "inject shellcode into" ascii
		$s5 = "Injecting shellcode" ascii
	condition:
		( uint16(0) == 0xbbef and filesize < 90KB and 1 of them ) or ( 3 of them )
}

rule ps1_toolkit_Invoke_Mimikatz {
	meta:
		description = "Auto-generated rule - file Invoke-Mimikatz.ps1"
		author = "Florian Roth"
		reference = "https://github.com/vysec/ps1-toolkit"
		date = "2016-09-04"
		score = 80
		hash1 = "5c31a2e3887662467cfcb0ac37e681f1d9b0f135e6dfff010aae26587e03d8c8"
	strings:
		$s1 = "Get-ProcAddress kernel32.dll WriteProcessMemory" fullword ascii
		$s2 = "ps | where { $_.Name -eq $ProcName } | select ProcessName, Id, SessionId" fullword ascii
		$s3 = "privilege::debug exit" ascii
		$s4 = "Get-ProcAddress Advapi32.dll AdjustTokenPrivileges" fullword ascii
		$s5 = "Invoke-Mimikatz -DumpCreds" fullword ascii
		$s6 = "| Add-Member -MemberType NoteProperty -Name IMAGE_FILE_EXECUTABLE_IMAGE -Value 0x0002" fullword ascii
	condition:
		( uint16(0) == 0xbbef and filesize < 10000KB and 1 of them ) or ( 3 of them )
}

rule ps1_toolkit_Invoke_RelfectivePEInjection {
	meta:
		description = "Auto-generated rule - file Invoke-RelfectivePEInjection.ps1"
		author = "Florian Roth"
		reference = "https://github.com/vysec/ps1-toolkit"
		date = "2016-09-04"
		score = 80
		hash1 = "510b345f821f93c1df5f90ac89ad91fcd0f287ebdabec6c662b716ec9fddb03a"
	strings:
		$x1 = "Invoke-ReflectivePEInjection -PEBytes $PEBytes -FuncReturnType WString -ComputerName (Get-Content targetlist.txt)" fullword ascii
		$x2 = "Invoke-ReflectivePEInjection -PEBytes $PEBytes -FuncReturnType WString -ComputerName Target.local" fullword ascii
		$x3 = "} = Get-ProcAddress Advapi32.dll OpenThreadToken" ascii
		$x4 = "Invoke-ReflectivePEInjection -PEBytes $PEBytes -ProcName lsass -ComputerName Target.Local" fullword ascii
		$s5 = "$PEBytes = [IO.File]::ReadAllBytes('DemoDLL_RemoteProcess.dll')" fullword ascii
		$s6 = "= Get-ProcAddress Advapi32.dll AdjustTokenPrivileges" ascii
	condition:
		( uint16(0) == 0xbbef and filesize < 700KB and 2 of them ) or ( all of them )
}

rule ps1_toolkit_Persistence {
	meta:
		description = "Auto-generated rule - file Persistence.ps1"
		author = "Florian Roth"
		reference = "https://github.com/vysec/ps1-toolkit"
		date = "2016-09-04"
		score = 80
		hash1 = "e1a4dd18b481471fc25adea6a91982b7ffed1c2d393c8c17e6e542c030ac6cbd"
	strings:
		$s1 = "\"`\"```$Filter=Set-WmiInstance -Class __EventFilter -Namespace ```\"root\\subscription```" ascii
		$s2 = "}=$PROFILE.AllUsersAllHosts;${" ascii
		$s3 = "C:\\PS> $ElevatedOptions = New-ElevatedPersistenceOption -Registry -AtStartup"  ascii
		$s4 = "= gwmi Win32_OperatingSystem | select -ExpandProperty OSArchitecture"  ascii
		$s5 = "-eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAxADQAQwA='))))"  ascii
		$s6 = "}=$PROFILE.CurrentUserAllHosts;${"  ascii
		$s7 = "FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAVABhAHMAawBPAG4ASQBkAGwAZQA=')" ascii
		$s8 = "[System.Text.AsciiEncoding]::ASCII.GetString($MZHeader)" fullword ascii
	condition:
		( uint16(0) == 0xbbef and filesize < 200KB and 2 of them ) or ( 4 of them )
}

rule ps1_toolkit_Invoke_Mimikatz_RelfectivePEInjection {
	meta:
		description = "Auto-generated rule - from files Invoke-Mimikatz.ps1, Invoke-RelfectivePEInjection.ps1"
		author = "Florian Roth"
		reference = "https://github.com/vysec/ps1-toolkit"
		date = "2016-09-04"
		score = 80
		super_rule = 1
		hash1 = "5c31a2e3887662467cfcb0ac37e681f1d9b0f135e6dfff010aae26587e03d8c8"
		hash2 = "510b345f821f93c1df5f90ac89ad91fcd0f287ebdabec6c662b716ec9fddb03a"
	strings:
		$s1 = "[IntPtr]$DllAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])" fullword ascii
		$s2 = "if ($GetCommandLineAAddr -eq [IntPtr]::Zero -or $GetCommandLineWAddr -eq [IntPtr]::Zero)" fullword ascii
		$s3 = "[Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xbb)" fullword ascii
		$s4 = "Function Import-DllInRemoteProcess" fullword ascii
		$s5 = "FromBase64String('QwBvAG4AdABpAG4AdQBlAA==')))" fullword ascii
		$s6 = "[Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x83, 0xec, 0x20, 0x83, 0xe4, 0xc0, 0xbb)" fullword ascii
		$s7 = "[System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPrivilegesMem)" fullword ascii
		$s8 = "[System.Runtime.InteropServices.Marshal]::StructureToPtr($CurrAddr, $FinalAddr, $false) | Out-Null" fullword ascii
		$s9 = "::FromBase64String('RABvAG4AZQAhAA==')))" ascii
		$s10 = "Write-Verbose \"PowerShell ProcessID: $PID\"" fullword ascii
		$s11 = "[IntPtr]$ProcAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])" fullword ascii
	condition:
		( uint16(0) == 0xbbef and filesize < 10000KB and 3 of them ) or ( 6 of them )
}

rule ps1_toolkit_Inveigh_BruteForce_2 {
	meta:
		description = "Auto-generated rule - from files Inveigh-BruteForce.ps1"
		author = "Florian Roth"
		reference = "https://github.com/vysec/ps1-toolkit"
		date = "2016-09-04"
		score = 80
		hash1 = "a2ae1e02bcb977cd003374f551ed32218dbcba3120124e369cc150b9a63fe3b8"
	strings:
		$s1 = "}.NTLMv2_file_queue[0]|Out-File ${" ascii
		$s2 = "}.NTLMv2_file_queue.RemoveRange(0,1)" ascii
		$s3 = "}.NTLMv2_file_queue.Count -gt 0)" ascii
		$s4 = "}.relay_running = $false" ascii
	condition:
		( uint16(0) == 0xbbef and filesize < 200KB and 2 of them ) or ( 4 of them )
}

rule ps1_toolkit_PowerUp_2 {
	meta:
		description = "Auto-generated rule - from files PowerUp.ps1"
		author = "Florian Roth"
		reference = "https://github.com/vysec/ps1-toolkit"
		date = "2016-09-04"
		score = 80
		hash1 = "fc65ec85dbcd49001e6037de9134086dd5559ac41ac4d1adf7cab319546758ad"
	strings:
		$s1 = "if($MyConString -like $([Text.Encoding]::Unicode.GetString([Convert]::" ascii
		$s2 = "FromBase64String('KgBwAGEAcwBzAHcAbwByAGQAKgA=')))) {" ascii
		$s3 = "$Null = Invoke-ServiceStart" ascii
		$s4 = "Write-Warning \"[!] Access to service $" ascii
		$s5 = "} = $MyConString.Split(\"=\")[1].Split(\";\")[0]" ascii
		$s6 = "} += \"net localgroup ${" ascii
	condition:
		( uint16(0) == 0xbbef and filesize < 2000KB and 2 of them ) or ( 4 of them )
}

rule ps1_toolkit_Persistence_2 {
	meta:
		description = "Auto-generated rule - from files Persistence.ps1"
		author = "Florian Roth"
		reference = "https://github.com/vysec/ps1-toolkit"
		date = "2016-09-04"
		score = 80
		hash1 = "e1a4dd18b481471fc25adea6a91982b7ffed1c2d393c8c17e6e542c030ac6cbd"
	strings:
		$s1 = "FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAVABhAHMAawBPAG4ASQBkAGwAZQA=')" ascii
		$s2 = "FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAVABhAHMAawBEAGEAaQBsAHkA')" ascii
		$s3 = "FromBase64String('UAB1AGIAbABpAGMALAAgAFMAdABhAHQAaQBjAA==')" ascii
		$s4 = "[Parameter( ParameterSetName = 'ScheduledTaskAtLogon', Mandatory = $True )]" ascii
		$s5 = "FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAVABhAHMAawBBAHQATABvAGcAbwBuAA==')))" ascii
		$s6 = "[Parameter( ParameterSetName = 'PermanentWMIAtStartup', Mandatory = $True )]" fullword ascii
		$s7 = "FromBase64String('TQBlAHQAaABvAGQA')" ascii
		$s8 = "FromBase64String('VAByAGkAZwBnAGUAcgA=')" ascii
		$s9 = "[Runtime.InteropServices.CallingConvention]::Winapi," fullword ascii
	condition:
		( uint16(0) == 0xbbef and filesize < 200KB and 2 of them ) or ( 4 of them )
}

rule ps1_toolkit_Inveigh_BruteForce_3 {
	meta:
		description = "Auto-generated rule - from files Inveigh-BruteForce.ps1"
		author = "Florian Roth"
		reference = "https://github.com/vysec/ps1-toolkit"
		date = "2016-09-04"
		score = 80
		hash3 = "a2ae1e02bcb977cd003374f551ed32218dbcba3120124e369cc150b9a63fe3b8"
	strings:
		$s1 = "::FromBase64String('TgBUAEwATQA=')" ascii
		$s2 = "::FromBase64String('KgBTAE0AQgAgAHIAZQBsAGEAeQAgACoA')))" ascii
		$s3 = "::FromBase64String('KgAgAGYAbwByACAAcgBlAGwAYQB5ACAAKgA=')))" ascii
		$s4 = "::FromBase64String('KgAgAHcAcgBpAHQAdABlAG4AIAB0AG8AIAAqAA==')))" ascii
		$s5 = "[Byte[]] $HTTP_response = (0x48,0x54,0x54,0x50,0x2f,0x31,0x2e,0x31,0x20)`" fullword ascii
		$s6 = "KgAgAGwAbwBjAGEAbAAgAGEAZABtAGkAbgBpAHMAdAByAGEAdABvAHIAIAAqAA" ascii
		$s7 = "}.bruteforce_running)" ascii
	condition:
		( uint16(0) == 0xbbef and filesize < 200KB and 2 of them ) or ( 4 of them )
}
