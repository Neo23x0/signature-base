/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-01-14
   Identifier: p0wnedShell
*/

/* Rule Set ----------------------------------------------------------------- */

rule p0wnedPowerCat {
   meta:
      description = "p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedPowerCat.cs"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/Cn33liz/p0wnedShell"
      date = "2017-01-14"
      hash1 = "6a3ba991d3b5d127c4325bc194b3241dde5b3a5853b78b4df1bce7cbe87c0fdf"
      id = "059a8e58-7b7e-582e-ba4a-80e4dffe9b5e"
   strings:
      $x1 = "Now if we point Firefox to http://127.0.0.1" fullword ascii
      $x2 = "powercat -l -v -p" fullword ascii
      $x3 = "P0wnedListener" fullword ascii
      $x4 = "EncodedPayload.bat" fullword ascii
      $x5 = "powercat -c " fullword ascii
      $x6 = "Program.P0wnedPath()" ascii
      $x7 = "Invoke-PowerShellTcpOneLine" fullword ascii
   condition:
      ( uint16(0) == 0x7375 and filesize < 150KB and 1 of them ) or ( 2 of them )
}

rule Hacktool_Strings_p0wnedShell : FILE {
   meta:
      description = "Detects strings found in Runspace Post Exploitation Toolkit"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth"
      reference = "https://github.com/Cn33liz/p0wnedShell"
      date = "2017-01-14"
      modified = "2023-02-10"
      hash1 = "e1f35310192416cd79e60dba0521fc6eb107f3e65741c344832c46e9b4085e60"
      nodeepdive = 1
      id = "0846039d-1e00-5224-9560-55ab18034d54"
   strings:
      $x1 = "Invoke-TokenManipulation" fullword ascii
      $x2 = "windows/meterpreter" fullword ascii
      $x3 = "lsadump::dcsync" fullword ascii
      $x4 = "p0wnedShellx86" fullword ascii
      $x5 = "p0wnedShellx64" fullword ascii
      $x6 = "Invoke_PsExec()" fullword ascii
      $x7 = "Invoke-Mimikatz" fullword ascii
      $x8 = "Invoke_Shellcode()" fullword ascii
      $x9 = "Invoke-ReflectivePEInjection" ascii

      $fp1 = "Sentinel Labs, Inc." wide
      $fp2 = "Copyright Elasticsearch B.V." ascii wide
      $fp3 = "Attack Information: Invoke-Mimikatz" ascii /* Check Point help files */
      $fp4 = "a30226 || INDICATOR-SHELLCODE Metasploit windows/meterpreter stage transfer attempt" /* snort message ID */
      $fp5 = "use strict"
   condition:
      filesize < 20MB
      and 1 of ($x*)
      and not 1 of ($fp*)
}

rule p0wnedPotato {
   meta:
      description = "p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedPotato.cs"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/Cn33liz/p0wnedShell"
      date = "2017-01-14"
      hash1 = "aff2b694a01b48ef96c82daf387b25845abbe01073b76316f1aab3142fdb235b"
      id = "2c2378e3-b948-5325-9afd-76424a7130b1"
   strings:
      $x1 = "Invoke-Tater" fullword ascii
      $x2 = "P0wnedListener.Execute(WPAD_Proxy);" fullword ascii
      $x3 = " -SpooferIP " ascii
      $x4 = "TaterCommand()" ascii
      $x5 = "FileName = \"cmd.exe\"," fullword ascii
   condition:
      1 of them
}

rule p0wnedExploits {
   meta:
      description = "p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedExploits.cs"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/Cn33liz/p0wnedShell"
      date = "2017-01-14"
      hash1 = "54548e7848e742566f5596d8f02eca1fd2cbfeae88648b01efb7bab014b9301b"
      id = "9f754f5f-85e8-5b6f-bde2-566da4d39586"
   strings:
      $x1 = "Pshell.RunPSCommand(Whoami);" fullword ascii
      $x2 = "If succeeded this exploit should popup a System CMD Shell" fullword ascii
   condition:
      all of them
}

rule p0wnedShellx64 {
   meta:
      description = "p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedShellx64.exe"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/Cn33liz/p0wnedShell"
      date = "2017-01-14"
      modified = "2021-09-15"
      hash1 = "d8b4f5440627cf70fa0e0e19e0359b59e671885f8c1855517211ba331f48c449"
      id = "c9791804-4f08-5b7e-8d9d-37e2dfccec47"
   strings:
      $x1 = "Oq02AB+LCAAAAAAABADs/QkW3LiOLQBuRUsQR1H731gHMQOkFGFnvvrdp/O4sp6tkDiAIIjhAryu4z6PVOtxHuXz3/xT6X9za/Df/Hsa/JT/9Pjgb/+kPPhv9Sjp01Wf" wide
      $x2 = "Invoke-TokenManipulation" wide
      $x3 = "-CreateProcess \"cmd.exe\" -Username \"nt authority\\system\"" fullword wide
      $x4 = "CommandShell with Local Administrator privileges :)" fullword wide
      $x5 = "Invoke-shellcode -Payload windows/meterpreter/reverse_https -Lhost " fullword wide

      $fp1 = "AVSignature" ascii wide 
   condition:
      1 of ($x*) and not 1 of them
}

rule p0wnedListenerConsole {
   meta:
      description = "p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedListenerConsole.cs"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/Cn33liz/p0wnedShell"
      date = "2017-01-14"
      hash1 = "d2d84e65fad966a8556696fdaab5dc8110fc058c9e9caa7ea78aa00921ae3169"
      id = "77d13c34-3e15-5bc1-a100-f04be38cfb44"
   strings:
      $x1 = "Invoke_ReflectivePEInjection" fullword wide
      $x5 = "p0wnedShell> " fullword wide
      $x6 = "Resources.Get_PassHashes" fullword wide
      $s7 = "Invoke_CredentialsPhish" fullword wide
      $s8 = "Invoke_Shellcode" fullword wide
      $s9 = "Resources.Invoke_TokenManipulation" fullword wide
      $s10 = "Resources.Port_Scan" fullword wide
      $s20 = "Invoke_PowerUp" fullword wide
   condition:
      1 of them
}

rule p0wnedBinaries {
   meta:
      description = "p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedBinaries.cs"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/Cn33liz/p0wnedShell"
      date = "2017-01-14"
      hash1 = "fd7014625b58d00c6e54ad0e587c6dba5d50f8ca4b0f162d5af3357c2183c7a7"
      id = "0c62dd3a-195c-5890-b262-2eb00c58f8c1"
   strings:
      $x1 = "Oq02AB+LCAAAAAAABADs/QkW3LiOLQBuRUsQR1H731gHMQOkFGFnvvrdp/O4sp6tkDiAIIjhAryu4z6PVOtxHuXz3/xT6X9za/Df/Hsa/JT/9" ascii
      $x2 = "wpoWAB+LCAAAAAAABADs/QeyK7uOBYhORUNIenL+E2vBA0ympH3erY4f8Tte3TpbUiY9YRbcGK91vVKtr+tV3v/B/yr/m1vD/+DvNOVb+V/f" ascii
      $x3 = "mo0MAB+LCAAAAAAABADsXQl24zqu3YqXII6i9r+xJ4AACU4SZcuJnVenf/9OxbHEAcRwcQGu62NbHsrax/Iw+3/hP5b+VzuH/4WfVeDf8n98" ascii
      $x4 = "LE4CAB+LCAAAAAAABADsfQmW2zqu6Fa8BM7D/jf2hRmkKNuVm/Tt9zunkipb4giCIGb2/prhFUt5hVe+/sNP4b+pVvwPn+OQp/LT9ge/+" ascii
      $x5 = "XpMCAB+LCAAAAAAABADsfQeWIzmO6FV0hKAn73+xL3iAwVAqq2t35r/tl53VyhCDFoQ3Y7zW9Uq1vq5Xef/CT+X/59bwFz6nKU/lp+8P/" ascii
      $x6 = "STwAAB+LCAAAAAAABADtWwmy6yoO3YqXgJjZ/8ZaRwNgx/HNfX/o7qqUkxgzCM0SmLR2jHBQzkc4En9xZbvHUuSLMnWv9ateK/70ilStR" ascii
      $x7 = "namespace p0wnedShell" fullword ascii
   condition:
      1 of them
}

rule p0wnedAmsiBypass {
   meta:
      description = "p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedAmsiBypass.cs"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/Cn33liz/p0wnedShell"
      date = "2017-01-14"
      hash1 = "345e8e6f38b2914f4533c4c16421d372d61564a4275537e674a2ac3360b19284"
      id = "168af265-d3e9-59a2-b754-20d6c9a298b1"
   strings:
      $x1 = "Program.P0wnedPath()" fullword ascii
      $x2 = "namespace p0wnedShell" fullword ascii
      $x3 = "H4sIAAAAAAAEAO1YfXRUx3WflXalFazQgiVb5nMVryzxIbGrt/rcFRZIa1CQYEFCQnxotUhP2pX3Q337HpYotCKrPdbmoQQnkOY0+BQCNKRpe" ascii
   condition:
      1 of them
}

rule p0wnedShell_outputs {
   meta:
      description = "p0wnedShell Runspace Post Exploitation Toolkit - from files p0wnedShell.cs, p0wnedShell.cs"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/Cn33liz/p0wnedShell"
      date = "2017-01-14"
      super_rule = 1
      hash1 = "e1f35310192416cd79e60dba0521fc6eb107f3e65741c344832c46e9b4085e60"
      id = "c19fc14b-0c42-5dd1-bff2-ba75f4168d9c"
   strings:
      $s1 = "[+] For this attack to succeed, you need to have Admin privileges." fullword ascii
      $s2 = "[+] This is not a valid hostname, please try again" fullword ascii
      $s3 = "[+] First return the name of our current domain." fullword ascii
   condition:
      1 of them
}
