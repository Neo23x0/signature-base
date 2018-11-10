
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-06-14
   Identifier: Invoke-Hash / Invoke-WMIExec
   Reference: https://github.com/Kevin-Robertson/Invoke-TheHash
*/

/* Rule Set ----------------------------------------------------------------- */

rule Invoke_SMBExec {
   meta:
      description = "Detects Invoke-WmiExec or Invoke-SmbExec"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/Kevin-Robertson/Invoke-TheHash"
      date = "2017-06-14"
      hash1 = "674fc045dc198874f323ebdfb9e9ff2f591076fa6fac8d1048b5b8d9527c64cd"
   strings:
      $x1 = "Invoke-SMBExec -Target" fullword ascii
      $x2 = "$packet_SMB_header = Get-PacketSMBHeader 0x71 0x18 0x07,0xc8 $SMB_tree_ID $process_ID_bytes $SMB_user_ID" fullword ascii

      $s1 = "Write-Output \"Command executed with service $SMB_service on $Target\"" fullword ascii
      $s2 = "$packet_RPC_data = Get-PacketRPCBind 1 0xb8,0x10 0x01 0x00,0x00 $SMB_named_pipe_UUID 0x02,0x00" fullword ascii
      $s3 = "$SMB_named_pipe_bytes = 0x73,0x00,0x76,0x00,0x63,0x00,0x63,0x00,0x74,0x00,0x6c,0x00 # \\svcctl" fullword ascii
   condition:
      ( filesize < 400KB and 1 of them )
}

rule Invoke_WMIExec_Gen_1 {
   meta:
      description = "Detects Invoke-WmiExec or Invoke-SmbExec"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/Kevin-Robertson/Invoke-TheHash"
      date = "2017-06-14"
      hash1 = "140c23514dbf8043b4f293c501c2f9046efcc1c08630621f651cfedb6eed8b97"
      hash2 = "7565d376665e3cd07d859a5cf37c2332a14c08eb808cc5d187a7f0533dc69e07"
   strings:
      $x1 = "Invoke-WMIExec " ascii
      $x2 = "$target_count = [System.math]::Pow(2,(($target_address.GetAddressBytes().Length * 8) - $subnet_mask_split))" fullword ascii
      $s1 = "Import-Module $PWD\\Invoke-TheHash.ps1" fullword ascii
      $s2 = "Import-Module $PWD\\Invoke-SMBClient.ps1" fullword ascii
      $s3 = "$target_address_list = [System.Net.Dns]::GetHostEntry($target_long).AddressList" fullword ascii
      $x4 = "Invoke-SMBClient -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0" ascii
   condition:
      1 of them
}

rule Invoke_SMBExec_Invoke_WMIExec_1 {
   meta:
      description = "Auto-generated rule - from files Invoke-SMBExec.ps1, Invoke-WMIExec.ps1"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/Kevin-Robertson/Invoke-TheHash"
      date = "2017-06-14"
      super_rule = 1
      hash1 = "674fc045dc198874f323ebdfb9e9ff2f591076fa6fac8d1048b5b8d9527c64cd"
      hash2 = "b41bd54bbf119d153e0878696cd5a944cbd4316c781dd8e390507b2ec2d949e7"
   strings:
      $s1 = "$process_ID = $process_ID -replace \"-00-00\",\"\"" fullword ascii
      $s2 = "Write-Output \"$Target did not respond\"" fullword ascii
      $s3 = "[Byte[]]$packet_call_ID_bytes = [System.BitConverter]::GetBytes($packet_call_ID)" fullword ascii
   condition:
      all of them
}

rule Invoke_WMIExec_Gen {
   meta:
      description = "Auto-generated rule - from files Invoke-SMBClient.ps1, Invoke-SMBExec.ps1, Invoke-WMIExec.ps1, Invoke-WMIExec.ps1"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/Kevin-Robertson/Invoke-TheHash"
      date = "2017-06-14"
      super_rule = 1
      hash1 = "56c6012c36aa863663fe5536d8b7fe4c460565d456ce2277a883f10d78893c01"
      hash2 = "674fc045dc198874f323ebdfb9e9ff2f591076fa6fac8d1048b5b8d9527c64cd"
      hash3 = "b41bd54bbf119d153e0878696cd5a944cbd4316c781dd8e390507b2ec2d949e7"
   strings:
      $s1 = "$NTLMv2_hash = $HMAC_MD5.ComputeHash($username_and_target_bytes)" fullword ascii
      $s2 = "$client_challenge = [String](1..8 | ForEach-Object {\"{0:X2}\" -f (Get-Random -Minimum 1 -Maximum 255)})" fullword ascii
      $s3 = "$NTLM_hash_bytes = $NTLM_hash_bytes.Split(\"-\") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}" fullword ascii
   condition:
      all of them
}
