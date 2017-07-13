
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-07-11
   Identifier: WinPayloads
   Reference: https://github.com/nccgroup/Winpayloads
*/

/* Rule Set ----------------------------------------------------------------- */

rule WinPayloads_PowerShell {
   meta:
      description = "Detects WinPayloads PowerShell Payload"
      author = "Florian Roth"
      reference = "https://github.com/nccgroup/Winpayloads"
      date = "2017-07-11"
      hash1 = "011eba8f18b66634f6eb47527b4ceddac2ae615d6861f89a35dbb9fc591cae8e"
   strings:
      $x1 = "$Base64Cert = 'MIIJeQIBAzCCCT8GCSqGSIb3DQEHAaCCCTAEggksMIIJKDCCA98GCSqGSIb3DQEHBqCCA9AwggPMAgEAMIIDxQYJKoZIhvcNAQcBMBwGCiqGSIb3D" ascii
      $x2 = "powershell -w hidden -noni -enc SQBF" fullword ascii nocase
      $x3 = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAGMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwA" ascii
      $x4 = "powershell.exe -WindowStyle Hidden -enc JABjAGwAaQBlAG4AdAA" ascii
   condition:
      filesize < 10KB and 1 of them
}

rule WinPayloads_Payload {
   meta:
      description = "Detects WinPayloads Payload"
      author = "Florian Roth"
      reference = "https://github.com/nccgroup/Winpayloads"
      date = "2017-07-11"
      super_rule = 1
      hash1 = "23a24f99c3c6c00cd4bf6cb968f813ba2ceadfa846c7f169f412bcbb71ba6573"
      hash2 = "35069905d9b7ba1fd57c8df03614f563504194e4684f47aafa08ebb8d9409d0b"
      hash3 = "a28d107f168d85c38fc76229b14561b472e60e60973eb10b6b554c1f57469322"
      hash4 = "ed93e28ca18f749a78678b1e8e8ac31f4c6c0bab2376d398b413dbdfd5af9c7f"
      hash5 = "26f5aee1ce65158e8375deb63c27edabfc9f5de3c1c88a4ce26a7e50b315b6d8"
      hash6 = "b25a515706085dbde0b98deaf647ef9a8700604652c60c6b706a2ff83fdcbf45"
   strings:
      $s1 = "bpayload.exe.manifest" fullword ascii
      $s2 = "spayload" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and all of them )
}
