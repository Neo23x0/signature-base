/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-03-24
   Identifier: WMImplant
*/

/* Rule Set ----------------------------------------------------------------- */

rule WMImplant {
   meta:
      description = "Auto-generated rule - file WMImplant.ps1"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.fireeye.com/blog/threat-research/2017/03/wmimplant_a_wmi_ba.html"
      date = "2017-03-24"
      hash1 = "860d7c237c2395b4f51b8c9bd0ee6cab06af38fff60ce3563d160d50c11d2f78"
      id = "18dadc55-e12f-5c4c-9e11-27dc2d6c8dd2"
   strings:
      $x1 = "Invoke-ProcessPunisher -Creds $RemoteCredential" fullword ascii
      $x2 = "$Target -query \"SELECT * FROM Win32_NTLogEvent WHERE (logfile='security')" ascii
      $x3 = "WMImplant -Creds" fullword ascii
      $x4 = "-Download -RemoteFile C:\\passwords.txt" ascii
      $x5 = "-Command 'powershell.exe -command \"Enable-PSRemoting" fullword ascii
      $x6 = "Invoke-WMImplant" fullword ascii
   condition:
      1 of them
}
