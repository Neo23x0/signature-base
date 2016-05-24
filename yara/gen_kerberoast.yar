/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-05-21
	Identifier: Kerberoast
*/

rule GetUserSPNs_VBS {
	meta:
		description = "Auto-generated rule - file GetUserSPNs.vbs"
		author = "Florian Roth"
		reference = "https://github.com/skelsec/PyKerberoast"
		date = "2016-05-21"
		hash1 = "8dcb568d475fd8a0557e70ca88a262b7c06d0f42835c855b52e059c0f5ce9237"
	strings:
		$s1 = "Wscript.Echo \"User Logon: \" & oRecordset.Fields(\"samAccountName\")" fullword ascii
		$s2 = "Wscript.Echo \" USAGE:        \" & WScript.ScriptName & \" SpnToFind [GC Servername or Forestname]\"" fullword ascii
		$s3 = "strADOQuery = \"<\" + strGCPath + \">;(&(!objectClass=computer)(servicePrincipalName=*));\" & _" fullword ascii
	condition:
		2 of them
}

rule GetUserSPNs_PS1 {
	meta:
		description = "Auto-generated rule - file GetUserSPNs.ps1"
		author = "Florian Roth"
		reference = "https://github.com/skelsec/PyKerberoast"
		date = "2016-05-21"
		hash1 = "1b69206b8d93ac86fe364178011723f4b1544fff7eb1ea544ab8912c436ddc04"
	strings:
		$s1 = "$ForestInfo = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()" fullword ascii
		$s2 = "@{Name=\"PasswordLastSet\";      Expression={[datetime]::fromFileTime($result.Properties[\"pwdlastset\"][0])} } #, `" fullword ascii
		$s3 = "Write-Host \"No Global Catalogs Found!\"" fullword ascii
		$s4 = "$searcher.PropertiesToLoad.Add(\"pwdlastset\") | Out-Null" fullword ascii
	condition:
		2 of them
}

rule kerberoast_PY {
	meta:
		description = "Auto-generated rule - file kerberoast.py"
		author = "Florian Roth"
		reference = "https://github.com/skelsec/PyKerberoast"
		date = "2016-05-21"
		hash1 = "73155949b4344db2ae511ec8cab85da1ccbf2dfec3607fb9acdc281357cdf380"
	strings:
		$s1 = "newencserverticket = kerberos.encrypt(key, 2, encoder.encode(decserverticket), nonce)" fullword ascii
		$s2 = "key = kerberos.ntlmhash(args.password)" fullword ascii
		$s3 = "help='the password used to decrypt/encrypt the ticket')" fullword ascii
      $s4 = "newencserverticket = kerberos.encrypt(key, 2, e, nonce)" fullword ascii
	condition:
		2 of them
}
