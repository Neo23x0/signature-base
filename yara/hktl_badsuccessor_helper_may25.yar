
rule HKTL_EXPL_WIN_PS1_BadSuccessor_May25 {
   meta:
      description = "Detects PowerShell tool called Get-BadSuccessorOUPermissions.ps1 that helps exploit a vulnerability in Active Directory. Lists every principal that can perform a BadSuccessor attack and the OUs where it holds the required permissions."
      author = "Florian Roth"
      reference = "https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory"
      date = "2025-05-22"
      score = 75
   strings:
      $x1 = "function Get-BadSuccessorOUPermissions" ascii wide
      $x2 = "\"0feb936f-47b3-49f2-9386-1dedc2c23765\"=\"msDS-DelegatedManagedServiceAccount\"" ascii wide
      $x3 = "CreateChild|GenericAll|WriteDACL|WriteOwner" ascii wide
   condition:
      filesize < 20MB and 1 of them
}
