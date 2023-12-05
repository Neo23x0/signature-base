rule ATM_Malware_XFSADM {
   meta:
      description = "Detects ATM Malware XFSADM"
      author = "Frank Boldewin (@r3c0nst), modified by Florian Roth"
      reference = "https://twitter.com/r3c0nst/status/1149043362244308992"
      date = "2019-06-21"
      hash1 = "2740bd2b7aa0eaa8de2135dd710eb669d4c4c91d29eefbf54f1b81165ad2da4d"
      id = "7bd7e194-1cf1-5d12-809b-25aaf7f62ca3"
   strings:
      $Code1 = {68 88 13 00 00 FF 35 ?? ?? ?? ?? 68 CF 00 00 00 50 FF 15} // Read Card Data
      $Code2 = {68 98 01 00 00 50 FF 15} // Get PIN Data
      $Mutex = "myXFSADM" wide
      $MSXFSDIR = "C:\\Windows\\System32\\msxfs.dll" ascii
      $XFSCommand1 = "WfsExecute" ascii
      $XFSCommand2 = "WfsGetInfo" ascii
      $PDB = "C:\\Work64\\ADM\\XFS\\Release\\XFS.pdb" ascii
      $WindowName = "XFS ADM" wide
      $FindWindow = "ADM rec" wide
      $LogFile = "xfs.log" ascii
      $TmpFile = "~pipe.tmp" ascii
   condition:
      uint16(0) == 0x5A4D and filesize < 500KB and ( 4 of them or $PDB )
}
