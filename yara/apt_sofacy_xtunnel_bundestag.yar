import "pe"

rule apt_sofacy_xtunnel {
    meta:
        author = "Claudio Guarnieri"
        description = "Sofacy Malware - German Bundestag"
        score = 75
        id = "aef091b5-cedf-5443-ab61-8b2dbc7e77fd"
    strings:
        $xaps = ":\\PROJECT\\XAPS_"
        $variant11 = "XAPS_OBJECTIVE.dll" $variant12 = "start"
        $variant21 = "User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64; rv:28.0) Gecko/20100101 Firefox/28.0"
        $variant22 = "is you live?"
        $mix1 = "176.31.112.10"
        $mix2 = "error in select, errno %d" $mix3 = "no msg"
        $mix4 = "is you live?"
        $mix5 = "127.0.0.1"
        $mix6 = "err %d"
        $mix7 = "i`m wait"
        $mix8 = "hello"
        $mix9 = "OpenSSL 1.0.1e 11 Feb 2013" $mix10 = "Xtunnel.exe"
    condition:
        ((uint16(0) == 0x5A4D) or (uint16(0) == 0xCFD0)) and (($xaps) or (all of ($variant1*)) or (all of ($variant2*)) or (6 of ($mix*)))
}

rule Winexe_RemoteExec {
   meta:
      description = "Winexe tool for remote execution (also used by Sofacy group)"
      author = "Florian Roth (Nextron Systems), Robert Simmons"
      reference = "http://dokumente.linksfraktion.de/inhalt/report-orig.pdf"
      date = "2015-06-19"
      modified = "2021-02-11"
      hash1 = "5130f600cd9a9cdc82d4bad938b20cbd2f699aadb76e7f3f1a93602330d9997d"
      hash2 = "d19dfdbe747e090c5aa2a70cc10d081ac1aa88f360c3f378288a3651632c4429"
      score = 70
      id = "5079557a-0461-5b04-b0f2-4265bf7ec041"
   strings:
      $s1 = "error Cannot LogonUser(%s,%s,%s) %d" ascii fullword
      $s2 = "error Cannot ImpersonateNamedPipeClient %d" ascii fullword
      $s3 = "\\\\.\\pipe\\ahexec" fullword ascii
      $s4 = "\\\\.\\pipe\\wmcex" fullword ascii
      $s5 = "implevel" fullword ascii
   condition:
   uint16(0) == 0x5a4d and filesize < 115KB and (
      3 of them or
      pe.imphash() == "2f8a475933ac82b8e09eaf26b396b54d"
   )
}

rule Sofacy_Mal2 {
    meta:
        description = "Sofacy Group Malware Sample 2"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://dokumente.linksfraktion.de/inhalt/report-orig.pdf"
        date = "2015-06-19"
        hash = "566ab945f61be016bfd9e83cc1b64f783b9b8deb891e6d504d3442bc8281b092"
        score = 70
        id = "1547cc67-7d7c-5ec9-816c-15b7d523376a"
    strings:
        $x1 = "PROJECT\\XAPS_OBJECTIVE_DLL\\" ascii
        $x2 = "XAPS_OBJECTIVE.dll" fullword ascii

        $s1 = "i`m wait" fullword ascii
    condition:
        uint16(0) == 0x5a4d and ( 1 of ($x*) ) and $s1
}

rule Sofacy_Mal3 {
    meta:
        description = "Sofacy Group Malware Sample 3"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://dokumente.linksfraktion.de/inhalt/report-orig.pdf"
        date = "2015-06-19"
        modified = "2023-01-06"
        hash = "5f6b2a0d1d966fc4f1ed292b46240767f4acb06c13512b0061b434ae2a692fa1"
        score = 70
        id = "67d002ef-4ed9-54ce-a6ef-49b7f3b951e2"
    strings:
        $s1 = "shell\\open\\command=\"System Volume Information\\USBGuard.exe\" install" fullword ascii
        $s2 = ".?AVAgentModuleRemoteKeyLogger@@" fullword ascii
        $s3 = "<font size=4 color=red>process isn't exist</font>" fullword ascii
        $s4 = "<font size=4 color=red>process is exist</font>" fullword ascii
        $s5 = ".winnt.check-fix.com" ascii
        $s6 = ".update.adobeincorp.com" ascii
        $s7 = ".microsoft.checkwinframe.com" ascii
        $s8 = "adobeincorp.com" fullword wide
        $s9 = "# EXC: HttpSender - Cannot create Get Channel!" fullword ascii

        $x1 = "User-Agent: Mozilla/5.0 (Windows NT 6.2; WOW64; rv:20.0) Gecko/20100101 Firefox/" wide
        $x2 = "User-Agent: Mozilla/5.0 (Windows NT 6.; WOW64; rv:20.0) Gecko/20100101 Firefox/2" wide
        $x3 = "C:\\Windows\\System32\\cmd.exe" fullword wide
    condition:
        uint16(0) == 0x5a4d and filesize < 300KB and (
            2 of ($s*) or
            ( 1 of ($s*) and all of ($x*) )
        )
}

rule Sofacy_Bundestag_Batch {
    meta:
        description = "Sofacy Bundestags APT Batch Script"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://dokumente.linksfraktion.de/inhalt/report-orig.pdf"
        date = "2015-06-19"
        score = 70
        id = "869dafec-1387-5640-b608-b84cf0d43342"
    strings:
        $s1 = "for %%G in (.pdf, .xls, .xlsx, .doc, .docx)" ascii
        $s2 = "cmd /c copy"
        $s3 = "forfiles"
    condition:
        filesize < 10KB and 2 of them
}
