rule MAL_RANSOM_Crime_DearCry_Mar2021_1 {
    meta:
        description = "Triggers on strings of known DearCry samples"
        author = "Nils Kuhnert"
        date = "2021-03-12"
        reference = "https://twitter.com/phillip_misner/status/1370197696280027136"
        hash1 = "2b9838da7edb0decd32b086e47a31e8f5733b5981ad8247a2f9508e232589bff"
        hash2 = "e044d9f2d0f1260c3f4a543a1e67f33fcac265be114a1b135fd575b860d2b8c6"
        hash3 = "feb3e6d30ba573ba23f3bd1291ca173b7879706d1fe039c34d53a4fdcdf33ede"
        id = "d9714502-f1ea-5fe8-b0ac-1f7a9a30d8f5"
    strings:
        $x1 = ".TIF .TIFF .PDF .XLS .XLSX .XLTM .PS .PPS .PPT .PPTX .DOC .DOCX .LOG .MSG .RTF .TEX .TXT .CAD .WPS .EML .INI .CSS .HTM .HTML  .XHTML .JS .JSP .PHP .KEYCHAIN .PEM .SQL .APK .APP .BAT .CGI .ASPX .CER .CFM .C .CPP .GO .CONFIG .PL .PY .DWG .XML .JPG .BMP .PNG .EXE .DLL .CAD .AVI .H.CSV .DAT .ISO .PST .PGD  .7Z .RAR .ZIP .ZIPX .TAR .PDB .BIN .DB .MDB .MDF .BAK .LOG .EDB .STM .DBF .ORA .GPG .EDB .MFS" ascii

        $s1 = "create rsa error" ascii fullword
        $s2 = "DEARCRY!" ascii fullword
        $s4 = "/readme.txt" ascii fullword
        $s5 = "msupdate" ascii fullword
        $s6 = "Your file has been encrypted!" ascii fullword
        $s7 = "%c:\\%s" ascii fullword
        $s8 = "C:\\Users\\john\\" ascii
        $s9 = "EncryptFile.exe.pdb" ascii
    condition:
        uint16(0) == 0x5a4d 
        and filesize > 1MB and filesize < 2MB 
        and ( 1 of ($x*) or 3 of them )
        or 5 of them
}

rule MAL_CRIME_RANSOM_DearCry_Mar21_1 {
   meta:
      description = "Detects DearCry Ransomware affecting Exchange servers"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/phillip_misner/status/1370197696280027136"
      date = "2021-03-12"
      hash1 = "2b9838da7edb0decd32b086e47a31e8f5733b5981ad8247a2f9508e232589bff"
      hash2 = "e044d9f2d0f1260c3f4a543a1e67f33fcac265be114a1b135fd575b860d2b8c6"
      hash3 = "feb3e6d30ba573ba23f3bd1291ca173b7879706d1fe039c34d53a4fdcdf33ede"
      id = "96cd2fe8-8bb9-5a3b-9bf1-c63a1148a817"
   strings:
      $s1 = "dear!!!" ascii fullword
      $s2 = "EncryptFile.exe.pdb" ascii fullword
      $s3 = "/readme.txt" ascii fullword
      $s4 = "C:\\Users\\john\\" ascii
      $s5 = "And please send me the following hash!" ascii fullword

      $op1 = { 68 e0 30 52 00 6a 41 68 a5 00 00 00 6a 22 e8 81 d0 f8 ff 83 c4 14 33 c0 5e }
      $op2 = { 68 78 6a 50 00 6a 65 6a 74 6a 10 e8 d9 20 fd ff 83 c4 14 33 c0 5e }
      $op3 = { 31 40 00 13 31 40 00 a4 31 40 00 41 32 40 00 5f 33 40 00 e5 }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 4000KB and
      3 of them or 5 of them
}
