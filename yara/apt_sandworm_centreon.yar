/*
    Reworked YARA rules as provided by FR/ANSSI/SDO in report on Sandworm activity 
    https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf

    - simplified structure (removed private rules)
    - performance / memory tuning by removal of unnecessary regular expressions
    - removal of overapping rules (rules that contained the specific socket path '/tmp/.applocktx')
*/

rule WEBSHELL_PAS_webshell {
   meta:
      author = "FR/ANSSI/SDO (modified by Florian Roth)"
      description = "Detects P.A.S. PHP webshell - Based on DHS/FBI JAR-16-2029 (Grizzly  Steppe)"
      reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
      date = "2021-02-15"
      score = 70
      id = "862aab77-936e-524c-8669-4f48730f4ed5"
   strings:
      $php = "<?php"
      $strreplace = "(str_replace("
      $md5 = ".substr(md5(strrev($"
      $gzinflate = "gzinflate"
      $cookie = "_COOKIE"
      $isset = "isset"
   condition:
      ( filesize > 20KB and filesize < 200KB ) and
      all of them
}

rule WEBSHELL_PAS_webshell_ZIPArchiveFile {
   meta:
      author = "FR/ANSSI/SDO (modified by Florian Roth)"
      description = "Detects an archive file created by P.A.S. for download operation"
      reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
      date = "2021-02-15"
      score = 80
      id = "081cc65b-e51c-59fc-a518-cd986e8ee2f7"
   strings:
      $s1 = "Archive created by P.A.S. v."
   condition:
      $s1
}

rule WEBSHELL_PAS_webshell_PerlNetworkScript {
   meta:
      author = "FR/ANSSI/SDO"
      description = "Detects PERL scripts created by P.A.S. webshell"
      reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
      date = "2021-02-15"
      score = 90
      id = "1625b63f-ead7-5712-92b4-0ce6ecc49fd4"
   strings:
      $pl_start = "#!/usr/bin/perl\n$SIG{'CHLD'}='IGNORE'; use IO::Socket; use FileHandle;"
      $pl_status = "$o=\" [OK]\";$e=\" Error: \""
      $pl_socket = "socket(SOCKET, PF_INET, SOCK_STREAM,$tcp) or die print \"$l$e$!$l"
      $msg1 = "print \"$l OK! I\\'m successful connected.$l\""
      $msg2 = "print \"$l OK! I\\'m accept connection.$l\""
   condition:
      filesize < 6000 and
      ( $pl_start at 0 and all of ($pl*) ) or
      any of ($msg*)
}

rule WEBSHELL_PAS_webshell_SQLDumpFile {
   meta:
      author = "FR/ANSSI/SDO"
      description = "Detects SQL dump file created by P.A.S. webshell"
      reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
      date = "2021-02-15"
      score = 90
      id = "4c26feeb-3031-5c91-9eeb-4b5fe9702e39"
   strings:
      $ = "-- [ SQL Dump created by P.A.S. ] --"
   condition:
      1 of them
}

rule APT_MAL_Sandworm_Exaramel_Configuration_Key {
   meta:
      author = "FR/ANSSI/SDO"
      description = "Detects the encryption key for the configuration file used by Exaramel malware as seen in sample e1ff72[...]"
      reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
      date = "2021-02-15"
      score = 80
      id = "8078de62-3dd2-5ee0-8bda-f508e4013144"
   strings:
      $ = "odhyrfjcnfkdtslt"
   condition:
      all of them
}

rule APT_MAL_Sandworm_Exaramel_Configuration_Name_Encrypted {
   meta:
      author = "FR/ANSSI/SDO"
      description = "Detects the specific name of the configuration file in Exaramel malware as seen in sample e1ff72[...]"
      reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
      date = "2021-02-15"
      score = 80
      id = "1c06f5fc-3435-51cd-92fb-17a4ab6b63ad"
   strings:
      $ = "configtx.json"
   condition:
      all of them
}

rule APT_MAL_Sandworm_Exaramel_Configuration_File_Plaintext {
   meta:
      author = "FR/ANSSI/SDO"
      description = "Detects contents of the configuration file used by Exaramel (plaintext)"
      reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
      date = "2021-02-15"
      score = 80
      id = "6f0d834b-e6c8-59e6-bf9a-b4fd9c0b2297"
   strings:
      $ = /\{"Hosts":\[".{10,512}"\],"Proxy":".{0,512}","Version":".{1,32}","Guid":"/
   condition:
      all of them
}

rule APT_MAL_Sandworm_Exaramel_Configuration_File_Ciphertext {
   meta:
      author = "FR/ANSSI/SDO"
      description = "Detects contents of the configuration file used by Exaramel (encrypted with key odhyrfjcnfkdtslt, sample e1ff72[...]"
      reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
      date = "2021-02-15"
      score = 80
      id = "763dbb17-2bad-5b40-8a7b-b71bc5849cd9"
   strings:
      $ = { 6F B6 08 E9 A3 0C 8D 5E DD BE D4 } // encrypted with key odhyrfjcnfkdtslt
   condition:
      all of them
}

rule APT_MAL_Sandworm_Exaramel_Socket_Path {
   meta:
      author = "FR/ANSSI/SDO"
      description = "Detects path of the unix socket created to prevent concurrent executions in Exaramel malware"
      reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
      date = "2021-02-15"
      score = 80
      id = "3aab84c9-9748-5d11-9cd7-efa9151036cf"
   strings:
      $ = "/tmp/.applocktx"
   condition:
      all of them
}

rule APT_MAL_Sandworm_Exaramel_Task_Names {
   meta:
      author = "FR/ANSSI/SDO"
      description = "Detects names of the tasks received from the CC server in Exaramel malware"
      reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
      date = "2021-02-15"
      score = 80
      id = "185f2f3b-bf5c-54af-bca2-400d08bf9c91"
   strings:
      $ = "App.Delete"
      $ = "App.SetServer"
      $ = "App.SetProxy"
      $ = "App.SetTimeout"
      $ = "App.Update"
      $ = "IO.ReadFile"
      $ = "IO.WriteFile"
      $ = "OS.ShellExecute"
   condition:
      all of them
}

rule APT_MAL_Sandworm_Exaramel_Struct {
   meta:
      author = "FR/ANSSI/SDO"
      description = "Detects the beginning of type _type struct for some of the most important structs in Exaramel malware"
      reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
      date = "2021-02-15"
      score = 80
      id = "8282e485-966c-554d-8e41-70dc1657f5ea"
   strings:
      $struct_le_config = {70 00 00 00 00 00 00 00 58 00 00 00 00 00 00 00 47 2d 28 42 0? [2] 19}
      $struct_le_worker = {30 00 00 00 00 00 00 00 30 00 00 00 00 00 00 00 46 6a 13 e2 0? [2] 19}
      $struct_le_client = {20 00 00 00 00 00 00 00 10 00 00 00 00 00 00 00 7b 6a 49 84 0? [2] 19}
      $struct_le_report = {30 00 00 00 00 00 00 00 28 00 00 00 00 00 00 00 bf 35 0d f9 0? [2] 19}
      $struct_le_task = {50 00 00 00 00 00 00 00 20 00 00 00 00 00 00 00 88 60 a1 c5 0? [2] 19}
   condition:
      any of them
}

rule APT_MAL_Sandworm_Exaramel_Strings_Typo {
   meta:
      author = "FR/ANSSI/SDO"
      description = "Detects misc strings in Exaramel malware with typos"
      reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
      date = "2021-02-15"
      score = 80
      id = "fdc79b87-eb9e-5751-9474-ff653b073165"
   strings:
      $typo1 = "/sbin/init | awk "
      $typo2 = "Syslog service for monitoring \n"
      $typo3 = "Error.Can't update app! Not enough update archive."
      $typo4 = ":\"metod\""
   condition:
      3 of ($typo*)
}

rule APT_MAL_Sandworm_Exaramel_Strings {
   meta:
      author = "FR/ANSSI/SDO (composed from 4 saparate rules by Florian Roth)"
      description = "Detects Strings used by Exaramel malware"
      reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
      date = "2021-02-15"
      score = 80
      id = "fdc79b87-eb9e-5751-9474-ff653b073165"
   strings:
      $persistence1 = "systemd"
      $persistence2 = "upstart"
      $persistence3 = "systemV"
      $persistence4 = "freebsd rc"

      $report1 = "systemdupdate.rep"
      $report2 = "upstartupdate.rep"
      $report3 = "remove.rep"

      $url1 = "/tasks.get/"
      $url2 = "/time.get/"
      $url3 = "/time.set"
      $url4 = "/tasks.report"
      $url5 = "/attachment.get/"
      $url6 = "/auth/app"
   condition:
      ( 5 of ($url*) and all of ($persistence*) ) or 
      ( all of ($persistence*) and all of ($report*) ) or 
      ( 5 of ($url*) and all of ($report*) )
}

