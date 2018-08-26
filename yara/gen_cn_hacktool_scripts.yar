/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2015-06-13
    Identifier: CN-Tools Scripts
    Reference: Diclosed hacktool set at http://w2op.us/ (Mirror: http://tools.zjqhr.com) 
*/


rule CN_Tools_xbat {
    meta:
        description = "Chinese Hacktool Set - file xbat.vbs"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "a7005acda381a09803b860f04d4cae3fdb65d594"
    strings:
        $s0 = "ws.run \"srss.bat /start\",0 " fullword ascii 
        $s1 = "Set ws = Wscript.CreateObject(\"Wscript.Shell\")" fullword ascii 
    condition:
        uint16(0) == 0x6553 and filesize < 0KB and all of them
}

rule CN_Tools_Temp {
    meta:
        description = "Chinese Hacktool Set - file Temp.war"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "c3327ef63b0ed64c4906e9940ef877c76ebaff58"
    strings:
        $s0 = "META-INF/context.xml<?xml version=\"1.0\" encoding=\"UTF-8\"?>" fullword ascii 
        $s1 = "browser.jsp" fullword ascii 
        $s3 = "cmd.jsp" fullword ascii
        $s4 = "index.jsp" fullword ascii
    condition:
        uint16(0) == 0x4b50 and filesize < 203KB and all of them
}

rule CN_Tools_srss {
    meta:
        description = "Chinese Hacktool Set - file srss.bat"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "092ab0797947692a247fe80b100fb4df0f9c37a0"
    strings:
        $s0 = "srss.exe -idx 0 -ip"
        $s1 = "-port 21 -logfilter \"_USER ,_P" ascii 
    condition:
        filesize < 100 and all of them
}

rule dll_UnReg {
    meta:
        description = "Chinese Hacktool Set - file UnReg.bat"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "d5e24ba86781c332d0c99dea62f42b14e893d17e"
    strings:
        $s0 = "regsvr32.exe /u C:\\windows\\system32\\PacketX.dll" fullword ascii 
        $s1 = "del /F /Q C:\\windows\\system32\\PacketX.dll" fullword ascii 
    condition:
        filesize < 1KB and 1 of them
}

rule dll_Reg {
    meta:
        description = "Chinese Hacktool Set - file Reg.bat"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "cb8a92fe256a3e5b869f9564ecd1aa9c5c886e3f"
    strings:
        $s0 = "copy PacketX.dll C:\\windows\\system32\\PacketX.dll" fullword ascii 
        $s1 = "regsvr32.exe C:\\windows\\system32\\PacketX.dll" fullword ascii 
    condition:
        filesize < 1KB and all of them
}

rule sbin_squid {
    meta:
        description = "Chinese Hacktool Set - file squid.bat"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "8b795a8085c3e6f3d764ebcfe6d59e26fdb91969"
    strings:
        $s0 = "del /s /f /q" fullword ascii
        $s1 = "squid.exe -z" fullword ascii
        $s2 = "net start Squid" fullword ascii 
        $s3 = "net stop Squid" fullword ascii 
    condition:
        filesize < 1KB and all of them
}

rule sql1433_creck {
    meta:
        description = "Chinese Hacktool Set - file creck.bat"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "189c11a3b268789a3fbcfac3bd4e03cbfde87b1d"
    strings:
        $s0 = "start anhao3.exe -i S.txt -p  pass3.txt -o anhao.txt -l Them.txt -t 1000" fullword ascii 
        $s1 = "start anhao1.exe -i S.txt -p  pass1.txt -o anhao.txt -l Them.txt -t 1000" fullword ascii 
        $s2 = "start anhao2.exe -i S.txt -p  pass2.txt -o anhao.txt -l Them.txt -t 1000" fullword ascii 
    condition:
        uint16(0) == 0x7473 and filesize < 1KB and 1 of them
}

rule sql1433_Start {
    meta:
        description = "Chinese Hacktool Set - file Start.bat"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "bd4be10f4c3a982647b2da1a8fb2e19de34eaf01"
    strings:
        $s1 = "for /f \"eol=- tokens=1 delims= \" %%i in (result.txt) do echo %%i>>s1.txt" fullword ascii 
        $s2 = "start creck.bat" fullword ascii 
        $s3 = "del s1.txt" fullword ascii
        $s4 = "del Result.txt" fullword ascii
        $s5 = "del s.TXT" fullword ascii
        $s6 = "mode con cols=48 lines=20" fullword ascii
    condition:
        filesize < 1KB and 2 of them
}