/*
   Yara Rule Set
   Author: US-CERT
   Date: 2017-10-21
   Identifier: TA17-293A
   Reference: https://www.us-cert.gov/ncas/alerts/TA17-293A

   Beware: Rules have been modified to reduce complexity and false positives as well as to
           improve the overall performance
*/

import "pe"

rule TA17_293A_malware_1 {
    meta:
        description = "inveigh pen testing tools & related artifacts"
        author = "US-CERT Code Analysis Team (modified by Florian Roth)"
        reference = "https://www.us-cert.gov/ncas/alerts/TA17-293A"
        date = "2017/07/17"
        hash0 = "61C909D2F625223DB2FB858BBDF42A76"
        hash1 = "A07AA521E7CAFB360294E56969EDA5D6"
        hash2 = "BA756DD64C1147515BA2298B6A760260"
        hash3 = "8943E71A8C73B5E343AA9D2E19002373"
        hash4 = "04738CA02F59A5CD394998A99FCD9613"
        hash5 = "038A97B4E2F37F34B255F0643E49FC9D"
        hash6 = "65A1A73253F04354886F375B59550B46"
        hash7 = "AA905A3508D9309A93AD5C0EC26EBC9B"
        hash8 = "5DBEF7BDDAF50624E840CCBCE2816594"
        hash9 = "722154A36F32BA10E98020A8AD758A7A"
        hash10 = "4595DBE00A538DF127E0079294C87DA0"
        id = "297611c9-f4b1-5618-bd43-5a7444365727"
    strings:
        $n1 = "file://"

        $ax1 = "184.154.150.66"
        $ax2 = "5.153.58.45"
        $ax3 = "62.8.193.206"
        $ax4 = "/pshare1/icon"
        $ax5 = "/ame_icon.png"
        $ax6 = "/1/ree_stat/p"

        /* Too many false positives with these strings
        $au1 = "/icon.png"
        $au2 = "/notepad.png"
        $au3 = "/pic.png"
        */

        $s1 = "(g.charCodeAt(c)^l[(l[b]+l[e])%256])"
        $s2 = "for(b=0;256>b;b++)k[b]=b;for(b=0;256>b;b++)"
        $s3 = "VXNESWJfSjY3grKEkEkRuZeSvkE="
        $s4 = "NlZzSZk="
        $s5 = "WlJTb1q5kaxqZaRnser3sw=="

        $x1 = { 87D081F60C67F5086A003315D49A4000F7D6E8EB12000081F7F01BDD21F7DE }
        $x2 = { 33C42BCB333DC0AD400043C1C61A33C3F7DE33F042C705B5AC400026AF2102 }
        $x3 = "fromCharCode(d.charCodeAt(e)^k[(k[b]+k[h])%256])"
        $x4 = "ps.exe -accepteula \\%ws% -u %user% -p %pass% -s cmd /c netstat"
        $x5 = { 22546F6B656E733D312064656C696D733D5C5C222025254920494E20286C6973742E74787429 }
        $x6 = { 68656C6C2E657865202D6E6F65786974202D657865637574696F6E706F6C69637920627970617373202D636F6D6D616E6420222E202E5C496E76656967682E70 }
        $x7 = { 476F206275696C642049443A202266626433373937623163313465306531 }
        $x8 = { 24696E76656967682E7374617475735F71756575652E4164642822507265737320616E79206B657920746F2073746F70207265616C2074696D65 }
        //specific malicious word document PK archive
        $x9 = { 2F73657474696E67732E786D6CB456616FDB3613FEFE02EF7F10F4798E64C54D06A14ED125F19A225E87C9FD0194485B }
        $x10 = { 6C732F73657474696E67732E786D6C2E72656C7355540500010076A41275780B0001040000000004000000008D90B94E03311086EBF014D6F4D87B48214471D2 }
        $x11 = { 8D90B94E03311086EBF014D6F4D87B48214471D210A41450A0E50146EBD943F8923D41C9DBE3A54A240ACA394A240ACA39 }
        $x12 = { 8C90CD4EEB301085D7BD4F61CDFEDA092150A1BADD005217B040E10146F124B1F09FEC01B56F8FC3AA9558B0B4 }
        $x13 = { 8C90CD4EEB301085D7BD4F61CDFEDA092150A1BADD005217B040E10146F124B1F09FEC01B56F8FC3AA9558B0B4 }

        $x14 = "http://bit.ly/2m0x8IH"

    condition:
        ( $n1 and 1 of ($ax*) ) or
        2 of ($s*) or
        1 of ($x*)
}

rule TA17_293A_energetic_bear_api_hashing_tool {
   meta:
      description = "Energetic Bear API Hashing Tool"
      assoc_report = "DHS Report TA17-293A"
      author = "CERT RE Team"
      version = "2"
      id = "4e58800a-9618-5d8b-954c-e843be6002c2"
   strings:
      $api_hash_func_v1 = { 8A 08 84 C9 74 ?? 80 C9 60 01 CB C1 E3 01 03 45 10 EB ED }
      $api_hash_func_v2 = { 8A 08 84 C9 74 ?? 80 C9 60 01 CB C1 E3 01 03 44 24 14 EB EC }
      $api_hash_func_x64 = { 8A 08 84 C9 74 ?? 80 C9 60 48 01 CB 48 C1 E3 01 48 03 45 20 EB EA }

      $http_push = "X-mode: push" nocase
      $http_pop = "X-mode: pop" nocase
   condition:
      $api_hash_func_v1 or $api_hash_func_v2 or $api_hash_func_x64 and (uint16(0) == 0x5a4d or $http_push or $http_pop)
}

rule TA17_293A_Query_XML_Code_MAL_DOC_PT_2 {
    meta:
        name= "Query_XML_Code_MAL_DOC_PT_2"
        author = "other (modified by Florian Roth)"
        reference = "https://www.us-cert.gov/ncas/alerts/TA17-293A"
        id = "82b0f28a-94b6-52ab-8fd6-cdc05823ac34"
    strings:
        $dir1 = "word/_rels/settings.xml.rels"
        $bytes = {8c 90 cd 4e eb 30 10 85 d7}
    condition:
        uint32(0) == 0x04034b50 and $dir1 and $bytes
}

rule TA17_293A_Query_XML_Code_MAL_DOC {
    meta:
        name= "Query_XML_Code_MAL_DOC"
        author = "other (modified by Florian Roth)"
        reference = "https://www.us-cert.gov/ncas/alerts/TA17-293A"
        id = "82b0f28a-94b6-52ab-8fd6-cdc05823ac34"
    strings:
        $dir = "word/_rels/" ascii
        $dir2 = "word/theme/theme1.xml" ascii
        $style = "word/styles.xml" ascii
    condition:
        uint32(0) == 0x04034b50 and $dir at 0x0145 and $dir2 at 0x02b7 and $style at 0x08fd
}

rule TA17_293A_Query_Javascript_Decode_Function {
    meta:
        name= "Query_Javascript_Decode_Function"
        author = "other (modified by Florian Roth)"
        reference = "https://www.us-cert.gov/ncas/alerts/TA17-293A"
        id = "bc206ab3-a86b-5abe-ae84-15abab838d4e"
    strings:
        $decode1 = {72 65 70 6C 61 63 65 28 2F 5B 5E 41 2D 5A 61 2D 7A 30 2D 39 5C 2B 5C 2F 5C 3D 5D 2F 67 2C 22 22 29 3B}
        $decode2 = {22 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F 50 51 52 53 54 55 56 57 58 59 5A 61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F 70 71 72 73 74 75 76 77 78 79 7A 30 31 32 33 34 35 36 37 38 39 2B 2F 3D 22 2E 69 6E 64 65 78 4F 66 28 ?? 2E 63 68 61 72 41 74 28 ?? 2B 2B 29 29}
        $decode3 = {3D ?? 3C 3C 32 7C ?? 3E 3E 34 2C ?? 3D 28 ?? 26 31 35 29 3C 3C 34 7C ?? 3E 3E 32 2C ?? 3D 28 ?? 26 33 29 3C 3C 36 7C ?? 2C ?? 2B 3D [1-2] 53 74 72 69 6E 67 2E 66 72 6F 6D 43 68 61 72 43 6F 64 65 28 ?? 29 2C 36 34 21 3D ?? 26 26 28 ?? 2B 3D 53 74 72 69 6E 67 2E 66 72 6F 6D 43 68 61 72 43 6F 64 65 28 ?? 29}
        $decode4 = {73 75 62 73 74 72 69 6E 67 28 34 2C ?? 2E 6C 65 6E 67 74 68 29}
        /* Only 3 characters atom - this is bad for performance - we're trying to leave this out
        $func_call="a(\""
        */
    condition:
        filesize < 20KB and
        /* #func_call > 20 and */
        all of ($decode*)
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-10-21
   Identifier: TA17-293A Extensions
   Reference: https://www.us-cert.gov/ncas/alerts/TA17-293A
*/

/* Rule Set ----------------------------------------------------------------- */

rule TA17_293A_Hacktool_PS_1 {
   meta:
      description = "Auto-generated rule"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.us-cert.gov/ncas/alerts/TA17-293A"
      date = "2017-10-21"
      hash1 = "72a28efb6e32e653b656ca32ccd44b3111145a695f6f6161965deebbdc437076"
      id = "e4b92536-fa9a-5a65-8bd6-84c037dfbdce"
   strings:
      $x1 = "$HashFormat = '$krb5tgs$23$*ID#124_DISTINGUISHED NAME: CN=fakesvc,OU=Service,OU=Accounts,OU=EnterpriseObjects,DC=asdf,DC=pd,DC=f" ascii
      $x2 = "} | Where-Object {$_.SamAccountName -notmatch 'krbtgt'} | Get-SPNTicket @GetSPNTicketArguments" fullword ascii
   condition:
      ( filesize < 80KB and 1 of them )
}

rule TA17_293A_Hacktool_Touch_MAC_modification {
   meta:
      description = "Auto-generated rule"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.us-cert.gov/ncas/alerts/TA17-293A"
      date = "2017-10-21"
      hash1 = "070d7082a5abe1112615877214ec82241fd17e5bd465e24d794a470f699af88e"
      id = "69240cc0-a04e-544a-b7e3-c5a08c062055"
   strings:
      $s1 = "-t time - use the time specified to update the access and modification times" fullword ascii
      $s2 = "Failed to set file times for %s. Error: %x" fullword ascii
      $s3 = "touch [-acm][ -r ref_file | -t time] file..." fullword ascii
      $s4 = "-m - change the modification time only" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and 1 of them )
}

rule TA17_293A_Hacktool_Exploit_MS16_032 {
   meta:
      description = "Auto-generated rule"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.us-cert.gov/ncas/alerts/TA17-293A"
      date = "2017-10-21"
      hash1 = "9b97290300abb68fb48480718e6318ee2cdd4f099aa6438010fb2f44803e0b58"
      id = "4c5838d7-9956-564e-a25c-f2ba5641ac03"
   strings:
      $x1 = "[?] Thread belongs to: $($(Get-Process -PID $([Kernel32]::GetProcessIdOfThread($Thread)))" ascii
      $x2 = "0x00000002, \"C:\\Windows\\System32\\cmd.exe\", \"\"," fullword ascii
      $x3 = "PowerShell implementation of MS16-032. The exploit targets all vulnerable" fullword ascii
      $x4 = "If we can't open the process token it's a SYSTEM shell!" fullword ascii
   condition:
      ( filesize < 40KB and 1 of them )
}

/* Extra Rules based on Imphash of involved malware - Generic approach */

rule Imphash_UPX_Packed_Malware_1_TA17_293A {
   meta:
      description = "Detects malware based on Imphash of malware used in TA17-293A"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.us-cert.gov/ncas/alerts/TA17-293A"
      date = "2017-10-21"
      hash1 = "a278256fbf2f061cfded7fdd58feded6765fade730374c508adad89282f67d77"
      id = "3ff28f06-8b69-5e8f-ab45-dfa4f6e69812"
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and pe.imphash() == "d7d745ea39c8c5b82d5e153d3313096c" )
}

rule Imphash_Malware_2_TA17_293A : HIGHVOL {
   meta:
      description = "Detects malware based on Imphash of malware used in TA17-293A"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.us-cert.gov/ncas/alerts/TA17-293A"
      date = "2017-10-21"
      id = "5c9f32a3-8c50-5d46-929b-bbe14697540e"
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and pe.imphash() == "a8f69eb2cf9f30ea96961c86b4347282" )
}
