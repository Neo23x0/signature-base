/*
    Copyright 2021 by FireEye, Inc.

    The 2-Clause BSD License

    Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
    1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
    2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

rule FE_Webshell_PL_ATRIUM_1
{
    meta:
        author = "Mandiant"
        date = "2021-04-16"
        hash = "ca0175d86049fa7c796ea06b413857a3"
        description = "Detects samples mentioned in PulseSecure report"
        reference = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
        id = "b2663343-0bae-5215-a443-866ab8626bff"
    strings:
        $s1 = "CGI::param("
        $s2 = "system("
        $s3 = /if[\x09\x20]{0,32}\(CGI::param\([\x22\x27]\w{1,64}[\x22\x27]\)\)\s{0,128}\{[\x09\x20]{0,32}print [\x22\x27]Cache-Control: no-cache\\n[\x22\x27][\x09\x20]{0,32};\s{0,128}print [\x22\x27]Content-type: text\/html\\n\\n[\x22\x27][\x09\x20]{0,32};\s{0,128}my \$\w{1,64}[\x09\x20]{0,32}=[\x09\x20]{0,32}CGI::param\([\x22\x27]\w{1,64}[\x22\x27]\)[\x09\x20]{0,32};\s{0,128}system\([\x22\x27]\$/
    condition:
        all of them
}

rule FE_Trojan_SH_ATRIUM_1
{
    meta:
        author = "Mandiant"
        date = "2021-04-16"
        hash = "a631b7a8a11e6df3fccb21f4d34dbd8a"
        description = "Detects samples mentioned in PulseSecure report"
        reference = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
        id = "c49441f4-a138-534c-a858-a7462ed865c9"
    strings:
        $s1 = "CGI::param("
        $s2 = "Cache-Control: no-cache"
        $s3 = "system("
        $s4 = /sed -i [^\r\n]{1,128}CGI::param\([^\r\n]{1,128}print[\x20\x09]{1,32}[^\r\n]{1,128}Cache-Control: no-cache[^\r\n]{1,128}print[\x20\x09]{1,32}[^\r\n]{1,128}Content-type: text\/html[^\r\n]{1,128}my [^\r\n]{1,128}=[\x09\x20]{0,32}CGI::param\([^\r\n]{1,128}system\(/
    condition:
        all of them
}
rule FE_APT_Webshell_PL_HARDPULSE 
{ 
    meta: 
        author = "Mandiant"  
        date = "2021-04-16"      
        hash = "980cba9e82faf194edb6f3cc20dc73ff"
        description = "Detects samples mentioned in PulseSecure report"
        reference = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
        id = "f9a2922e-6b8e-5f92-a947-3215ee8883ac"
    strings: 
        $r1 = /if[\x09\x20]{0,32}\(\$\w{1,64}[\x09\x20]{1,32}eq[\x09\x20]{1,32}[\x22\x27]\w{1,64}[\x22\x27]\)\s{0,128}\{\s{1,128}my[\x09\x20]{1,32}\$\w{1,64}[\x09\x20]{0,32}\x3b\s{1,128}unless[\x09\x20]{0,32}\(open\(\$\w{1,64},[\x09\x20]{0,32}\$\w{1,64}\)\)\s{0,128}\{\s{1,128}goto[\x09\x20]{1,32}\w{1,64}[\x09\x20]{0,32}\x3b\s{1,128}return[\x09\x20]{1,32}0[\x09\x20]{0,32}\x3b\s{0,128}\}/ 
        $r2 = /open[\x09\x20]{0,32}\(\*\w{1,64}[\x09\x20]{0,32},[\x09\x20]{0,32}[\x22\x27]>/ 
        $r3 = /if[\x09\x20]{0,32}\(\$\w{1,64}[\x09\x20]{1,32}eq[\x09\x20]{1,32}[\x22\x27]\w{1,64}[\x22\x27]\)\s{0,128}\{\s{1,128}print[\x09\x20]{0,32}[\x22\x27]Content-type/ 
        $s1 = "CGI::request_method()" 
        $s2 = "CGI::param(" 
        $s3 = "syswrite(" 
        $s4 = "print $_" 
    condition: 
        all of them 
} 
rule FE_APT_Trojan_Linux32_LOCKPICK_1
{
    meta:
        author = "Mandiant"
        date = "2021-04-16"
        hash = "e8bfd3f5a2806104316902bbe1195ee8"
        description = "Detects samples mentioned in PulseSecure report"
        reference = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
        id = "00c09378-25a0-55f1-8d93-7b22d98bd8c2"
    strings:
        $sb1 = { 83 ?? 63 0F 84 [4] 8B 45 ?? 83 ?? 01 89 ?? 24 89 44 24 04 E8 [4] 85 C0 }
        $sb2 = { 83 [2] 63 74 ?? 89 ?? 24 04 89 ?? 24 E8 [4] 83 [2] 01 85 C0 0F [5] EB 00 8B ?? 04 83 F8 02 7? ?? 83 E8 01 C1 E0 02 83 C0 00 89 44 24 08 8D 83 [4] 89 44 24 04 8B ?? 89 04 24 E8 }
    condition:
        ((uint32(0) == 0x464c457f) and (uint8(4) == 1)) and (@sb1[1] < @sb2[1])
}
rule FE_APT_Trojan_Linux32_PACEMAKER 
{ 
    meta: 
        author = "Mandiant"  
        date = "2021-04-16"   
        hash = "d7881c4de4d57828f7e1cab15687274b"
        description = "Detects samples mentioned in PulseSecure report"
        reference = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
        id = "459e26f1-4ea9-56dd-ad71-0ed2c7499aea"
    strings: 
        $s1 = "\x00/proc/%d/mem\x00" 
        $s2 = "\x00/proc/%s/maps\x00" 
        $s3 = "\x00/proc/%s/cmdline\x00" 
        $sb1 = { C7 44 24 08 10 00 00 00 C7 44 24 04 00 00 00 00 8D 45 E0 89 04 24 E8 [4] 8B 45 F4 83 C0 0B C7 44 24 08 10 00 00 00 89 44 24 04 8D 45 E0 89 04 24 E8 [4] 8D 45 E0 89 04 24 E8 [4] 85 C0 74 ?? 8D 45 E0 89 04 24 E8 [4] 85 C0 74 ?? 8D 45 E0 89 04 24 E8 [4] EB } 
        $sb2 = { 8B 95 [4] B8 [4] 8D 8D [4] 89 4C 24 10 8D 8D [4] 89 4C 24 0C 89 54 24 08 89 44 24 04 8D 85 [4] 89 04 24 E8 [4] C7 44 24 08 02 00 00 00 C7 44 24 04 00 00 00 00 8B 45 ?? 89 04 24 E8 [4] 89 45 ?? 8D 85 [4] 89 04 24 E8 [4] 89 44 24 08 8D 85 [4] 89 44 24 04 8B 45 ?? 89 04 24 E8 [4] 8B 45 ?? 89 45 ?? C7 45 ?? 00 00 00 00 [0-16] 83 45 ?? 01 8B 45 ?? 3B 45 0C } 
    condition: 
        ((uint32(0) == 0x464c457f) and (uint8(4) == 1)) and all of them 
} 
rule FE_APT_Trojan_Linux_PACEMAKER 
{ 
    meta: 
        author = "Mandiant"  
        date = "2021-04-16"     
        hash = "d7881c4de4d57828f7e1cab15687274b"
        description = "Detects samples mentioned in PulseSecure report"
        reference = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
        id = "5a20260a-5389-57da-956c-97063fed5015"
    strings: 
        $s1 = "\x00Name:%s || Pwd:%s || AuthNum:%s\x0a\x00" 
        $s2 = "\x00/proc/%d/mem\x00" 
        $s3 = "\x00/proc/%s/maps\x00" 
        $s4 = "\x00/proc/%s/cmdline\x00" 
    condition: 
        (uint32(0) == 0x464c457f) and all of them 
}
rule FE_APT_Webshell_PL_PULSECHECK_1 
{ 
    meta: 
        author = "Mandiant" 
        date = "2021-04-16"  
        sha256 = "a1dcdf62aafc36dd8cf64774dea80d79fb4e24ba2a82adf4d944d9186acd1cc1"
        description = "Detects samples mentioned in PulseSecure report"
        reference = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
        id = "f375fdd8-567b-569b-85f4-af54a35d2a93"
    strings: 
        $r1 = /while[\x09\x20]{0,32}\(<\w{1,64}>\)[\x09\x20]{0,32}\{\s{1,256}\$\w{1,64}[\x09\x20]{0,32}\.=[\x09\x20]{0,32}\$_;\s{0,256}\}/ 
        $s1 = "use Crypt::RC4;" 
        $s2 = "use MIME::Base64" 
        $s3 = "MIME::Base64::decode(" 
        $s4 = "popen(" 
        $s5 = " .= $_;" 
        $s6 = "print MIME::Base64::encode(RC4(" 
        $s7 = "HTTP_X_" 
    condition: 
        $s1 and $s2 and (@s3[1] < @s4[1]) and (@s4[1] < @s5[1]) and (@s5[1] < @s6[1]) and (#s7 > 2) and $r1 
} 
rule FE_APT_Trojan_PL_PULSEJUMP_1
{
    meta:
        author = "Mandiant"
        date = "2021-04-16"
        hash = "91ee23ee24e100ba4a943bb4c15adb4c"
        description = "Detects samples mentioned in PulseSecure report"
        reference = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
        id = "690cc347-e60f-5cac-b65d-367ecee69251"
    strings:
        $s1 = "open("
        $s2 = ">>/tmp/"
        $s3 = "syswrite("
        $s4 = /\}[\x09\x20]{0,32}elsif[\x09\x20]{0,32}\([\x09\x20]{0,32}\$\w{1,64}[\x09\x20]{1,32}eq[\x09\x20]{1,32}[\x22\x27](Radius|Samba|AD)[\x22\x27][\x09\x20]{0,32}\)\s{0,128}\{\s{0,128}@\w{1,64}[\x09\x20]{0,32}=[\x09\x20]{0,32}&/
    condition:
        all of them
}
rule FE_APT_Trojan_PL_QUIETPULSE 
{
    meta: 
        author = "Mandiant"  
        date = "2021-04-16"       
        hash = "00575bec8d74e221ff6248228c509a16"
        description = "Detects samples mentioned in PulseSecure report"
        reference = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
        id = "4c49eef7-b8fa-55d5-8fb8-8964f6f50003"
    strings: 
        $s1 = /open[\x09\x20]{0,32}\(\*STDOUT[\x09\x20]{0,32},[\x09\x20]{0,32}[\x22\x27]>&CLIENT[\x22\x27]\)/ 
        $s2 = /open[\x09\x20]{0,32}\(\*STDERR[\x09\x20]{0,32},[\x09\x20]{0,32}[\x22\x27]>&CLIENT[\x22\x27]\)/ 
        $s3 = /socket[\x09\x20]{0,32}\(SERVER[\x09\x20]{0,32},[\x09\x20]{0,32}PF_UNIX[\x09\x20]{0,32},[\x09\x20]{0,32}SOCK_STREAM[\x09\x20]{0,32},[\x09\x20]{0,32}0[\x09\x20]{0,32}\)[\x09\x20]{0,32};\s{0,128}unlink/ 
        $s4 = /bind[\x09\x20]{0,32}\([\x09\x20]{0,32}SERVER[\x09\x20]{0,32},[\x09\x20]{0,32}sockaddr_un\(/ 
        $s5 = /listen[\x09\x20]{0,32}\([\x09\x20]{0,32}SERVER[\x09\x20]{0,32},[\x09\x20]{0,32}SOMAXCONN[\x09\x20]{0,32}\)[\x09\x20]{0,32};/ 
        $s6 = /my[\x09\x20]{1,32}\$\w{1,64}[\x09\x20]{0,32}=[\x09\x20]{0,32}fork\([\x09\x20]{0,32}\)[\x09\x20]{0,32};\s{1,128}if[\x09\x20]{0,32}\([\x09\x20]{0,32}\$\w{1,64}[\x09\x20]{0,32}==[\x09\x20]{0,32}0[\x09\x20]{0,32}\)[\x09\x20]{0,32}\{\s{1,128}exec\(/ 
    condition: 
        all of them 
} 
rule FE_APT_Trojan_PL_RADIALPULSE_1 
{
    meta: 
        author = "Mandiant" 
        date = "2021-04-16"       
        sha256 = "d72daafedf41d484f7f9816f7f076a9249a6808f1899649b7daa22c0447bb37b"
        description = "Detects samples mentioned in PulseSecure report"
        reference = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"        
        id = "1fab6d2f-96e8-5def-a93e-2bddd04e7ec8"
    strings: 
        $s1 = "->getRealmInfo()->{name}" 
        $s2 = /open\(\*fd,[\x09\x20]{0,32}[\x22\x27]>>/ 
        $s3 = /syswrite\(\*fd,[\x09\x20]{0,32}[\x22\x27]realm=\$/ 
        $s4 = /syswrite\(\*fd,[\x09\x20]{0,32}[\x22\x27]username=\$/ 
        $s5 = /syswrite\(\*fd,[\x09\x20]{0,32}[\x22\x27]password=\$/ 
    condition: 
        (@s1[1] < @s2[1]) and (@s2[1] < @s3[1]) and $s4 and $s5 
} 
rule FE_APT_Trojan_PL_RADIALPULSE_2 
{ 
    meta: 
        author = "Mandiant"  
        date = "2021-04-16"       
        hash = "4a2a7cbc1c8855199a27a7a7b51d0117"
        description = "Detects samples mentioned in PulseSecure report"
        reference = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
        id = "dc941935-aec7-54b6-a278-f1453b9785df"
    strings: 
        $s1 = "open(*fd," 
        $s2 = "syswrite(*fd," 
        $s3 = "close(*fd);" 
        $s4 = /open\(\*fd,[\x09\x20]{0,32}[\x22\x27]>>\/tmp\/[\w.]{1,128}[\x22\x27]\);[\x09\x20]{0,32}syswrite\(\*fd,[\x09\x20]{0,32}/ 
        $s5 = /syswrite\(\*fd,[\x09\x20]{0,32}[\x22\x27][\w]{1,128}=\$\w{1,128} ?[\x22\x27],[\x09\x20]{0,32}5000\)/ 
    condition: 
        all of them 
} 
rule FE_APT_Trojan_PL_RADIALPULSE_3 
{ 
    meta: 
        author = "Mandiant"  
        date = "2021-04-16"  
        hash = "4a2a7cbc1c8855199a27a7a7b51d0117"
        description = "Detects samples mentioned in PulseSecure report"
        reference = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
        id = "8a597521-c873-5bcc-85e6-5a0a061fffb7"
    strings: 
        $s1 = "open(*fd," 
        $s2 = "syswrite(*fd," 
        $s3 = "close(*fd);" 
        $s4 = /open\(\*fd,[\x09\x20]{0,32}[\x22\x27]>>\/tmp\/dsstartssh\.statementcounters[\x22\x27]\);[\x09\x20]{0,32}syswrite\(\*fd,[\x09\x20]{0,32}/ 
        $s5 = /syswrite\(\*fd,[\x09\x20]{0,32}[\x22\x27][\w]{1,128}=\$username ?[\x22\x27],[\x09\x20]{0,32}\d{4}\)/ 
    condition: 
        all of them 
} 
rule FE_APT_Backdoor_Linux32_SLOWPULSE_1 
{ 
    meta: 
        author = "Mandiant" 
        date = "2021-04-16"
        sha256 = "cd09ec795a8f4b6ced003500a44d810f49943514e2f92c81ab96c33e1c0fbd68"
        description = "Detects samples mentioned in PulseSecure report"
        reference = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"        
        id = "dd35257f-5b6f-55a6-a709-873ded1f4b72"
    strings: 
        $sb1 = {FC b9 [4] e8 00 00 00 00 5? 8d b? [4] 8b} 
        $sb2 = {f3 a6 0f 85 [4] b8 03 00 00 00 5? 5? 5?} 
        $sb3 = {9c 60 e8 00 00 00 00 5? 8d [5] 85 ?? 0f 8?} 
        $sb4 = {89 13 8b 51 04 89 53 04 8b 51 08 89 53 08} 
        $sb5 = {8d [5] b9 [4] f3 a6 0f 8?} 
    condition: 
        ((uint32(0) == 0x464c457f) and (uint8(4) == 1)) and all of them 
}

/* TOO SLOW 
rule FE_APT_Backdoor_Linux32_SLOWPULSE_2
{ 
    meta: 
        author = "Strozfriedberg" 
        date = "2021-04-16"
        sha256 = "cd09ec795a8f4b6ced003500a44d810f49943514e2f92c81ab96c33e1c0fbd68"
        description = "Detects samples mentioned in PulseSecure report"
        reference = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"        
    strings: 
        $sig = /[\x20-\x7F]{16}([\x20-\x7F\x00]+)\x00.{1,32}\xE9.{3}\xFF\x00+[\x20-\x7F][\x20-\x7F\x00]{16}/ 

        // TOI_MAGIC_STRING 
        $exc1 = /\xED\xC3\x02\xE9\x98\x56\xE5\x0C/ 
    condition:
        uint32(0) == 0x464C457F and (1 of ($sig*)) and (not (1 of ($exc*)))
}
*/

rule FE_APT_Webshell_PL_STEADYPULSE_1
{  
    meta:  
        author = "Mandiant"  
        date = "2021-04-16"      
        sha256 = "168976797d5af7071df257e91fcc31ce1d6e59c72ca9e2f50c8b5b3177ad83cc"
        description = "Detects samples mentioned in PulseSecure report"
        reference = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"     
        id = "49457fbb-9288-565f-909d-e8228c21c1e4"
    strings:  
        $s1 = "parse_parameters" 
        $s2 = "s/\\+/ /g"  
        $s3 = "s/%(..)/pack("  
        $s4 = "MIME::Base64::encode($"  
        $s5 = "$|=1;" 
        $s6 = "RC4(" 
        $s7 = "$FORM{'cmd'}" 
    condition:  
        all of them  
}