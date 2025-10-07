rule MAL_G_APT_Backdoor_BRICKSTORM_3 {
   meta:
      description = "Detects BRICKSTORM backdoor used by APT group UNC5221 (China Nexus)"
      author = "Google Threat Intelligence Group (GTIG) (modified by Florian Roth)"
      date = "2025-09-25"
      score = 75
      reference = "https://cloud.google.com/blog/topics/threat-intelligence/brickstorm-espionage-campaign"
      md5 = "931eacd7e5250d29903924c31f41b7e5"
   strings:
      $str1 = { 48 8B 05 ?? ?? ?? ?? 48 89 04 24 E8 ?? ?? ?? ?? 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 04 24 [0-5] E8 ?? ?? ?? ?? EB ?? }
      $str4 = "decompress" ascii  // wide nocase
      $str5 = "MIMEHeader" ascii  // wide nocase
      $str6 = "ResolveReference" ascii  // wide nocase
      $str7 = "115792089210356248762697446949407573529996955224135760342422259061068512044369115792089210356248762697446949407573530086143415290314195533631308867097853951" ascii  // wide nocase
   condition:
      uint16(0) == 0x457F and all of them
}

rule MAL_G_Backdoor_BRICKSTORM_2 {
   meta:
      description = "Detects BRICKSTORM backdoor used by APT group UNC5221 (China Nexus)"
      author = "Google Threat Intelligence Group (GTIG) (modified by Florian Roth)"
      date = "2025-09-25"
      score = 75
      reference = "https://cloud.google.com/blog/topics/threat-intelligence/brickstorm-espionage-campaign"
   strings:
      // $obf_func = /[a-z]{20}\/[a-z]{20}\/[a-z]{20}\/[a-z]{20}.go/
      $decr1 = { 0F B6 4C 04 ?? 0F B6 54 04 ?? 31 D1 88 4C 04 ?? 48 FF C0 [0-4] 48 83 F8 ?? 7C }
      $decr2 = { 40 88 7C 34 34 48 FF C3 48 FF C6 48 39 D6 7D 18 0F B6 3B 48 39 CE 73 63 44 0F B6 04 30 44 31 C7 48 83 FE 04 72 DA }
      $decr3 = { 0F B6 54 0C ?? 0F B6 5C 0C ?? 31 DA 88 14 08 48 FF C1 48 83 F9 ?? 7C E8 }

      $str1 = "main.selfWatcher"
      $str2 = "main.copyFile"
      $str3 = "main.startNew"

      $str4 = "WRITE_LOG=true"
      $str5 = "WRITE_LOGWednesday"
      $str6 = "vami-httpdvideo/webm"
      $str7 = "/opt/vmware/sbin/"
      $str8 = "/home/vsphere-ui/"
      $str9 = "/opt/vmware/sbin/vami-http"
      $str10 = "main.getVFromEnv"
   condition:
      uint32(0) == 0x464c457f
      and filesize < 10MB
      and (
         1 of ($decr*)
         and 1 of ($str*)
         or 5 of ($str*)
      )
}

rule MAL_G_APT_Backdoor_BRICKSTORM_1 {
   meta:
      description = "Detects BRICKSTORM backdoor used by APT group UNC5221 (China Nexus)"
      author = "Google Threat Intelligence Group (GTIG) (modified by Florian Roth)"
      date = "2025-09-25"
      score = 75
      reference = "https://cloud.google.com/blog/topics/threat-intelligence/brickstorm-espionage-campaign"
      md5 = "4645f2f6800bc654d5fa812237896b00"
   strings:
      $ = "WRITE_LOGWednesday"
      $ = "/home/vsphere-ui/"
      $ = "WRITE_LOG=true"
      $ = "dns rcode: %v"
      $ = "/libs/doh.createDnsMessage"
      $ = "/libs/func1.(*Client).BackgroundRun"
      $ = "/libs/func1.CreateClient"
      $ = "/core/extends/command.CommandNoContext"
      $ = "/core/extends/command.ExecuteCmd"
      $ = "/core/extends/command.RunShell"
      $ = "/libs/fs.(*RemoteDriver).DeleteFile"
      $ = "/libs/fs.(*RemoteDriver).GetFile"
      $ = "/libs/fs.(*RemoteDriver).PutFile"
      $ = "/libs/doh/doh.go"
   condition:
      uint32(0) == 0x464c457f and 5 of them
}

rule MAL_G_APT_Backdoor_BRICKSTORM_2 {
   meta:
      description = "Detects BRICKSTORM backdoor used by APT group UNC5221 (China Nexus)"
      author = "Google Threat Intelligence Group (GTIG) (modified by Florian Roth)"
      date = "2025-09-25"
      score = 75
      reference = "https://cloud.google.com/blog/topics/threat-intelligence/brickstorm-espionage-campaign"
   strings:
      $str1 = { 0F 57 C0 0F 11 84 ?? ?? ?? ?? ?? C6 44 ?? ?? 00 4? C7 84 ?? ?? ?? ?? ?? 00 00 00 00 0F 57 C0 0F 11 84 ?? ?? ?? ?? ?? 0F 11 84 ?? ?? ?? ?? ?? 4? 8B 84 ?? ?? ?? ?? ?? 4? 89 04 ?? 4? 8B 8C ?? ?? ?? ?? ?? 4? 89 4C ?? ?? E8 ?? ?? ?? ?? 4? 83 7C ?? ?? 00 0F 84 ?? ?? ?? ?? 4? 8D 05 ?? ?? ?? ?? 4? 89 ?? ?? E8 ?? ?? ?? ?? 4? 8B 7C ?? ?? 4? 8B 84 ?? ?? ?? ?? ?? 4? 89 47 08 83 3D ?? ?? ?? ?? 00 75 ?? 4? 8B 84 ?? ?? ?? ?? ?? 4? 89 07 4? 89 BC ?? ?? ?? ?? ?? 4? C7 84 ?? ?? ?? ?? ?? 01 00 00 00 4? C7 84 ?? ?? ?? ?? ?? 01 00 00 00 0F 57 C0 0F 11 84 ?? ?? ?? ?? ?? 4? 8B ?? ?? ?? ?? ?? ?? 4? 81 C4 ?? ?? ?? ?? C3 }
      $str2 = { 4? C7 84 ?? ?? ?? ?? ?? 00 00 00 00 4? C7 84 ?? ?? ?? ?? ?? 00 00 00 00 4? C7 84 ?? ?? ?? ?? ?? 00 00 00 00 4? C7 84 ?? ?? ?? ?? ?? 00 00 00 00 4? C7 84 ?? ?? ?? ?? ?? 00 00 00 00 4? 8B 84 ?? ?? ?? ?? ?? 4? 89 04 ?? 4? 8B 8C ?? ?? ?? ?? ?? 4? 89 4C ?? ?? E8 ?? ?? ?? ?? 4? 8B 44 ?? ?? 4? 85 C0 0F 84 ?? ?? ?? ?? 4? 8D 05 ?? ?? ?? ?? 4? 89 ?? ?? E8 ?? ?? ?? ?? 4? 8B 44 ?? ?? 4? 8B 8C ?? ?? ?? ?? ?? 4? 89 48 08 8B 0D ?? ?? ?? ?? 85 C9 75 ?? 4? 8B 8C ?? ?? ?? ?? ?? 4? 89 08 84 00 4? 89 84 ?? ?? ?? ?? ?? 4? C7 84 ?? ?? ?? ?? ?? 01 00 00 00 4? C7 84 ?? ?? ?? ?? ?? 01 00 00 00 4? C7 84 ?? ?? ?? ?? ?? 00 00 00 00 4? C7 84 ?? ?? ?? ?? ?? 00 00 00 00 90 E8 ?? ?? ?? ?? 4? 8B ?? ?4 D8 00 00 00 4? 81 C4 E0 00 00 00 C3 }
   condition:
      uint32be(0) == 0x7F454C46 and any of them
}

rule WEBSHELL_G_APT_BackdoorWebshell_SLAYSTYLE_1 {
   meta:
      description = "Detects webshell used by APT group UNC5221 (China Nexus)"
      author = "Google Threat Intelligence Group (GTIG) (modified by Florian Roth)"
      date = "2025-09-25"
      score = 75
      reference = "https://cloud.google.com/blog/topics/threat-intelligence/brickstorm-espionage-campaign"
   strings:
      //$str1 = /String \w{1,10}=request\.getParameter\(\"\w{1,15}\"\);/ ascii wide nocase
      $str1_alt = "=request.getParameter(\""
      $str2 = "=new String(java.util.Base64.getDecoder().decode(" ascii wide nocase
      //$str21 = /String\[\]\s\w{1,10}=\{\"\/bin\/sh\",\"-c\",\w{1,10}\+\"\s2>&1\"\};/ ascii wide nocase
      $str21_alt = "={\"/bin/sh\",\"-c\"," ascii
      $str3 = "= Runtime.getRuntime().exec(" ascii
      $str4 = "java.io.InputStream" ascii
      $str5 = "java.util.Base64.getEncoder().encodeToString(org.apache.commons.io.IOUtils.toByteArray(" ascii
   condition:
      filesize < 5MB and all of them
}

rule WEBSHELL_G_APT_BackdoorWebshell_SLAYSTYLE_2 {
   meta:
      description = "Detects webshell used by APT group UNC5221 (China Nexus)"
      author = "Google Threat Intelligence Group (GTIG) (modified by Florian Roth)"
      date = "2025-09-25"
      score = 75
      reference = "https://cloud.google.com/blog/topics/threat-intelligence/brickstorm-espionage-campaign"
   strings:
      $str1 = "request.getParameter"
      $str2 = "/bin/sh"
      $str3 = "java.io.InputStream"
      $str4 = "Runtime.getRuntime().exec("
      $str5 = "2>&1"
   condition:
      (uint16(0) != 0x5A4D and uint32(0) != 0x464C457F) and filesize < 7KB and all of them and @str4 > @str2
}

rule MAL_G_Backdoor_BRICKSTEAL_1 {
   meta:
      description = "Detects backdoor BRICKSTEAL used by APT group UNC5221 (China Nexus)"
      author = "Google Threat Intelligence Group (GTIG) (modified by Florian Roth)"
      date = "2025-09-25"
      score = 75
      reference = "https://cloud.google.com/blog/topics/threat-intelligence/brickstorm-espionage-campaign"
   strings:
      $str1 = "comvmware"
      $str2 = "abcdABCD1234!@#$"
      $str3 = "ads.png"
      $str4 = "User-Agent"
      $str5 = "com/vmware/"
   condition:
      all of them and filesize < 10KB
}

rule MAL_G_Dropper_BRICKSTEAL_1 {
   meta:
      description = "Detects backdoor BRICKSTEAL dropper used by APT group UNC5221 (China Nexus)"
      author = "Google Threat Intelligence Group (GTIG) (modified by Florian Roth)"
      date = "2025-09-25"
      score = 75
      reference = "https://cloud.google.com/blog/topics/threat-intelligence/brickstorm-espionage-campaign"
   strings:
      $str1 = "Base64.getDecoder().decode"
      $str2 = "Thread.currentThread().getContextClassLoader()"
      $str3 = ".class.getDeclaredMethod"
      $str4 = "byte[].class"
      $str5 = "method.invoke"
      $str6 = "filterClass.newInstance()"
      $str7 = "/websso/SAML2/SSO/*"
   condition:
      all of them
}

rule MAL_G_Dropper_BRICKSTEAL_2 {
   meta:
      description = "Detects backdoor BRICKSTEAL dropper used by APT group UNC5221 (China Nexus)"
      author = "Google Threat Intelligence Group (GTIG) (modified by Florian Roth)"
      date = "2025-09-25"
      score = 75
      reference = "https://cloud.google.com/blog/topics/threat-intelligence/brickstorm-espionage-campaign"
   strings:
      // $str1 = /\(Class<\?>\)\smethod\.invoke\(\w{1,20},\s\w{1,20},\s0,\s\w{1,20}\.length\);/i ascii wide
      $str1_alt = "(Class<?>) method.invoke(" ascii wide
      $str2 = "(\"yv66vg" ascii wide
      $str3 = "request.getSession().getServletContext" ascii wide
      $str4 = ".getClass().getDeclaredField(" ascii wide
      $str5 = "new FilterDef();" ascii wide
      $str6 = "new FilterMap();" ascii wide
   condition:
      all of them
}
