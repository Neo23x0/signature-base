
rule APT_UNC5221_Ivanti_ForensicArtifacts_Jan24_1 {
   meta:
      description = "Detects forensic artifacts found in the Ivanti VPN exploitation campaign by APT UNC5221"
      author = "Florian Roth"
      reference = "https://www.mandiant.com/resources/blog/suspected-apt-targets-ivanti-zero-day"
      date = "2024-01-11"
      score = 75
      id = "49ba2a96-379d-5a58-979d-45e83fa546e7"
   strings:
      $x1 = "system(\"chmod a+x /home/etc/sql/dsserver/sessionserver.sh\");"
      $x2 = "SSH-2.0-OpenSSH_0.3xx."
      $x3 = "sed -i '/retval=$(exec $installer $@)/d' /pkg/do-install"
   condition:
      filesize < 5MB and 1 of them
}

rule M_Hunting_Backdoor_ZIPLINE_1 {
  meta:
    author = "Mandiant"
    description = "This rule detects unique strings in ZIPLINE, a passive ELF backdoor that waits for incoming TCP connections to receive commands from the threat actor."
    reference = "https://www.mandiant.com/resources/blog/suspected-apt-targets-ivanti-zero-day"
    date = "2024-01-11"
    score = 75
    id = "753884d6-d4c1-5e94-9d2c-f6ebb7bfaf85"
  strings:
    $s1 = "SSH-2.0-OpenSSH_0.3xx" ascii
    $s2 = "$(exec $installer $@)" ascii
    $t1 = "./installer/do-install" ascii
    $t2 = "./installer/bom_files/" ascii
    $t3 = "/tmp/data/root/etc/ld.so.preload" ascii
    $t4 = "/tmp/data/root/home/etc/manifest/exclusion_list" ascii
  condition:
    uint32(0) == 0x464c457f and
    filesize < 5MB and
    ((1 of ($s*)) or
    (3 of ($t*)))
}

rule M_Hunting_Dropper_WIREFIRE_1 {
  meta:
    author = "Mandiant"
    description = "This rule detects WIREFIRE, a web shell written in Python that exists as trojanized logic to a component of the pulse secure appliance."
    md5 = "6de651357a15efd01db4e658249d4981"
    reference = "https://www.mandiant.com/resources/blog/suspected-apt-targets-ivanti-zero-day"
    date = "2024-01-11"
    score = 75
    id = "051244f0-00b1-5a4b-8c81-f4ce6f1aa22a"
  strings:
    $s1 = "zlib.decompress(aes.decrypt(base64.b64decode(" ascii
    $s2 = "aes.encrypt(t+('\\x00'*(16-len(t)%16))" ascii
    $s3 = "Handles DELETE request to delete an existing visits data." ascii
    $s4 = "request.data.decode().startswith('GIF'):" ascii
    $s5 = "Utils.api_log_admin" ascii
  condition:
    filesize < 10KB
    and all of them
}

rule M_Hunting_Webshell_LIGHTWIRE_2 {
  meta:
    author = "Mandiant (modified by Florian Roth)"
    description = "Detects LIGHTWIRE based on the RC4 decoding and execution 1-liner."
    md5 = "3d97f55a03ceb4f71671aa2ecf5b24e9"
    reference = "https://www.mandiant.com/resources/blog/suspected-apt-targets-ivanti-zero-day"
    date = "2024-01-11"
    modified = "2024-01-12"
    score = 75
    id = "9451da63-c68e-51e8-b4b1-c3082d46fbf6"
  strings:
    // rewritten as strings - because a regex is unnecessary
    // $re1 = /eval\{my.{1,20}Crypt::RC4->new\(\".{1,50}->RC4\(decode_base64\(CGI::param\(\'.{1,30};eval\s\$.{1,30}\"Compatibility\scheck:\s\$@\";\}/
    $s1 = "eval{my"
    $s2 = "Crypt::RC4->new(\""
    $s3 = "->RC4(decode_base64(CGI::param('"
    $s4 = ";eval $"
    $s5 = "\"Compatibility check: $@\";}"
  condition:
    filesize < 10KB
    and all of them
}

rule M_Hunting_Dropper_THINSPOOL_1 {
  meta:
    author = "Mandiant"
    description = "This rule detects THINSPOOL, a dropper that installs the LIGHTWIRE web shell onto a Pulse Secure system."
    md5 = "677c1aa6e2503b56fe13e1568a814754"
    reference = "https://www.mandiant.com/resources/blog/suspected-apt-targets-ivanti-zero-day"
    date = "2024-01-11"
    score = 75
    id = "dd340f72-0a2c-5b66-9e31-1c0f20cd842f"
  strings:
    $s1 = "/tmp/qactg/" ascii
    $s2 = "echo '/home/config/dscommands'" ascii
    $s3 = "echo '/home/perl/DSLogConfig.pm'" ascii
    $s4 = "ADM20447" ascii
  condition:
    filesize < 10KB
    and all of them
}

rule M_Hunting_CredTheft_WARPWIRE_1 {
  meta:
    author = "Mandiant"
    description = "This rule detects WARPWIRE, a credential stealer written in JavaScript that is embedded into a legitimate Pulse Secure file."
    md5 = "d0c7a334a4d9dcd3c6335ae13bee59ea"
    reference = "https://www.mandiant.com/resources/blog/suspected-apt-targets-ivanti-zero-day"
    date = "2024-01-11"
    score = 75
    id = "9a6a8783-b531-560d-998d-8aa7c90158a8"
  strings:
    $s1 = {76 61 72 20 77 64 61 74 61 20 3d 20 64 6f 63 75 6d 65 6e 74 2e 66 72 6d 4c 6f 67 69 6e 2e 75 73 65 72 6e 61 6d 65 2e 76 61 6c 75 65 3b}
    $s2 = {76 61 72 20 73 64 61 74 61 20 3d 20 64 6f 63 75 6d 65 6e 74 2e 66 72 6d 4c 6f 67 69 6e 2e 70 61 73 73 77 6f 72 64 2e 76 61 6c 75 65 3b}
    $s3 = {2b 77 64 61 74 61 2b 27 26 27 2b 73 64 61 74 61 3b}
    $s4 = {76 61 72 20 78 68 72 20 3d 20 6e 65 77 20 58 4d 4c 48 74 74 70 52 65 71 75 65 73 74}
    $s5 = "Remember the last selected auth realm for 30 days" ascii
  condition:
   filesize < 8KB and 
   all of them
}
