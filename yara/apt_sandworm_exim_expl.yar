
rule APT_Sandworm_Keywords_May20_1 {
   meta:
      description = "Detects commands used by Sandworm group to exploit critical vulernability CVE-2019-10149 in Exim"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://media.defense.gov/2020/May/28/2002306626/-1/-1/0/CSA%20Sandworm%20Actors%20Exploiting%20Vulnerability%20in%20Exim%20Transfer%20Agent%2020200528.pdf"
      date = "2020-05-28"
      id = "e0d4e90e-5547-5487-8d0c-a141d88fff7c"
   strings:
      $x1 = "MAIL FROM:<$(run("
      $x2 = "exec\\x20\\x2Fusr\\x2Fbin\\x2Fwget\\x20\\x2DO\\x20\\x2D\\x20http"
   condition:
      filesize < 8000KB and
      1 of them
}

rule APT_Sandworm_SSH_Key_May20_1 {
   meta:
      description = "Detects SSH key used by Sandworm on exploited machines"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://media.defense.gov/2020/May/28/2002306626/-1/-1/0/CSA%20Sandworm%20Actors%20Exploiting%20Vulnerability%20in%20Exim%20Transfer%20Agent%2020200528.pdf"
      date = "2020-05-28"
      hash1 = "dc074464e50502459038ac127b50b8c68ed52817a61c2f97f0add33447c8f730"
      hash2 = "538d713cb47a6b5ec6a3416404e0fc1ebcbc219a127315529f519f936420c80e"
      id = "ea2968b8-7ae4-56b8-9547-816c5e37c50a"
   strings:
      $x1 = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC2q/NGN/brzNfJiIp2zswtL33tr74pIAjMeWtXN1p5Hqp5fTp058U1EN4NmgmjX0KzNjjV"
   condition:
      filesize < 1000KB and
      1 of them
}

rule APT_Sandworm_SSHD_Config_Modification_May20_1 {
   meta:
      description = "Detects ssh config entry inserted by Sandworm on compromised machines"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://media.defense.gov/2020/May/28/2002306626/-1/-1/0/CSA%20Sandworm%20Actors%20Exploiting%20Vulnerability%20in%20Exim%20Transfer%20Agent%2020200528.pdf"
      date = "2020-05-28"
      hash1 = "dc074464e50502459038ac127b50b8c68ed52817a61c2f97f0add33447c8f730"
      hash2 = "538d713cb47a6b5ec6a3416404e0fc1ebcbc219a127315529f519f936420c80e"
      id = "dd60eeb7-3d4b-5a6a-8054-50c617ee8c73"
   strings:     
      $x1 = "AllowUsers mysql_db" ascii

      $a1 = "ListenAddress" ascii fullword
   condition:
      filesize < 10KB and
      all of them
}

rule APT_Sandworm_InitFile_May20_1 {
   meta:
      description = "Detects mysql init script used by Sandworm on compromised machines"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://media.defense.gov/2020/May/28/2002306626/-1/-1/0/CSA%20Sandworm%20Actors%20Exploiting%20Vulnerability%20in%20Exim%20Transfer%20Agent%2020200528.pdf"
      date = "2020-05-28"
      hash1 = "dc074464e50502459038ac127b50b8c68ed52817a61c2f97f0add33447c8f730"
      hash2 = "538d713cb47a6b5ec6a3416404e0fc1ebcbc219a127315529f519f936420c80e"
      id = "0bd613e3-6bd4-5cec-bc0d-2bdb83caf142"
   strings:     
      $s1 = "GRANT ALL PRIVILEGES ON * . * TO 'mysqldb'@'localhost';" ascii
      $s2 = "CREATE USER 'mysqldb'@'localhost' IDENTIFIED BY '" ascii fullword
   condition:
      filesize < 10KB and
      all of them
}

rule APT_Sandworm_User_May20_1 {
   meta:
      description = "Detects user added by Sandworm on compromised machines"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://media.defense.gov/2020/May/28/2002306626/-1/-1/0/CSA%20Sandworm%20Actors%20Exploiting%20Vulnerability%20in%20Exim%20Transfer%20Agent%2020200528.pdf"
      date = "2020-05-28"
      hash1 = "dc074464e50502459038ac127b50b8c68ed52817a61c2f97f0add33447c8f730"
      hash2 = "538d713cb47a6b5ec6a3416404e0fc1ebcbc219a127315529f519f936420c80e"
      id = "ada549a4-abcc-5c0a-9601-75631e78c835"
   strings:     
      $s1 = "mysql_db:x:" ascii /* malicious user */

      $a1 = "root:x:"
      $a2 = "daemon:x:"
   condition:
      filesize < 4KB and all of them
}

rule APT_WEBSHELL_PHP_Sandworm_May20_1 {
   meta:
      description = "Detects GIF header PHP webshell used by Sandworm on compromised machines"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://media.defense.gov/2020/May/28/2002306626/-1/-1/0/CSA%20Sandworm%20Actors%20Exploiting%20Vulnerability%20in%20Exim%20Transfer%20Agent%2020200528.pdf"
      date = "2020-05-28"
      hash1 = "dc074464e50502459038ac127b50b8c68ed52817a61c2f97f0add33447c8f730"
      hash2 = "538d713cb47a6b5ec6a3416404e0fc1ebcbc219a127315529f519f936420c80e"
      id = "b9ec02c2-fa83-5f21-95cf-3528047b2d01"
   strings:     
      $h1 = "GIF89a <?php $" ascii
      $s1 = "str_replace(" ascii
   condition:
      filesize < 10KB and
      $h1 at 0 and $s1
}

rule APT_SH_Sandworm_Shell_Script_May20_1 {
   meta:
      description = "Detects shell script used by Sandworm in attack against Exim mail server"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://media.defense.gov/2020/May/28/2002306626/-1/-1/0/CSA%20Sandworm%20Actors%20Exploiting%20Vulnerability%20in%20Exim%20Transfer%20Agent%2020200528.pdf"
      date = "2020-05-28"
      hash1 = "dc074464e50502459038ac127b50b8c68ed52817a61c2f97f0add33447c8f730"
      hash2 = "538d713cb47a6b5ec6a3416404e0fc1ebcbc219a127315529f519f936420c80e"
      id = "21cf2c89-5511-5eb6-a2dd-4ad54ebfa2d1"
   strings:     
      $x1 = "echo \"GRANT ALL PRIVILEGES ON * . * TO 'mysqldb'@'localhost';\" >> init-file.txt" ascii fullword
      $x2 = "import base64,sys;exec(base64.b64decode({2:str,3:lambda b:bytes(b,'UTF-8')}[sys.version" ascii fullword
      $x3 = "sed -i -e '/PasswordAuthentication/s/no/yes/g; /PermitRootLogin/s/no/yes/g;" ascii fullword
      $x4 = "useradd -M -l -g root -G root -b /root -u 0 -o mysql_db" ascii fullword
      
      $s1 = "/ip.php?port=${PORT}\"" ascii fullword
      $s2 = "sed -i -e '/PasswordAuthentication" ascii fullword
      $s3 = "PATH_KEY=/root/.ssh/authorized_keys" ascii fullword
      $s4 = "CREATE USER" ascii fullword
      $s5 = "crontab -l | { cat; echo" ascii fullword
      $s6 = "mysqld --user=mysql --init-file=/etc/opt/init-file.txt --console" ascii fullword
      $s7 = "sshkey.php" ascii fullword
   condition:
      uint16(0) == 0x2123 and
      filesize < 20KB and
      1 of ($x*) or 4 of them
}

rule APT_RU_Sandworm_PY_May20_1 {
   meta:
      description = "Detects Sandworm Python loader"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/billyleonard/status/1266054881225236482"
      date = "2020-05-28"
      hash1 = "c025008463fdbf44b2f845f2d82702805d931771aea4b506573b83c8f58bccca"
      id = "a392d800-1fe8-5ae9-b813-e1dfcedecda6"
   strings:
      $x1 = "o.addheaders=[('User-Agent','Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko')]" ascii fullword
      
      $s1 = "exec(o.open('http://" ascii
      $s2 = "__import__({2:'urllib2',3:'urllib.request'}"
   condition:
      uint16(0) == 0x6d69 and
      filesize < 1KB and
      1 of ($x*) or 2 of them
}

rule APT_RU_Sandworm_PY_May20_2 {
   meta:
      description = "Detects Sandworm Python loader"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/billyleonard/status/1266054881225236482"
      date = "2020-05-28"
      hash1 = "abfa83cf54db8fa548942acd845b4f34acc94c46d4e1fb5ce7e97cc0c6596676"
      id = "5b32ad64-d959-5632-a03c-17aa055b213f"
   strings:
      $x1 = "import sys;import re, subprocess;cmd" ascii fullword
      $x2 = "UA='Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko';server='http"
      $x3 = "';t='/admin/get.php';req" ascii
      $x4 = "ps -ef | grep Little\\ Snitch | grep " ascii fullword
   condition:
      uint16(0) == 0x6d69 and
      filesize < 2KB and
      1 of them
}
