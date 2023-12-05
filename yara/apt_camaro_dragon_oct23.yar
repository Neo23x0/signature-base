
rule MAL_LNX_CamaroDragon_Sheel_Oct23 {
   meta:
      description = "Detects CamaroDragon's tool named sheel"
      author = "Florian Roth"
      reference = "https://research.checkpoint.com/2023/the-dragon-who-sold-his-camaro-analyzing-custom-router-implant/"
      date = "2023-10-06"
      score = 85
      hash1 = "7985f992dcc6fcce76ee2892700c8538af075bd991625156bf2482dbfebd5a5a"
      id = "f6f08c0e-236c-5194-9369-da8fdef4aa21"
   strings:
      $x1 = "-h server_ip -p server_port -i update_index[0-4] [-r]" ascii fullword

      $s1 = "read_ip" ascii fullword
      $s2 = "open fail.%m" ascii fullword
      $s3 = "ri:h:p:" ascii fullword /* flags */
      $s4 = "update server list success!" ascii fullword
   condition:
      uint16(0) == 0x457f and
      filesize < 30KB and (
         1 of ($x*)
         or 3 of them
      ) 
      or 4 of them
}

rule MAL_LNX_CamaroDragon_HorseShell_Oct23 {
   meta:
      description = "Detects CamaroDragon's HorseShell implant for routers"
      author = "Florian Roth"
      reference = "https://research.checkpoint.com/2023/the-dragon-who-sold-his-camaro-analyzing-custom-router-implant/"
      date = "2023-10-06"
      score = 85
      hash1 = "998788472cb1502c03675a15a9f09b12f3877a5aeb687f891458a414b8e0d66c"
      id = "9e54745f-146f-50a6-b30f-53aaaa6907b5"
   strings:
      $x1 = "echo \"start shell '%s' failed!\" > .remote_shell.log" ascii fullword
      $x2 = "*****recv NET_REQ_HORSE_SHELL REQ_CONNECT_PORT*****" ascii fullword

      $s1 = "m.cremessage.com" ascii fullword
      $s2 = "POST http://%s/index.php HTTP/1.1" ascii fullword
      $s3 = "wzsw_encrypt_buf" ascii fullword
      $s4 = "body:%d-%s" ascii fullword
      $s5 = "User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident" ascii fullword /* String occurs 1 times in goodware */
      $s6 = "process_http_read_events" ascii fullword

      $op1 = { c4 34 42 00 02 30 63 00 40 10 60 00 09 ae 62 00 48 8e 62 00 cc }
      $op2 = { 27 f4 8c 46 27 f0 03 20 f8 09 00 60 28 21 }
   condition:
      uint16(0) == 0x457f and
      filesize < 600KB and (
         1 of ($x*)
         or 3 of them
      )
      or 5 of them
}
