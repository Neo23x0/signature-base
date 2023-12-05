
rule HKTL_FRP_Apr20_1 {
   meta:
      description = "Detects FRP fast reverse proxy tool often used by threat groups"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/fatedier/frp"
      date = "2020-04-07"
      modified = "2022-11-03"
      score = 70
      hash1 = "05537c1c4e29db76a24320fb7cb80b189860389cdb16a9dbeb0c8d30d9b37006"
      hash2 = "08c685c8febb5385f7548c2a64a27bae7123a937c5af958ebc08a3accb29978d"
      id = "55483832-0e0b-5c28-8be5-dbd14ddb50e3"
   strings:
      $x1 = "frp/vendor/github.com/spf13/" ascii
      $x2 = "github.com/fatedier/frp/vendor/" ascii

      $fpg2 = "<html"
      $fpg3 = "<HTML"
      $fpg6 = "<?xml"
   condition:
      1 of ($x*) and not 1 of ($fp*)
}

rule HKTL_FRP_INI_Apr20_1 {
   meta:
      description = "Detects FRP fast reverse proxy tool INI file often used by threat groups"
      author = "Florian Roth (Nextron Systems)"
      reference = "Chinese Hacktools OpenDir"
      date = "2020-04-07"
      score = 60
      hash1 = "1dabef3c170e4e559c50d603d47fb7f66f6e3da75a65c3435b18175d6e9785bb"
      id = "5c652c9c-715d-5ba5-821a-3e533b1e78c6"
   strings:
      $h1 = "[common]" ascii
      $s1 = "server_addr =" ascii fullword
      $s2 = "remote_port =" ascii fullword
      $s3 = "[RemoteDesktop]" ascii fullword
      $s4 = "local_ip = " ascii
      $s5 = "type = tcp" ascii fullword
   condition:
      uint16(0) == 0x635b and
      filesize < 1KB and
      $h1 at 0 and all of them
}
