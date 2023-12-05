
rule HKTL_NATBypass_Dec22_1 : T1090 {
   meta:
      description = "Detects NatBypass tool (also used by APT41)"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/cw1997/NATBypass"
      date = "2022-12-27"
      score = 80
      hash1 = "4550635143c9997d5499d1d4a4c860126ee9299311fed0f85df9bb304dca81ff"
      id = "54af4d84-72f7-5ec4-b0bf-7ba228fdf508"
   strings:
      $x1 = "nb -slave 127.0.0.1:3389 8.8.8.8:1997" ascii
      $x2 = "| Welcome to use NATBypass Ver" ascii

      $s1 = "main.port2host.func1" ascii fullword
      $s2 = "start to transmit address:" ascii
      $s3 = "^(\\d{1,2}|1\\d\\d|2[0-4]\\d|25[0-5])\\.(\\d{1,2}|1\\d\\d|2[0-4]\\d|25[0-5])\\.(\\d{1,2}|1\\d\\d|2[0-4]\\d|25[0-5])\\.(\\d{1,2}|1\\d\\d|2[0-4]\\d|25[0-5])"
   condition:
      filesize < 8000KB 
      and (
         1 of ($x*)
         or 2 of them
      ) or 3 of them
}
