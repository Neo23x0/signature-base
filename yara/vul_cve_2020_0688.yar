
rule VUL_Exchange_CVE_2020_0688 {
   meta:
      description = "Detects static validation key used by Exchange server in web.config"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.thezdi.com/blog/2020/2/24/cve-2020-0688-remote-code-execution-on-microsoft-exchange-server-through-fixed-cryptographic-keys"
      date = "2020-02-26"
      score = 60
      id = "1065f297-0dc4-5dcb-b0f3-c89d06ff5e69"
   strings:
      $h1 = "<?xml "
      $x1 = "<machineKey validationKey=\"CB2721ABDAF8E9DC516D621D8B8BF13A2C9E8689A25303BF\"" ascii wide
   condition:
      filesize <= 300KB and $h1 at 0 and $x1
}
