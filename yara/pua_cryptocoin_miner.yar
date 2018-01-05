
rule CoinMiner_Strings {
   meta:
      description = "Detects mining pool protocol string in Executable"
      author = "Florian Roth"
      score = 50
      reference = "https://minergate.com/faq/what-pool-address"
      date = "2018-01-04"
   strings:
      $s1 = "stratum+tcp://" ascii
      $s2 = "\"normalHashing\": true,"
   condition:
      filesize < 600KB and 1 of them
}

rule CoinHive_Javascript_MoneroMiner {
   meta:
      description = "Detects CoinHive - JavaScript Crypto Miner"
      author = "Florian Roth"
      score = 50
      reference = "https://coinhive.com/documentation/miner"
      date = "2018-01-04"
   strings:
      $s2 = "CoinHive.CONFIG.REQUIRES_AUTH" fullword ascii
   condition:
      filesize < 65KB and 1 of them
}
