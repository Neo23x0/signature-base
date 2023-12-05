
rule CoinMiner_Strings : SCRIPT HIGHVOL {
   meta:
      description = "Detects mining pool protocol string in Executable"
      author = "Florian Roth (Nextron Systems)"
      score = 60
      reference = "https://minergate.com/faq/what-pool-address"
      date = "2018-01-04"
      modified = "2021-10-26"
      nodeepdive = 1
      id = "ac045f83-5f32-57a9-8011-99a2658a0e05"
   strings:
      $sa1 = "stratum+tcp://" ascii
      $sa2 = "stratum+udp://" ascii
      $sb1 = "\"normalHashing\": true,"
   condition:
      filesize < 3000KB and 1 of them
}

rule CoinHive_Javascript_MoneroMiner : HIGHVOL {
   meta:
      description = "Detects CoinHive - JavaScript Crypto Miner"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      score = 50
      reference = "https://coinhive.com/documentation/miner"
      date = "2018-01-04"
      id = "4f40c342-fcdc-5c73-a3cf-7b2ed438eaaf"
   strings:
      $s2 = "CoinHive.CONFIG.REQUIRES_AUTH" fullword ascii
   condition:
      filesize < 65KB and 1 of them
}

rule PUA_CryptoMiner_Jan19_1 {
   meta:
      description = "Detects Crypto Miner strings"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2019-01-31"
      score = 80
      hash1 = "ede858683267c61e710e367993f5e589fcb4b4b57b09d023a67ea63084c54a05"
      id = "aebfdce9-c2dd-5f24-aa25-071e1a961239"
   strings:
      $s1 = "Stratum notify: invalid Merkle branch" fullword ascii
      $s2 = "-t, --threads=N       number of miner threads (default: number of processors)" fullword ascii
      $s3 = "User-Agent: cpuminer/" ascii
      $s4 = "hash > target (false positive)" fullword ascii
      $s5 = "thread %d: %lu hashes, %s khash/s" fullword ascii
   condition:
      filesize < 1000KB and 1 of them
}

rule PUA_Crypto_Mining_CommandLine_Indicators_Oct21 : SCRIPT {
   meta:
      description = "Detects command line parameters often used by crypto mining software"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.poolwatch.io/coin/monero"
      date = "2021-10-24"
      score = 65
      id = "afe5a63a-08c3-5cb7-b4b1-b996068124b7"
   strings:
      $s01 = " --cpu-priority="
      $s02 = "--donate-level=0"
      $s03 = " -o pool."
      $s04 = " -o stratum+tcp://"
      $s05 = " --nicehash"
      $s06 = " --algo=rx/0 "

      /* base64 encoded: --donate-level= */
      $se1 = "LS1kb25hdGUtbGV2ZWw9"
      $se2 = "0tZG9uYXRlLWxldmVsP"
      $se3 = "tLWRvbmF0ZS1sZXZlbD"

      /* 
         base64 encoded:
         stratum+tcp:// 
         stratum+udp:// 
      */
      $se4 = "c3RyYXR1bSt0Y3A6Ly"
      $se5 = "N0cmF0dW0rdGNwOi8v"
      $se6 = "zdHJhdHVtK3RjcDovL"
      $se7 = "c3RyYXR1bSt1ZHA6Ly"
      $se8 = "N0cmF0dW0rdWRwOi8v"
      $se9 = "zdHJhdHVtK3VkcDovL"
   condition:
      filesize < 5000KB and 1 of them
}
