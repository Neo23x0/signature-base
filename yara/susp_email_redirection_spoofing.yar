rule SUSP_Email_Redirection_Spoofing_Feb25 {
   meta:
      description = "Detects redirect spoofing in embedded URLs. This technique is used by threat actors to obscure the actual destination of a link"
      author = "Jonathan Peters (cod3nym)"
      date = "2025-02-20"
      reference = "https://any.run/cybersecurity-blog/cyber-attacks-january-2025/#fake-youtube-links-redirect-users-to-phishing-pages-11298"
      hash = "9b196220b369c199a7e4d57cb5db18b32eb2565a6f9190929c5c01ac4fa04ac8"
      hash = "c4eb35c1a1c10226bff9bb0c88ca516441208d193b4994eeb292a66e53a2cc04"
      hash = "e3b8ea03a472348814c6ac81088234836e627a1878ec36e46ce62526e1390935"
      score = 70
      id = "bf3a2b06-4dc5-5f0f-bf1f-2bd6a1cc4a8d"
   strings:
      $sa1 = "Content-Transfer-Encoding:" ascii
      $sa2 = "Subject:" ascii

      $x = ".com%20%20%20%20%20%" ascii
   condition:
      all of them
}
