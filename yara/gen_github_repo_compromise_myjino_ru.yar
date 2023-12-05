
rule MAL_Github_Repo_Compromise_MyJino_Ru_Aug22 {
   meta:
      description = "Detects URL mentioned in report on compromised Github repositories in August 2022"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/stephenlacy/status/1554697077430505473"
      date = "2022-08-03"
      score = 90
      id = "1eaabad5-d0de-5d17-a5fa-3c638354843d"
   strings:
      $x1 = "curl http://ovz1.j19544519.pr46m.vps.myjino.ru" ascii wide
      $x2 = "http__.Post(\"http://ovz1.j19544519.pr46m.vps.myjino.ru" ascii wide
   condition:
      1 of them
}
