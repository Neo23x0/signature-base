
rule Malware_JS_powershell_obfuscated {
   meta:
      description = "Unspecified malware - file rechnung_3.js"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-03-24"
      hash1 = "3af15a2d60f946e0c4338c84bd39880652f676dc884057a96a10d7f802215760"
      id = "7995dd3a-5942-5c48-9e50-64f4964249a7"
   strings:
      $x1 = "po\" + \"wer\" + \"sh\" + \"e\" + \"ll\";" fullword ascii
   condition:
      filesize < 30KB and 1 of them
}
