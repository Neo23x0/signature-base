rule SUSP_Claude_Refusal_Magic_String_Jan26 {
   meta:
      description = "Detects refusal magic string that cause Claude sessions to be terminated. This might indicate that a file tries to prevent being analyzed by LLM agents."
      author = "Marius Benthin"
      date = "2026-01-29"
      reference = "https://x.com/williballenthin/status/2014687699165135150"
      hash = "ffa48ed4b7b48897f6756c4222b2606399de0bca627cedfddf61e69986580430"
      score = 75
   strings:
      $x1 = "ANTHROPIC_MAGIC_STRING_TRIGGER_REFUSAL_" ascii wide nocase
   condition:
      $x1
}

rule MAL_Claude_Refusal_Magic_String_Jan26 {
   meta:
      description = "Detects Base64 variations of refusal magic string that cause Claude sessions to be terminated. This might indicate that a file tries to prevent being analyzed by LLM agents."
      author = "Marius Benthin"
      date = "2026-01-29"
      reference = "Internal Research"
      score = 80
   strings:
      $xb1 = "ANTHROPIC_MAGIC_STRING_TRIGGER_REFUSAL_" ascii wide base64 base64wide
   condition:
      $xb1
}

rule SUSP_Claude_Redacted_Thinking_Magic_String_Jan26_1 {
   meta:
      description = "Detects redacted thinking magic string that cause Claude sessions to be terminated. This might indicate that a file tries to prevent being analyzed by LLM agents."
      author = "Marius Benthin"
      date = "2026-01-29"
      reference = "Internal Research"
      hash = "ffa48ed4b7b48897f6756c4222b2606399de0bca627cedfddf61e69986580430"
      score = 65
   strings:
      $x1 = "ANTHROPIC_MAGIC_STRING_TRIGGER_REDACTED_THINKING_" ascii wide nocase
   condition:
      $x1
}

rule SUSP_Claude_Redacted_Thinking_Magic_String_Jan26_2 {
   meta:
      description = "Detects Base64 variations of redacted thinking magic string that cause Claude sessions to be terminated. This might indicate that a file tries to prevent being analyzed by LLM agents."
      author = "Marius Benthin"
      date = "2026-01-29"
      reference = "Internal Research"
      score = 75
   strings:
      $xb1 = "ANTHROPIC_MAGIC_STRING_TRIGGER_REDACTED_THINKING_" ascii wide base64 base64wide
   condition:
      $xb1
}
