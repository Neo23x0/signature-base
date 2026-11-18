rule MAL_APT_NK_JS_ContagiousInterview_TCP_Backdoor_Nov26 {
   meta:
      description = "Detects the Node.js backdoor of the Contagious Interview campaign (git hook lure) that talks to its C2 over plain TCP with newline-delimited JSON. Works on the javascript-obfuscator output as distributed: it relies on top-level names that the obfuscator keeps (renameGlobals is off by default) and on key strings, which end up either as literals or in the base64 encoded string array"
      author = "n4uu"
      reference = "https://n4uu.github.io/2026/raw-tcp-backdoor-cleverstack/"
      date = "2026-11-05"
      modified = "2026-11-06"
      score = 80
      hash1 = "281d4d60fc99cf7f54819defb1c7c14b9202d46890936c4c6b9ebe3ddc75dd2f"
      hash2 = "6db4c3d2ab56227d36eff59d1dc9e13eadf9959996fab1e0b04591cc5e637d04"
      hash3 = "1bcf17ce99fc748536317f9d28fd79f103f6166c1e548c0255ede0b434314352"
      id = "fdd732d7-e852-4f09-b57c-f1893cc1ec64"
   strings:
      $r1 = "require(" ascii

      // top-level identifiers, not renamed by javascript-obfuscator
      $g1 = "GIT_CHECKER_MARKER" ascii fullword
      $g2 = "LOCK_UPDATE_INTERVAL" ascii fullword
      $g3 = "getHandleParam" ascii fullword
      $g4 = "createSocketConnection" ascii fullword
      $g5 = "lockUpdateTimer" ascii fullword
      $g6 = "git_content" ascii fullword
      $g7 = "SERVER_API_URL" ascii fullword
      $g8 = "attemptReconnect" ascii fullword

      // key strings as literals or base64 encoded
      $s1 = "vscode-ext.lock" ascii
      $s2 = ".git-checker" ascii
      $s3 = "start /b cmd /c \"cd /d " ascii
      $s4 = "ss_exec " ascii
      $sb1 = "vscode-ext.lock" base64
      $sb2 = ".git-checker" base64
      $sb3 = "start /b cmd /c \"cd /d " base64
      $sb4 = "ss_exec " base64
      // javascript-obfuscator encodes its string array with a case-swapped alphabet
      $sc1 = "vscode-ext.lock" base64("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/")
      $sc2 = ".git-checker" base64("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/")
      $sc3 = "start /b cmd /c \"cd /d " base64("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/")
      $sc4 = "ss_exec " base64("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/")
   condition:
      filesize < 1MB
      and $r1
      and (
         6 of ($g*)
         or ( 3 of ($g*) and 2 of ($s*) )
         // still matches a build with renameGlobals enabled
         or 3 of ($s*)
      )
}
