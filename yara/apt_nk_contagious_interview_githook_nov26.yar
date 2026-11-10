rule SUSP_SH_Git_Hook_Remote_Script_To_Shell_And_Cmd_Nov26 {
   meta:
      description = "Detects shell scripts, such as git hooks, that pick a payload per OS with uname and pipe a remote script into sh and, under Git for Windows (MINGW/MSYS), into cmd. Seen in fake coding assessment repos of the Contagious Interview campaign, where a post-checkout hook runs the payload as soon as the candidate switches branch"
      author = "n4uu"
      reference = "https://bazaar.abuse.ch/sample/13e558bf5c80b16595161327d3104e11ae9fc8deab4b96917bb01278931891cf/"
      date = "2026-11-09"
      score = 65
      hash1 = "13e558bf5c80b16595161327d3104e11ae9fc8deab4b96917bb01278931891cf"
      id = "3884137c-5237-44b9-9337-35d9a5d330bd"
   strings:
      $sh1 = "#!/bin/sh"
      $sh2 = "#!/bin/bash"
      $sh3 = "#!/usr/bin/env sh"
      $sh4 = "#!/usr/bin/env bash"

      $u1 = "uname -s" ascii
      $u2 = /MINGW\*\s*\|\s*MSYS\*/ ascii

      $p1 = /(curl|wget) [^\n|]{0,64}['"]?https?:\/\/[^\n|]{1,200}\|\s*(ba)?sh\b/ ascii
      $p2 = /curl [^\n|]{0,64}['"]?https?:\/\/[^\n|]{1,200}\|\s*cmd(\.exe)?\b/ ascii
   condition:
      filesize < 32KB
      and ( $sh1 at 0 or $sh2 at 0 or $sh3 at 0 or $sh4 at 0 )
      and all of ($u*)
      and all of ($p*)
}

rule MAL_APT_NK_SH_ContagiousInterview_PostCheckout_Hook_Nov26 {
   meta:
      description = "Detects the post-checkout git hook planted in fake coding assessment repos of the Contagious Interview campaign (one repo per language, November 2026). After about 45 lines of filler comments it fetches /settings/<os>?flag=<n> and pipes it into sh or cmd"
      author = "n4uu"
      reference = "https://bazaar.abuse.ch/sample/13e558bf5c80b16595161327d3104e11ae9fc8deab4b96917bb01278931891cf/"
      date = "2026-11-09"
      score = 85
      hash1 = "13e558bf5c80b16595161327d3104e11ae9fc8deab4b96917bb01278931891cf"
      id = "aa1b1e6c-f13f-42ef-be33-f72b898a3661"
   strings:
      $c1 = "# post-checkout: invoked after checkout or branch switch (success only)." ascii
      $c2 = "# End of post-checkout hook example." ascii
      $c3 = "# This hook can improve developer workflow when used wisely." ascii

      $x1 = /\/settings\/(mac|linux|windows)\?flag=[0-9]/ ascii
      $x2 = "| cmd >/dev/null 2>&1" ascii
   condition:
      filesize < 32KB
      and (
         2 of ($c*)
         or ( 1 of ($c*) and 1 of ($x*) )
         or all of ($x*)
      )
}

rule MAL_APT_NK_JS_ContagiousInterview_OtterCookie_Loader_Nov26 {
   meta:
      description = "Detects the obfuscated Node.js loader uploaded alongside the Contagious Interview post-checkout hook repos in November 2026. It carries OtterCookie modules (socket.io control, file and browser wallet upload) as split strings. The rule keys on the C2 config and helper names that javascript-obfuscator leaves in clear, so it works on the files as distributed"
      author = "n4uu"
      reference = "https://bazaar.abuse.ch/sample/d395f5cf1c1b049acaac87586787cdace39e8be51b9ffdedf90bad28088a43e5/"
      date = "2026-11-09"
      score = 80
      hash1 = "d395f5cf1c1b049acaac87586787cdace39e8be51b9ffdedf90bad28088a43e5"
      id = "33739b84-a0db-43dc-8452-a526feafa1c4"
   strings:
      $r1 = "require(" ascii

      // C2 config, kept as top-level names by the obfuscator
      $a1 = /(const|let|var|,) ?u_s=/ ascii
      $a2 = /(const|let|var|,) ?l_s=/ ascii
      $a3 = /(const|let|var|,) ?s_s=/ ascii
      $a4 = /(const|let|var|,) ?u_k=/ ascii

      // helpers
      $b1 = "async function f_s_l(" ascii
      $b2 = /(const|let|var|,) ?s_u_c=/ ascii
      $b3 = "const gsi=Utils[" ascii
      $b4 = "const Utils={" ascii
   condition:
      filesize > 500KB and filesize < 10MB
      and $r1
      and 3 of ($a*)
      and 2 of ($b*)
}
