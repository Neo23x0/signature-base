/*
   YARA rules for the Megalodon GitHub Actions supply-chain backdoor campaign (May 2026)

   Megalodon compromised 5,561 GitHub repositories by pushing malicious workflow files
   using stolen Personal Access Tokens. Two variants were observed:
     - Mass variant:     pull_request_target + id-token:write → exfiltrates OIDC tokens
     - Targeted variant: workflow_dispatch (Optimize-Build.yml) → manual-trigger exfiltration

   Both variants deliver a base64-encoded bash payload exfiltrating secrets to C2 at
   216.126.225.129:8443.

   Intelligence source: SafeDep.io, "Megalodon: Mass GitHub Repository Backdooring via
   CI Workflows", May 2026 — https://safedep.io/megalodon-mass-github-repo-backdooring-ci-workflows/

   Detection rule logic is original work by Spyced Concepts Ltd. (https://spycedconcepts.co.uk)
   Full rule set with test harness: https://github.com/Spyced-Concepts/detection-rules
*/

rule MAL_GitHub_Actions_Megalodon_C2_IP {
   meta:
      description = "Detects Megalodon C2 IP address (216.126.225.129) in GitHub Actions workflow files"
      author = "Spyced Concepts Ltd."
      date = "2026-05-30"
      reference = "https://safedep.io/megalodon-mass-github-repo-backdooring-ci-workflows/"
      score = 90
      id = "879f1aeb-46a8-41da-9d74-97c3130e757e"
   strings:
      $c2_ip   = "216.126.225.129" ascii wide
      $c2_port = "216.126.225.129:8443" ascii wide
   condition:
      any of them
}

rule MAL_GitHub_Actions_Megalodon_Workflow_Names {
   meta:
      description = "Detects Megalodon malicious workflow names SysDiag and Optimize-Build in GitHub Actions workflow files"
      author = "Spyced Concepts Ltd."
      date = "2026-05-30"
      reference = "https://safedep.io/megalodon-mass-github-repo-backdooring-ci-workflows/"
      score = 75
      id = "0be9c2c6-57c4-45d7-9653-e710cbe6d7cc"
   strings:
      $sysdiag        = "name: SysDiag" ascii
      $optimize_build = "name: Optimize-Build" ascii
   condition:
      any of them
}

rule MAL_GitHub_Actions_Megalodon_Forged_Author {
   meta:
      description = "Detects Megalodon forged git author email addresses and bot identity strings used in malicious commits"
      author = "Spyced Concepts Ltd."
      date = "2026-05-30"
      reference = "https://safedep.io/megalodon-mass-github-repo-backdooring-ci-workflows/"
      score = 75
      id = "35ac2bbf-e0fc-4934-91fa-074fecfd9f92"
   strings:
      $email1 = "[email protected]" ascii
      $email2 = "[email protected]" ascii
      $name1  = "\"build-bot\"" ascii
      $name2  = "\"auto-ci\"" ascii
      $name3  = "\"ci-bot\"" ascii
      $name4  = "\"pipeline-bot\"" ascii
   condition:
      any of them
}

rule SUSP_GitHub_Actions_Megalodon_Dangerous_Permissions {
   meta:
      description = "Detects workflows combining pull_request_target with id-token:write — the core Megalodon mass-variant pattern. Treat as a triage signal; legitimate PR deploy preview workflows use the same combination."
      author = "Spyced Concepts Ltd."
      date = "2026-05-30"
      reference = "https://safedep.io/megalodon-mass-github-repo-backdooring-ci-workflows/"
      score = 60
      id = "190b6d97-8211-4cc2-92fc-94685b1db2f1"
   strings:
      $prt       = "pull_request_target" ascii
      $id_token  = "id-token: write" ascii
      $id_token2 = "id-token:write" ascii
   condition:
      $prt and ($id_token or $id_token2)
}

rule MAL_GitHub_Actions_Megalodon_Base64_Payload {
   meta:
      description = "Detects base64-encoded bash payload delivery pattern used by both Megalodon variants in GitHub Actions workflow files"
      author = "Spyced Concepts Ltd."
      date = "2026-05-30"
      reference = "https://safedep.io/megalodon-mass-github-repo-backdooring-ci-workflows/"
      score = 80
      id = "b9656256-a84a-465c-8a27-cc2dc5d5ccb7"
   strings:
      $b64_pipe_bash   = /\|\s*base64\s+(-d|-D|--decode)\s*\|\s*(bash|sh)/ ascii
      $b64_decode_exec = /base64\s+(-d|-D|--decode)\s+[^\|]+\|\s*(bash|sh)/ ascii
      $eval_b64        = /eval\s+\$\(echo\s+[A-Za-z0-9+\/]{20,}={0,2}\s*\|\s*base64/ ascii
      $echo_b64_pipe   = /echo\s+[A-Za-z0-9+\/]{40,}={0,2}\s*\|\s*base64\s+(-d|-D|--decode)\s*\|\s*(bash|sh)/ ascii
   condition:
      any of them
}

rule MAL_GitHub_Actions_Megalodon_Dispatch_Backdoor {
   meta:
      description = "Detects Megalodon targeted variant — workflow_dispatch combined with Optimize-Build name or C2 IP in GitHub Actions workflow files"
      author = "Spyced Concepts Ltd."
      date = "2026-05-30"
      reference = "https://safedep.io/megalodon-mass-github-repo-backdooring-ci-workflows/"
      score = 75
      id = "803edf63-5764-4d9c-8c0a-88a2bb21e9ed"
   strings:
      $wf_dispatch   = "workflow_dispatch:" ascii
      $optimize_name = "name: Optimize-Build" ascii
      $base64_any    = /base64/ ascii
      $c2_ip         = "216.126.225.129" ascii
   condition:
      ($optimize_name and $wf_dispatch) or
      ($wf_dispatch and $c2_ip) or
      ($wf_dispatch and $base64_any and $c2_ip)
}

rule MAL_GitHub_Actions_Megalodon_High_Confidence {
   meta:
      description = "High-confidence Megalodon detection — multiple corroborating IoCs present in a GitHub Actions workflow file"
      author = "Spyced Concepts Ltd."
      date = "2026-05-30"
      reference = "https://safedep.io/megalodon-mass-github-repo-backdooring-ci-workflows/"
      score = 95
      id = "f65905f2-a279-4619-902e-f2138ae3cf77"
   strings:
      $c2_ip          = "216.126.225.129" ascii
      $sysdiag        = "name: SysDiag" ascii
      $optimize       = "name: Optimize-Build" ascii
      $base64_payload = /base64\s+(-d|-D|--decode)\s*[^#\n]*\|\s*(bash|sh)/ ascii
      $prt            = "pull_request_target" ascii
   condition:
      $c2_ip or
      ($sysdiag and $base64_payload) or
      ($optimize and $base64_payload) or
      ($prt and $base64_payload and $c2_ip)
}
