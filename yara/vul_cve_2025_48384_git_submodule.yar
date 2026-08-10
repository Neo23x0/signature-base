rule VULN_Git_CVE_2025_48384_Git_Submodule_Path_CR{
    meta:
        description = "Detects .gitmodules entries with submodule paths containing a trailing CR (\r) causing Git to write an incorrect submodule entry and enabling subsequent hook injection - indicator of supply chain compromise (via compromised submodule), as in CVE-2025-48384."
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Vinicius Egerland (github.com/vinieger)"
        date = "2025-09-15"
        reference = "https://github.com/vinieger/CVE-2025-48384"
        reference2 = "https://nvd.nist.gov/vuln/detail/CVE-2025-48384"
        reference3 = "https://github.com/git/git/security/advisories/GHSA-vwqx-4fm8-6qc9"
		score = 50
        id = "cd69998f-0517-4349-b5b7-4cfef7121788"
        
    strings:
        $section = "[submodule \"" ascii
        $path    = /\s*path\s*=\s*(".+"|[^\s]+)\r"/ ascii nocase

    condition:
        $section and $path and filesize < 10KB
}