rule mal_nodepkg_versions_terminalstyle_sep25
{
  meta:
    description = "Detect specific versions of terminal styling npm packages known to be a malware"
    author = "Samuel Monsempes"
    date = "2025-09-09"
    reference = "https://www.aikido.dev/blog/npm-debug-and-chalk-packages-compromised"
    affected_files = "package-lock.json, npm-shrinkwrap.json, package.json"
    threat_level = "high"

  strings:
    $v1 = "ansi-styles\": \"6.2.2"
    $v2 = "chalk\": \"5.6.1"
    $v3 = "strip-ansi\": \"7.1.1"
    $v4 = "supports-color\": \"10.2.1"
    $v5 = "ansi-regex\": \"6.2.1"
    $v6 = "wrap-ansi\": \"9.0.1"
    $v7 = "color-convert\": \"3.1.1"
    $v8 = "color-name\": \"2.0.1"
    $v9 = "slice-ansi\": \"7.1.1"
    $v10 = "color\": \"5.0.1"
    $v11 = "color-string\": \"2.1.1"
    $v12 = "simple-swizzle\": \"0.2.3"
    $v13 = "supports-hyperlinks\": \"4.1.1"
    $v14 = "has-ansi\": \"6.0.1"
    $v15 = "chalk-template\": \"1.1.1"
    $v16 = "backslash\": \"0.2.1"

  condition:
    any of ($v*)
}
