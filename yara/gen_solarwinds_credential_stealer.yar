
rule HKTL_Solarwinds_credential_stealer {
    meta:
        description = "Detects solarwinds credential stealers like e.g. solarflare via the touched certificate, files and database columns"
        reference = "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/solarwinds-raindrop-malware"
        reference = "https://github.com/mubix/solarflare"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp"
        date = "2021-01-20"
		hash = "1b2e5186464ed0bdd38fcd9f4ab294a7ba28bd829bf296584cbc32e2889037e4"
		hash = "4adb69d4222c80d97f8d64e4d48b574908a518f8d504f24ce93a18b90bd506dc"
        id = "87dba889-367a-5fc3-b5e0-eb8e3c36a5e9"
    strings:
        $certificate = "CN=SolarWinds-Orion" ascii nocase wide
        $credfile1 = "\\CredentialStorage\\SolarWindsDatabaseAccessCredential" ascii nocase wide
        $credfile2 = "\\KeyStorage\\CryptoHelper\\default.dat" ascii nocase wide
        $credfile3 = "\\Orion\\SWNetPerfMon.DB" ascii nocase wide
        $credfile4 = "\\Orion\\RabbitMQ\\.erlang.cookie" ascii nocase wide
        $sql1 = "encryptedkey" ascii nocase wide fullword
        $sql2 = "protectiontype" ascii nocase wide fullword
        $sql3 = "CredentialProperty" ascii nocase wide fullword
        $sql4 = "passwordhash" ascii nocase wide fullword
        $sql5 = "credentialtype" ascii nocase wide fullword
        $sql6 = "passwordsalt" ascii nocase wide fullword
    condition:
        uint16(0) == 0x5A4D and $certificate and ( 2 of ( $credfile* ) or 5 of ( $sql* ) )
}

