rule EXPL_ODF_DBRange_Remote_ODB_CVE_2026_59265_Oct26 {
   meta:
      description = "Detects an OpenDocument spreadsheet with an auto-refreshing database range whose data source is a remote database document (ODB), as used to load attacker-controlled JDBC drivers in Apache OpenOffice (CVE-2026-59265). Matches content.xml of ODS files or flat FODS files. Note: this detects the database-range trigger; the LibreOffice CVE-2026-63277 data-provider trigger (calcext:data-mappings) is not covered by this rule."
      author = "Piotr P. Karwasz"
      reference = "https://www.cve.org/CVERecord?id=CVE-2026-59265"
      date = "2026-10-01"
      score = 75
      hash1 = "97daed94ddff0cc3267f8deb11ceaf76ae2f9dc270307333d5e0fe47eadb7a07"
      id = "d5355005-453d-4660-89a8-6e81948288be"
   strings:
      $a1 = "<table:database-range " ascii
      $a2 = "table:refresh-delay=" ascii

      $r1 = /table:database-name="(https?|ftps?|webdavs?|smb):\/\// nocase ascii
      /* UNC: file://host/..., file:////..., or a backslash (literal or %5C-encoded) in the leading separators */
      $r2 = /table:database-name="file:(\/\/[^\/"]|\/{4}|(\/|%2f){0,3}(\\|%5c))/ nocase ascii
   condition:
      filesize < 20MB
      and all of ($a*)
      and 1 of ($r*)
}

rule EXPL_ODF_DataMapping_SQL_Remote_CVE_2026_63277_Oct26 {
   meta:
      description = "Detects a LibreOffice Calc data mapping (calcext:data-mappings) using the SQL provider whose data source reference is a remote location or a UNC path, as used to load attacker-controlled JDBC drivers on document open (CVE-2026-63277). The SQL-provider data source is resolved as a database document; the reference lives in calcext:id (table@url), xlink:href or calcext:database-name. Matches content.xml of ODS/ODT files and embedded Calc objects."
      author = "Piotr P. Karwasz"
      reference = "https://www.cve.org/CVERecord?id=CVE-2026-63277"
      date = "2026-10-06"
      score = 75
      id = "a21d5990-dd86-484b-9e7d-8d797557fe81"
   strings:
      $a = "<calcext:data-mapping" ascii
      $sql = /calcext:provider="org\.libreoffice\.calc\.sql"/ nocase ascii

      /* remote or UNC data source in calcext:id (table@url), xlink:href or calcext:database-name */
      $r1 = /(calcext:id|xlink:href|calcext:database-name)="[^"]{0,512}(https?|ftps?|webdavs?|smb):\/\// nocase ascii
      $r2 = /(calcext:id|xlink:href|calcext:database-name)="[^"]{0,512}file:(\/\/[^\/"]|\/{4}|(\/|%2f){0,3}(\\|%5c))/ nocase ascii
   condition:
      filesize < 20MB and $a and $sql and 1 of ($r*)
}

rule EXPL_ODB_Remote_JDBC_ClassPath_CVE_2026_59265_Oct26 {
   meta:
      description = "Detects an OpenDocument database definition whose JDBC driver class path points to a remote location, as used to load attacker-controlled JDBC drivers in Apache OpenOffice (CVE-2026-59265) and LibreOffice (CVE-2026-63277). The class path may appear as an attribute on db:data-source or inside db:driver-settings. Matches content.xml of ODB files, or an inline database definition in another ODF document."
      author = "Piotr P. Karwasz"
      reference = "https://www.cve.org/CVERecord?id=CVE-2026-59265"
      reference = "https://www.cve.org/CVERecord?id=CVE-2026-63277"
      date = "2026-10-01"
      score = 70
      hash1 = "aa2889d26859275455fa227ed731de04bba00da850c0b2d334b41a2e42a71762"
      id = "e7447d61-6732-4986-9183-544caec350b5"
   strings:
      $r1 = /db:java-classpath="[^"]{0,512}(https?|ftps?|webdavs?|smb):\/\// nocase ascii
      /* UNC: file://host/..., file:////..., or a backslash (literal or %5C-encoded) in the leading separators */
      $r2 = /db:java-classpath="[^"]{0,512}file:(\/\/[^\/"]|\/{4}|(\/|%2f){0,3}(\\|%5c))/ nocase ascii
   condition:
      filesize < 20MB
      and 1 of ($r*)
}
