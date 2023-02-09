rule SUSP_Filesize_Exfil {
   meta:
      description = "Detects uncommon file sizes for files associated with web apps"
      author = "Janantha Marasinghe"
      reference = "Internal Research"
      date = "2023-01-10"
      score = 40
   condition:
      ( 
      	extension == ".css" or 
	extension == ".js" or 
	extension == ".php" or 
	// extension == ".html" or 
	// extension == ".htm" or 
	extension == ".asp" or 
	extension == ".aspx" or 
	extension == ".jsp" or 
	extension == ".gif" or 
	extension == ".jpg" or 
	extension == ".png" or 
	extension == ".jpeg" or 
	// extension == ".txt" or 
	extension == ".woff" or 
	// extension == ".json" or 
	// extension == ".xml" or 
	extension == ".svg"
      ) 
	  and
	    ( filesize > 50MB ) /* Usually the file sizes of files with extensions mentioned above should be below 50MB. Especially on a web server. A match may be indicative of file extension manipulation to evade detection of a potential exfil package.*/
}
