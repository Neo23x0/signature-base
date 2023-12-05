
rule WEBSHELL_Csharp_Hash_String_Oct22 {
	meta:
		description = "C# webshell using specific hash check for the password."
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Nils Kuhnert (modified by Florian Roth)"
		hash = "29c187ad46d3059dc25d5f0958e0e8789fb2a51b9daaf90ea27f001b1a9a603c"
		date = "2022-10-27"
		score = 60
		id = "c7d459be-5e61-57b7-b738-051c0cec62d2"
	strings:
		$gen1 = "void Page_Load" ascii
		$gen2 = "FromBase64String" ascii
		$gen3 = "CryptoServiceProvider" ascii
		$gen4 = "ComputeHash" ascii

		$hashing1 = "BitConverter.ToString(" ascii /* Webshell uses ToString from a string: BitConverter.ToString(ptqVQ) */
		$hashing2 = ").Replace(\"-\", \"\") == \"" ascii

      $filter1 = "BitConverter.ToString((" ascii /* Usually it's something like: return ((BitConverter.ToString((new SHA1CryptoServiceProvider() */
	condition:
		filesize < 10KB 
		and all of ($gen*) and all of ($hashing*)
		and not 1 of ($filter*)
}