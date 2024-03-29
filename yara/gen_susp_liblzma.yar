rule SUSP_liblzma_backdoor
{
	meta:
		author = "Vegard Nossum, Nils Kuhnert"
		description = "Triggers on a suspicious code pattern inside backdoored liblzma. Taken from Vergard Nossum's detection script."
		reference = "https://www.openwall.com/lists/oss-security/2024/03/29/4"
		hash = "cbeef92e67bf41ca9c015557d81f39adaba67ca9fb3574139754999030b83537"
		score = 75
		date = "2024-03-29"
		id = "b6968830-d7da-4f3d-8c70-999344d8a927"
	strings:
		$ = { f3 0f 1e fa 55 48 89 f5 4c 89 ce 53 89 fb 81 e7 00 00 00 80 48 83 ec 28 48 89 54 24 18 48 89 4c 24 10 }
	condition:
		all of them
}