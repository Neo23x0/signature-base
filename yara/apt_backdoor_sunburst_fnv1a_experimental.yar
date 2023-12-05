
rule APT_fnv1a_plus_extra_XOR_in_MSIL_experimental
{
    meta:
        description = "This rule detects the specific MSIL implementation of fnv1a of the SUNBURST backdoor (standard fnv1a + one final XOR before RET) independent of the XOR-string. (fnv64a_offset and fnv64a_prime are standard constants in the fnv1a hashing algorithm.)"
		reference = "https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html"
        author = "Arnim Rupp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		date = "2020-12-22"
		hash1 = "32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77"
		hash2 = "ce77d116a074dab7a22a0fd4f2c1ab475f16eec42e1ded3c0b0aa8211fe858d6"
		hash3 = "019085a76ba7126fff22770d71bd901c325fc68ac55aa743327984e89f4b0134"
        id = "5505f7ff-eca5-5274-bdd1-dbbd648c3ccc"
    strings:
		$fnv64a_offset = { 25 23 22 84 e4 9c f2 cb }
		$fnv64a_prime_plus_gap_plus_xor_ret = { B3 01 00 00 00 01 [8-40] 61 2A 00 00 }

		// use for less false positives, xor before fnv1a prime
		//$fnv64a_prime_plus_gap_plus_xor_ret = { 61 [0-3] B3 01 00 00 00 01 [8-40] 61 2A }
		// even less false positives, not sure if it misses beef
		//$fnv64a_prime_plus_gap_plus_xor_ret = { 61 [0-3] B3 01 00 00 00 01 [8-40] 61 2A 00 00 }
    condition:
		(uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

// todo:
// Rules wouldn't work yet for bitshift instead of multiplication as described in http://www.isthe.com/chongo/tech/comp/fnv/index.html :  hval += (hval << 1) + (hval << 4) + (hval << 5) + (hval << 7) + (hval << 8) + (hval << 40);

// Deactivated. This rule is probably only useful for developers to check their own software repository
/*
rule TEST_false_positive_plain_fnv1a_in_x64
{
    meta:
        description = "This rule detects x64 implementations of standard fnv1a just by looking for the standard fnv64a_offset and fnv64a_prime (unless bitshifting is used instead of multiplication). This rule would have found the SUNBURST backdoor at Solarwinds but will also find any other programm which implements fnv1a. Just useful for developers, pls check if that fnv1a was put there by you ;)"
		reference = "https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html"
        author = "Arnim Rupp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		date = "2020-12-22"
		score = 10
    strings:
		$fnv64a_offset = { 25 23 22 84 e4 9c f2 cb }
		$fnv64a_prime = { B3 01 00 00 00 01 }
    condition:
		// MZ or ELF
		( uint16(0) == 0x5a4d or uint32be(0) == 0x7f454c46 ) and all of them
}
*/
