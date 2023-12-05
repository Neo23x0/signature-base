/* requires YARA 3.11 */

rule HKTL_CobaltStrike_SleepMask_Jul22 {
   meta:
      description = "Detects static bytes in Cobalt Strike 4.5 sleep mask function that are not obfuscated"
      author = "CodeX"
      date = "2022-07-04"
      reference = "https://codex-7.gitbook.io/codexs-terminal-window/blue-team/detecting-cobalt-strike/sleep-mask-kit-iocs"
      score = 80
      id = "d396ab0e-b584-5a7c-8627-5f318a20f9dd"
   strings:
      $sleep_mask = { 48 8B C4 48 89 58 08 48 89 68 10 48 89 70 18 48 89 78 20 45 33 DB 45 33 D2 33 FF 33 F6 48 8B E9 BB 03 00 00 00 85 D2 0F 84 81 00 00 00 0F B6 45 }
   condition:
      $sleep_mask
}

// This file contain Yara rule for opcodes which target CS version 4.9.1 and prior.
// This yara target the Socks and Remote Connection functionality which cannot
// be modified by an operator. These can only be modified by Fortra as it needs
// changes to the source code. This detection was written to target leaked  CS 4.9
// versions, but has been tested backwards till v4.5.
// This yara wont hit beacon.exe, it was written for the shellcode
// This yara was specially crafted for the core (in-memory scans) which cannot be
// avoided in way by an operator, making the malleability, UDRL or IAT hooking useless

/* FR: rule caused 6490 false positives in our testing environment - cannot be used in the current form

rule HKTL_CobaltStrike_CS_Core_Oct23 {
    meta:
        description = "Hunts for opcodes used in Cobaltstrike 4.9.1 and earlier"
        version = "0.1"
        author = "@ninjaparanoid"
        reference = "https://github.com/paranoidninja/Cobaltstrike-Detection/blob/main/cs49.yara"
        date = "2023-10-12"
        score = 75
    strings:
        $socks = { 49 8D 55 02 48 8D 4C 24 30 44 0F B7 F8 B8 FF 03 00 00 }
        $core = { 49 B9 01 01 01 01 01 01 01 01 49 0F AF D1 49 83 F8 40 }
    condition:
        1 of them
}
*/