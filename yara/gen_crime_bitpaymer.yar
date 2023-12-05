rule BitPaymer {
   meta:
      description = "Rule to detect newer Bitpaymer samples. Rule is based on BitPaymer custom packer"
      author = "Morphisec labs"
      refrence = "http://blog.morphisec.com/bitpaymer-ransomware-with-new-custom-packer-framework"
      id = "916de232-1f1b-5853-a57f-623812cfed16"
   strings:
      $opcodes1 = {B9 ?? 00 00 00 FF 14 0F B8 FF 00 00 00 C3 89 45 FC}
      $opcodes2 = {61 55 FF 54 B7 01 B0 FF C9 C3 CC 89 45 FC}
   condition:
      (uint16 (0) == 0x5a4d) and ($opcodes1 or $opcodes2)
}
