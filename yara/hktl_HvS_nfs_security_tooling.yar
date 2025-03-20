rule HKTL_NFS_Fuse_NFS {
   meta:
      description = "Detects the nfs-security-tooling fuse_nfs by HvS Consulting"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Moritz Oettle"
      date = "2024-10-22"
      score = 75
      reference = "https://github.com/hvs-consulting/nfs-security-tooling"

      id = "287fbe7d-ee1c-58a4-aa2d-9d9bec8321b4"
   strings:
      $s1 = "NFS3ConnectionFactory" fullword ascii
      $s2 = "fuse_to_nfs_timestamp" fullword ascii
      $s3 = "--manual-fh" fullword ascii
      $s4 = "--fake-uid-allow-root" fullword ascii
      $s5 = "nfs.rpc.credential" fullword ascii
      $s6 = "nfs.readlink" fullword ascii
      $s7 = "pyfuse3.EntryAttributes" fullword ascii
      $s8 = "Make nested exports on NetApp servers work" fullword ascii
      $s9 = "add_mutually_exclusive_group" fullword ascii

   condition:
      4 of them
}

rule HKTL_NFS_NFS_Analyze {
   meta:
      description = "Detects the nfs-security-tooling nfy_analyze by HvS Consulting"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Marc Stroebel"
      date = "2024-10-22"
      score = 75
      reference = "https://github.com/hvs-consulting/nfs-security-tooling"
      
      id = "3350d0ae-e638-5c8f-a578-ba0ac5521053"
   strings:
      $s1 = "no_root_squash_exports" fullword ascii
      $s2 = "nfs lock manager" fullword ascii
      $s3 = "netapp partner" fullword ascii
      $s4 = "xdrdef.mnt3_type" fullword ascii
      $s5 = "BTRFS subvolumes" fullword ascii
      $s6 = "Unsupported fsid" fullword ascii
      $s7 = "nfs3_read_etc_shadow" fullword ascii
      $s8 = "nfs3_check_no_root_squash" fullword ascii
      $s9 = "krb5i" fullword ascii
      $s10 = "nfs4_overview" fullword ascii
      $s11 = "--btrfs-subvolumes" fullword ascii
      $s12 = "when escaping a BTRFS export" fullword ascii
      $s13 = "No NFS server detected" fullword ascii

   condition:
      6 of them
}
