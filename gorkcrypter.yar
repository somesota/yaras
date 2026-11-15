import "pe"


// ---------------------------------------------------------------------
// Campaign Rule (Mix1 build)
// ---------------------------------------------------------------------
rule MAL_GorkCrypter_CampaignMix1
{
    meta:
        description    = "Detects Go packer via its Go build ID, garble-obfuscated symbol names, rodata literal-pool layout and blob-decoder startup constants"
        author         = "somesota"
        date           = "2026-09-03"
        version        = "2.0"
        sample_sha256  = "21768f84350ec5f530bd1ebf6058c8840c55b0513eaca927b623500c81f834e2"
        sample_md5     = "3b48178697b9231ef43c0f167c9202fc"
        family         = "GorkCrypter"
        confidence     = "High"
        tlp            = "TLP:WHITE"
        mitre_attack   = "T1027, T1140"

    strings:
        // --- Go build ID. Unique per compile, so it pins this build.
        $buildid = "Go build ID: \"SwTplaK7hGOHZYKSqgl8/-OZgemwG2GQ5TiywQeBT/zVTOLLoDDBnNUoH-jEw5/sZ-K_z96u1gtvI2Q5GGY\"" ascii

        // --- Garble-randomized symbol names that survive in the symbol table.
        $sym_g9izpq = "main.g9IzPQ" ascii          // payload PE decoder
        $sym_vc8    = "main.vc8OCtbFnfRR" ascii    // startup string init
        $sym_oli    = "main.oLi8xoMw" ascii        // decoded-blob slice accessor
        $sym_v1l1   = "main.v1L1O7Q4" ascii        // WinAPI LazyProc trampoline

        // --- Word-list literals from the .rodata string pool.
        $litpool1 = "text tick atlasbirchdeltaember" ascii
        $litpool2 = " position  for type /dev/stdin1" ascii
        $litpool3 = " total length generaloffpeakrepo" ascii

        // --- Blob-copy-and-decode call with this build's exact constants:
        //     blob length 0x9748 qwords, length/key immediates 0x4ba42 and
        //     0xcfa97, prefix literal 0x1a194ff188c80d91. The constants stay
        //     exact on purpose: this rule pins the build. The call-site rule
        //     below wildcards them to match the technique across builds.
        $blobsetup = {
            48 B8 91 0D C8 88 F1 4F 19 1A     // mov rax, 0x1a194ff188c80d91
            48 89 84 24 86 1A 00 00           // mov [rsp+0x1a86], rax
            48 8D BC 24 88 1A 00 00           // lea rdi, [rsp+0x1a88]
            48 8D 35 ?? ?? ?? ??              // lea rsi, [rip+off]  (.rdata blob)
            B9 48 97 00 00                    // mov ecx, 0x9748     (qword count)
            F3 48 A5                          // rep movsq
            48 8D 84 24 86 1A 00 00           // lea rax, [rsp+0x1a86]
            BB 42 BA 04 00                    // mov ebx, 0x4ba42
            48 89 D9                          // mov rcx, rbx
            BF 97 FA 0C 00                    // mov edi, 0xcfa97
        }

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        3 of ($buildid, $sym_g9izpq, $sym_vc8, $sym_oli, $sym_v1l1,
              $litpool1, $litpool2, $litpool3, $blobsetup)
}

// ---------------------------------------------------------------------
// Campaign Rule (Mix2 build)
// ---------------------------------------------------------------------
rule MAL_GorkCrypter_CampaignMix2
{
    meta:
        description    = "Detects copies of the Mix2 build of the GorkCrypter Go packer via the per-build key and blob-length constants at its blob-decode call site"
        author         = "somesota"
        date           = "2026-09-20"
        version        = "1.0"
        sample_sha256  = "b10c774e310afc6f2c71fc294b39b0402c8ace437e71bb1ece12473e0f22ebf3"
        sample_md5     = "1434f56494d7f652dc42b079d21c4a35"
        family         = "GorkCrypter"
        confidence     = "High"
        tlp            = "TLP:WHITE"
        mitre_attack   = "T1140, T1027.002"

    strings:
        // --- Per-build key 0x7e404 in the MOV EDI that seeds the six-pass
        //     blob decoder, plus the CALL displacement to this build's
        //     decoder function.
        $camp_key_and_calltarget = { 48 89 D9 BF 04 E4 07 00 31 F6 E8 A1 01 1D 00 }

        // --- Blob-length immediate 0x45a00 (285,184 bytes, the decoded
        //     master blob) with the buffer setup that precedes the key MOV.
        $camp_bloblen_and_bufsetup = { 48 8D 84 24 30 09 00 00 BB 00 5A 04 00 48 89 D9 }

    condition:
        uint16(0) == 0x5A4D and
        filesize > 2000000 and filesize < 8000000 and
        all of them
}

// ---------------------------------------------------------------------
// Family Rule (Go toolchain traits, key/infrastructure-agnostic)
// ---------------------------------------------------------------------
rule MAL_GorkCrypter_Family
{
    meta:
        description    = "Detects GorkCrypter Go packer builds via toolchain traits that survive a rebuild with new keys: a Go 1.21/1.22 build tag, syscall.LazyDLL runtime strings, a .symtab section and a KERNEL32-only import table"
        author         = "somesota"
        date           = "2026-09-20"
        version        = "1.0"
        sample_sha256  = "b10c774e310afc6f2c71fc294b39b0402c8ace437e71bb1ece12473e0f22ebf3"
        sample_md5     = "1434f56494d7f652dc42b079d21c4a35"
        family         = "GorkCrypter"
        confidence     = "Medium"
        tlp            = "TLP:WHITE"
        mitre_attack   = "T1027, T1106, T1129"

    strings:
        // --- Go compiler version tag. Mix1 is go1.21.8 and Mix2 is go1.22.1,
        //     so this alone marks the toolchain, not the family.
        $fam_govers = /go1\.2[12]\.[0-9]+/ ascii

        // --- Go runtime strings for syscall.LazyDLL/LazyProc, the way the
        //     packer resolves every non-KERNEL32 API at runtime.
        $fam_lazydll  = "syscall.NewLazyDLL" ascii
        $fam_lazyproc = "syscall.(*LazyDLL).NewProc" ascii

        // --- Go runtime entry symbol. Confirms the toolchain only.
        $fam_rt0 = "_rt0_amd64_windows" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize > 500000 and filesize < 20000000 and
        pe.machine == 0x8664 and
        pe.section_index(".symtab") >= 0 and
        pe.number_of_imports == 1 and
        pe.import_details[0].library_name icontains "kernel32" and
        3 of ($fam_govers, $fam_lazydll, $fam_lazyproc, $fam_rt0)
}

// ---------------------------------------------------------------------
// Blob Decoder Call Site (key-agnostic, both build shapes)
// ---------------------------------------------------------------------
rule MAL_GorkCrypter_BlobDecoderCallsite
{
    meta:
        description    = "Detects the call site that copies an embedded .rdata blob into a stack buffer and runs a six-pass keyed byte transform on it, with stack offsets, blob address, lengths, key and call target wildcarded so it survives key rotation"
        author         = "somesota"
        date           = "2026-09-20"
        version        = "1.0"
        sample_sha256  = "b10c774e310afc6f2c71fc294b39b0402c8ace437e71bb1ece12473e0f22ebf3"
        sample_md5     = "1434f56494d7f652dc42b079d21c4a35"
        family         = "GorkCrypter"
        confidence     = "Medium"
        tlp            = "TLP:WHITE"
        mitre_attack   = "T1140, T1027.002, T1129"

    strings:
        // --- Mix2 shape: no prefix literal. XOR ESI,ESI and the CALL follow
        //     the key load.
        //     LEA RDI,[RSP+i]; LEA RSI,[RIP+i] (blob); MOV ECX,i (qword count);
        //     REP MOVSQ; LEA RAX,[RSP+i]; MOV EBX,i (blob length);
        //     MOV RCX,RBX; MOV EDI,i (key); XOR ESI,ESI; CALL rel32 (decoder).
        $callsite_noprefix = {
            48 8D BC 24 ?? ?? ?? ??
            48 8D 35 ?? ?? ?? ??
            B9 ?? ?? ?? ??
            F3 48 A5
            48 8D 84 24 ?? ?? ?? ??
            BB ?? ?? ?? ??
            48 89 D9
            BF ?? ?? ?? ??
            31 F6
            E8 ?? ?? ?? ??
        }

        // --- Mix1 shape: a 64-bit prefix literal is written first. REP MOVSQ
        //     then overwrites bytes 2..7 of it, and the key load ends the block.
        $callsite_prefixed = {
            48 B8 ?? ?? ?? ?? ?? ?? ?? ??
            48 89 ( 84 24 ?? ?? ?? ?? | 44 24 ?? )
            48 8D ( BC 24 ?? ?? ?? ?? | 7C 24 ?? )
            48 8D 35 ?? ?? ?? ??
            B9 ?? ?? ?? ??
            F3 48 A5
            48 8D ( 84 24 ?? ?? ?? ?? | 44 24 ?? )
            BB ?? ?? ?? ??
            48 89 D9
            BF ?? ?? ?? ??
        }

    condition:
        uint16(0) == 0x5A4D and
        filesize > 500000 and filesize < 20000000 and
        ($callsite_noprefix or $callsite_prefixed)
}

// ---------------------------------------------------------------------
// Anti-Analysis Decoy (inlined word-counter camouflage)
// ---------------------------------------------------------------------
rule MAL_GorkCrypter_DecoyWordCounterCamouflage
{
    meta:
        description    = "Detects the packer's camouflage: a working word-counter demo routine, built around a fixed 48-byte sentence, that the obfuscator inlines dozens of times to bury the real blob-decoder logic"
        author         = "somesota"
        date           = "2026-09-03"
        version        = "2.0"
        sample_sha256  = "21768f84350ec5f530bd1ebf6058c8840c55b0513eaca927b623500c81f834e2"
        sample_md5     = "3b48178697b9231ef43c0f167c9202fc"
        family         = "GorkCrypter"
        confidence     = "Medium"
        tlp            = "TLP:WHITE"
        mitre_attack   = "T1027, T1027.002, T1140"

    strings:
        // --- Go string literal, stored in the pool without a NUL, so no fullword.
        $decoy_sentence = "go code counts words and go code logs every word" ascii

        // --- Opcode skeleton shared by the inlined repetitions. The copies are
        //     not byte-identical: call targets, one SIB/ModRM byte, one CMP
        //     register nibble, one branch displacement and some stack offsets
        //     differ per site, so those fields are wildcarded.
        $camo_skeleton = {
            4C 89 DB                  // mov rbx, rbx           (repetition entry marker)
            [0-2]                     // optional 66 90 alignment NOP
            E8 ?? ?? ?? ??            // call rel32              (shared decoy helper)
            49 89 1B                  // mov [r11], rbx
            4C 8B 2C ??               // mov r13, [reg+SIB]      (register varies)
            4D 89 6B 08               // mov [r11+8], r13
            49 89 DB                  // mov r11, rbx
            4C 8D 2D ?? ?? ?? ??      // lea r13, [rip+disp32]
            4C 89 1C 0A               // mov [rdx+rcx*1], r11
            48 8D 5E 01               // lea rbx, [rsi+1]
            49 39 D?                  // cmp reg, rbx            (register nibble varies)
            73 ??                     // jae short
            48 89 94 24 ?? 07 00 00   // mov [rsp+disp32], rdx   (low byte varies)
            4C 89 BC 24 ?? 05 00 00   // mov [rsp+disp32], r15   (low byte varies)
        }

    condition:
        uint16(0) == 0x5A4D and
        filesize > 1MB and filesize < 10MB and
        $decoy_sentence and
        #camo_skeleton >= 3
}

// ---------------------------------------------------------------------
// Hunting Rule (low precision, triage only)
// ---------------------------------------------------------------------
// Matches any Go binary that imports only KERNEL32 and resolves the rest
// through syscall.LazyDLL. Legitimate Go tools share this pattern, so use it
// for hunting and never for automated blocking.
rule MAL_GorkCrypter_DynamicApiResolution
{
    meta:
        description    = "Flags Go PE binaries that import only KERNEL32.dll and resolve every other API at runtime through syscall.LazyDLL/LazyProc, the general technique of this packer family"
        author         = "somesota"
        date           = "2026-09-20"
        version        = "1.0"
        sample_sha256  = "b10c774e310afc6f2c71fc294b39b0402c8ace437e71bb1ece12473e0f22ebf3"
        sample_md5     = "1434f56494d7f652dc42b079d21c4a35"
        family         = "GorkCrypter"
        confidence     = "Low"
        tlp            = "TLP:WHITE"
        mitre_attack   = "T1106, T1027"

    strings:
        // --- Go runtime strings of the LazyDLL/LazyProc mechanism.
        $lazydll  = "syscall.NewLazyDLL" ascii
        $lazyproc = "syscall.(*LazyDLL).NewProc" ascii
        $lazyload = "syscall.(*LazyDLL).Load" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize > 500000 and filesize < 20000000 and
        pe.number_of_imports == 1 and
        pe.import_details[0].library_name icontains "kernel32" and
        2 of ($lazydll, $lazyproc, $lazyload)
}

// ---------------------------------------------------------------------
// Signer Certificate (self-issued, one entry per build)
// ---------------------------------------------------------------------
rule MAL_GorkCrypter_SelfIssuedSignerCert
{
    meta:
        description    = "Detects PEs Authenticode-signed with one of the packer's self-issued certificates: 'Cedar Stone Collective' on Mix1 and 'Delta Dynamics Group' on Mix2"
        author         = "somesota"
        date           = "2026-09-03"
        version        = "2.1"
        sample_sha256  = "21768f84350ec5f530bd1ebf6058c8840c55b0513eaca927b623500c81f834e2, b10c774e310afc6f2c71fc294b39b0402c8ace437e71bb1ece12473e0f22ebf3"
        family         = "GorkCrypter"
        confidence     = "High"
        tlp            = "TLP:WHITE"
        mitre_attack   = "T1553.002, T1588.003"

    condition:
        // The signer changes per build, so each build adds its own entry.
        // Thumbprint and serial are matched, not the subject name: the
        // operator can mint a new certificate with the same name.
        uint16(0) == 0x5A4D and
        for any sig in pe.signatures : (
            // Mix1: Cedar Stone Collective, valid 2026-08-16 to 2027-08-23
            sig.thumbprint == "ca498375f10f74e5f89417a7a76fcd565cebf4c9" or
            sig.serial == "4a:bc:ba:78:cb:40:69:9f:c8:29:16:41:69:40:5d:dc" or
            // Mix2: Delta Dynamics Group, valid 2026-09-09 to 2027-09-16
            sig.thumbprint == "a60475d2c515bde13334329255db22924d01912c" or
            sig.serial == "00:f2:ed:93:3c:c6:a1:1d:bd:87:dc:58:ef:12:c7:90:62"
        )
}
