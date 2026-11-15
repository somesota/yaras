// TLP (strictest rule): WHITE
import "pe"
import "hash"


// ===========================================================================
//  RWX Alloc-Decrypt-ManualMap-Execute Orchestrator
//           (the Packer rule for this sample)
// ===========================================================================
rule ArxCrypter_RWXDecryptExecuteOrchestrator
{
    meta:
        description    = "Detects the crypter/packer's alloc-RWX -> memcpy ciphertext -> custom-cipher-decrypt -> manual-map-and-run orchestrator function, identified by its exact sequence of hash-resolved-API constants, allocation size, and protection flags"
        author         = "somesota"
        date           = "2026-09-05"
        version        = "1.0"
        sample_sha256  = "5541bf99ebfee0f4c9ab33624b49e125348bf02280b9efbb8824919f53c8630c"
        sample_md5     = "803fa2ddc9de8e377e526a06aca89551"
        family         = "ArxCrypter"
        confidence     = "High"
        tlp            = "TLP:WHITE"
        mitre_attack   = "T1140, T1620, T1027.002"

    strings:
        // Orchestrator function body: VirtualAlloc-class hash (0x5ebbb6ce) ->
        // VirtualFree-class hash (0xc9223d4c) -> alloc 0x11a800 bytes with
        // MEM_COMMIT|MEM_RESERVE (0x3000) -> memcpy ciphertext (LEA to
        // DAT_14007b100, wildcarded rel32) -> decrypt with 128-byte
        // (0x80) key (LEA to DAT_14007b000, wildcarded rel32) over 0x11a800
        // bytes. All 4 CALL/LEA rel32 displacements wildcarded since they are
        // link-time-resolved and would shift on recompilation; every
        // immediate constant (API hashes, sizes, flags) is preserved exact.
        $orchestrator = {
            BA CE B6 BB 5E                  // MOV EDX, 0x5ebbb6ce   (VirtualAlloc-class API hash)
            48 8B C8                        // MOV RCX, RAX
            48 89 7C 24 38                  // MOV [RSP+0x38], RDI
            E8 ?? ?? ?? ??                  // CALL resolve_api_by_hash
            BA 4C 3D 22 C9                  // MOV EDX, 0xc9223d4c   (VirtualFree-class API hash)
            48 8B CB                        // MOV RCX, RBX
            48 8B F0                        // MOV RSI, RAX
            E8 ?? ?? ?? ??                  // CALL resolve_api_by_hash
            48 8B F8                        // MOV RDI, RAX
            48 85 F6                        // TEST RSI, RSI
            74 66                           // JZ
            48 85 C0                        // TEST RAX, RAX
            74 61                           // JZ
            BA 00 A8 11 00                  // MOV EDX, 0x11a800     (RWX region size, ~1.15MB)
            33 C9                           // XOR ECX, ECX
            41 B9 04 00 00 00               // MOV R9D, 4
            41 B8 00 30 00 00               // MOV R8D, 0x3000       (MEM_COMMIT | MEM_RESERVE)
            FF D6                           // CALL RSI              (VirtualAlloc-class)
            48 8B D8                        // MOV RBX, RAX
            48 85 C0                        // TEST RAX, RAX
            74 44                           // JZ
            41 B8 00 A8 11 00               // MOV R8D, 0x11a800
            48 8D 15 ?? ?? ?? ??            // LEA RDX, [DAT_14007b100_stage2_ciphertext]
            48 8B C8                        // MOV RCX, RAX
            E8 ?? ?? ?? ??                  // CALL memcpy-helper (FUN_140075f60)
            41 B9 80 00 00 00               // MOV R9D, 0x80         (128-byte key length)
            4C 8D 05 ?? ?? ?? ??            // LEA R8, [DAT_14007b000_stage2_key]
            BA 00 A8 11 00                  // MOV EDX, 0x11a800
            48 8B CB                        // MOV RCX, RBX
            E8 ?? ?? ?? ??                  // CALL FUN_140073be0_stream_cipher_decrypt_stage2
        }

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        $orchestrator
}

// ===========================================================================
// CIS-Locale + Tick-Count Anti-Sandbox Gates
// ===========================================================================
rule ArxCrypter_CISLocaleTimingAntiAnalysis
{
    meta:
        description    = "Detects the packer's two anti-analysis gates: a CIS-region (Russia/Belarus) locale/keyboard-layout check and a ~1000ms+/-50ms GetTickCount-based timing check, both resolved via hash-based API lookup rather than the import table"
        author         = "somesota"
        date           = "2026-09-05"
        version        = "1.0"
        sample_sha256  = "5541bf99ebfee0f4c9ab33624b49e125348bf02280b9efbb8824919f53c8630c"
        sample_md5     = "803fa2ddc9de8e377e526a06aca89551"
        family         = "ArxCrypter"
        confidence     = "High"
        tlp            = "TLP:WHITE"
        mitre_attack   = "T1497.001, T1622, T1614.001"

    strings:
        // Locale/CIS gate: keyboard-layout-class hash (0x2559ef13) into
        // resolve_api_by_hash, then locale-info-class hash (0xabac9d89) into
        // a second resolve_api_by_hash call. CALL rel32 operands wildcarded.
        $locale_gate = {
            BA 13 EF 59 25                  // MOV EDX, 0x2559ef13   (GetKeyboardLayout-class API hash)
            48 8B C8                        // MOV RCX, RAX
            E8 ?? ?? ?? ??                  // CALL resolve_api_by_hash
            BA 89 9D AC AB                  // MOV EDX, 0xabac9d89   (GetLocaleInfo-class API hash)
            48 8B CB                        // MOV RCX, RBX
            48 8B F0                        // MOV RSI, RAX
            E8 ?? ?? ?? ??                  // CALL resolve_api_by_hash
        }

        // Timing gate: tick-count-class hash (0x80e273a9) into
        // resolve_api_by_hash. CALL rel32 operand wildcarded.
        $timing_gate = {
            BA A9 73 E2 80                  // MOV EDX, 0x80e273a9   (GetTickCount-class API hash)
            48 8B C8                        // MOV RCX, RAX
            E8 ?? ?? ?? ??                  // CALL resolve_api_by_hash
        }

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        all of them
}

// ===========================================================================
//  No-IAT XXHash32-Based Dynamic API Resolution
// ===========================================================================
rule ArxCrypter_XXHash32NoIATApiResolution
{
    meta:
        description    = "Detects a compiled XXHash32 (seed 0) avalanche/finalization sequence used as the malware's export-name hashing function for import-free (no-IAT) API resolution via PEB-walk"
        author         = "somesota"
        date           = "2026-09-05"
        version        = "1.0"
        sample_sha256  = "5541bf99ebfee0f4c9ab33624b49e125348bf02280b9efbb8824919f53c8630c"
        sample_md5     = "803fa2ddc9de8e377e526a06aca89551"
        family         = "ArxCrypter"
        confidence     = "Medium"
        tlp            = "TLP:WHITE"
        mitre_attack   = "T1027.007"

    strings:
        // XXH32 finalization/avalanche block: IMUL by PRIME32_3 (0x3d4d51cb),
        // SUB/ROR, IMUL by PRIME32_4 (0x27d4eb2f), ROR, XOR, loop-compare —
        // an exact 32-byte instruction sequence unique to this compiled
        // hash routine, no wildcards needed (no external references).
        $xxh32_avalanche = {
            41 69 14 0B CB 51 4D 3D         // IMUL EDX, [R11+RCX], 0x3d4d51cb   (XXH_PRIME32_3)
            2B C2                           // SUB EAX, EDX
            C1 C8 0F                        // ROR EAX, 0xf
            69 C8 2F EB D4 27               // IMUL ECX, EAX, 0x27d4eb2f          (XXH_PRIME32_4)
            8B C1                           // MOV EAX, ECX
            C1 C8 19                        // ROR EAX, 0x19
            33 C1                           // XOR EAX, ECX
            41 83 F8 04                     // CMP R8D, 0x4
            7D D5                           // JGE (loop back)
        }

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        $xxh32_avalanche
}

// ===========================================================================
// Custom Stream-Cipher Key-Schedule (SHA-256-IV-ARX)
// ===========================================================================
rule ArxCrypter_CustomStreamCipherKeySchedule
{
    meta:
        description    = "Detects the non-standard stream cipher's key-schedule routine: SHA-256 initial-hash-value constants loaded as scattered MOV-immediate operands (not a real SHA-256 compression, only the IV words borrowed as ARX mixing seeds) combined with the scheme's two 32-byte constant substitution tables"
        author         = "somesota"
        date           = "2026-09-05"
        version        = "1.0"
        sample_sha256  = "5541bf99ebfee0f4c9ab33624b49e125348bf02280b9efbb8824919f53c8630c"
        sample_md5     = "803fa2ddc9de8e377e526a06aca89551"
        family         = "ArxCrypter"
        confidence     = "High"
        tlp            = "TLP:WHITE"
        mitre_attack   = "T1027, T1140"

    strings:
        // Six of the eight SHA-256 IV words (0xbb67ae85, 0x5be0cd19,
        // 0x6a09e667, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x1f83d9ab) loaded
        // as scattered MOV reg,imm32 operands interleaved with unrelated
        // instructions — the signature of "borrowed IV constants as an ARX
        // seed", not a genuine SHA-256 implementation. No wildcards needed;
        // fully local, no external references.
        $kdf_iv_scatter = {
            B9 85 AE 67 BB                  // MOV ECX, 0xbb67ae85     (SHA-256 IV[1])
            0F 10 4B 10                     // MOVUPS XMM1, [RBX+0x10]
            45 33 F6                        // XOR R14D, R14D
            41 BD 19 CD E0 5B               // MOV R13D, 0x5be0cd19    (SHA-256 IV[7])
            89 8D 00 02 00 00               // MOV [RBP+0x200], ECX
            41 BA 67 E6 09 6A               // MOV R10D, 0x6a09e667    (SHA-256 IV[0])
            44 8B D9                        // MOV R11D, ECX
            BA 72 F3 6E 3C                  // MOV EDX, 0x3c6ef372     (SHA-256 IV[2])
            BB 3A F5 4F A5                  // MOV EBX, 0xa54ff53a     (SHA-256 IV[3])
            41 B8 7F 52 0E 51               // MOV R8D, 0x510e527f     (SHA-256 IV[4])
            41 B9 AB D9 83 1F               // MOV R9D, 0x1f83d9ab     (SHA-256 IV[5])
        }

        // The scheme's two 32-byte constant substitution tables, contiguous
        // in .rdata, exact bytes.
        $cipher_tables = {
            80 F3 8E 9E 24 0F A2 D6 D0 DE EE 99 D1 48 61 45
            E4 BC 92 AE 52 C5 55 AA F7 FF A4 C7 EB DB 30 40
            B0 AA 96 CB C1 66 EF 82 45 9F CE C4 FE E6 9B 5F
            A0 D3 D1 49 E8 68 80 39 DB A7 4F F8 34 CD AB D7
        }

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        all of them
}

// ===========================================================================
//  Fabricated Builder Version-Resource Metadata
// ===========================================================================
rule ArxCrypter_DecoyVersionInfoMetadata
{
    meta:
        description    = "Detects the fabricated (Faker/Bogus-style) VS_VERSION_INFO metadata embedded by the crypter builder — a randomly-generated company/product identity that does not correspond to any real software"
        author         = "somesota"
        date           = "2026-09-05"
        version        = "1.0"
        sample_sha256  = "5541bf99ebfee0f4c9ab33624b49e125348bf02280b9efbb8824919f53c8630c"
        sample_md5     = "803fa2ddc9de8e377e526a06aca89551"
        family         = "ArxCrypter"
        confidence     = "Medium"
        tlp            = "TLP:WHITE"
        mitre_attack   = "T1036.005"

    strings:
        // VS_VERSION_INFO strings, UTF-16LE, from .rsrc — confirmed
        // fabricated/decoy metadata (Faker/Bogus-style surname pair,
        // generic "indexer" product name mismatching the real MWDB
        // filename and the sample's actual packer behavior).
        $company    = "Lubowitz - Strosin" wide            // CompanyName / LegalCopyright / LegalTrademarks field
        $origfile   = "indexer_client.exe" wide             // OriginalFilename field
        $filedesc   = "indexer Expert Controller" wide      // FileDescription field
        $comments   = "Built with Multi-threading framework" wide  // Comments field (generic builder filler text)

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        2 of them
}

