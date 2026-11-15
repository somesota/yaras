// TLP (strictest rule): WHITE
import "hash"

// ---------------------------------------------------------------------
// Campaign Rule
// ---------------------------------------------------------------------
rule CryptOne_GCleanerCampaign
{
    meta:
        description    = "Detects this build/campaign's CryptOne packer via its exact custom resource identifiers and hardcoded constant-setup and XOR-key derivation code"
        author         = "somesota"
        date           = "2026-08-30"
        version        = "1.0"
        sample_sha256  = "84283e597223c0857b113cdb5b74f63eff49f9fa8addab0d759c491cd08b9aa5"
        sample_md5     = "326967443551cd0c43e384fc79f38414"
        family         = "CryptOne"
        confidence     = "High"
        tlp            = "TLP:WHITE"
        mitre_attack   = "T1027.002, T1140"

    strings:
        // --- Custom RCDATA resource identifiers (type/name pair) used to locate
        //     the encrypted embedded PE payload. Non-dictionary, semi-random
        //     looking names — Phase 2 (reverse.md Sec 1/3), confirmed present
        //     as literal ASCII at 0x0045d04c/0x0045d058 this phase.
        $res_type = "tjertier6" fullword ascii
        $res_name = "rtirtwerqq" fullword ascii

        // --- Per-build constant setup: XOR-key component 0x8A0E, then the
        //     data-block and junk-block size immediates (wildcarded),
        //     written to stack locals at 0x0045ce3b.
        $const_setup = { C7 45 CC 0E 8A 00 00     // mov [ebp-0x34], 0x8A0E
                         C7 45 C8 ?? ?? 00 00     // mov [ebp-0x38], data_block_size (wildcarded)
                         C7 45 C4 ?? 00 00 00 }   // mov [ebp-0x3C], junk_block_size (wildcarded)

        // --- XOR-key derivation immediates: 0x8A58A and 0x51612, which
        //     combine with 0x8A0E into this build's static key.
        //     reverse.md Sec 3 @0x0045cf98-cfa5.
        $key_deriv = { 8B 7D CC                  // mov edi,[ebp-0x34]        (0x8A0E)
                       81 C7 8A A5 08 00         // add edi, 0x0008A58A
                       03 FB                     // add edi, ebx
                       03 F8                     // add edi, eax
                       81 EF 12 16 05 00 }       // sub edi, 0x00051612

    condition:
        uint16(0) == 0x5A4D and
        filesize > 100KB and filesize < 3MB and
        2 of ($res_type, $res_name) and
        1 of ($const_setup, $key_deriv)
}

// ---------------------------------------------------------------------
// Family Rule (CryptOne Delphi packer, campaign/key-agnostic)
// ---------------------------------------------------------------------
rule CryptOne_DelphiFamily
{
    meta:
        description    = "Detects the CryptOne Delphi/VCL packer family via its generic decrypt-stub code idiom and dynamic-import-resolution pattern, independent of this build's specific resource names or XOR key"
        author         = "somesota"
        date           = "2026-08-30"
        version        = "1.0"
        sample_sha256  = "84283e597223c0857b113cdb5b74f63eff49f9fa8addab0d759c491cd08b9aa5"
        sample_md5     = "326967443551cd0c43e384fc79f38414"
        family         = "CryptOne"
        confidence     = "Medium"
        tlp            = "TLP:WHITE"
        mitre_attack   = "T1027, T1027.002, T1140"

    strings:
        // --- Opaque "self-store no-op" idiom immediately preceding the real
        //     ADD in the per-DWORD decrypt loop: MOV EDX,[ESI]; MOV [ESI],EDX;
        //     ADD [ESI],EBX. Pure register ops, no build-specific immediates,
        //     so it survives a resource-name/key change. reverse.md Sec 1/4.
        $selfstore_noop = { 8B 16 89 16 01 1E }

        // --- 4x repeated junk "PUSH 0; CALL <StrokePath thunk>" padding
        //     inside the decrypt loop (call-target offsets wildcarded since
        //     they shift with code layout across builds). reverse.md Sec 3/4.
        $strokepath_4x = { 6A 00 E8 ?? ?? ?? FF
                            6A 00 E8 ?? ?? ?? FF
                            6A 00 E8 ?? ?? ?? FF
                            6A 00 E8 ?? ?? ?? FF }

        // --- Dynamic import-resolution strings: "VirtualAlloc" / "kernel32"
        //     passed as bare, lowercase-DLL-name strings to
        //     GetModuleHandleA/GetProcAddress rather than a static import —
        //     evasion pattern documented in reverse.md Sec 1/3/4.
        $s_valloc  = "VirtualAlloc" fullword ascii
        $s_kernel32 = "kernel32" fullword ascii

        // --- Standard Borland/Delphi OMF-style section names (weak/generic
        //     on their own; static.md Sections table).
        $sec_code = "CODE" fullword ascii
        $sec_data = "DATA" fullword ascii
        $sec_bss  = "BSS" fullword ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize > 50KB and filesize < 5MB and
        2 of ($selfstore_noop, $strokepath_4x) and
        1 of ($s_valloc, $s_kernel32) and
        1 of ($sec_code, $sec_data, $sec_bss)
}

// ---------------------------------------------------------------------
//  Packer (decrypt-then-non-CALL-tail-jump)
// ---------------------------------------------------------------------
rule CryptOne_DelphiResourceDecryptTailJumpLoader
{
    meta:
        description    = "Detects the CryptOne packer's technique of decrypting an embedded PE resource in-memory and transferring control to it via a PUSH-target/RET tail jump (no CALL instruction), leaving 6 stack values as ad hoc arguments"
        author         = "somesota"
        date           = "2026-08-30"
        version        = "1.0"
        sample_sha256  = "84283e597223c0857b113cdb5b74f63eff49f9fa8addab0d759c491cd08b9aa5"
        sample_md5     = "326967443551cd0c43e384fc79f38414"
        family         = "CryptOne"
        confidence     = "Medium"
        tlp            = "TLP:WHITE"
        mitre_attack   = "T1620, T1140, T1027.002"

    strings:
        // --- Six PUSH instructions preparing ad hoc "arguments" for the
        //     decrypted payload's entry point, followed by
        //     XOR EDX,EDX; ADD EDX,[EBP-0x14]; PUSH EDX; RET  (the actual
        //     no-CALL tail jump into the decrypted buffer).
        //     reverse.md Sec 1/3 @0x0045cff8-0045d015.
        $tailjump = { FF 75 FC              // push [ebp-0x4]
                      FF 75 F8              // push [ebp-0x8]
                      FF 75 F8              // push [ebp-0x8]  (again)
                      FF 75 F0              // push [ebp-0x10]
                      FF 75 F4              // push [ebp-0xc]
                      FF 35 68 06 46 00     // push dword ptr [0x00460668]  (module handle global)
                      6A 00                 // push 0
                      31 D2                 // xor edx,edx
                      03 55 EC              // add edx,[ebp-0x14]
                      52                    // push edx  (= computed target, top of stack)
                      C3 }                  // ret  -> tail-jump into decrypted buffer

        // --- Custom resource identifiers scoping this behavior to the
        //     CryptOne resource-based loader (same as Rule 2's evidence,
        //     reused here to anchor the *capability*, not the exact build).
        $res_type = "tjertier6" fullword ascii
        $res_name = "rtirtwerqq" fullword ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize > 100KB and filesize < 3MB and
        $tailjump and
        1 of ($res_type, $res_name)
}

// ---------------------------------------------------------------------
// Anti-Sandbox CPU-Burn Timing Delay
// ---------------------------------------------------------------------
rule CryptOne_DelphiAntiSandboxStrokePathDelay
{
    meta:
        description    = "Detects a GDI32 StrokePath(0)-based busy-loop of ~32.3 million iterations used as a real-Win32-API CPU-time-burning anti-sandbox/anti-emulation delay, bracketing the CryptOne decrypt stage"
        author         = "somesota"
        date           = "2026-08-30"
        version        = "1.0"
        sample_sha256  = "84283e597223c0857b113cdb5b74f63eff49f9fa8addab0d759c491cd08b9aa5"
        sample_md5     = "326967443551cd0c43e384fc79f38414"
        family         = "CryptOne"
        confidence     = "Medium"
        tlp            = "TLP:WHITE"
        mitre_attack   = "T1497.003, T1497"

    strings:
        // --- mov ebx, 0x1EF6154 (~32,299,860); push 0  — setup of the
        //     StrokePath(NULL) busy-loop counter immediately before the
        //     junk GDI32 call. reverse.md Sec 3/4.
        $busyloop_setup = { BB 54 61 EF 01   // mov ebx, 0x01EF6154
                             6A 00 }         // push 0

    condition:
        uint16(0) == 0x5A4D and
        filesize > 50KB and filesize < 5MB and
        $busyloop_setup
}