// ----------------------------------------------------------------------------
// Family Rule (NetZipPacker template, Win32 packer)
// ----------------------------------------------------------------------------
rule MAL_NetZipPacker_TemplateFamily
{
    meta:
        description    = "Detects the NetZipPacker/StateofDecay .NET template shared by FishCrypter builds, independent of build token and password: class and method names plus a decoy Advent-of-Code literal"
        author         = "somesota"
        date           = "2026-08-30"
        version        = "1.0"
        sample_sha256  = "20082d2052d2d406bb4193990d933dc9b78bf2ccc3f2618144ada1fb7e0a995e"
        sample_md5     = "8adc5c25b4fe2bfe0fd5d623ade01b76"
        family         = "NetZipPacker"
        confidence     = "Medium"
        tlp            = "TLP:WHITE"
        mitre_attack   = "T1027, T1027.007, T1140"

    strings:
        // --- Namespace and decoy-class vocabulary. The same names appear in
        //     builds with a different token and password.
        $ns_stateofdecay   = "StateofDecay" ascii fullword           // root namespace of loader and decoy classes
        $cls_covertop      = "CovertOperationModule" ascii fullword  // real orchestration class
        $method_isrunning  = "IsRunningFromCopy" ascii fullword      // anti-recursion / sandbox guard
        $cls_fractiondepth = "FractionDepth" ascii fullword          // static call counter that gates the hidden trigger
        $cls_machinepart   = "MachinePart" ascii fullword            // decoy class reused for reflective invocation
        $cls_beaconresolv  = "BeaconResolver" ascii fullword         // decoy class reused as a type-cache field

        // --- Decoy literal copied from Advent of Code 2023 day 19,
        //     identical across builds.
        $aoc_literal = "px{a<2006:qkq,m>2090:A,rfg}" wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 20MB and
        3 of them
}

// ----------------------------------------------------------------------------
// Family Rule (NetZipPacker template, Win64 packer)
// ----------------------------------------------------------------------------
rule MAL_NetZipPacker_Win64Family
{
    meta:
        description    = "Detects the NetZipPacker .NET template of the win64 builds, independent of build token and password: the StateofDecay decoy namespace plus the LfdReader.dll and ADXPlot crypto-helper names"
        author         = "somesota"
        date           = "2026-08-30"
        version        = "1.0"
        sample_sha256  = "64acf136e30d15f4ff8fe0eee978d30c249d28ca7578cf60d138aa79cb4e7632"
        sample_md5     = "6d3be6d1627576a18a464bf890a8f96b"
        family         = "NetZipPacker"
        confidence     = "Medium"
        tlp            = "TLP:WHITE"
        mitre_attack   = "T1027, T1027.007, T1140"

    strings:
        // --- Namespace and decoy-class vocabulary. Names like BigFloat can
        //     occur in other .NET code, so the rule needs 5 of the 8.
        $ns_stateofdecay  = "StateofDecay" ascii fullword          // root namespace of loader and decoy classes
        $cls_aapoly       = "AAPoly" ascii fullword                // decoy class hosting trigger site A
        $cls_beaconresolv = "BeaconResolver" ascii fullword        // decoy class hosting trigger site B
        $cls_bigfloat     = "BigFloat" ascii wide fullword         // decoy class hosting trigger site C
        $cls_machinepart  = "MachinePart" ascii fullword           // decoy class reused for the Reflection.Emit invoker

        // --- Crypto-helper vocabulary.
        $res_lfdreader = "LfdReader.dll" ascii wide fullword       // bundled helper assembly, manifest resource name
        $cls_adxplot   = "ADXPlot" ascii wide fullword             // helper class that implements the decryption
        $res_consttable = "IBar2Double&&" ascii fullword           // DES+Deflate-obfuscated constant-table resource

    condition:
        uint16(0) == 0x5A4D and
        filesize < 20MB and
        5 of them
}

// ----------------------------------------------------------------------------
// Anti-Analysis Drop-and-Launch Chain
// ----------------------------------------------------------------------------
rule MAL_NetZipPacker_DropAndLaunchSandboxCheck
{
    meta:
        description    = "Detects the CovertOperationModule drop-and-launch method chain (extract the embedded ZIP, then Process.Start) together with its IsRunningFromCopy execution-path check"
        author         = "somesota"
        date           = "2026-08-30"
        version        = "1.0"
        sample_sha256  = "20082d2052d2d406bb4193990d933dc9b78bf2ccc3f2618144ada1fb7e0a995e"
        sample_md5     = "8adc5c25b4fe2bfe0fd5d623ade01b76"
        family         = "NetZipPacker"
        confidence     = "Medium"
        tlp            = "TLP:WHITE"
        mitre_attack   = "T1497, T1105, T1059.003, T1027"

    strings:
        // --- Method names are plain English, not mangled. One name alone is
        //     generic, so the rule needs 5 of the 9.
        $m_isrunning   = "IsRunningFromCopy" ascii fullword
        $m_locate      = "LocateEmbeddedComponent" ascii fullword
        $m_establish   = "EstablishTemporaryPerimeter" ascii fullword
        $m_transfer    = "TransferAssetToPerimeter" ascii fullword
        $m_unpack      = "UnpackContainerContents" ascii fullword
        $m_activate    = "ActivatePerimeterComponents" ascii fullword
        $m_execute     = "InitiateComponentExecution" ascii fullword
        $m_removeasset = "RemoveTemporaryAsset" ascii fullword

        // --- Transient file name written before the ZIP is extracted.
        $stage_filename = "payload_package.dat" wide fullword

    condition:
        uint16(0) == 0x5A4D and
        filesize < 20MB and
        5 of them
}

// ----------------------------------------------------------------------------
// Marker File Drop
// ----------------------------------------------------------------------------
rule MAL_NetZipPacker_MarkerFileDrop
{
    meta:
        description    = "Detects the stub_exe.dat marker: when the hidden-payload trigger fires, the packer writes its own file path to stub_exe.dat under %LOCALAPPDATA%\\Microsoft\\Windows\\Caches\\ and %TEMP%\\BrightInfo\\cache\\"
        author         = "somesota"
        date           = "2026-08-30"
        version        = "1.0"
        sample_sha256  = "20082d2052d2d406bb4193990d933dc9b78bf2ccc3f2618144ada1fb7e0a995e, 64acf136e30d15f4ff8fe0eee978d30c249d28ca7578cf60d138aa79cb4e7632"
        family         = "NetZipPacker"
        confidence     = "High"
        tlp            = "TLP:WHITE"
        mitre_attack   = "T1074.001, T1027"

    strings:
        // --- "Caches" is a normal Windows folder name. "BrightInfo" is an
        //     invented folder and "stub_exe.dat" a fixed file name.
        $marker_file   = "stub_exe.dat" wide fullword
        $marker_folder = "BrightInfo" wide fullword
        $caches_folder = "Caches" wide fullword

    condition:
        uint16(0) == 0x5A4D and
        filesize < 20MB and
        2 of them
}
