import Foundation

/// Static kernel patches that let an already-running process modify its own
/// executable pages without being killed for a code-signing violation. This is
/// what a runtime function hook (ElleKit's `MSHookFunction`) needs: the AMFI
/// PPL trust-cache stub alone lets an ad-hoc binary *launch*, but the first
/// time a tweak rewrites an instruction in a signed page the process dies with
/// `CODESIGNING / Invalid Page` unless these three decisions are relaxed.
///
/// The patterns are ported from the palera1n/PongoOS KPF (MIT), the `t8020`
/// bring-up branch for the PPL producer, with Liter8's own guards layered on:
/// every resolver is gated on a kernel profile that opts in, requires a single
/// unambiguous match, and records the exact original word so the guarded
/// applier refuses a kernel whose bytes differ. A kernel that does not match
/// produces no candidate rather than a wrong patch.
///
/// These are deliberately NOT part of `boot-public`. They widen the attack
/// surface of every process, so they belong in the opt-in `boot-jit` plan and
/// are selected per boot, not baked into the reviewed default.
public enum KernelCodeSigningResolver {
    /// Opt-in variant key a kernel profile sets to request these patches.
    static let variantKey = "kernel-codesign-invalid"

    /// Records for the composed JIT plan. Empty unless the detected profile
    /// opts in, so a kernel with no entry here is never touched.
    static func requiredRecords(in image: BinaryImage) throws -> [PatchRecord] {
        guard KernelResolverProfileRegistry.detect(in: image)?
            .variants(for: variantKey) != nil else {
            return []
        }
        return try KernelPPLAllowInvalidResolver().resolve(in: image)
            + KernelVMFaultCSBypassResolver().resolve(in: image)
            + KernelVMMapProtectResolver().resolve(in: image)
    }

    /// Shared opt-in gate. Each resolver still runs standalone for diagnosis
    /// (`liter8 resolve kernel ppl-allow-invalid <kc>`), where the gate is
    /// skipped so a researcher can probe an unregistered kernel on purpose.
    fileprivate static func requireOptIn(
        _ resolver: String, in image: BinaryImage
    ) throws {
        let profile = KernelResolverProfileRegistry.detect(in: image)
        guard profile?.variants(for: variantKey) != nil else {
            throw PatchfinderError.unsupportedFirmwareProfile(
                resolver: resolver,
                profile: profile?.id ?? "unidentified",
                variant: "codesign-invalid not opted in"
            )
        }
    }
}

// MARK: - PPL: every pmap is created allow-invalid

/// On T8020, PPL (not just AMFI) decides whether a page whose hash no longer
/// matches its signature may stay executable. The decision is a per-pmap byte
/// at `pmap + 0xc2`, initialised to 0 in `pmap_create_options_internal`. Set it
/// to 1 for every pmap at creation.
///
/// The producer stores `w8 = 1` as a halfword to `pmap + 0xc1`, which writes
/// `+0xc1 = 1` and `+0xc2 = 0`, and then reuses the same `w8` as the reference
/// count at `pmap + 0xb0`. Raising the immediate to `0x101` sets `+0xc2 = 1`
/// but would also make the reference count `0x101`, so the count store is
/// narrowed to a byte. Both edits are required and are applied together.
public struct KernelPPLAllowInvalidResolver: Sendable {
    public static let name = "kernel-ppl-allow-invalid"
    public init() {}

    private enum Opcode {
        static let movW8One: UInt32 = 0x5280_0028        // mov  w8, #1
        static let movW8_0x101: UInt32 = 0x5280_2028     // mov  w8, #0x101
        static let strW8X19_0xb0: UInt32 = 0xb900_b268   // str  w8, [x19, #0xb0]
        static let strbW8X19_0xb0: UInt32 = 0x3902_c268  // strb w8, [x19, #0xb0]
    }

    // The 13-word final-state producer, exact for T8020. Index 10 has two
    // encodings (STP of two words vs a 64-bit STUR) depending on the Darwin 25
    // point release; both clear pmap+0xb4. Nothing here is masked: this is an
    // exact byte signature, and a build that differs must be re-confirmed.
    private static let producer: [UInt32] = [
        0x6f00_e400, // movi.2d v0, #0
        0x3c85_8260, // stur q0, [x19, #0x58]
        0xf900_3e7f, // str xzr, [x19, #0x78]
        0xb900_827f, // str wzr, [x19, #0x80]
        0x780c_527f, // sturh wzr, [x19, #0xc5]
        0x3c88_8260, // stur q0, [x19, #0x88]
        0x3d80_2a60, // str q0, [x19, #0xa0]
        0x3902_627f, // strb wzr, [x19, #0x98]
        Opcode.movW8One,
        0x780c_1268, // sturh w8, [x19, #0xc1]
        0x2916_fe7f, // stp wzr, wzr, [x19, #0xb4]   (variant A)
        0xd503_3bbf, // dmb ish
        Opcode.strW8X19_0xb0,
    ]
    private static let producerVariantBWord10: UInt32 = 0xf80b_427f // stur xzr, [x19, #0xb4]

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        try KernelCodeSigningResolver.requireOptIn(Self.name, in: image)
        let layout = try MachOLayout(image: image)

        var hits: [UInt64] = []
        let count = Self.producer.count
        let byteCount = UInt64(count * 4)
        for range in layout.executableFileRanges
            where range.upperBound - range.lowerBound >= byteCount {
            var offset = (range.lowerBound + 3) & ~UInt64(3)
            while offset + byteCount <= range.upperBound {
                if try Self.matchesProducer(in: image, at: offset) { hits.append(offset) }
                offset += 4
            }
        }
        guard hits.count == 1, let entry = hits.first else {
            if hits.isEmpty { throw PatchfinderError.noCandidate("PPL pmap allow-invalid producer") }
            throw PatchfinderError.ambiguousCandidate("PPL pmap allow-invalid producer", offsets: hits)
        }

        let immOffset = entry + 8 * 4
        let refcountOffset = entry + 12 * 4
        let evidence = [
            "exact 13-word T8020 pmap_create_options_internal final-state producer",
            "unique match in executable kernel segments",
            "allow-invalid byte pmap+0xc2 set via the existing +0xc1 halfword store",
            "reference-count store narrowed to a byte so pmap+0xb0 stays 1",
        ]
        return [
            PatchRecord(
                id: "kernel.codesign.ppl-allow-invalid.immediate",
                component: "kernelcache",
                offset: immOffset,
                original: Opcode.movW8One,
                replacement: Opcode.movW8_0x101,
                summary: "Initialise every pmap with the PPL allow-invalid byte set",
                evidence: evidence
            ),
            PatchRecord(
                id: "kernel.codesign.ppl-allow-invalid.refcount",
                component: "kernelcache",
                offset: refcountOffset,
                original: Opcode.strW8X19_0xb0,
                replacement: Opcode.strbW8X19_0xb0,
                summary: "Keep the pmap reference count a byte after widening the init immediate",
                evidence: evidence
            ),
        ]
    }

    private static func matchesProducer(in image: BinaryImage, at offset: UInt64) throws -> Bool {
        for index in producer.indices {
            let word = try image.readUInt32(at: offset + UInt64(index * 4))
            if index == 10 {
                if word != producer[10] && word != producerVariantBWord10 { return false }
            } else if word != producer[index] {
                return false
            }
        }
        return true
    }
}

// MARK: - XNU: do not flag a modified page in vm_fault_enter

/// `vm_fault_enter` decides whether a page fault on an executable page whose
/// code signature no longer validates is a violation. The tested bit (bit 3 of
/// the page flags) gates the branch that records the violation. Neutralising
/// that test lets a page that a tweak has rewritten fault back in without the
/// process being killed.
///
/// Ported from KPF's `vm_fault_enter` family. The anchor is the preceding
/// `tbz w{16-31}, #2` / `tbz w{16-31}, #0x13|0x14` pair that uniquely locates
/// the function; the single `tb(n)z w*, #3` immediately after it is the test
/// that is turned into a fall-through.
public struct KernelVMFaultCSBypassResolver: Sendable {
    public static let name = "kernel-vm-fault-cs-bypass"
    public init() {}

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        try KernelCodeSigningResolver.requireOptIn(Self.name, in: image)
        let layout = try MachOLayout(image: image)

        // Anchor: TBNZ Wn,#0x13 ; (optional CBZ) ; TBNZ Wn,#0x12  — the two
        // bit tests KPF uses to recognise the vm_fault_enter cs path on modern
        // XNU. We then locate the nearby TBZ Wn,#3 (the cs-violation test).
        var anchors: [UInt64] = []
        for range in layout.executableFileRanges {
            var offset = (range.lowerBound + 3) & ~UInt64(3)
            while offset + 12 <= range.upperBound {
                let a = try image.readUInt32(at: offset)
                let b = try image.readUInt32(at: offset + 4)
                // TBNZ Wn,#0x13 then TBNZ Wn,#0x12 within one or two slots.
                if Self.isTBNZ(a, bit: 0x13) {
                    if Self.isTBNZ(b, bit: 0x12) {
                        anchors.append(offset)
                    } else if offset + 12 <= range.upperBound,
                              Self.isTBNZ(try image.readUInt32(at: offset + 8), bit: 0x12) {
                        anchors.append(offset)
                    }
                }
                offset += 4
            }
        }
        guard anchors.count == 1, let anchor = anchors.first else {
            if anchors.isEmpty { throw PatchfinderError.noCandidate("vm_fault_enter cs path") }
            throw PatchfinderError.ambiguousCandidate("vm_fault_enter cs path", offsets: anchors)
        }

        // The cs-violation test is a TBZ Wn,#3 a short distance after the
        // anchor. Scan forward a bounded window for the first one.
        var testOffset: UInt64?
        var cursor = anchor
        let end = min(anchor + 0x40, UInt64(image.count) - 4)
        while cursor <= end {
            if Self.isTBZ(try image.readUInt32(at: cursor), bit: 3) { testOffset = cursor; break }
            cursor += 4
        }
        guard let testOffset else {
            throw PatchfinderError.noCandidate("vm_fault_enter cs-violation TBZ #3")
        }
        let original = try image.readUInt32(at: testOffset)
        return [PatchRecord(
            id: "kernel.codesign.vm-fault-cs-violation",
            component: "kernelcache",
            offset: testOffset,
            original: original,
            replacement: ARM64.nop,
            summary: "Do not flag a rewritten executable page as a code-signing violation",
            evidence: [
                "unique vm_fault_enter cs path anchored by the TBNZ #0x13/#0x12 pair",
                "the single TBZ Wn,#3 within 0x40 bytes is the cs-violation test",
                "only that test becomes a fall-through; the rest of the fault path is intact",
            ]
        )]
    }

    private static func isTBNZ(_ word: UInt32, bit: UInt32) -> Bool {
        // TBNZ (b5=0 for #<32): 0x37000000 base, bit number in [23:19].
        word & 0xFFF8_0000 == (0x3700_0000 | (bit << 19))
    }
    private static func isTBZ(_ word: UInt32, bit: UInt32) -> Bool {
        word & 0xFFF8_0000 == (0x3600_0000 | (bit << 19))
    }
}

// MARK: - XNU: allow RW->RX reprotect and ignore map_disallow_new_exec

/// `vm_map_protect` refuses to add `VM_PROT_EXECUTE` to a writable mapping and
/// honours `map_disallow_new_exec`. A runtime hook that makes a code page
/// writable, edits it and restores execute permission needs both relaxed.
///
/// Ported from KPF's `vm_map_protect` family. Several encodings exist across
/// XNU versions; the recent Darwin-25 forms are matched here. The transform is
/// KPF's: force the preflight reject branch to fall through, then neutralise
/// the `tb(n)z w*, #9` that applies the execute downgrade.
public struct KernelVMMapProtectResolver: Sendable {
    public static let name = "kernel-vm-map-protect"
    public init() {}

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        try KernelCodeSigningResolver.requireOptIn(Self.name, in: image)
        let layout = try MachOLayout(image: image)

        // Match the XNU 25.5 arm64e preflight gate (KPF matches_255):
        //   and  wF, wEntryFlags, #0x400000
        //   mov  wM, #6
        //   bic  wM, wM, wProt
        //   cmp  wM, #0
        //   ccmp wF, #0, #0, eq
        //   b.ne skip_downgrade
        // Masks keep the opcode and fixed operands, relaxing the register and
        // immediate fields KPF relaxes in masks_255.
        let gate = MaskedInstructionPattern(name: "vm_map_protect 25.5 gate", values: [
            0x120a_0000, 0x5280_00c0, 0x0a20_0000, 0x7100_001f, 0x7a40_0800, 0x5400_0001,
        ], masks: [
            0xffff_fc00, 0xffff_ffe0, 0xffe0_fc00, 0xffff_fc1f, 0xffff_fe1f, 0xff00_001f,
        ])

        var hits: [UInt64] = []
        let byteCount = UInt64(gate.values.count * 4)
        for range in layout.executableFileRanges
            where range.upperBound - range.lowerBound >= byteCount {
            var offset = (range.lowerBound + 3) & ~UInt64(3)
            while offset + byteCount <= range.upperBound {
                if try gate.matches(in: image, at: offset) { hits.append(offset) }
                offset += 4
            }
        }
        guard hits.count == 1, let entry = hits.first else {
            if hits.isEmpty { throw PatchfinderError.noCandidate("vm_map_protect 25.5 gate") }
            throw PatchfinderError.ambiguousCandidate("vm_map_protect 25.5 gate", offsets: hits)
        }

        // opcode_stream[5] is the b.ne to skip_downgrade; make it unconditional.
        let branchOffset = entry + 5 * 4
        let branch = try image.readUInt32(at: branchOffset)
        guard let skipTarget = ARM64.conditionalTarget(instruction: branch, at: branchOffset) else {
            throw PatchfinderError.noCandidate("vm_map_protect skip branch")
        }
        guard let branchVA = layout.virtualAddress(forFileOffset: branchOffset),
              let targetVA = layout.virtualAddress(forFileOffset: skipTarget),
              let uncond = ARM64.encodeDirectBranch(link: false, instructionOffset: branchVA, target: targetVA) else {
            throw PatchfinderError.noCandidate("vm_map_protect skip branch encoding")
        }

        // At the skip target, the map_disallow_new_exec decision is a
        // TBNZ Wn,#7 (KPF: 0x37380000 / mask 0xfff80010) within 3 slots.
        var disallowOffset: UInt64?
        var cursor = skipTarget
        let end = min(skipTarget + 0x0c, UInt64(image.count) - 4)
        while cursor <= end {
            if try image.readUInt32(at: cursor) & 0xfff8_0010 == 0x3738_0000 {
                disallowOffset = cursor; break
            }
            cursor += 4
        }
        guard let disallowOffset else {
            throw PatchfinderError.noCandidate("map_disallow_new_exec decision")
        }
        let disallow = try image.readUInt32(at: disallowOffset)
        let evidence = [
            "XNU 25.5 arm64e vm_map_protect execute-downgrade preflight gate",
            "unique match in executable kernel segments",
            "reject branch forced to its existing skip target, not a fabricated one",
            "map_disallow_new_exec TBNZ #7 within 0x0c bytes neutralised",
        ]
        return [
            PatchRecord(
                id: "kernel.codesign.vm-map-protect.allow-rx",
                component: "kernelcache",
                offset: branchOffset,
                original: branch,
                replacement: uncond,
                summary: "Allow vm_map_protect to keep execute on a writable mapping",
                evidence: evidence
            ),
            PatchRecord(
                id: "kernel.codesign.vm-map-protect.disallow-new-exec",
                component: "kernelcache",
                offset: disallowOffset,
                original: disallow,
                replacement: ARM64.nop,
                summary: "Ignore map_disallow_new_exec in vm_map_protect",
                evidence: evidence
            ),
        ]
    }
}
