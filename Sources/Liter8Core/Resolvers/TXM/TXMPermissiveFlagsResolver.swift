import Foundation

/// Resolves the block where TXM writes its code-signing policy flags once at
/// startup, and turns those flags on.
///
/// Release TXM hardcodes the flags. The block follows the only call to the
/// function that logs "resolving to internal device variant due to fusing
/// state", which returns 1 only on internal-fused hardware; that result is the
/// one flag stored from a register. A development TXM fills the same fields
/// from boot-args, which is where the names come from. Relative to the
/// internal-CA byte `X`:
///
/// - `X-3` halfword: skip trust evaluation, allow any signature
/// - `X-1` byte: unrestricted local signing
/// - `X` byte: allow internal CAs (the call's result)
/// - `X+1` halfword: enforce CoreTrust, relax restricted-mode perms
/// - `X+3` byte: relax profile trust (bit 1 of another config byte)
/// - `Y` halfword: CS enforcement disable, unrestrict task_for_pid
/// - `Y+6` byte: emulate device UDID
///
/// The call becomes `MOV X0,#-1` and the four stores of the permissive flags
/// store W0 instead. `X+1` and `Y+6` keep their zero, so CoreTrust stays
/// enforced. The flags become 0xFF/0xFFFF; the `Y` readers (validator,
/// selectors 41 and 42) test bit 0. The enclosing function's only caller does
/// not read X0 after it returns (checked on 24B5099f).
///
/// `Y+1` is the byte the selector-42 handler tests just before the branch
/// `TXMDebugMappingResolver` forces for error 37; requiring that match ties `Y`
/// to the task_for_pid flag rather than to any halfword in the right place.
/// `boot-permissive` relies on that tie to leave the error-37 branch stock.
public struct TXMPermissiveFlagsResolver: Sendable {
    public static let name = "txm-permissive-flags"

    /// MOVN X0,#0, i.e. MOV X0,#-1: sf=1, opc=00, hw=0, imm16=0, Rd=0.
    static let movX0MinusOne: UInt32 = 0x9280_0000

    public init() {}

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        let layout = try MachOLayout(image: image)
        let message = try uniqueCString(
            "resolving to internal device variant due to fusing state", in: image
        )
        let refs = try layout.adrpAddReferences(toFileOffset: message)
        guard let reference = refs.only else {
            if refs.isEmpty { throw PatchfinderError.missingAnchor("\(Self.name) internal-variant reference") }
            throw PatchfinderError.ambiguousAnchor("\(Self.name) internal-variant reference", count: refs.count)
        }
        guard let check = ARM64.functionStart(beforeOrAt: reference.adrpOffset, in: image, layout: layout) else {
            throw PatchfinderError.noCandidate("\(Self.name) internal-variant function")
        }

        let calls = try callers(of: check, image: image, layout: layout)
        guard let call = calls.only else {
            if calls.isEmpty { throw PatchfinderError.noCandidate("\(Self.name) internal-variant caller") }
            throw PatchfinderError.ambiguousCandidate("\(Self.name) internal-variant caller", offsets: calls)
        }
        let block = try flagBlock(after: call, image: image)

        let taskForPid = try selector42PolicyByte(in: image)
        guard taskForPid == block.y + 1 else {
            throw PatchfinderError.invalidPatch(
                id: Self.name,
                reason: "flag halfword at +\(block.y.hex) but the selector-42 handler tests +\(taskForPid.hex)"
            )
        }

        let shape = "BL internal-variant check / LDRB / STRH / STRB W0 / STRB / STRH / UBFX / STRB / STRH / STRB at \(call.hex)"
        return [
            try record(
                id: "txm.permissive-flags.all-ones",
                site: call,
                replacement: Self.movX0MinusOne,
                image: image,
                summary: "Replace the internal-device result with all ones for every flag stored from W0",
                evidence: [
                    shape,
                    "BL target \(check.hex) is the only function referencing the internal-variant message",
                    "this is its only caller",
                ]
            ),
            try storeW0(
                id: "txm.permissive-flags.skip-trust-any-signature", site: block.trustSite, image: image,
                summary: "Turn on skip trust evaluation and allow any signature (+\(block.trustOffset.hex))",
                evidence: shape
            ),
            try storeW0(
                id: "txm.permissive-flags.local-signing", site: block.localSigningSite, image: image,
                summary: "Turn on unrestricted local signing (+\(block.localSigningOffset.hex))",
                evidence: shape
            ),
            try storeW0(
                id: "txm.permissive-flags.profile-trust", site: block.profileSite, image: image,
                summary: "Turn on relaxed profile trust (+\(block.profileOffset.hex))",
                evidence: shape
            ),
            try storeW0(
                id: "txm.permissive-flags.cs-enforcement-task-for-pid", site: block.debugSite, image: image,
                summary: "Turn on CS enforcement disable and unrestricted task_for_pid (+\(block.y.hex))",
                evidence: shape + "; +\((block.y + 1).hex) is the byte the selector-42 handler tests"
            ),
        ]
    }

    // MARK: - The store block

    private struct FlagBlock {
        let trustSite: UInt64
        let trustOffset: UInt64
        let localSigningSite: UInt64
        let localSigningOffset: UInt64
        let profileSite: UInt64
        let profileOffset: UInt64
        let debugSite: UInt64
        let y: UInt64
    }

    /// The nine words after the call, in this order on 24A5370h, 24A5390f and
    /// 24B5099f. One base register throughout; offsets are checked relative to
    /// the W0 store, never against absolute values, because the struct moves
    /// between builds.
    private func flagBlock(after call: UInt64, image: BinaryImage) throws -> FlagBlock {
        let fail = PatchfinderError.noCandidate("\(Self.name) flag store block after \(call.hex)")
        var words: [UInt32] = []
        for index in 1...9 {
            words.append(try image.readUInt32(at: call + UInt64(index) * 4))
        }
        guard let load = Self.decodeLoadByte(words[0]),
              let trust = Self.decodeStore(words[1]), trust.size == 2, trust.rt == 31,
              let internalCA = Self.decodeStore(words[2]), internalCA.size == 1, internalCA.rt == 0,
              let localSigning = Self.decodeStore(words[3]), localSigning.size == 1, localSigning.rt == 31,
              let coreTrust = Self.decodeStore(words[4]), coreTrust.size == 2, coreTrust.rt == 31,
              // UBFX Wt,Wt,#1,#1 is UBFM Wd,Wn,#1,#1: 0x53010400 | Rn<<5 | Rd.
              words[5] == 0x5301_0400 | load.rt << 5 | load.rt,
              let profile = Self.decodeStore(words[6]), profile.size == 1, profile.rt == load.rt,
              let debug = Self.decodeStore(words[7]), debug.size == 2, debug.rt == 31,
              let udid = Self.decodeStore(words[8]), udid.size == 1, udid.rt == 31
        else { throw fail }

        let base = internalCA.rn
        let x = internalCA.offset
        guard base != 0, base != load.rt, base != 31,
              [load.rn, trust.rn, localSigning.rn, coreTrust.rn, profile.rn, debug.rn, udid.rn]
                .allSatisfy({ $0 == base }),
              x >= 3,
              trust.offset == x - 3,
              localSigning.offset == x - 1,
              coreTrust.offset == x + 1,
              profile.offset == x + 3,
              debug.offset > x + 3,
              udid.offset == debug.offset + 6
        else { throw fail }

        return FlagBlock(
            trustSite: call + 8, trustOffset: trust.offset,
            localSigningSite: call + 16, localSigningOffset: localSigning.offset,
            profileSite: call + 28, profileOffset: profile.offset,
            debugSite: call + 32, y: debug.offset
        )
    }

    /// The config byte the selector-42 handler tests right before its error-37
    /// branch: `LDRB Wt,[Xn,#imm]` immediately ahead of the TBNZ that
    /// `TXMDebugMappingResolver` resolves and forces.
    private func selector42PolicyByte(in image: BinaryImage) throws -> UInt64 {
        let records = try TXMDebugMappingResolver().resolve(in: image)
        guard let branch = records.first(where: { $0.id == "txm.debug-mapping.caller-entitlement" }),
              branch.offset >= 4,
              let load = Self.decodeLoadByte(try image.readUInt32(at: branch.offset - 4)),
              let test = branch.originalWord,
              test & 0x1F == load.rt   // the TBNZ tests the byte just loaded
        else {
            throw PatchfinderError.noCandidate("\(Self.name) selector-42 policy byte")
        }
        return load.offset
    }

    // MARK: - Encodings

    /// STRB/STRH (immediate, unsigned offset), 32-bit register form:
    /// size(31:30)=00/01, 111001, opc(23:22)=00, imm12(21:10), Rn(9:5), Rt(4:0).
    /// The offset is imm12 scaled by the access size.
    static func decodeStore(_ word: UInt32) -> (size: UInt64, rt: UInt32, rn: UInt32, offset: UInt64)? {
        let size: UInt64
        switch word & 0xFFC0_0000 {
        case 0x3900_0000: size = 1
        case 0x7900_0000: size = 2
        default: return nil
        }
        return (size, word & 0x1F, (word >> 5) & 0x1F, UInt64((word >> 10) & 0xFFF) * size)
    }

    /// LDRB Wt,[Xn,#imm] (immediate, unsigned offset): fixed 0x39400000.
    static func decodeLoadByte(_ word: UInt32) -> (rt: UInt32, rn: UInt32, offset: UInt64)? {
        guard word & 0xFFC0_0000 == 0x3940_0000 else { return nil }
        return (word & 0x1F, (word >> 5) & 0x1F, UInt64((word >> 10) & 0xFFF))
    }

    /// Same store with Rt cleared to W0; size, base and offset unchanged.
    private func storeW0(
        id: String,
        site: UInt64,
        image: BinaryImage,
        summary: String,
        evidence: String
    ) throws -> PatchRecord {
        let original = try image.readUInt32(at: site)
        return try record(
            id: id, site: site, replacement: original & ~UInt32(0x1F), image: image,
            summary: summary, evidence: [evidence, "store keeps its size, base and offset; source becomes W0"]
        )
    }

    private func record(
        id: String,
        site: UInt64,
        replacement: UInt32,
        image: BinaryImage,
        summary: String,
        evidence: [String]
    ) throws -> PatchRecord {
        PatchRecord(
            id: id,
            component: "TXM",
            offset: site,
            original: try image.readUInt32(at: site),
            replacement: replacement,
            summary: summary,
            evidence: evidence
        )
    }

    // MARK: - Lookup

    /// Every BL in executable segments whose target is `function`. File offsets
    /// stand in for addresses: TXM maps each segment at a fixed slide, and the
    /// caller and callee share one segment, so the PC-relative target agrees.
    private func callers(of function: UInt64, image: BinaryImage, layout: MachOLayout) throws -> [UInt64] {
        var hits: [UInt64] = []
        for range in layout.executableFileRanges {
            var offset = (range.lowerBound + 3) & ~UInt64(3)
            while offset + 4 <= range.upperBound {
                let word = try image.readUInt32(at: offset)
                if ARM64.branchLinkTarget(instruction: word, at: offset) == function {
                    hits.append(offset)
                }
                offset += 4
            }
        }
        return hits
    }

    /// A whole C string, NUL on both sides.
    private func uniqueCString(_ text: String, in image: BinaryImage) throws -> UInt64 {
        var needle = Data([0])
        needle.append(contentsOf: text.utf8)
        needle.append(0)
        let hits = image.findAll(needle)
        guard let hit = hits.only else {
            if hits.isEmpty { throw PatchfinderError.missingAnchor("TXM string \"\(text)\"") }
            throw PatchfinderError.ambiguousAnchor("TXM string \"\(text)\"", count: hits.count)
        }
        return hit + 1
    }
}

private extension Collection {
    var only: Element? { count == 1 ? first : nil }
}
