import Foundation

/// Resolves the three TXM branches that refuse a debug mapping, the mapping a
/// process needs before a code page it has made writable can execute again.
///
/// When a process asks `vm_protect` for `VM_PROT_COPY` on a code page, XNU asks
/// TXM to approve a debug mapping (selector 42). On refusal XNU still makes the
/// private copy, but without execute in its maximum protection, so the page can
/// never return to `r-x` and a runtime function hook cannot work. Measured on
/// n104ap 24B5099f: a plain process logs `TXM [Error]: selector: 42 | 37`, one
/// holding `com.apple.private.cs.debugger` logs `42 | 29`, and a traced
/// `get-task-allow` process logs nothing, keeps `rwx` and runs the patched code.
///
/// Three branches decide it, each an existing `TBNZ` whose taken edge is the
/// allow path. Each becomes an unconditional `B` to the target that instruction
/// already names, so no control flow is manufactured:
///
/// - error 37, selector-42 handler: the caller lacks the debugger entitlement
///   and a policy byte is clear;
/// - error 29, same handler: the address space is not marked. Only selector
///   41's handler sets that mark, for a debugged `get-task-allow` target;
/// - error 30, the writable/executable debug-mapping validator: neither the
///   entitlement nor the mark. It is not on the selector-42 path; it is reached
///   through TXM's other entry trampoline, case 1, with page-aligned arguments
///   (inferred to be SPTM's page-mapping callback), so it relaxes every
///   writable debug mapping that entry validates.
///
/// The third is needed for an ordinary process. Measured on n104 24B5099f with
/// only the first two applied: the copy kept `rwx` for every caller, but the
/// write into it faulted for a probe holding neither the entitlement nor the
/// mark, and landed for each of the other three combinations. That is exactly
/// the validator's rule, and its refusal is not logged.
///
/// Each site is tied to the entitlement check in its own function: the forced
/// branch must name the same target that holding the entitlement already jumps
/// to. A data patch to the policy byte was tried first and refuted on device;
/// the byte reads zero at runtime regardless of the image.
public struct TXMDebugMappingResolver: Sendable {
    public static let name = "txm-debug-mapping"

    public init() {}

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        let layout = try MachOLayout(image: image)
        let entitlement = try uniqueCString("com.apple.private.cs.debugger", in: image)
        let entitlementRefs = try layout.adrpAddReferences(toFileOffset: entitlement)

        let handler = try resolveHandler(image: image, layout: layout, entitlementRefs: entitlementRefs)
        let validator = try resolveValidator(
            image: image, layout: layout, entitlementRefs: entitlementRefs
        )
        guard validator.function != handler.function else {
            throw PatchfinderError.invalidPatch(
                id: Self.name,
                reason: "the validator and the selector-42 handler resolved to one function"
            )
        }

        return [
            try forcedBranch(
                id: "txm.debug-mapping.caller-entitlement",
                site: handler.callerSite,
                target: handler.allow,
                image: image,
                summary: "Allow a debug mapping requested without com.apple.private.cs.debugger",
                evidence: [
                    "unique \"disallowed non-debugger initiated debug mapping\" reference in \(handler.function.hex)",
                    "TBNZ immediately before it skips to \(handler.allow.hex), the same target the entitlement result branches to",
                    "the refusal path sets error 0x25 (37)",
                ]
            ),
            try forcedBranch(
                id: "txm.debug-mapping.address-space",
                site: handler.markSite,
                target: handler.markAllow,
                image: image,
                summary: "Allow a debug mapping for an address space that is not marked",
                evidence: [
                    "ADD #0x30 / LDARB / TBNZ #0 / MOV #0x1d is unique in \(handler.function.hex)",
                    "the fall-through sets error 0x1d (29)",
                ]
            ),
            try forcedBranch(
                id: "txm.debug-mapping.validator-address-space",
                site: validator.site,
                target: validator.allow,
                image: image,
                summary: "Let the debug-mapping validator accept an address space that is not marked",
                evidence: [
                    "unique \"disallowed writable debug mapping due to address space\" reference in \(validator.function.hex)",
                    "ADD #0x30 / LDARB / TBNZ #0 immediately before it reads the same mark",
                    "TBNZ target \(validator.allow.hex) equals the entitlement result's allow target",
                ]
            ),
        ]
    }

    // MARK: - Selector-42 handler: errors 37 and 29

    private struct Handler {
        let function: UInt64
        let callerSite: UInt64
        let allow: UInt64
        let markSite: UInt64
        let markAllow: UInt64
    }

    private func resolveHandler(
        image: BinaryImage,
        layout: MachOLayout,
        entitlementRefs: [ADRPAddReference]
    ) throws -> Handler {
        let message = try uniqueCString("disallowed non-debugger initiated debug mapping", in: image)
        let reference = try onlyReference(to: message, layout: layout, what: "error-37 message")
        let (function, end) = try bounds(of: reference.adrpOffset, image: image, layout: layout)

        // The word before the message's ADRP is the decision: TBNZ Wt,#0 jumps
        // over the logging and error assignment when the policy byte is set.
        let callerSite = reference.adrpOffset - 4
        let caller = try image.readUInt32(at: callerSite)
        guard isTBNZBitZero(caller),
              let allow = ARM64.testBranchTarget(instruction: caller, at: callerSite),
              (function..<end).contains(allow)
        else {
            throw PatchfinderError.noCandidate("\(Self.name) error-37 decision")
        }
        // ADRP/ADD message, BL log, MOV Wd,#0x25: the path being skipped really
        // is the one that produces error 37.
        let log = try image.readUInt32(at: reference.addOffset + 4)
        let status = try image.readUInt32(at: reference.addOffset + 8)
        guard ARM64.branchLinkTarget(instruction: log, at: reference.addOffset + 4) != nil,
              isMOVZ32(status, immediate: 0x25)
        else {
            throw PatchfinderError.noCandidate("\(Self.name) error-37 refusal path")
        }
        let entitled = try entitlementAllowTarget(
            refs: entitlementRefs, function: function, end: end, image: image
        )
        guard entitled == allow else {
            throw PatchfinderError.invalidPatch(
                id: Self.name,
                reason: "error-37 TBNZ targets \(allow.hex) but the entitlement allows at \(entitled.hex)"
            )
        }

        var marks: [(site: UInt64, allow: UInt64)] = []
        var cursor = function
        while cursor + 16 <= end {
            if let match = try markCheck(endingAt: cursor + 8, image: image),
               isMOVZ32(try image.readUInt32(at: cursor + 12), immediate: 0x1D),
               (function..<end).contains(match.allow) {
                marks.append(match)
            }
            cursor += 4
        }
        guard let mark = marks.only else {
            if marks.isEmpty { throw PatchfinderError.noCandidate("\(Self.name) error-29 decision") }
            throw PatchfinderError.ambiguousCandidate(
                "\(Self.name) error-29 decision", offsets: marks.map(\.site)
            )
        }
        return Handler(
            function: function, callerSite: callerSite, allow: allow,
            markSite: mark.site, markAllow: mark.allow
        )
    }

    // MARK: - Validator: error 30, second reader of the mark

    private struct Validator {
        let function: UInt64
        let site: UInt64
        let allow: UInt64
    }

    private func resolveValidator(
        image: BinaryImage,
        layout: MachOLayout,
        entitlementRefs: [ADRPAddReference]
    ) throws -> Validator {
        let message = try uniqueCString(
            "disallowed writable debug mapping due to address space", in: image
        )
        let reference = try onlyReference(to: message, layout: layout, what: "error-30 message")
        let (function, end) = try bounds(of: reference.adrpOffset, image: image, layout: layout)

        guard reference.adrpOffset >= function + 12,
              let mark = try markCheck(endingAt: reference.adrpOffset - 4, image: image),
              (function..<end).contains(mark.allow)
        else {
            throw PatchfinderError.noCandidate("\(Self.name) validator mark check")
        }
        let entitled = try entitlementAllowTarget(
            refs: entitlementRefs, function: function, end: end, image: image
        )
        guard entitled == mark.allow else {
            throw PatchfinderError.invalidPatch(
                id: Self.name,
                reason: "validator TBNZ targets \(mark.allow.hex) but the entitlement allows at \(entitled.hex)"
            )
        }
        return Validator(function: function, site: mark.site, allow: mark.allow)
    }

    // MARK: - Shared shapes

    /// `ADD Xk,Xn,#0x30 ; LDARB Wt,[Xk] ; TBNZ Wt,#0,allow` with the TBNZ at
    /// `site`. The acquire load of byte +0x30 is how both readers consume the
    /// address-space mark; requiring the register chain stops an unrelated
    /// TBNZ that happens to sit nearby from matching.
    private func markCheck(
        endingAt site: UInt64,
        image: BinaryImage
    ) throws -> (site: UInt64, allow: UInt64)? {
        guard site >= 8 else { return nil }
        let add = try image.readUInt32(at: site - 8)
        let load = try image.readUInt32(at: site - 4)
        let test = try image.readUInt32(at: site)
        // ADD (immediate), 64-bit, no shift, imm12 = 0x30: fixed 0x9100C000;
        // only Rn (bits 9:5) and Rd (bits 4:0) vary.
        guard add & 0xFFFF_FC00 == 0x9100_C000 else { return nil }
        // LDARB Wt,[Xn]: fixed 0x08DFFC00; Rn (bits 9:5) and Rt (bits 4:0) vary.
        guard load & 0xFFFF_FC00 == 0x08DF_FC00 else { return nil }
        guard (load >> 5) & 0x1F == add & 0x1F,   // loads through the ADD's result
              isTBNZBitZero(test),
              test & 0x1F == load & 0x1F,         // tests the byte just loaded
              let allow = ARM64.testBranchTarget(instruction: test, at: site)
        else { return nil }
        return (site, allow)
    }

    /// Where holding `com.apple.private.cs.debugger` jumps inside one function:
    /// ADRP/ADD of the entitlement name, the query BL within the next few
    /// words, then `TBNZ W0,#0,allow` on its result.
    private func entitlementAllowTarget(
        refs: [ADRPAddReference],
        function: UInt64,
        end: UInt64,
        image: BinaryImage
    ) throws -> UInt64 {
        let inside = refs.filter { (function..<end).contains($0.addOffset) }
        guard let reference = inside.only else {
            if inside.isEmpty {
                throw PatchfinderError.noCandidate("\(Self.name) entitlement check in \(function.hex)")
            }
            throw PatchfinderError.ambiguousCandidate(
                "\(Self.name) entitlement check in \(function.hex)",
                offsets: inside.map(\.addOffset)
            )
        }
        // Two argument MOVs separate the ADD from the BL on every build seen;
        // allow a little slack, but the result test must follow the BL directly.
        var cursor = reference.addOffset + 4
        while cursor < min(end, reference.addOffset + 4 * 6) {
            let word = try image.readUInt32(at: cursor)
            if ARM64.branchLinkTarget(instruction: word, at: cursor) != nil {
                let test = try image.readUInt32(at: cursor + 4)
                // TBNZ W0,#0: the query's boolean result, register fixed to 0.
                guard test & 0xFFF8_001F == 0x3700_0000,
                      let allow = ARM64.testBranchTarget(instruction: test, at: cursor + 4)
                else { break }
                return allow
            }
            cursor += 4
        }
        throw PatchfinderError.noCandidate("\(Self.name) entitlement result in \(function.hex)")
    }

    private func forcedBranch(
        id: String,
        site: UInt64,
        target: UInt64,
        image: BinaryImage,
        summary: String,
        evidence: [String]
    ) throws -> PatchRecord {
        guard let branch = ARM64.encodeDirectBranch(link: false, instructionOffset: site, target: target) else {
            throw PatchfinderError.invalidPatch(id: id, reason: "B to \(target.hex) is out of range")
        }
        return PatchRecord(
            id: id,
            component: "TXM",
            offset: site,
            original: try image.readUInt32(at: site),
            replacement: branch,
            summary: summary,
            evidence: evidence + ["TBNZ at \(site.hex) becomes B to its own target \(target.hex)"]
        )
    }

    /// TBNZ Wt,#0,<label>: b5 (bit 31) and b40 (bits 23:19) zero select bit 0
    /// of a W register; imm14 and Rt vary.
    private func isTBNZBitZero(_ word: UInt32) -> Bool {
        word & 0xFFF8_0000 == 0x3700_0000
    }

    /// MOVZ Wd,#imm with no shift: 0x52800000 | imm16 << 5 | Rd.
    private func isMOVZ32(_ word: UInt32, immediate: UInt32) -> Bool {
        word & 0xFFFF_FFE0 == 0x5280_0000 | immediate << 5
    }

    /// A whole C string: NUL on both sides, so neither a longer string ending
    /// with this text nor one starting with it can stand in for it.
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

    private func onlyReference(
        to offset: UInt64,
        layout: MachOLayout,
        what: String
    ) throws -> ADRPAddReference {
        let refs = try layout.adrpAddReferences(toFileOffset: offset)
        guard let reference = refs.only else {
            if refs.isEmpty { throw PatchfinderError.missingAnchor("\(Self.name) \(what) reference") }
            throw PatchfinderError.ambiguousAnchor("\(Self.name) \(what) reference", count: refs.count)
        }
        return reference
    }

    private func bounds(
        of offset: UInt64,
        image: BinaryImage,
        layout: MachOLayout
    ) throws -> (UInt64, UInt64) {
        guard let start = ARM64.functionStart(beforeOrAt: offset, in: image, layout: layout) else {
            throw PatchfinderError.noCandidate("\(Self.name) function containing \(offset.hex)")
        }
        return (start, ARM64.nextFunctionStart(after: start, in: image, layout: layout))
    }
}

private extension Collection {
    var only: Element? { count == 1 ? first : nil }
}
