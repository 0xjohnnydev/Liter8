import Foundation

/// Clears the switch that kills a process for registering a non-identity-protected
/// exception handler.
///
/// XNU's `set_exception_behavior_allowed` (osfmk/kern/ipc_tt.c) requires tasks
/// whose IPC space policy is enhanced, which includes every platform binary, to
/// register exception ports with `EXCEPTION_STATE` or an identity-protected
/// behavior. Anything else raises `EXC_GUARD` flavor 6
/// (`kGUARD_EXC_EXCEPTION_BEHAVIOR_ENFORCE`) and returns `KERN_DENIED` while the
/// byte `thid_should_crash` is set. Liter8's trust-cache patches make every
/// binary a platform binary, so App Store apps whose crash SDK registers
/// `EXCEPTION_DEFAULT` die at launch (measured on n104 24B5099f: IPC policy 0x407
/// for the apps, identical to SpringBoard). With the byte clear the violation is
/// ignored and the handler is registered normally.
///
/// The byte was a boot-arg tunable in xnu-12377; 27.x kernels no longer carry the
/// boot-arg string, so it is patched in the image. It lives in `__DATA_CONST`,
/// holds 1, and no instruction writes it. It is found from the policy function,
/// the only code referencing `com.apple.security.only-one-exception-port`:
///
/// - every ADRP+LDRB in that function loads the same byte;
/// - one load is followed directly by TBZ/TBNZ on the loaded register, and the
///   function's only `MOV W2,#6 ; BL` (the guard call) is on that path;
/// - `SBFX Wd,Wt,#0,#1 ; MOV Wx,#0x35 ; AND` turns the byte into the
///   `KERN_DENIED` result.
public struct KernelExceptionPortResolver: Sendable {
    public static let name = "kernel-exception-port"
    static let anchor = "com.apple.security.only-one-exception-port"

    /// MOVZ W2,#6: the guard flavor argument.
    private static let movW2Flavor6: UInt32 = 0x5280_00C2

    public init() {}

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        let layout = try MachOLayout(image: image)
        let anchors = image.findAll(Data([0]) + Data(Self.anchor.utf8) + Data([0]))
        guard let anchor = anchors.only else {
            if anchors.isEmpty { throw PatchfinderError.missingAnchor(Self.anchor) }
            throw PatchfinderError.ambiguousAnchor(Self.anchor, count: anchors.count)
        }
        let refs = try layout.adrpAddReferences(toFileOffset: anchor + 1)
        guard let ref = refs.only else {
            if refs.isEmpty { throw PatchfinderError.missingAnchor("\(Self.name) \(Self.anchor) reference") }
            throw PatchfinderError.ambiguousAnchor("\(Self.name) \(Self.anchor) reference", count: refs.count)
        }
        guard let start = ARM64.functionStart(beforeOrAt: ref.adrpOffset, in: image, layout: layout) else {
            throw PatchfinderError.noCandidate("\(Self.name) policy function")
        }
        let end = ARM64.nextFunctionStart(after: start, in: image, layout: layout)

        var loads: [(offset: UInt64, target: UInt64, rt: UInt32)] = []
        var guardCalls: [UInt64] = []
        var denyFromByte = false
        var cursor = start
        while cursor + 12 <= end {
            let word = try image.readUInt32(at: cursor)
            let next = try image.readUInt32(at: cursor + 4)
            if let load = try byteLoad(adrp: word, at: cursor, next: next, layout: layout) {
                loads.append((cursor + 4, load.target, load.rt))
            }
            if word == Self.movW2Flavor6, ARM64.branchLinkTarget(instruction: next, at: cursor + 4) != nil {
                guardCalls.append(cursor)
            }
            // SBFX Wd,Wn,#0,#1 is SBFM Wd,Wn,#0,#0: 0x13000000 | Rn<<5 | Rd.
            // MOVZ Wx,#0x35 is 0x528006A0 | Rd; AND (shifted register) 32-bit
            // is 0x0A000000 with Rm/Rn/Rd varying.
            if word & 0xFFFF_FC00 == 0x1300_0000,
               next & 0xFFFF_FFE0 == 0x5280_06A0,
               try image.readUInt32(at: cursor + 8) & 0xFF20_0000 == 0x0A00_0000 {
                denyFromByte = true
            }
            cursor += 4
        }

        let targets = Set(loads.map(\.target))
        guard let byte = targets.only else {
            if targets.isEmpty { throw PatchfinderError.noCandidate("\(Self.name) enforcement byte load") }
            throw PatchfinderError.ambiguousCandidate("\(Self.name) enforcement byte", offsets: targets.sorted())
        }
        guard let guardCall = guardCalls.only else {
            if guardCalls.isEmpty { throw PatchfinderError.noCandidate("\(Self.name) flavor-6 guard call") }
            throw PatchfinderError.ambiguousCandidate("\(Self.name) flavor-6 guard call", offsets: guardCalls)
        }
        guard try loads.contains(where: { try gates(load: $0, guardCall: guardCall, image: image) }) else {
            throw PatchfinderError.noCandidate("\(Self.name) byte test leading to the guard call")
        }
        guard denyFromByte else {
            throw PatchfinderError.noCandidate("\(Self.name) KERN_DENIED derived from the byte")
        }
        guard let segment = layout.segments.first(where: { $0.fileRange.contains(byte) }),
              segment.name == "__DATA_CONST", !segment.isExecutable
        else {
            throw PatchfinderError.invalidPatch(id: Self.name, reason: "enforcement byte \(byte.hex) is not in __DATA_CONST")
        }
        let original = try image.bytes(at: byte, count: 1)
        guard original == Data([1]) else {
            throw PatchfinderError.invalidPatch(id: Self.name, reason: "enforcement byte \(byte.hex) is \(String(format: "%02x", original.first ?? 0)), expected 01")
        }

        return [
            PatchRecord(
                id: "kernel.exception-port.behavior-enforcement",
                component: "kernelcache",
                offset: byte,
                originalBytes: original,
                replacementBytes: Data([0]),
                summary: "Ignore non-identity-protected exception-port registrations instead of killing the caller",
                evidence: [
                    "only function referencing \(Self.anchor): \(start.hex)",
                    "all \(loads.count) ADRP+LDRB loads in it read \(byte.hex) (__DATA_CONST, value 1)",
                    "a load of it is tested by TBZ/TBNZ #0 on the path to MOV W2,#6 ; BL at \(guardCall.hex)",
                    "SBFX/MOV #0x35/AND derives KERN_DENIED from the byte",
                ]
            ),
        ]
    }

    /// ADRP Xd,page followed by LDRB Wt,[Xd,#imm] (unsigned offset, fixed
    /// 0x39400000 with imm12/Rn/Rt varying). The page is computed in virtual
    /// addresses so code and data segments may slide differently.
    private func byteLoad(
        adrp: UInt32,
        at offset: UInt64,
        next: UInt32,
        layout: MachOLayout
    ) throws -> (target: UInt64, rt: UInt32)? {
        guard adrp & 0x9F00_0000 == 0x9000_0000,
              next & 0xFFC0_0000 == 0x3940_0000,
              (next >> 5) & 0x1F == adrp & 0x1F,
              let pc = layout.virtualAddress(forFileOffset: offset)
        else { return nil }
        let address = ARM64.adrpTarget(instruction: adrp, at: pc) + UInt64((next >> 10) & 0xFFF)
        guard let target = layout.fileOffset(forVirtualAddress: address) else { return nil }
        return (target, next & 0x1F)
    }

    /// The word after the load is TBZ/TBNZ Wt,#0 on the loaded register, and the
    /// guard call is its fall-through (TBZ) or its target (TBNZ), allowing the
    /// two argument moves that precede `MOV W2,#6`.
    private func gates(
        load: (offset: UInt64, target: UInt64, rt: UInt32),
        guardCall: UInt64,
        image: BinaryImage
    ) throws -> Bool {
        let test = try image.readUInt32(at: load.offset + 4)
        // TBZ is 0x36000000, TBNZ 0x37000000; b5 and b40 zero select bit 0 of W.
        guard test & 0xFEF8_0000 == 0x3600_0000, test & 0x1F == load.rt,
              let target = ARM64.testBranchTarget(instruction: test, at: load.offset + 4)
        else { return false }
        let entry = test & 0x0100_0000 == 0 ? load.offset + 8 : target
        return guardCall >= entry && guardCall - entry <= 8
    }
}

private extension Collection {
    var only: Element? { count == 1 ? first : nil }
}
