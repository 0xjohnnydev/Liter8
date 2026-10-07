import Foundation
import XCTest
@testable import Liter8Core

/// Synthetic-image coverage for the code-signing-invalid resolvers. These pin
/// the transform and the fail-safe behaviour; they do not read firmware, so the
/// exact-build fixtures still have to confirm the real 23H30 kernel.
///
/// The images carry the T8020 kernel fingerprint so the opt-in gate is
/// satisfied the same way a real kernelcache satisfies it.
final class KernelCodeSigningResolverTests: XCTestCase {
    private let fingerprint = "xnu-12377.162.13.700.38~2/RELEASE_ARM64_T8020"

    /// One executable __TEXT_EXEC segment holding `words`, plus the T8020
    /// fingerprint string so profile detection opts the kernel in.
    private func image(words: [UInt32], textFileOffset: UInt64 = 0x4000) -> BinaryImage {
        var data = Data(count: Int(textFileOffset))
        data.replaceSubrange(0..<4, with: withUnsafeBytes(of: UInt32(0xFEED_FACF).littleEndian, Array.init))
        data.replaceSubrange(16..<20, with: withUnsafeBytes(of: UInt32(1).littleEndian, Array.init))

        var command = Data()
        func append<T: FixedWidthInteger>(_ value: T) {
            command.append(contentsOf: withUnsafeBytes(of: value.littleEndian, Array.init))
        }
        append(UInt32(0x19))                                   // LC_SEGMENT_64
        append(UInt32(72))                                     // cmdsize
        command.append(Data("__TEXT_EXEC".utf8))
        command.append(Data(count: 16 - "__TEXT_EXEC".utf8.count))
        append(UInt64(0xFFFF_FFF0_0814_8000))                  // vmaddr
        append(UInt64(words.count * 4))                        // vmsize
        append(textFileOffset)                                 // fileoff
        append(UInt64(words.count * 4))                        // filesize
        append(UInt32(5))                                      // maxprot  r-x
        append(UInt32(5))                                      // initprot r-x
        append(UInt32(0))                                      // nsects
        append(UInt32(0))                                      // flags
        data.replaceSubrange(32..<(32 + command.count), with: command)

        for word in words {
            data.append(contentsOf: withUnsafeBytes(of: word.littleEndian, Array.init))
        }
        // The fingerprint lives outside the executable segment, which is fine:
        // detection scans the whole image, resolvers scan only __TEXT_EXEC.
        data.append(Data(fingerprint.utf8))
        data.append(0)
        return BinaryImage(data: data)
    }

    private func nop(_ n: Int) -> [UInt32] { Array(repeating: 0xD503_201F, count: n) }

    // MARK: - PPL allow-invalid

    private var pplProducer: [UInt32] {
        [
            0x6f00_e400, 0x3c85_8260, 0xf900_3e7f, 0xb900_827f, 0x780c_527f,
            0x3c88_8260, 0x3d80_2a60, 0x3902_627f, 0x5280_0028, 0x780c_1268,
            0x2916_fe7f, 0xd503_3bbf, 0xb900_b268,
        ]
    }

    func testPPLAllowInvalidRewritesImmediateAndNarrowsRefcount() throws {
        let image = image(words: nop(4) + pplProducer + nop(4))
        let records = try KernelPPLAllowInvalidResolver().resolve(in: image)
        XCTAssertEqual(records.count, 2)
        XCTAssertEqual(records[0].offset, 0x4000 + UInt64((4 + 8) * 4))
        XCTAssertEqual(records[0].replacementBytes.withUnsafeBytes { UInt32(littleEndian: $0.loadUnaligned(as: UInt32.self)) }, 0x5280_2028)
        XCTAssertEqual(records[1].offset, 0x4000 + UInt64((4 + 12) * 4))
        XCTAssertEqual(records[1].replacementBytes.withUnsafeBytes { UInt32(littleEndian: $0.loadUnaligned(as: UInt32.self)) }, 0x3902_c268)
        // Guarded applier must accept the original bytes we recorded.
        _ = try GuardedPatchApplier.apply(records, to: image)
    }

    func testPPLAllowInvalidAcceptsTheSturVariant() throws {
        var producer = pplProducer
        producer[10] = 0xf80b_427f // stur xzr, [x19, #0xb4]
        let image = image(words: producer)
        XCTAssertEqual(try KernelPPLAllowInvalidResolver().resolve(in: image).count, 2)
    }

    func testPPLAllowInvalidRejectsADuplicateProducer() throws {
        let image = image(words: pplProducer + nop(2) + pplProducer)
        XCTAssertThrowsError(try KernelPPLAllowInvalidResolver().resolve(in: image))
    }

    func testPPLAllowInvalidFindsNothingWhenAbsent() throws {
        let image = image(words: nop(20))
        XCTAssertThrowsError(try KernelPPLAllowInvalidResolver().resolve(in: image)) { error in
            guard case PatchfinderError.noCandidate = error else {
                return XCTFail("expected noCandidate, got \(error)")
            }
        }
    }

    // MARK: - vm_fault_enter

    // tbz w17, #2, +4  -> lands on the candidate four slots later
    private let tbz2To4: UInt32 = 0x3610_0091
    // tbz w9, #3, +8   -> the cs_bypass test
    private let tbz3: UInt32 = 0x3618_0109
    // mov w10, #0      -> cs_violation = FALSE
    private let movW10Zero: UInt32 = 0x5280_000A

    func testVMFaultRemovesTheCSBypassTest() throws {
        // index 2: tbz #2 -> index 6 ; index 6: tbz #3 ; index 7: mov #0
        let words = nop(2) + [tbz2To4] + nop(3) + [tbz3, movW10Zero] + nop(2)
        let image = image(words: words)
        let records = try KernelVMFaultCSBypassResolver().resolve(in: image)
        XCTAssertEqual(records.count, 1)
        XCTAssertEqual(records[0].offset, 0x4000 + UInt64(6 * 4))
        XCTAssertEqual(records[0].replacementWord, 0xD503_201F)
        _ = try GuardedPatchApplier.apply(records, to: image)
    }

    func testVMFaultAcceptsTheMovRegisterForm() throws {
        // KPF's mask fixes the source register: mov xD, x23 with xD >= 16.
        let movX17X23: UInt32 = 0xAA17_03F1 // mov x17, x23
        let words = nop(2) + [tbz2To4] + nop(3) + [tbz3, movX17X23, movW10Zero] + nop(2)
        XCTAssertEqual(try KernelVMFaultCSBypassResolver().resolve(in: image(words: words)).count, 1)
    }

    func testVMFaultRequiresTheBit2BranchToLandOnTheTest() throws {
        // tbz #2 lands three slots before the candidate: outside KPF's window.
        let tbz2To1: UInt32 = 0x3610_0031 // tbz w17, #2, +1
        let words = nop(2) + [tbz2To1] + nop(3) + [tbz3, movW10Zero] + nop(2)
        XCTAssertThrowsError(try KernelVMFaultCSBypassResolver().resolve(in: image(words: words)))
    }

    func testVMFaultRejectsALoneBypassShape() throws {
        let words = nop(4) + [tbz3, movW10Zero] + nop(2)
        XCTAssertThrowsError(try KernelVMFaultCSBypassResolver().resolve(in: image(words: words)))
    }

    func testVMFaultRejectsTwoSites() throws {
        let block = [tbz2To4] + nop(3) + [tbz3, movW10Zero]
        XCTAssertThrowsError(
            try KernelVMFaultCSBypassResolver().resolve(in: image(words: block + nop(4) + block))
        )
    }

    // MARK: - vm_map_protect

    func testVMMapProtectForcesSkipAndDropsDisallow() throws {
        // and w8,w?,#0x400000 ; mov w9,#6 ; bic w9,w9,w? ; cmp w9,#0 ;
        // ccmp w8,#0,#0,eq ; b.ne skip ; <downgrade> ; (skip:) tbnz w8,#7
        let and400000: UInt32 = 0x120a_0008   // and w8, w0, #0x400000
        let movW9_6: UInt32 = 0x5280_00c9     // mov w9, #6
        let bic: UInt32 = 0x0a20_0129         // bic w9, w9, w0
        let cmp: UInt32 = 0x7100_013f         // cmp w9, #0
        let ccmp: UInt32 = 0x7a40_0900        // ccmp w8, #0, #0, eq
        let bne: UInt32 = 0x5400_0061         // b.ne +0xc (skip two slots ahead)
        let downgrade = nop(2)
        let tbnz7: UInt32 = 0x3738_0008       // tbnz w8, #7, ...
        let words = nop(2) + [and400000, movW9_6, bic, cmp, ccmp, bne] + downgrade + [tbnz7] + nop(2)
        let image = image(words: words)
        let records = try KernelVMMapProtectResolver().resolve(in: image)
        XCTAssertEqual(records.count, 2)
        // First record makes the b.ne unconditional to the same target.
        let bneOffset = 0x4000 + UInt64((2 + 5) * 4)
        XCTAssertEqual(records[0].offset, bneOffset)
        let newBranch = records[0].replacementBytes.withUnsafeBytes { UInt32(littleEndian: $0.loadUnaligned(as: UInt32.self)) }
        XCTAssertEqual(newBranch & 0xFC00_0000, 0x1400_0000) // unconditional B
        // Second record nops the disallow TBNZ.
        XCTAssertEqual(records[1].replacementBytes.withUnsafeBytes { UInt32(littleEndian: $0.loadUnaligned(as: UInt32.self)) }, 0xD503_201F)
        _ = try GuardedPatchApplier.apply(records, to: image)
    }

    func testVMMapProtectHandlesTheDarwin264Shape() throws {
        // ldr x22,[x1,#0x10] ; mov w9,#6 ; bic w9,w9,w20 ; and w8,w8,#0x400000 ;
        // cmp w9,#0 ; ccmp w8,#0,#0,eq ; b.ne +2 ; nop ; (target) nop ; tbz w8,#9,+3
        let gate: [UInt32] = [
            0xF940_0836, 0x5280_00C9, 0x0A34_0129, 0x120A_0108,
            0x7100_013F, 0x7A40_0900, 0x5400_0041,
        ]
        let tbz9: UInt32 = 0x3648_0068
        let words = nop(2) + gate + nop(1) + [0xD503_201F, tbz9] + nop(4)
        let image = image(words: words)
        let records = try KernelVMMapProtectResolver().resolve(in: image)
        XCTAssertEqual(records.count, 2)
        XCTAssertEqual(records[0].offset, 0x4000 + UInt64((2 + 6) * 4))
        XCTAssertEqual((records[0].replacementWord ?? 0) & 0xFC00_0000, 0x1400_0000)
        // tbz #9 becomes an unconditional branch to its own target.
        XCTAssertEqual(records[1].offset, 0x4000 + UInt64((2 + 7 + 1 + 1) * 4))
        XCTAssertEqual((records[1].replacementWord ?? 0) & 0xFC00_0000, 0x1400_0000)
        _ = try GuardedPatchApplier.apply(records, to: image)
    }

    // MARK: - opt-in gate

    func testCompositeRecordsAreEmptyWithoutAProfileOptIn() throws {
        // An image with no recognised fingerprint is not opted in.
        var data = Data(count: 0x4000)
        data.replaceSubrange(0..<4, with: withUnsafeBytes(of: UInt32(0xFEED_FACF).littleEndian, Array.init))
        let bare = BinaryImage(data: data)
        XCTAssertEqual(try KernelCodeSigningResolver.requiredRecords(in: bare).count, 0)
    }
}
