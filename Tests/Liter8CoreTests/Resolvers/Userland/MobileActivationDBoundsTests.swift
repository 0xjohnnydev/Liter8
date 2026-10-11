import Foundation
import XCTest
@testable import Liter8Core

/// Bounds coverage for the 23H30 dictionary-fallback locator.
///
/// The exact-build fixtures prove the offsets this resolver finds on real
/// binaries; what they cannot reach is a branch that resolves outside the
/// image, because no shipped mobileactivationd has one. These do.
///
/// `ARM64.testBranchTarget` returns `UInt64(bitPattern:)` of a signed sum, so a
/// TBZ resolving below zero comes back as a value just under `UInt64.max`. That
/// value is greater than any `methodOffset`, so the first half of the old guard
/// passed and `fallback + 0x38` then overflowed. Swift traps on unsigned
/// overflow rather than wrapping, so the process died on SIGTRAP with no
/// diagnostic instead of reporting that nothing matched. Same defect as the
/// iBEC leaf branch in `IBECRestoreResolverTests`.
final class MobileActivationDBoundsTests: XCTestCase {
    /// `TBZ W22, #0, <words>` with a signed imm14, the shape the gate matches.
    private func tbzW22Bit0(words: Int32) -> UInt32 {
        let imm14 = UInt32(bitPattern: words) & 0x3FFF
        return 0x3600_0000 | (imm14 << 5) | 22
    }

    private func image(gateAt offset: Int, branch: UInt32, count: Int = 0x200) -> BinaryImage {
        var bytes = [UInt8](repeating: 0, count: count)
        withUnsafeBytes(of: branch.littleEndian) { source in
            bytes.replaceSubrange(offset..<(offset + 4), with: source)
        }
        return BinaryImage(data: Data(bytes))
    }

    private func candidates(_ image: BinaryImage, methodOffset: UInt64 = 0) throws -> Int {
        try MobileActivationDResolver()
            .findStateLoadCandidates(in: image, methodOffset: methodOffset)
            .count
    }

    /// The exact window that trapped. Only a target within 0x38 of zero
    /// overflows: the wrapped value is `UInt64.max - |target| + 1`, so adding
    /// 0x38 crosses the top only while `|target| <= 0x38`. Words -1 through -14
    /// give targets -4 through -0x38, so each of these is a trap case and not
    /// merely a value the comparison happens to reject.
    func testEveryBranchInTheOverflowWindowIsRejected() throws {
        for words in stride(from: Int32(-1), through: Int32(-14), by: -1) {
            let branch = tbzW22Bit0(words: words)
            let target = ARM64.testBranchTarget(instruction: branch, at: 0)
            XCTAssertEqual(target, UInt64(bitPattern: Int64(words) * 4), "words=\(words)")
            XCTAssertGreaterThan(target!, UInt64.max - 0x38, "words=\(words) must be a trap case")
            XCTAssertEqual(try candidates(image(gateAt: 0, branch: branch)), 0, "words=\(words)")
        }
    }

    /// Wider backward displacements wrap too but stay clear of the top, so they
    /// never trapped. They must still be rejected, and from a nonzero gate as
    /// well as from zero.
    func testWiderBackwardBranchesAreRejectedFromEitherGate() throws {
        for words in [Int32(-15), -0x40, -0x400, -0x1FFF] {
            let branch = tbzW22Bit0(words: words)
            XCTAssertEqual(try candidates(image(gateAt: 0, branch: branch)), 0, "words=\(words)")
        }
        let gate = 0x40
        let branch = tbzW22Bit0(words: -0x100)
        XCTAssertEqual(
            try candidates(image(gateAt: gate, branch: branch), methodOffset: UInt64(gate)),
            0
        )
    }

    /// The forward side, which the original comparison did handle. Kept so a
    /// future rewrite cannot lose it while fixing the backward side.
    func testAForwardBranchBeyondTheScanWindowIsRejected() throws {
        let branch = tbzW22Bit0(words: 0x1F00)
        XCTAssertEqual(try candidates(image(gateAt: 0, branch: branch)), 0)
    }

    /// An image shorter than the 0x38-byte body the match needs. The bound is
    /// expressed as `end - fallback`, so this must not underflow either.
    func testAnImageShorterThanTheMatchBodyIsRejected() throws {
        for count in [0x08, 0x10, 0x20, 0x34] {
            let branch = tbzW22Bit0(words: 1)
            XCTAssertEqual(try candidates(image(gateAt: 0, branch: branch, count: count)), 0,
                           "count=\(count)")
        }
    }

    /// A gate whose target is in range finds no candidate either, because the
    /// body is zeroes, which proves these tests fail for the bounds reason and
    /// not because every input is rejected for the same unrelated one.
    func testAnInRangeTargetWithTheWrongBodyIsAlsoRejected() throws {
        let branch = tbzW22Bit0(words: 4)
        let target = ARM64.testBranchTarget(instruction: branch, at: 0)
        XCTAssertEqual(target, 0x10, "the control case must resolve inside the image")
        XCTAssertEqual(try candidates(image(gateAt: 0, branch: branch)), 0)
    }
}
