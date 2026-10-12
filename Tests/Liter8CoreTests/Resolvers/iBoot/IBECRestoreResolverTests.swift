import Foundation
import XCTest
@testable import Liter8Core

/// Bounds coverage for the `ibec-restore` scan.
///
/// The nonce-cache address can be built inline or inside a leaf reached by BL.
/// Resolving the leaf means turning a branch displacement into a file offset,
/// and a displacement that points outside the payload must be rejected rather
/// than read. `directBranchTarget` hands back the bit pattern of a *signed*
/// result, so an out-of-range branch arrives here as a very large `UInt64`, and
/// arithmetic on it has to stay inside the type.
///
/// These are deliberately crash tests as much as assertion tests: an unchecked
/// `helper + 16` traps on overflow, which takes the whole test process down
/// rather than failing one case.
final class IBECRestoreResolverTests: XCTestCase {
    /// `BL #offset`, where `offset` is a byte displacement from the instruction.
    private func branchAndLink(byteDisplacement: Int) -> UInt32 {
        let imm26 = UInt32(bitPattern: Int32(byteDisplacement / 4)) & 0x03FF_FFFF
        return 0x9400_0000 | imm26
    }

    /// A payload whose first word is the given instruction, long enough for the
    /// scan loop to run (it requires at least 0x3C bytes).
    private func image(firstWord: UInt32, byteCount: Int = 256) -> BinaryImage {
        var data = Data()
        data.append(contentsOf: withUnsafeBytes(of: firstWord.littleEndian, Array.init))
        data.append(Data(count: byteCount - 4))
        return BinaryImage(data: data)
    }

    private func expectNoCandidate(_ image: BinaryImage, _ message: String) {
        XCTAssertThrowsError(try IBECRestoreResolver().resolve(in: image), message) { error in
            guard case PatchfinderError.noCandidate = error else {
                return XCTFail("\(message): expected noCandidate, got \(error)")
            }
        }
    }

    /// A backward branch resolves to a negative file offset. Every displacement
    /// here lands in the window that made `helper + 16` overflow.
    func testABackwardBranchNearTheStartIsRejectedWithoutTrapping() {
        for displacement in [-4, -8, -12, -16, -20, -64, -4096] {
            expectNoCandidate(
                image(firstWord: branchAndLink(byteDisplacement: displacement)),
                "BL #\(displacement)"
            )
        }
    }

    /// The same shape at later cursor positions, so the scan reaches a negative
    /// target from a nonzero cursor as well.
    func testABackwardBranchFromALaterCursorIsRejected() {
        var data = Data(count: 16)
        data.append(contentsOf: withUnsafeBytes(of: branchAndLink(byteDisplacement: -32).littleEndian, Array.init))
        data.append(Data(count: 256))
        expectNoCandidate(BinaryImage(data: data), "BL #-32 at offset 16")
    }

    /// A forward branch past the end of the payload must also be rejected. This
    /// is the side the original `helper + 16 <= count` comparison did handle,
    /// so it pins that the rewrite did not lose it.
    func testAForwardBranchBeyondTheImageIsRejected() {
        for displacement in [252, 256, 260, 4096, 1 << 20] {
            expectNoCandidate(
                image(firstWord: branchAndLink(byteDisplacement: displacement)),
                "BL #\(displacement)"
            )
        }
    }

    /// A branch landing exactly at the last four words the check allows is
    /// in bounds, so it is read and then rejected on its contents, not on its
    /// offset. Pins the boundary itself.
    func testABranchToTheLastReadableWordsIsReadNotRejectedOnBounds() {
        let count = 256
        var data = Data()
        // Target the final 16 bytes: count - 16.
        data.append(contentsOf: withUnsafeBytes(of: branchAndLink(byteDisplacement: count - 16).littleEndian, Array.init))
        data.append(Data(count: count - 4))
        // Zero bytes are not the nonce-cache sequence, so this still produces no
        // candidate. The point is that it does not trap and does not throw
        // outOfBounds.
        expectNoCandidate(BinaryImage(data: data), "BL to count-16")
    }

    /// An image too short for the scan loop produces no candidate rather than
    /// reading past the end.
    func testAnImageShorterThanTheScanWindowIsRejected() {
        for byteCount in [0, 4, 16, 0x3B] {
            expectNoCandidate(BinaryImage(data: Data(count: byteCount)), "\(byteCount)-byte image")
        }
    }
}
