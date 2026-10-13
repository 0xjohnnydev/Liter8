import Foundation
import XCTest
@testable import Liter8Core

/// The exception-port enforcement byte on real kernelcaches. The same resolver
/// also resolved, by the CLI, on 24A5370h d421, 24A435, 24A437 and 24B5084k
/// (0xbc3278, 0xbc7158, 0xbc7158, 0xbff278).
final class KernelExceptionPortResolverTests: XCTestCase {
    private func kernel(_ path: String) throws -> URL {
        let url = liter8PrivateFixtureRoot(from: #filePath).appendingPathComponent(path)
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw XCTSkip("local kernelcache \(path) is absent")
        }
        return url
    }

    private var beta4: URL {
        get throws { try kernel("offsets/kc/kc_b4_n104.raw") }
    }

    func testClearsTheEnforcementByteOnBeta4() throws {
        let records = try KernelExceptionPortResolver().resolve(in: BinaryImage(contentsOf: beta4))
        XCTAssertEqual(records.map(\.offset), [0xBBF278])
        XCTAssertEqual(records.map(\.originalBytes), [Data([1])])
        XCTAssertEqual(records.map(\.replacementBytes), [Data([0])])
    }

    func testClearsTheEnforcementByteOn24B5099f() throws {
        let records = try KernelExceptionPortResolver().resolve(
            in: BinaryImage(contentsOf: kernel("offsets/kc/kc_24B5099f_n104.raw"))
        )
        XCTAssertEqual(records.map(\.offset), [0xBDB278])
        XCTAssertEqual(records.map(\.originalBytes), [Data([1])])
    }

    func testBootJITPlanIncludesTheByte() throws {
        let image = try BinaryImage(contentsOf: beta4)
        let plan = try KernelBootJITResolver().resolve(in: image)
        XCTAssertEqual(plan.filter { $0.id == "kernel.exception-port.behavior-enforcement" }.map(\.offset), [0xBBF278])
        XCTAssertEqual(Set(plan.map(\.offset)).count, plan.count)
    }

    /// An image this patch already applied still resolves, naming the stock 1 as
    /// the original so the guarded applier sees "already applied".
    func testResolvesAnAlreadyAppliedByte() throws {
        let image = try mutatedBeta4(bytes: [0xBBF278: 0])
        let records = try KernelExceptionPortResolver().resolve(in: image)
        XCTAssertEqual(records.map(\.offset), [0xBBF278])
        XCTAssertEqual(records.map(\.originalBytes), [Data([1])])
        XCTAssertEqual(records.map(\.replacementBytes), [Data([0])])
    }

    /// Neither the stock value nor the patched one.
    func testRejectsAnUnexpectedByteValue() throws {
        let image = try mutatedBeta4(bytes: [0xBBF278: 2])
        assertThrows(try KernelExceptionPortResolver().resolve(in: image)) {
            if case .invalidPatch = $0 { return true } else { return false }
        }
    }

    /// The deny result must come from the loaded register: SBFX W8,W9 instead
    /// of SBFX W8,W8 on the bypass edge.
    func testRejectsWhenTheDenyResultIgnoresTheLoadedByte() throws {
        let image = try mutatedBeta4(words: [0x322610C: 0x1300_0128])
        assertThrows(try KernelExceptionPortResolver().resolve(in: image)) {
            if case .noCandidate = $0 { return true } else { return false }
        }
    }

    /// AND W0,W10,W9 instead of AND W0,W8,W9: the result no longer uses SBFX's.
    func testRejectsWhenTheAndSkipsTheSignExtendedByte() throws {
        let image = try mutatedBeta4(words: [0x3226114: 0x0A09_0140])
        assertThrows(try KernelExceptionPortResolver().resolve(in: image)) {
            if case .noCandidate = $0 { return true } else { return false }
        }
    }

    /// The bypass edge's exit branch redirected into the guard call path
    /// (B +4 to 0x322611C): clearing the byte would no longer skip the guard.
    func testRejectsWhenTheBypassRejoinsTheGuardCall() throws {
        let image = try mutatedBeta4(words: [0x3226118: 0x1400_0001])
        assertThrows(try KernelExceptionPortResolver().resolve(in: image)) {
            if case .noCandidate = $0 { return true } else { return false }
        }
    }

    /// Without the flavor-6 guard call the byte is not tied to this guard.
    func testRejectsWithoutTheFlavor6GuardCall() throws {
        let image = try mutatedBeta4(words: [0x3226124: 0x5280_00A2]) // MOV W2,#5
        assertThrows(try KernelExceptionPortResolver().resolve(in: image)) {
            if case .noCandidate = $0 { return true } else { return false }
        }
    }

    /// A test of a different register is not a test of the loaded byte.
    func testRejectsWhenTheTestIsNotOnTheLoadedRegister() throws {
        let image = try mutatedBeta4(words: [0x3226108: 0x3700_00A9]) // TBNZ W9,#0
        assertThrows(try KernelExceptionPortResolver().resolve(in: image)) {
            if case .noCandidate = $0 { return true } else { return false }
        }
    }

    /// The exit branch aimed at the guard's BL itself (B +0x10 to 0x3226128).
    func testRejectsWhenTheBypassExitTargetsTheGuardBL() throws {
        let image = try mutatedBeta4(words: [0x3226118: 0x1400_0004])
        assertThrows(try KernelExceptionPortResolver().resolve(in: image)) {
            if case .noCandidate = $0 { return true } else { return false }
        }
    }

    /// The exit branch looping on itself never reaches the epilogue.
    func testRejectsWhenTheBypassExitIsASelfBranch() throws {
        let image = try mutatedBeta4(words: [0x3226118: 0x1400_0000])
        assertThrows(try KernelExceptionPortResolver().resolve(in: image)) {
            if case .noCandidate = $0 { return true } else { return false }
        }
    }

    private func mutatedBeta4(words: [UInt64: UInt32] = [:], bytes: [UInt64: UInt8] = [:]) throws -> BinaryImage {
        var data = try Data(contentsOf: beta4)
        for (offset, word) in words {
            let start = Int(offset)
            data.replaceSubrange(start..<start + 4, with: withUnsafeBytes(of: word.littleEndian, Array.init))
        }
        for (offset, byte) in bytes {
            data[Int(offset)] = byte
        }
        return BinaryImage(data: data)
    }

    private func assertThrows<T>(
        _ expression: @autoclosure () throws -> T,
        file: StaticString = #filePath,
        line: UInt = #line,
        matching: (PatchfinderError) -> Bool
    ) {
        XCTAssertThrowsError(try expression(), file: file, line: line) { error in
            guard let patchError = error as? PatchfinderError else {
                return XCTFail("unexpected error \(error)", file: file, line: line)
            }
            XCTAssertTrue(matching(patchError), "wrong error: \(patchError)", file: file, line: line)
        }
    }
}
