import Foundation
import XCTest
@testable import Liter8Core

/// Synthetic-image coverage for the kernel version-string marker. The exact-build
/// fixtures already pin the T8030 offsets and the patched output hash; what they
/// cannot reach is the fail-closed behaviour, because every shipped kernelcache
/// is well formed. These images exercise that.
///
/// The resolver reads bytes and searches for a string, so a plain buffer is
/// enough. No Mach-O structure is needed.
final class KernelIdentityResolverTests: XCTestCase {
    private let prefix = "/RELEASE_ARM64_"

    /// One buffer holding each supplied version string, NUL terminated and
    /// separated by padding, in the shape a real kernelcache has.
    private func image(versions: [String]) -> BinaryImage {
        var data = Data(count: 32)
        for version in versions {
            data.append(Data(version.utf8))
            data.append(0)
            data.append(Data(count: 32))
        }
        return BinaryImage(data: data)
    }

    private func records(_ versions: [String]) throws -> [PatchRecord] {
        try KernelIdentityResolver().resolve(in: image(versions: versions))
    }

    // MARK: - The patch itself

    func testBothVersionStringsAreMarkedWithoutChangingLength() throws {
        let version = "Darwin Kernel Version 25.0.0: root:xnu-13432.40.144~55/RELEASE_ARM64_T8030"
        let records = try records([version, version])

        XCTAssertEqual(records.map(\.id), ["kernel.identity.0", "kernel.identity.1"])
        for record in records {
            XCTAssertEqual(record.component, "kernelcache")
            XCTAssertEqual(String(decoding: record.originalBytes, as: UTF8.self), "/RELEASE_ARM64_T8030")
            XCTAssertEqual(String(decoding: record.replacementBytes, as: UTF8.self), "/PATCHED_ARM64_T8030")
            // A different length would move data and invalidate the container.
            XCTAssertEqual(record.originalBytes.count, record.replacementBytes.count)
        }
        // Ascending, so index 0 is the earlier string.
        XCTAssertLessThan(records[0].offset, records[1].offset)
    }

    func testTheRecordsLandOnTheAnchorOffsets() throws {
        let version = "xnu-1~1/RELEASE_ARM64_T8030"
        let data = image(versions: [version, version])
        let anchors = data.findAll(utf8: prefix)
        let records = try KernelIdentityResolver().resolve(in: data)

        XCTAssertEqual(records.map(\.offset), anchors.sorted())
        for record in records {
            // The preimage must be exactly what is in the buffer, or the guarded
            // applier would refuse it.
            XCTAssertEqual(
                try data.bytes(at: record.offset, count: record.originalBytes.count),
                record.originalBytes
            )
        }
    }

    /// The SoC token is read from the binary, which is the point of the change.
    func testTheSoCTokenComesFromTheBinaryNotFromAConstant() throws {
        for platform in ["T8020", "T8101", "T6000"] {
            let records = try records(Array(repeating: "xnu-1~1/RELEASE_ARM64_\(platform)", count: 2))
            XCTAssertEqual(
                String(decoding: records[0].originalBytes, as: UTF8.self),
                "/RELEASE_ARM64_\(platform)"
            )
            XCTAssertEqual(
                String(decoding: records[0].replacementBytes, as: UTF8.self),
                "/PATCHED_ARM64_\(platform)"
            )
        }
    }

    // MARK: - Fail closed

    func testAnAbsentAnchorIsRejected() {
        XCTAssertThrowsError(try records(["Darwin Kernel Version 25.0.0: no platform token here"])) { error in
            guard case PatchfinderError.missingAnchor = error else {
                return XCTFail("expected missingAnchor, got \(error)")
            }
        }
    }

    func testAThirdOccurrenceIsRejectedRatherThanGuessed() {
        let version = "xnu-1~1/RELEASE_ARM64_T8030"
        XCTAssertThrowsError(try records([version, version, version])) { error in
            guard case let PatchfinderError.ambiguousAnchor(_, count) = error else {
                return XCTFail("expected ambiguousAnchor, got \(error)")
            }
            XCTAssertEqual(count, 3)
        }
    }

    func testASingleOccurrenceIsRejected() {
        XCTAssertThrowsError(try records(["xnu-1~1/RELEASE_ARM64_T8030"])) { error in
            guard case let PatchfinderError.ambiguousAnchor(_, count) = error else {
                return XCTFail("expected ambiguousAnchor, got \(error)")
            }
            XCTAssertEqual(count, 1)
        }
    }

    /// Two anchors whose tokens differ mean the anchor did not land on the
    /// paired copies of one version string, so no patch is proposed.
    func testDisagreeingTokensAreRejected() {
        XCTAssertThrowsError(
            try records(["xnu-1~1/RELEASE_ARM64_T8030", "xnu-1~1/RELEASE_ARM64_T8020"])
        ) { error in
            guard case let PatchfinderError.noCandidate(reason) = error else {
                return XCTFail("expected noCandidate, got \(error)")
            }
            XCTAssertTrue(reason.contains("T8030"), reason)
            XCTAssertTrue(reason.contains("T8020"), reason)
        }
    }

    /// The prefix immediately followed by a non-alphanumeric byte yields an
    /// empty token, which means this is not a version string.
    func testAnEmptyTokenIsRejected() {
        XCTAssertThrowsError(try records(["xnu-1~1/RELEASE_ARM64_", "xnu-1~1/RELEASE_ARM64_"])) { error in
            guard case PatchfinderError.missingAnchor = error else {
                return XCTFail("expected missingAnchor, got \(error)")
            }
        }
    }

    /// An anchor that ends the buffer leaves no room for a token. The clamp in
    /// platformToken must turn that into a missing anchor, not an out-of-bounds
    /// read.
    func testAnAnchorAtTheEndOfTheImageIsRejected() {
        var data = Data(count: 32)
        data.append(Data(prefix.utf8))
        data.append(Data(count: 32))
        data.append(Data(prefix.utf8))
        let image = BinaryImage(data: data)
        XCTAssertEqual(image.findAll(utf8: prefix).count, 2)

        XCTAssertThrowsError(try KernelIdentityResolver().resolve(in: image)) { error in
            guard case PatchfinderError.missingAnchor = error else {
                return XCTFail("expected missingAnchor, got \(error)")
            }
        }
    }

    // MARK: - The length bound

    /// A token longer than the scan bound is truncated, which is safe: the
    /// record's preimage is still a real prefix of the buffer, both sides stay
    /// the same length, and the only edit remains RELEASE to PATCHED. This pins
    /// that property so the bound cannot quietly become a mispatch.
    func testAnOverlongTokenStillProducesASameLengthPrefixPatch() throws {
        let token = String(repeating: "A", count: 24)
        let data = image(versions: Array(repeating: "xnu-1~1/RELEASE_ARM64_\(token)", count: 2))
        let records = try KernelIdentityResolver().resolve(in: data)

        for record in records {
            XCTAssertEqual(record.originalBytes.count, record.replacementBytes.count)
            XCTAssertEqual(
                try data.bytes(at: record.offset, count: record.originalBytes.count),
                record.originalBytes
            )
            let original = String(decoding: record.originalBytes, as: UTF8.self)
            let replacement = String(decoding: record.replacementBytes, as: UTF8.self)
            XCTAssertTrue(original.hasPrefix("/RELEASE_ARM64_A"), original)
            XCTAssertTrue(replacement.hasPrefix("/PATCHED_ARM64_A"), replacement)
            // Everything after the prefix is carried through untouched.
            XCTAssertEqual(original.dropFirst("/RELEASE_ARM64_".count), replacement.dropFirst("/PATCHED_ARM64_".count))
        }
    }
}
