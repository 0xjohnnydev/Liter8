import Foundation
import XCTest
@testable import Liter8Core

final class TXMResolverTests: XCTestCase {
    private var packageRoot: URL {
        liter8PackageRoot(from: #filePath)
    }

    private var beta4TXM: URL {
        liter8PrivateFixtureRoot(from: #filePath)
            .appendingPathComponent("offsets/txm/txm_b4_n104.raw")
    }

    override func setUpWithError() throws {
        guard FileManager.default.fileExists(atPath: beta4TXM.path) else {
            throw XCTSkip("local beta-4 TXM fixture is absent")
        }
    }

    func testQueryModuleResolverSelectsThreeCDHashComparisons() throws {
        let records = try TXMQueryModuleResolver().resolve(
            in: BinaryImage(contentsOf: beta4TXM)
        )
        XCTAssertEqual(records.map(\.offset), [0x39E28, 0x39F90, 0x3A124])
        XCTAssertEqual(records.compactMap(\.replacementWord), Array(repeating: 0xD2800000, count: 3))
    }

    func testConstraintResolverSelectsBothIndependentChecks() throws {
        let records = try TXMConstraintsResolver().resolve(
            in: BinaryImage(contentsOf: beta4TXM)
        )
        XCTAssertEqual(Set(records.map(\.offset)), Set([0x3F624, 0x3F690, 0x3F698]))
    }

    func testBootStateResolverLinksBothFunctionsThroughSharedState() throws {
        let records = try TXMBootStateResolver().resolve(
            in: BinaryImage(contentsOf: beta4TXM)
        )
        XCTAssertEqual(Set(records.map(\.offset)), Set([0x2BCD4, 0x2BCD8, 0x2BA58]))
    }

    // MARK: - Debug mapping (every fw get-boot boot)

    /// The three allow branches, each becoming a B to the TBNZ's own target:
    /// +0x18, +0x38 and +0xEC, which is why the replacements are fixed here.
    private let debugMappingBeta4: [UInt64: UInt32] = [
        0x2B3D8: 0x1400_0006, // error 37, caller entitlement
        0x2B420: 0x1400_000E, // error 29, address-space mark
        0x28A34: 0x1400_003B, // error 30, validator's read of the same mark
    ]

    func testDebugMappingResolverForcesThreeAllowBranches() throws {
        let records = try TXMDebugMappingResolver().resolve(in: BinaryImage(contentsOf: beta4TXM))
        XCTAssertEqual(
            Dictionary(uniqueKeysWithValues: records.map { ($0.offset, $0.replacementWord) }),
            debugMappingBeta4
        )
        XCTAssertEqual(records.compactMap(\.originalWord).filter { $0 & 0xFFF8_0000 == 0x3700_0000 }.count, 3)
    }

    /// Same sites on the 27.2 build the device runs, where every offset moved.
    func testDebugMappingResolverOn24B5099f() throws {
        let txm = liter8PrivateFixtureRoot(from: #filePath)
            .appendingPathComponent("offsets/txm/txm_24B5099f_n104_pristine.raw")
        guard FileManager.default.fileExists(atPath: txm.path) else {
            throw XCTSkip("local 24B5099f TXM fixture is absent")
        }
        let records = try TXMDebugMappingResolver().resolve(in: BinaryImage(contentsOf: txm))
        XCTAssertEqual(
            Dictionary(uniqueKeysWithValues: records.map { ($0.offset, $0.replacementWord) }),
            [0x2F408: 0x1400_0006, 0x2F450: 0x1400_000E, 0x2CA64: 0x1400_003B]
        )
    }

    func testBootDebugPlanIsBootPlanPlusDebugMapping() throws {
        let image = try BinaryImage(contentsOf: beta4TXM)
        let boot = try TXMBootResolver().resolve(in: image)
        let debug = try TXMDebugMappingResolver().resolve(in: image)
        let plan = try TXMBootDebugResolver().resolve(in: image)
        XCTAssertEqual(plan.map(\.offset), boot.map(\.offset) + debug.map(\.offset))
        XCTAssertTrue(Set(boot.map(\.offset)).isDisjoint(with: debug.map(\.offset)))
        XCTAssertEqual(plan.count, 12)
    }

    /// Pointing the error-37 branch anywhere but the entitlement's allow target
    /// must refuse, not patch a branch to the wrong place.
    func testDebugMappingRejectsCallerBranchWithForeignTarget() throws {
        let image = try mutatedBeta4([0x2B3D8: 0x3700_00E8]) // TBNZ W8,#0,+0x1C
        assertThrows(try TXMDebugMappingResolver().resolve(in: image)) {
            if case .invalidPatch = $0 { return true } else { return false }
        }
    }

    /// The skipped path must really be the one that sets error 37.
    func testDebugMappingRejectsWhenRefusalIsNotError37() throws {
        let image = try mutatedBeta4([0x2B3E8: 0x5280_04D4]) // MOV W20,#0x26
        assertThrows(try TXMDebugMappingResolver().resolve(in: image)) {
            if case .noCandidate = $0 { return true } else { return false }
        }
    }

    /// A TBNZ that does not test the byte just loaded is not the mark check.
    func testDebugMappingRejectsBrokenMarkRegisterChain() throws {
        let image = try mutatedBeta4([0x2B420: 0x3700_01C9]) // TBNZ W9 instead of W8
        assertThrows(try TXMDebugMappingResolver().resolve(in: image)) {
            if case .noCandidate = $0 { return true } else { return false }
        }
    }

    func testDebugMappingRejectsValidatorBranchWithForeignTarget() throws {
        let image = try mutatedBeta4([0x28A34: 0x3700_0788]) // TBNZ W8,#0,+0xF0
        assertThrows(try TXMDebugMappingResolver().resolve(in: image)) {
            if case .invalidPatch = $0 { return true } else { return false }
        }
    }

    // MARK: - Permissive flags (every fw get-boot boot)

    /// The call becomes MOV X0,#-1 and four stores switch their source to W0;
    /// each replacement is the original store with Rt cleared, decoded by hand:
    /// STRH WZR,[X20,#0x218] / STRB WZR,[X20,#0x21A] / STRB W8,[X20,#0x21E] /
    /// STRH WZR,[X20,#0x2C4].
    func testPermissiveFlagsResolverOnBeta4() throws {
        let records = try TXMPermissiveFlagsResolver().resolve(in: BinaryImage(contentsOf: beta4TXM))
        XCTAssertEqual(
            Dictionary(uniqueKeysWithValues: records.map { ($0.offset, $0.replacementWord) }),
            [
                0x2C354: 0x9280_0000,
                0x2C35C: 0x7904_3280,
                0x2C364: 0x3908_6A80,
                0x2C370: 0x3908_7A80,
                0x2C374: 0x7905_8A80,
            ]
        )
    }

    /// 24B5099f moves the struct by 8 and the code by 0x4054; the block keeps
    /// its shape. STRH WZR,[X20,#0x220] / STRB WZR,[X20,#0x222] /
    /// STRB W8,[X20,#0x226] / STRH WZR,[X20,#0x2CC].
    func testPermissiveFlagsResolverOn24B5099f() throws {
        let txm = liter8PrivateFixtureRoot(from: #filePath)
            .appendingPathComponent("offsets/txm/txm_24B5099f_n104_pristine.raw")
        guard FileManager.default.fileExists(atPath: txm.path) else {
            throw XCTSkip("local 24B5099f TXM fixture is absent")
        }
        let records = try TXMPermissiveFlagsResolver().resolve(in: BinaryImage(contentsOf: txm))
        XCTAssertEqual(
            Dictionary(uniqueKeysWithValues: records.map { ($0.offset, $0.replacementWord) }),
            [
                0x303A8: 0x9280_0000,
                0x303B0: 0x7904_4280,
                0x303B8: 0x3908_8A80,
                0x303C4: 0x3908_9A80,
                0x303C8: 0x7905_9A80,
            ]
        )
    }

    /// Boot plan, the two mark branches, then the flags. The error-37 branch
    /// (0x2B3D8 on beta 4) is the one left out: the task_for_pid flag covers it.
    func testBootPermissivePlanIsBootPlusMarkBranchesPlusFlags() throws {
        let image = try BinaryImage(contentsOf: beta4TXM)
        let boot = try TXMBootResolver().resolve(in: image)
        let flags = try TXMPermissiveFlagsResolver().resolve(in: image)
        let plan = try TXMBootPermissiveResolver().resolve(in: image)
        XCTAssertEqual(plan.map(\.offset), boot.map(\.offset) + [0x2B420, 0x28A34] + flags.map(\.offset))
        XCTAssertFalse(plan.map(\.offset).contains(0x2B3D8))
        XCTAssertEqual(Set(plan.map(\.offset)).count, plan.count)
        XCTAssertEqual(plan.count, 16)
    }

    /// A consistent block whose task_for_pid halfword is not the byte the
    /// selector-42 handler tests must refuse: STRH WZR,[X20,#0x2C6] and
    /// STRB WZR,[X20,#0x2CC] keep the +6 spacing but move Y by two.
    func testPermissiveFlagsRejectsHalfwordTheHandlerDoesNotRead() throws {
        let image = try mutatedBeta4([0x2C374: 0x7905_8E9F, 0x2C378: 0x390B_329F])
        assertThrows(try TXMPermissiveFlagsResolver().resolve(in: image)) {
            if case .invalidPatch = $0 { return true } else { return false }
        }
    }

    /// The internal-CA store through a different base (X21) breaks the block.
    func testPermissiveFlagsRejectsMixedBaseRegister() throws {
        let image = try mutatedBeta4([0x2C360: 0x3908_6EA0]) // STRB W0,[X21,#0x21B]
        assertThrows(try TXMPermissiveFlagsResolver().resolve(in: image)) {
            if case .noCandidate = $0 { return true } else { return false }
        }
    }

    /// If CoreTrust's halfword is no longer a zero store, the block is not the
    /// one this plan understands, so nothing is patched.
    func testPermissiveFlagsRejectsChangedCoreTrustStore() throws {
        let image = try mutatedBeta4([0x2C368: 0x7904_3A80]) // STRH W0,[X20,#0x21C]
        assertThrows(try TXMPermissiveFlagsResolver().resolve(in: image)) {
            if case .noCandidate = $0 { return true } else { return false }
        }
    }

    /// A block that loads, extracts and stores the profile bit through W0 is
    /// otherwise consistent, but the LDRB would overwrite the patched all-ones
    /// X0 before the W0 stores run: LDRB W0,[X20,#0x2CC] / UBFX W0,W0,#1,#1 /
    /// STRB W0,[X20,#0x21E].
    func testPermissiveFlagsRejectsW0AsTheLoadRegister() throws {
        let image = try mutatedBeta4([0x2C358: 0x394B_3280, 0x2C36C: 0x5301_0400, 0x2C370: 0x3908_7A80])
        assertThrows(try TXMPermissiveFlagsResolver().resolve(in: image)) {
            if case .noCandidate = $0 { return true } else { return false }
        }
    }

    private func mutatedBeta4(_ words: [UInt64: UInt32]) throws -> BinaryImage {
        var data = try Data(contentsOf: beta4TXM)
        for (offset, word) in words {
            let start = Int(offset)
            data.replaceSubrange(start..<start + 4, with: withUnsafeBytes(of: word.littleEndian, Array.init))
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

    func testTXMPlanManifestsVerifyCompleteOutputs() throws {
        let cases = [
            ("fixtures/24A5390f/n104ap/txm-restore-n104-24A5390f.json", 6),
            ("fixtures/24A5390f/n104ap/txm-boot-n104-24A5390f.json", 9),
        ]
        for (manifestPath, expectedCount) in cases {
            let manifest = try FixtureManifest.load(
                from: packageRoot.appendingPathComponent(manifestPath)
            )
            XCTAssertEqual(
                try manifest.verify(binaryAt: beta4TXM).count,
                expectedCount,
                manifestPath
            )
        }
    }
}
