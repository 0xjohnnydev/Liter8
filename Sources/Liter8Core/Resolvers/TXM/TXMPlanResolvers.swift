import Foundation

/// Six patches needed while restoring: trust-cache comparisons plus both
/// constraint-validation families. Normal-boot state changes are intentionally
/// excluded from the restore plan.
public struct TXMRestoreResolver: Sendable {
    public static let name = "txm-restore"
    public init() {}

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        try TXMQueryModuleResolver().resolve(in: image)
            + TXMConstraintsResolver().resolve(in: image)
    }
}

/// Nine-patch normal-boot plan: the restore-safe six plus secure-channel and
/// developer-mode state publication.
public struct TXMBootResolver: Sendable {
    public static let name = "txm-boot"
    public init() {}

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        try TXMRestoreResolver().resolve(in: image)
            + TXMBootStateResolver().resolve(in: image)
    }
}

/// Normal-boot plan for runtime function hooks without the policy flags: the
/// boot plan plus the three debug-mapping branches. Kept as a named plan;
/// `fw get-boot` builds `boot-permissive` instead.
public struct TXMBootDebugResolver: Sendable {
    public static let name = "txm-boot-debug"
    public init() {}

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        try TXMBootResolver().resolve(in: image)
            + TXMDebugMappingResolver().resolve(in: image)
    }
}

/// The plan `fw get-boot` builds: the boot plan, the permissive policy flags
/// (any signature, local signing, profile trust, CS enforcement, task_for_pid)
/// and the two debug-mapping branches the flags cannot reach.
///
/// The task_for_pid flag is the byte the error-37 branch tests, so that branch
/// (`txm.debug-mapping.caller-entitlement`) is left stock; measured on n104
/// 24B5099f, with the flags and no branches TXM refused at error 29, past 37.
/// The address-space mark checks (errors 29 and 30) read no config byte and
/// keep their branches.
public struct TXMBootPermissiveResolver: Sendable {
    public static let name = "txm-boot-permissive"
    public init() {}

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        let markBranches = try TXMDebugMappingResolver().resolve(in: image)
            .filter { $0.id != "txm.debug-mapping.caller-entitlement" }
        guard markBranches.count == 2 else {
            throw PatchfinderError.invalidPatch(
                id: Self.name, reason: "expected the two address-space branches, got \(markBranches.count)"
            )
        }
        return try TXMBootResolver().resolve(in: image)
            + markBranches
            + TXMPermissiveFlagsResolver().resolve(in: image)
    }
}
