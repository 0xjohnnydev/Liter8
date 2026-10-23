import Foundation

/// The three PongoOS-style patches needed by libkrw's tfp0 adapter.
public struct KernelTFP0Resolver: Sendable {
    public static let name = "kernel-tfp0"
    static let variantKey = name
    static let signatureID = "ios27-24A435-tfp0-v1"
    static let payloadID = "task-for-pid-zero-v1"

    private struct Site: Sendable {
        let id: String
        let summary: String
        let pattern: MaskedInstructionPattern
        let wordIndex: Int
        let original: UInt32
        let replacement: UInt32
    }

    private static let sites = [
        Site(
            id: "kernel.tfp0.task-conversion",
            summary: "Make the task-conversion success edge unconditional",
            pattern: patchPattern(
                name: "tfp0 task conversion",
                words: [
                    0xAA00_03E8, 0xAA13_03E0, 0x3400_0268, 0x5280_0008,
                    0xEB01_001F, 0x5400_0240, 0xB0FE_D5A9, 0xF945_3129,
                    0xEB09_001F, 0x5400_01C0, 0xEB09_003F, 0x5400_0160,
                ],
                patchIndex: 8,
                allowDataLayoutDrift: true
            ),
            wordIndex: 8,
            original: 0xEB09_001F,       // CMP X0,X9
            replacement: 0xEB1F_03FF     // CMP XZR,XZR
        ),
        Site(
            id: "kernel.tfp0.pid-zero",
            summary: "Let task_for_pid continue when PID is zero",
            pattern: patchPattern(
                name: "tfp0 PID-zero gate",
                words: [
                    0x9101_C3FD, 0xAA00_03E8, 0xB940_0000, 0xB940_0917,
                    0xF940_0913, 0xB900_1FFF, 0xA900_FFFF, 0xF900_03FF,
                    0x3400_07F7, 0x5280_0001, 0x5280_0002, 0x5280_0003,
                    0xD280_0004, 0x9400_0000, 0xB400_0720, 0xAA00_03F4,
                ],
                patchIndex: 8
            ),
            wordIndex: 8,
            original: 0x3400_07F7,       // CBZ W23,reject
            replacement: ARM64.nop
        ),
        Site(
            id: "kernel.tfp0.kernel-map",
            summary: "Skip the userspace kernel_pmap panic",
            pattern: patchPattern(
                name: "tfp0 kernel-map panic",
                words: [
                    0xF2E4_A191, 0xDAC1_1A30, 0xAA10_03F1, 0xDAC1_47F1,
                    0xEB11_021F, 0x5400_0040, 0xD438_8E40, 0xB000_59A8,
                    0x9122_4108, 0xEB08_021F, 0x5400_0141, 0x5281_6C08,
                ],
                patchIndex: 10,
                allowDataLayoutDrift: true
            ),
            wordIndex: 10,
            original: 0x5400_0141,       // B.NE allowed
            replacement: 0x1400_000A     // B allowed
        ),
    ]

    public init() {}

    static func requiredRecords(in image: BinaryImage) throws -> [PatchRecord] {
        let profile = KernelResolverProfileRegistry.detect(in: image)
        guard let profile,
              let variant = profile.variants(for: variantKey),
              variant.support == .supported,
              variant.signature == signatureID,
              variant.payload == payloadID
        else {
            throw PatchfinderError.unsupportedFirmwareProfile(
                resolver: Self.name,
                profile: profile?.id ?? "unidentified",
                variant: "unregistered"
            )
        }
        return try Self().resolve(in: image)
    }

    public func resolve(in image: BinaryImage) throws -> [PatchRecord] {
        let layout = try MachOLayout(image: image)
        return try Self.sites.map { site in
            let start = try site.pattern.uniqueMatch(in: image, layout: layout)
            let offset = start + UInt64(site.wordIndex * 4)
            let current = try image.readUInt32(at: offset)
            guard current == site.original || current == site.replacement else {
                throw PatchfinderError.invalidPatch(
                    id: site.id,
                    reason: "unexpected instruction at \(offset.hex)"
                )
            }
            return PatchRecord(
                id: site.id,
                component: "kernelcache",
                offset: offset,
                original: site.original,
                replacement: site.replacement,
                summary: site.summary,
                evidence: ["unique \(site.pattern.name) instruction sequence"]
            )
        }
    }

    private static func patchPattern(
        name: String,
        words: [UInt32],
        patchIndex: Int,
        allowDataLayoutDrift: Bool = false
    ) -> MaskedInstructionPattern {
        let reference = MaskedInstructionPattern(
            name: name,
            referenceWords: words,
            allowDataLayoutDrift: allowDataLayoutDrift
        )
        var masks = reference.masks
        masks[patchIndex] = 0
        return MaskedInstructionPattern(
            name: name,
            values: zip(words, masks).map { $0 & $1 },
            masks: masks
        )
    }
}
