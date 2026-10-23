import Foundation

/// The four kernel patches needed by libkrw's tfp0 adapter.
public struct KernelTFP0Resolver: Sendable {
    public static let name = "kernel-tfp0"
    static let variantKey = name
    static let signatureID = "ios27-24A435-tfp0-v2"
    static let payloadID = "task-for-pid-zero-slide-v2"
    private static let kernelSlideFormat = "KernelCache slide: 0x%016lx\n"
    private static let slideRecordID = "kernel.tfp0.dyld-info-slide"

    /// `task_info(TASK_DYLD_INFO)` normally returns the userspace dyld-info
    /// pointer and size. libkrw0-tfp0 deliberately uses the same fields as a
    /// kernel-slide transport: address 0 means the backend contract is active,
    /// and size carries `vm_kernel_slide`.
    ///
    /// The three instructions that become the transport are excluded from the
    /// signature so the resolver is idempotent. The surrounding count checks,
    /// branch conditions, second-field store and register flow stay pinned.
    private static let taskDyldInfoPattern: MaskedInstructionPattern = {
        let words: [UInt32] = [
            0xB940_02A8, 0x7100_111F, 0x5400_1A83,
            0xF941_F288, 0xF900_02C8, 0xF941_F688,
            0xF900_06C8, 0xB940_02A8, 0x7100_151F, 0x5400_24C3,
        ]
        let reference = MaskedInstructionPattern(
            name: "TASK_DYLD_INFO result construction",
            referenceWords: words,
            allowDataLayoutDrift: true
        )
        var masks = reference.masks
        masks[3] = 0
        masks[4] = 0
        masks[5] = 0
        return MaskedInstructionPattern(
            name: reference.name,
            values: zip(words, masks).map { $0 & $1 },
            masks: masks
        )
    }()

    /// Clean bytes shared by the supported profiles. These reconstruct an
    /// idempotent record after an exact profile-gated build is already patched.
    private static let taskDyldInfoOriginal: [UInt32] = [
        0xF941_F288, 0xF900_02C8, 0xF941_F688,
    ]

    private struct Site: Sendable {
        let id: String
        let summary: String
        let pattern: MaskedInstructionPattern
        let patchIndex: Int
        let original: UInt32
        let replacement: UInt32

        init(
            id: String,
            summary: String,
            patternName: String,
            words: [UInt32],
            patchIndex: Int,
            replacement: UInt32,
            allowDataLayoutDrift: Bool = false
        ) {
            precondition(words.indices.contains(patchIndex))
            let reference = MaskedInstructionPattern(
                name: patternName,
                referenceWords: words,
                allowDataLayoutDrift: allowDataLayoutDrift
            )
            var masks = reference.masks
            masks[patchIndex] = 0

            self.id = id
            self.summary = summary
            self.pattern = MaskedInstructionPattern(
                name: patternName,
                values: zip(words, masks).map { $0 & $1 },
                masks: masks
            )
            self.patchIndex = patchIndex
            self.original = words[patchIndex]
            self.replacement = replacement
        }
    }

    private static let sites = [
        Site(
            id: "kernel.tfp0.task-conversion",
            summary: "Make the task-conversion success edge unconditional",
            patternName: "tfp0 task conversion",
            words: [
                0xAA00_03E8, 0xAA13_03E0, 0x3400_0268, 0x5280_0008,
                0xEB01_001F, 0x5400_0240, 0xB0FE_D5A9, 0xF945_3129,
                0xEB09_001F, // CMP X0,X9
                0x5400_01C0, 0xEB09_003F, 0x5400_0160,
            ],
            patchIndex: 8,
            replacement: 0xEB1F_03FF, // CMP XZR,XZR
            allowDataLayoutDrift: true
        ),
        Site(
            id: "kernel.tfp0.pid-zero",
            summary: "Let task_for_pid continue when PID is zero",
            patternName: "tfp0 PID-zero gate",
            words: [
                0x9101_C3FD, 0xAA00_03E8, 0xB940_0000, 0xB940_0917,
                0xF940_0913, 0xB900_1FFF, 0xA900_FFFF, 0xF900_03FF,
                0x3400_07F7, // CBZ W23,reject
                0x5280_0001, 0x5280_0002, 0x5280_0003,
                0xD280_0004, 0x9400_0000, 0xB400_0720, 0xAA00_03F4,
            ],
            patchIndex: 8,
            replacement: ARM64.nop
        ),
        Site(
            id: "kernel.tfp0.kernel-map",
            summary: "Skip the userspace kernel_pmap panic",
            patternName: "tfp0 kernel-map panic",
            words: [
                0xF2E4_A191, 0xDAC1_1A30, 0xAA10_03F1, 0xDAC1_47F1,
                0xEB11_021F, 0x5400_0040, 0xD438_8E40, 0xB000_59A8,
                0x9122_4108, 0xEB08_021F,
                0x5400_0141, // B.NE allowed
                0x5281_6C08,
            ],
            patchIndex: 10,
            replacement: 0x1400_000A, // B allowed
            allowDataLayoutDrift: true
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
        let records = try Self.sites.map { site in
            let start = try site.pattern.uniqueMatch(in: image, layout: layout)
            let offset = start + UInt64(site.patchIndex * 4)
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
        return records + [try taskDyldInfoSlideRecord(in: image, layout: layout)]
    }

    private func taskDyldInfoSlideRecord(
        in image: BinaryImage,
        layout: MachOLayout
    ) throws -> PatchRecord {
        let slide = try kernelSlideGlobal(in: image, layout: layout)
        let sequence = try Self.taskDyldInfoPattern.uniqueMatch(in: image, layout: layout)
        let site = sequence + 12

        let finalStore = try image.readUInt32(at: site + 12)
        guard isUnsigned64Store(finalStore), unsignedByteOffset(finalStore) == 8 else {
            throw PatchfinderError.invalidPatch(
                id: Self.slideRecordID,
                reason: "TASK_DYLD_INFO second result field is not a 64-bit +8 store"
            )
        }
        let valueRegister = finalStore & 0x1F
        let outputRegister = (finalStore >> 5) & 0x1F
        guard valueRegister != 31,
              outputRegister != 31,
              let siteAddress = layout.virtualAddress(forFileOffset: site),
              let page = ARM64.encodeADRP(
                register: valueRegister,
                instructionOffset: siteAddress,
                target: slide.virtualAddress
              ),
              let load = ARM64.encodeLoadUnsigned64(
                destination: valueRegister,
                base: valueRegister,
                byteOffset: UInt32(slide.virtualAddress & 0xFFF)
              ),
              let clearAddress = ARM64.encodeStoreUnsigned64(
                source: 31,
                base: outputRegister,
                byteOffset: 0
              )
        else {
            throw PatchfinderError.invalidPatch(
                id: Self.slideRecordID,
                reason: "cannot encode the TASK_DYLD_INFO slide transport"
            )
        }

        let replacementWords = [page, load, clearAddress]
        let replacement = littleEndianData(replacementWords)
        let current = try image.bytes(at: site, count: replacement.count)
        let original: Data
        if current == replacement {
            original = littleEndianData(Self.taskDyldInfoOriginal)
        } else {
            try validateCleanTaskDyldInfo(
                current: current,
                valueRegister: valueRegister,
                outputRegister: outputRegister
            )
            original = current
        }

        return PatchRecord(
            id: Self.slideRecordID,
            component: "kernelcache",
            offset: site,
            originalBytes: original,
            replacementBytes: replacement,
            summary: "Return vm_kernel_slide through TASK_DYLD_INFO for libkrw0-tfp0",
            evidence: [
                "unique TASK_DYLD_INFO count checks and two-field result construction",
                "unique \(Self.kernelSlideFormat.trimmingCharacters(in: .newlines)) format string",
                "the value spilled immediately before that format string resolves to vm_kernel_slide at \(slide.fileOffset.hex)",
                "the replacement clears all_image_info_addr and returns the live slide in all_image_info_size",
            ]
        )
    }

    private func kernelSlideGlobal(
        in image: BinaryImage,
        layout: MachOLayout
    ) throws -> (fileOffset: UInt64, virtualAddress: UInt64) {
        let strings = image.findAll(utf8: Self.kernelSlideFormat, nulTerminated: true)
        guard strings.count == 1, let string = strings.first else {
            if strings.isEmpty { throw PatchfinderError.missingAnchor(Self.kernelSlideFormat) }
            throw PatchfinderError.ambiguousAnchor(Self.kernelSlideFormat, count: strings.count)
        }
        let references = try layout.adrpAddReferences(toFileOffset: string)
        guard references.count == 1, let reference = references.first else {
            if references.isEmpty {
                throw PatchfinderError.missingAnchor("kernel slide format reference")
            }
            throw PatchfinderError.ambiguousAnchor(
                "kernel slide format reference",
                count: references.count
            )
        }
        guard reference.adrpOffset >= 12,
              try image.readUInt32(at: reference.adrpOffset) & 0x1F == 0,
              try image.readUInt32(at: reference.addOffset) & 0x1F == 0,
              ARM64.branchLinkTarget(
                instruction: try image.readUInt32(at: reference.addOffset + 4),
                at: reference.addOffset + 4
              ) != nil
        else {
            throw PatchfinderError.noCandidate("kernel slide formatter X0 argument")
        }

        let pageOffset = reference.adrpOffset - 12
        let page = try image.readUInt32(at: pageOffset)
        let load = try image.readUInt32(at: pageOffset + 4)
        let spill = try image.readUInt32(at: pageOffset + 8)
        let pageRegister = page & 0x1F
        let valueRegister = load & 0x1F
        guard page & 0x9F00_0000 == 0x9000_0000,
              pageRegister != 31,
              isUnsigned64Load(load),
              valueRegister != 31,
              (load >> 5) & 0x1F == pageRegister,
              isUnsigned64Store(spill),
              spill & 0x1F == valueRegister,
              (spill >> 5) & 0x1F == 31,
              let pageAddress = layout.virtualAddress(forFileOffset: pageOffset)
        else {
            throw PatchfinderError.noCandidate("vm_kernel_slide formatter argument load")
        }

        let virtualAddress = ARM64.adrpTarget(instruction: page, at: pageAddress)
            + UInt64(unsignedByteOffset(load))
        guard let fileOffset = layout.fileOffset(forVirtualAddress: virtualAddress),
              layout.segments.contains(where: {
                $0.fileRange.contains(fileOffset) && !$0.isExecutable
              })
        else {
            throw PatchfinderError.invalidPatch(
                id: Self.slideRecordID,
                reason: "vm_kernel_slide does not resolve to mapped data"
            )
        }
        return (fileOffset, virtualAddress)
    }

    private func validateCleanTaskDyldInfo(
        current: Data,
        valueRegister: UInt32,
        outputRegister: UInt32
    ) throws {
        let words = current.withUnsafeBytes { bytes in
            (0..<3).map { index in
                UInt32(littleEndian: bytes.loadUnaligned(
                    fromByteOffset: index * MemoryLayout<UInt32>.size,
                    as: UInt32.self
                ))
            }
        }
        let firstLoad = words[0]
        let addressStore = words[1]
        let secondLoad = words[2]
        guard isUnsigned64Load(firstLoad),
              firstLoad & 0x1F == valueRegister,
              isUnsigned64Store(addressStore),
              addressStore & 0x1F == valueRegister,
              (addressStore >> 5) & 0x1F == outputRegister,
              unsignedByteOffset(addressStore) == 0,
              isUnsigned64Load(secondLoad),
              secondLoad & 0x1F == valueRegister,
              (secondLoad >> 5) & 0x1F == (firstLoad >> 5) & 0x1F,
              unsignedByteOffset(secondLoad) == unsignedByteOffset(firstLoad) + 8
        else {
            throw PatchfinderError.invalidPatch(
                id: Self.slideRecordID,
                reason: "unexpected TASK_DYLD_INFO result construction"
            )
        }
    }

    private func isUnsigned64Load(_ instruction: UInt32) -> Bool {
        instruction & 0xFFC0_0000 == 0xF940_0000
    }

    private func isUnsigned64Store(_ instruction: UInt32) -> Bool {
        instruction & 0xFFC0_0000 == 0xF900_0000
    }

    private func unsignedByteOffset(_ instruction: UInt32) -> UInt32 {
        ((instruction >> 10) & 0xFFF) * 8
    }

    private func littleEndianData(_ words: [UInt32]) -> Data {
        var data = Data()
        for word in words {
            var littleEndian = word.littleEndian
            withUnsafeBytes(of: &littleEndian) { data.append(contentsOf: $0) }
        }
        return data
    }
}
