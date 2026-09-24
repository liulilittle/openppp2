// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "OpenPPP2LogicTests",
    platforms: [.iOS(.v15), .macOS(.v13)],
    products: [],
    targets: [
        .target(
            name: "OpenPPP2Logic",
            path: "OpenPPP2",
            sources: [
                "AppGroupResolver.swift",
                "AppModels.swift",
                "TunnelSharedState.swift",
                "ProfileImportExport.swift",
                "Runtime/RuntimeSnapshot.swift",
                "Runtime/RuntimeStore.swift",
                "Runtime/RuntimeTrafficRate.swift",
                "Runtime/RuntimeControls.swift",
                "Runtime/TunnelRuntimeBridge.swift",
                "SubscriptionUrlPolicy.swift",
            ]
        ),
        .testTarget(
            name: "OpenPPP2LogicTests",
            dependencies: ["OpenPPP2Logic"],
            path: "Tests/OpenPPP2LogicTests"
        ),
    ]
)
