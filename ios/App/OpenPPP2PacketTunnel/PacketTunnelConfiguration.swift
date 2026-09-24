import Foundation
import OpenPPP2

func openPPP2LastErrorText() -> String {
    guard let error = openppp2_ios_last_error_text() else {
        return "Unknown OpenPPP2 error"
    }
    return String(cString: error)
}

func openPPP2LastErrorCode() -> Int {
    Int(openppp2_ios_last_error_code())
}

struct PacketTunnelOptions: Codable {
    var tunIp: String = "10.8.0.2"
    var tunMask: String = "255.255.255.0"
    var tunPrefix: Int = 24
    var gateway: String = "10.8.0.1"
    var route: String = "0.0.0.0"
    var routePrefix: Int = 0
    var dns1: String = "8.8.8.8"
    var dns2: String = "1.1.1.1"
    var mtu: Int = 1400
    var mux: Int = 0
    var vnet: Bool = false
    var lwip: Bool = false
    var blockQuic: Bool = true
    var staticMode: Bool = true
    var bypassIpList: String = "10.0.0.0/8\n172.16.0.0/12\n192.168.0.0/16\n169.254.0.0/16\n100.64.0.0/10"
    var dnsRulesList: String = ""
    var geoEnabled: Bool = true
    var routeMode: String = "geo"

    init() {}

    enum CodingKeys: String, CodingKey {
        case tunIp
        case tunMask
        case tunPrefix
        case gateway
        case route
        case routePrefix
        case dns1
        case dns2
        case mtu
        case mux
        case vnet
        case lwip
        case blockQuic
        case staticMode
        case bypassIpList
        case dnsRulesList
        case geoEnabled
        case routeMode
    }

    init(from decoder: Decoder) throws {
        let defaults = PacketTunnelOptions()
        let container = try decoder.container(keyedBy: CodingKeys.self)
        tunIp = try container.decodeIfPresent(String.self, forKey: .tunIp) ?? defaults.tunIp
        tunMask = try container.decodeIfPresent(String.self, forKey: .tunMask) ?? defaults.tunMask
        tunPrefix = try container.decodeIfPresent(Int.self, forKey: .tunPrefix) ?? defaults.tunPrefix
        gateway = try container.decodeIfPresent(String.self, forKey: .gateway) ?? defaults.gateway
        route = try container.decodeIfPresent(String.self, forKey: .route) ?? defaults.route
        routePrefix = try container.decodeIfPresent(Int.self, forKey: .routePrefix) ?? defaults.routePrefix
        dns1 = try container.decodeIfPresent(String.self, forKey: .dns1) ?? defaults.dns1
        dns2 = try container.decodeIfPresent(String.self, forKey: .dns2) ?? defaults.dns2
        mtu = try container.decodeIfPresent(Int.self, forKey: .mtu) ?? defaults.mtu
        mux = try container.decodeIfPresent(Int.self, forKey: .mux) ?? defaults.mux
        vnet = try container.decodeIfPresent(Bool.self, forKey: .vnet) ?? defaults.vnet
        lwip = try container.decodeIfPresent(Bool.self, forKey: .lwip) ?? defaults.lwip
        blockQuic = try container.decodeIfPresent(Bool.self, forKey: .blockQuic) ?? defaults.blockQuic
        staticMode = try container.decodeIfPresent(Bool.self, forKey: .staticMode) ?? defaults.staticMode
        bypassIpList = try container.decodeIfPresent(String.self, forKey: .bypassIpList) ?? defaults.bypassIpList
        dnsRulesList = try container.decodeIfPresent(String.self, forKey: .dnsRulesList) ?? defaults.dnsRulesList
        geoEnabled = try container.decodeIfPresent(Bool.self, forKey: .geoEnabled) ?? defaults.geoEnabled
        let decodedRouteMode = try container.decodeIfPresent(String.self, forKey: .routeMode)?.lowercased()
        if decodedRouteMode == "geo" || decodedRouteMode == "global" || decodedRouteMode == "basic" {
            routeMode = decodedRouteMode ?? defaults.routeMode
        } else {
            routeMode = geoEnabled ? "geo" : "basic"
        }
    }

    var effectiveBypassIpList: String {
        routeMode == "global" ? "" : bypassIpList
    }
}

func openPPP2PacketWriter(
    packet: UnsafeRawPointer?,
    packetSize: Int32,
    packetContext: UnsafeMutableRawPointer?,
    packetRelease: openppp2_ios_packet_release?,
    userData: UnsafeMutableRawPointer?
) -> Int32 {
    guard let userData, let packet, packetSize > 0 else {
        return 0
    }

    let adapter = Unmanaged<OpenPPP2PacketTunnelAdapter>
        .fromOpaque(userData)
        .takeUnretainedValue()

    return adapter.writePacket(
        packet,
        size: packetSize,
        packetContext: packetContext,
        release: packetRelease
    )
}
