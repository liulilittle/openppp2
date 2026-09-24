import Darwin
import Foundation
import NetworkExtension
import OpenPPP2

final class ProviderOwnedP2PDatagramTransport {
    private weak var provider: NEPacketTunnelProvider?
    private let lock = NSLock()
    private var active = false

    init(provider: NEPacketTunnelProvider) {
        self.provider = provider
    }

    func install(on tap: OpaquePointer) -> Bool {
        lock.lock()
        active = true
        lock.unlock()

        var callbacks = openppp2_ios_p2p_datagram_provider(
            ready: openPPP2P2PProviderReady,
            create: openPPP2P2PProviderCreate,
            start: openPPP2P2PProviderStart,
            send: openPPP2P2PProviderSend,
            close: openPPP2P2PProviderClose
        )
        let userData = Unmanaged.passUnretained(self).toOpaque()
        guard openppp2_ios_tap_set_p2p_datagram_provider(
            tap, &callbacks, userData) != 0
        else {
            lock.lock()
            active = false
            lock.unlock()
            return false
        }
        return true
    }

    func uninstall(from tap: OpaquePointer) {
        lock.lock()
        active = false
        lock.unlock()
        openppp2_ios_tap_clear_p2p_datagram_provider(tap)
    }

    fileprivate func isReady() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return active && provider != nil
    }

    fileprivate func createSession(
        receive: @escaping openppp2_ios_p2p_receive_fn,
        receiveContext: UnsafeMutableRawPointer
    ) -> ProviderOwnedP2PDatagramHandle? {
        lock.lock()
        defer { lock.unlock() }
        guard active, let provider else { return nil }
        return ProviderOwnedP2PDatagramHandle(
            provider: provider,
            receive: receive,
            receiveContext: receiveContext
        )
    }
}

private final class ProviderOwnedP2PDatagramHandle {
    private struct EndpointKey: Hashable {
        let address: Data
        let port: UInt16
    }

    private weak var provider: NEPacketTunnelProvider?
    private let receive: openppp2_ios_p2p_receive_fn
    private let receiveContext: UnsafeMutableRawPointer
    private let queue = DispatchQueue(label: "io.github.openppp2.p2p.provider-udp")
    private var sessions: [EndpointKey: NWUDPSession] = [:]
    private var started = false
    private var closed = false

    init(
        provider: NEPacketTunnelProvider,
        receive: @escaping openppp2_ios_p2p_receive_fn,
        receiveContext: UnsafeMutableRawPointer
    ) {
        self.provider = provider
        self.receive = receive
        self.receiveContext = receiveContext
    }

    func start() -> Bool {
        queue.sync {
            guard !closed, !started else { return false }
            started = true
            return true
        }
    }

    func send(address: Data, port: UInt16, packet: Data) -> Bool {
        queue.sync {
            guard started, !closed, let provider,
                  let host = Self.numericHost(address) else {
                return false
            }

            let key = EndpointKey(address: address, port: port)
            let session: NWUDPSession
            if let existing = sessions[key] {
                session = existing
            } else {
                let endpoint = NWHostEndpoint(
                    hostname: host,
                    port: String(port)
                )
                session = provider.createUDPSession(to: endpoint, from: nil)
                session.setReadHandler({ [weak self] datagrams, error in
                    guard let self else { return }
                    if error != nil {
                        self.deliverError()
                        return
                    }
                    for datagram in datagrams ?? [] {
                        self.deliver(datagram, source: key)
                    }
                }, maxDatagrams: 32)
                sessions[key] = session
            }

            session.writeDatagram(packet) { [weak self] error in
                if error != nil {
                    self?.deliverError()
                }
            }
            return true
        }
    }

    func close() {
        queue.sync {
            guard !closed else { return }
            closed = true
            started = false
            for session in sessions.values {
                session.cancel()
            }
            sessions.removeAll()
        }
    }

    private func deliver(_ packet: Data, source: EndpointKey) {
        queue.async { [weak self] in
            guard let self, !self.closed else { return }
            source.address.withUnsafeBytes { addressBuffer in
                packet.withUnsafeBytes { packetBuffer in
                    self.receive(
                        self.receiveContext,
                        0,
                        addressBuffer.bindMemory(to: UInt8.self).baseAddress,
                        Int32(source.address.count),
                        source.port,
                        packetBuffer.baseAddress,
                        Int32(packet.count)
                    )
                }
            }
        }
    }

    private func deliverError() {
        queue.async { [weak self] in
            guard let self, !self.closed else { return }
            self.receive(self.receiveContext, 1, nil, 0, 0, nil, 0)
        }
    }

    private static func numericHost(_ address: Data) -> String? {
        let family: Int32
        let bufferSize: Int
        switch address.count {
        case 4:
            family = AF_INET
            bufferSize = Int(INET_ADDRSTRLEN)
        case 16:
            family = AF_INET6
            bufferSize = Int(INET6_ADDRSTRLEN)
        default:
            return nil
        }

        var output = [CChar](repeating: 0, count: bufferSize)
        let converted = address.withUnsafeBytes { bytes in
            inet_ntop(family, bytes.baseAddress, &output, socklen_t(output.count))
        }
        guard converted != nil else { return nil }
        return String(cString: output)
    }
}

private func openPPP2P2PProviderReady(
    _ userData: UnsafeMutableRawPointer?
) -> Int32 {
    guard let userData else { return 0 }
    let owner = Unmanaged<ProviderOwnedP2PDatagramTransport>
        .fromOpaque(userData).takeUnretainedValue()
    return owner.isReady() ? 1 : 0
}

private func openPPP2P2PProviderCreate(
    _ receive: openppp2_ios_p2p_receive_fn?,
    _ receiveContext: UnsafeMutableRawPointer?,
    _ userData: UnsafeMutableRawPointer?
) -> UnsafeMutableRawPointer? {
    guard let receive, let receiveContext, let userData else { return nil }
    let owner = Unmanaged<ProviderOwnedP2PDatagramTransport>
        .fromOpaque(userData).takeUnretainedValue()
    guard let handle = owner.createSession(
        receive: receive,
        receiveContext: receiveContext
    ) else {
        return nil
    }
    return Unmanaged.passRetained(handle).toOpaque()
}

private func openPPP2P2PProviderStart(
    _ opaque: UnsafeMutableRawPointer?
) -> Int32 {
    guard let opaque else { return 0 }
    let handle = Unmanaged<ProviderOwnedP2PDatagramHandle>
        .fromOpaque(opaque).takeUnretainedValue()
    return handle.start() ? 1 : 0
}

private func openPPP2P2PProviderSend(
    _ opaque: UnsafeMutableRawPointer?,
    _ address: UnsafePointer<UInt8>?,
    _ addressSize: Int32,
    _ port: UInt16,
    _ packet: UnsafeRawPointer?,
    _ packetSize: Int32
) -> Int32 {
    guard let opaque, let address, let packet,
          (addressSize == 4 || addressSize == 16), packetSize > 0 else {
        return 0
    }
    let handle = Unmanaged<ProviderOwnedP2PDatagramHandle>
        .fromOpaque(opaque).takeUnretainedValue()
    let addressData = Data(bytes: address, count: Int(addressSize))
    let packetData = Data(bytes: packet, count: Int(packetSize))
    return handle.send(address: addressData, port: port, packet: packetData) ? 1 : 0
}

private func openPPP2P2PProviderClose(_ opaque: UnsafeMutableRawPointer?) {
    guard let opaque else { return }
    let handle = Unmanaged<ProviderOwnedP2PDatagramHandle>
        .fromOpaque(opaque).takeRetainedValue()
    handle.close()
}
