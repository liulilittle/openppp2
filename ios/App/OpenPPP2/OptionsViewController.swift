import UIKit

// MARK: - Options

final class OptionsViewController: UIViewController {
    private let store = ProfileStore.shared
    private let scrollView = UIScrollView()
    private let content = UIStackView()
    private var options = LaunchOptions()

    private let tunIp = FormTextField(label: "TUN IP")
    private let tunMask = FormTextField(label: "TUN Mask")
    private let tunPrefix = FormTextField(label: "TUN Prefix", keyboard: .numberPad)
    private let gateway = FormTextField(label: "Gateway")
    private let mtu = FormTextField(label: "MTU", keyboard: .numberPad)
    private let route = FormTextField(label: "Route")
    private let routePrefix = FormTextField(label: "Route Prefix", keyboard: .numberPad)
    private let dns1 = FormTextField(label: "DNS 1")
    private let dns2 = FormTextField(label: "DNS 2")
    private let bypassList = FormTextView(label: "Bypass IP / CIDR")
    private let dnsRules = FormTextView(label: "DNS Rules")
    private let dnsDomestic = FormTextField(label: "Domestic DNS")
    private let dnsForeign = FormTextField(label: "Foreign DNS")
    private let dnsFakeIpRange = FormTextField(label: "Fake-IP Range")
    private let stunCandidates = FormTextView(label: "STUN Candidates")
    private let geoCountry = FormTextField(label: "Geo Country")
    private let geoIpDat = FormTextField(label: "GeoIP.dat")
    private let geoSiteDat = FormTextField(label: "GeoSite.dat")
    private let mux = FormTextField(label: "VNet Mux", keyboard: .numberPad)
    private let httpProxyPort = FormTextField(label: L10n.tr("options.httpProxyPort"), keyboard: .numberPad)
    private let socksProxyPort = FormTextField(label: L10n.tr("options.socksProxyPort"), keyboard: .numberPad)

    private let allowLan = UISwitch()
    private let blockQuic = UISwitch()
    private let vnet = UISwitch()
    private let lwip = UISwitch()
    private let staticMode = UISwitch()
    private let autoReconnectOnPathRecovery = UISwitch()
    private let routeModeControl = UISegmentedControl(items: LaunchRouteMode.allCases.map(\.localizedDisplayName))
    private let ecsEnabled = UISwitch()
    private let fakeIpEnabled = UISwitch()
    private let tlsVerifyPeer = UISwitch()
    private var selectedMuxMode = "compat"

    override func viewDidLoad() {
        super.viewDidLoad()
        title = L10n.tr("options.title")
        view.backgroundColor = .systemGroupedBackground
        navigationItem.rightBarButtonItem = UIBarButtonItem(
            title: L10n.tr("options.save"),
            style: .done,
            target: self,
            action: #selector(save)
        )
        setupLayout()
        NotificationCenter.default.addObserver(self, selector: #selector(load), name: ProfileStore.didChangeNotification, object: nil)
        load()
    }

    deinit {
        NotificationCenter.default.removeObserver(self)
    }

    private func setupLayout() {
        scrollView.translatesAutoresizingMaskIntoConstraints = false
        content.axis = .vertical
        content.spacing = 12
        content.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(scrollView)
        scrollView.addSubview(content)

        NSLayoutConstraint.activate([
            scrollView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            scrollView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            scrollView.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            scrollView.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            content.leadingAnchor.constraint(equalTo: scrollView.contentLayoutGuide.leadingAnchor, constant: 16),
            content.trailingAnchor.constraint(equalTo: scrollView.contentLayoutGuide.trailingAnchor, constant: -16),
            content.topAnchor.constraint(equalTo: scrollView.contentLayoutGuide.topAnchor, constant: 16),
            content.bottomAnchor.constraint(equalTo: scrollView.contentLayoutGuide.bottomAnchor, constant: -24),
            content.widthAnchor.constraint(equalTo: scrollView.frameLayoutGuide.widthAnchor, constant: -32)
        ])

        content.addArrangedSubview(SectionView(title: L10n.tr("options.proxy"), symbol: "point.3.connected.trianglepath.dotted", views: [
            row([httpProxyPort, socksProxyPort], weights: [1, 1]),
            switchRow(title: L10n.tr("options.allowLan"), subtitle: L10n.tr("options.allowLan.detail"), control: allowLan)
        ]))
        content.addArrangedSubview(SectionView(title: L10n.tr("options.dns"), symbol: "network", views: [
            row([dns1, dns2], weights: [1, 1]),
            dnsRules,
            row([dnsDomestic, dnsForeign], weights: [1, 1]),
            switchRow(title: "Fake-IP", subtitle: "Clash-style instant fake A records", control: fakeIpEnabled),
            dnsFakeIpRange,
            switchRow(title: "ECS", subtitle: "EDNS Client Subnet", control: ecsEnabled),
            switchRow(title: L10n.tr("options.tlsVerify"), subtitle: L10n.tr("options.tlsVerify.detail"), control: tlsVerifyPeer),
            stunCandidates
        ]))
        content.addArrangedSubview(SectionView(title: L10n.tr("options.geoBypass"), symbol: "globe.asia.australia", views: [
            routeModeRow(),
            geoCountry,
            row([geoIpDat, geoSiteDat], weights: [1, 1]),
            bypassList
        ]))
        content.addArrangedSubview(SectionView(title: L10n.tr("options.tun"), symbol: "cable.connector", views: [
            row([tunIp, tunMask], weights: [1, 1]),
            row([tunPrefix, gateway], weights: [1, 1]),
            mtu
        ]))
        let advancedRow = disclosureRow(
            title: L10n.tr("options.advancedParams"),
            subtitle: L10n.tr("options.advanced.detail")
        )
        advancedRow.addTarget(self, action: #selector(openAdvancedOptions), for: .touchUpInside)
        content.addArrangedSubview(SectionView(title: L10n.tr("options.advanced"), symbol: "tuningfork", views: [
            advancedRow
        ]))
        content.addArrangedSubview(resetDefaultsButton())
    }

    @objc private func load() {
        options = store.launchOptions()
        hydrate()
    }

    private func hydrate() {
        tunIp.text = options.tunIp
        tunMask.text = options.tunMask
        tunPrefix.text = String(options.tunPrefix)
        gateway.text = options.gateway
        mtu.text = String(options.mtu)
        route.text = options.route
        routePrefix.text = String(options.routePrefix)
        dns1.text = options.dns1
        dns2.text = options.dns2
        bypassList.text = options.bypassIpList
        dnsRules.text = options.dnsRulesList
        dnsDomestic.text = options.dnsDomestic
        dnsForeign.text = options.dnsForeign
        dnsFakeIpRange.text = options.dnsFakeIpRange
        stunCandidates.text = options.dnsStunCandidates
        geoCountry.text = options.geoCountry
        geoIpDat.text = options.geoIpDat
        geoSiteDat.text = options.geoSiteDat
        mux.text = String(options.mux)
        selectedMuxMode = options.muxMode
        httpProxyPort.text = String(options.httpProxyPort)
        socksProxyPort.text = String(options.socksProxyPort)
        allowLan.isOn = options.allowLan
        blockQuic.isOn = options.blockQuic
        vnet.isOn = options.vnet
        lwip.isOn = options.lwip
        staticMode.isOn = options.staticMode
        autoReconnectOnPathRecovery.isOn = options.autoReconnectOnPathRecovery
        routeModeControl.selectedSegmentIndex = LaunchRouteMode.allCases.firstIndex(of: options.routeMode) ?? 0
        ecsEnabled.isOn = options.dnsEcsEnabled
        fakeIpEnabled.isOn = options.dnsFakeIpEnabled
        tlsVerifyPeer.isOn = options.dnsTlsVerifyPeer
    }

    @objc private func save() {
        options.tunIp = tunIp.textValue
        options.tunMask = tunMask.textValue
        options.tunPrefix = Int(tunPrefix.textValue) ?? 24
        options.gateway = gateway.textValue
        options.mtu = Int(mtu.textValue) ?? 1400
        options.route = route.textValue
        options.routePrefix = Int(routePrefix.textValue) ?? 0
        options.dns1 = dns1.textValue
        options.dns2 = dns2.textValue
        options.bypassIpList = bypassList.textValue
        options.dnsRulesList = dnsRules.textValue
        options.dnsDomestic = dnsDomestic.textValue
        options.dnsForeign = dnsForeign.textValue
        options.dnsFakeIpRange = dnsFakeIpRange.textValue
        options.dnsStunCandidates = stunCandidates.textValue
        options.geoCountry = geoCountry.textValue
        options.geoIpDat = geoIpDat.textValue
        options.geoSiteDat = geoSiteDat.textValue
        options.mux = Int(mux.textValue) ?? 0
        options.muxMode = selectedMuxMode
        options.httpProxyPort = proxyPortValue(httpProxyPort.textValue, fallback: 8080)
        options.socksProxyPort = proxyPortValue(socksProxyPort.textValue, fallback: 1080)
        options.allowLan = allowLan.isOn
        options.blockQuic = blockQuic.isOn
        options.vnet = vnet.isOn
        options.lwip = lwip.isOn
        options.staticMode = staticMode.isOn
        options.autoReconnectOnPathRecovery = autoReconnectOnPathRecovery.isOn
        let routeModes = LaunchRouteMode.allCases
        options.setRouteMode(routeModes[max(0, min(routeModeControl.selectedSegmentIndex, routeModes.count - 1))])
        options.dnsEcsEnabled = ecsEnabled.isOn
        options.dnsFakeIpEnabled = fakeIpEnabled.isOn
        options.dnsTlsVerifyPeer = tlsVerifyPeer.isOn
        store.setLaunchOptions(options)

        if let profile = store.activeProfile() {
            promptRestartForActiveTunnelIfNeeded(
                profile: profile,
                message: L10n.tr("options.saved.message"),
                noRestartMessage: L10n.tr("options.saved.toast")
            )
        } else {
            presentToast(L10n.tr("options.saved.toast"))
        }
    }

    @objc private func resetDefaults() {
        options = LaunchOptions()
        hydrate()
    }

    @objc private func confirmResetDefaults() {
        let alert = UIAlertController(
            title: L10n.tr("options.reset.title"),
            message: L10n.tr("options.reset.message"),
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: L10n.tr("common.cancel"), style: .cancel))
        alert.addAction(UIAlertAction(title: L10n.tr("options.reset.action"), style: .destructive) { [weak self] _ in
            self?.resetDefaults()
        })
        present(alert, animated: true)
    }

    private func resetDefaultsButton() -> UIButton {
        var configuration = UIButton.Configuration.tinted()
        configuration.title = L10n.tr("options.resetDefaults")
        configuration.baseForegroundColor = .systemRed
        configuration.baseBackgroundColor = .systemRed
        configuration.cornerStyle = .medium
        configuration.contentInsets = NSDirectionalEdgeInsets(top: 13, leading: 16, bottom: 13, trailing: 16)

        let button = UIButton(configuration: configuration, primaryAction: nil)
        button.titleLabel?.font = .systemFont(ofSize: 16, weight: .semibold)
        button.addTarget(self, action: #selector(confirmResetDefaults), for: .touchUpInside)
        button.heightAnchor.constraint(greaterThanOrEqualToConstant: 48).isActive = true
        return button
    }

    private func routeModeRow() -> UIView {
        routeModeControl.selectedSegmentTintColor = AppTheme.primary
        routeModeControl.setTitleTextAttributes([.foregroundColor: UIColor.white], for: .selected)
        routeModeControl.setTitleTextAttributes([.foregroundColor: UIColor.label], for: .normal)
        routeModeControl.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)

        let titleLabel = UILabel()
        titleLabel.text = L10n.tr("home.routeMode")
        titleLabel.font = .preferredFont(forTextStyle: .body)
        titleLabel.textColor = .label
        titleLabel.setContentHuggingPriority(.required, for: .horizontal)

        let detailLabel = UILabel()
        detailLabel.text = L10n.tr("options.routeMode.detail")
        detailLabel.font = .preferredFont(forTextStyle: .caption1)
        detailLabel.textColor = .secondaryLabel
        detailLabel.numberOfLines = 2

        let labels = UIStackView(arrangedSubviews: [titleLabel, detailLabel])
        labels.axis = .vertical
        labels.spacing = 2
        labels.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)

        let stack = UIStackView(arrangedSubviews: [labels, routeModeControl])
        stack.axis = .horizontal
        stack.alignment = .center
        stack.spacing = 12
        return stack
    }

    private func proxyPortValue(_ value: String, fallback: Int) -> Int {
        guard let port = Int(value), (1...65535).contains(port) else {
            return fallback
        }
        return port
    }

    @objc private func openAdvancedOptions() {
        let snapshot = TunnelSharedState.readRuntimeSnapshotJsonIfAlive()
            .flatMap { try? TunnelRuntimeBridge.decodeSnapshot($0) }
            ?? RuntimeSnapshot(
                generation: 0,
                monotonicMs: 0,
                phase: .idle,
                capabilities: RuntimeSnapshot.bundledCapabilities
            )
        let controller = OptionsAdvancedViewController(
            mux: mux,
            vnet: vnet,
            blockQuic: blockQuic,
            staticMode: staticMode,
            autoReconnectOnPathRecovery: autoReconnectOnPathRecovery,
            muxModes: snapshot.availableMuxModes(experimental: store.debugPanelEnabled()),
            selectedMuxMode: selectedMuxMode,
            effectiveMuxMode: snapshot.effectiveMuxDisplayName,
            onMuxModeChanged: { [weak self] in self?.selectedMuxMode = $0 }
        )
        navigationController?.pushViewController(controller, animated: true)
    }
}

final class OptionsAdvancedViewController: UIViewController {
    private let scrollView = UIScrollView()
    private let content = UIStackView()
    private let mux: FormTextField
    private let vnet: UISwitch
    private let blockQuic: UISwitch
    private let staticMode: UISwitch
    private let autoReconnectOnPathRecovery: UISwitch
    private let muxModes: [String]
    private let selectedMuxMode: String
    private let effectiveMuxMode: String
    private let onMuxModeChanged: (String) -> Void

    init(
        mux: FormTextField,
        vnet: UISwitch,
        blockQuic: UISwitch,
        staticMode: UISwitch,
        autoReconnectOnPathRecovery: UISwitch,
        muxModes: [String],
        selectedMuxMode: String,
        effectiveMuxMode: String,
        onMuxModeChanged: @escaping (String) -> Void
    ) {
        self.mux = mux
        self.vnet = vnet
        self.blockQuic = blockQuic
        self.staticMode = staticMode
        self.autoReconnectOnPathRecovery = autoReconnectOnPathRecovery
        self.muxModes = muxModes
        self.selectedMuxMode = selectedMuxMode
        self.effectiveMuxMode = effectiveMuxMode
        self.onMuxModeChanged = onMuxModeChanged
        super.init(nibName: nil, bundle: nil)
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        title = L10n.tr("options.advancedParams")
        view.backgroundColor = .systemGroupedBackground
        setupLayout()
    }

    private func setupLayout() {
        scrollView.translatesAutoresizingMaskIntoConstraints = false
        content.axis = .vertical
        content.spacing = 12
        content.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(scrollView)
        scrollView.addSubview(content)

        NSLayoutConstraint.activate([
            scrollView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            scrollView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            scrollView.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            scrollView.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            content.leadingAnchor.constraint(equalTo: scrollView.contentLayoutGuide.leadingAnchor, constant: 16),
            content.trailingAnchor.constraint(equalTo: scrollView.contentLayoutGuide.trailingAnchor, constant: -16),
            content.topAnchor.constraint(equalTo: scrollView.contentLayoutGuide.topAnchor, constant: 16),
            content.bottomAnchor.constraint(equalTo: scrollView.contentLayoutGuide.bottomAnchor, constant: -24),
            content.widthAnchor.constraint(equalTo: scrollView.frameLayoutGuide.widthAnchor, constant: -32)
        ])

        let modeControl = UISegmentedControl(items: muxModes.map {
            $0 == "compat" ? "Compatibility" : $0
        })
        modeControl.selectedSegmentIndex = muxModes.firstIndex(of: selectedMuxMode) ?? UISegmentedControl.noSegment
        modeControl.addAction(UIAction { [weak self, weak modeControl] _ in
            guard let self, let modeControl,
                  self.muxModes.indices.contains(modeControl.selectedSegmentIndex) else { return }
            self.onMuxModeChanged(self.muxModes[modeControl.selectedSegmentIndex])
        }, for: .valueChanged)
        let restartLabel = UILabel()
        restartLabel.text = "Takes effect on next connection"
        restartLabel.font = .preferredFont(forTextStyle: .footnote)
        restartLabel.textColor = .secondaryLabel
        let effectiveLabel = UILabel()
        effectiveLabel.text = effectiveMuxMode.isEmpty ? nil : "Effective now: \(effectiveMuxMode)"
        effectiveLabel.isHidden = effectiveMuxMode.isEmpty

        content.addArrangedSubview(SectionView(title: "VNet", symbol: "network", views: [
            modeControl,
            restartLabel,
            effectiveLabel,
            mux,
            switchRow(title: "VNet", subtitle: L10n.tr("options.vnet.detail"), control: vnet)
        ]))
        content.addArrangedSubview(SectionView(title: L10n.tr("options.network"), symbol: "shield.lefthalf.filled", views: [
            switchRow(title: "Block QUIC", subtitle: L10n.tr("options.blockQuic.detail"), control: blockQuic),
            switchRow(title: "Static Mode", subtitle: L10n.tr("options.staticMode.detail"), control: staticMode),
            switchRow(title: L10n.tr("options.autoReconnect"), subtitle: L10n.tr("options.autoReconnect.detail"), control: autoReconnectOnPathRecovery)
        ]))
    }
}
