import NetworkExtension
import QuartzCore
import UIKit

// MARK: - Home

final class HomeViewController: UIViewController {
    private let store = ProfileStore.shared
    private let vpn = VPNController.shared
    private let runtimeStore = RuntimeStore()
    private let documentPicker = ProfileDocumentPicker()
    private var temporaryShareURL: URL?
    private let scrollView = UIScrollView()
    private let content = UIStackView()
    private let statusCard = HomeStatusCard()
    private let profileListView = HomeProfileListView()
    private let diagnosticLabel = PaddingLabel()
    private let errorLabel = PaddingLabel()
    private var timer: Timer?
    private var pollTimer: Timer?
    private var linkState = 6
    private var traffic = RuntimeTrafficRate.empty
    private var previousTrafficSample: RuntimeSnapshot?
    private var connectStartedAt: Date?
    private var connectWatchdogTimer: Timer?
    private var stopPresentationTimer: Timer?
    private var stopStartedAt: Date?
    private var pendingStartGeneration: UInt64?
    private var pendingStopGeneration: UInt64?
    private var runtimeDecodeError: String?
    private var elapsedText = ""

    override func viewDidLoad() {
        super.viewDidLoad()
        title = "OPENPPP2"
        view.backgroundColor = .systemGroupedBackground
        setupLayout()
        NotificationCenter.default.addObserver(self, selector: #selector(refreshUI), name: ProfileStore.didChangeNotification, object: nil)
        NotificationCenter.default.addObserver(self, selector: #selector(refreshUI), name: VPNController.didChangeNotification, object: nil)
        vpn.refresh()
        refreshUI()
    }

    deinit {
        timer?.invalidate()
        pollTimer?.invalidate()
        connectWatchdogTimer?.invalidate()
        stopPresentationTimer?.invalidate()
        NotificationCenter.default.removeObserver(self)
    }

    private func setupLayout() {
        scrollView.translatesAutoresizingMaskIntoConstraints = false
        content.axis = .vertical
        content.spacing = 14
        content.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(scrollView)
        scrollView.addSubview(content)

        NSLayoutConstraint.activate([
            scrollView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            scrollView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            scrollView.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            scrollView.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor),
            content.leadingAnchor.constraint(equalTo: scrollView.contentLayoutGuide.leadingAnchor, constant: AppTheme.horizontalPadding),
            content.trailingAnchor.constraint(equalTo: scrollView.contentLayoutGuide.trailingAnchor, constant: -AppTheme.horizontalPadding),
            content.topAnchor.constraint(equalTo: scrollView.contentLayoutGuide.topAnchor, constant: 14),
            content.bottomAnchor.constraint(equalTo: scrollView.contentLayoutGuide.bottomAnchor, constant: -24),
            content.widthAnchor.constraint(equalTo: scrollView.frameLayoutGuide.widthAnchor, constant: -(AppTheme.horizontalPadding * 2))
        ])

        statusCard.addConnectionTarget(self, action: #selector(toggleConnection))
        statusCard.addAllowLanTarget(self, action: #selector(allowLanChanged(_:)))
        statusCard.addBlockQuicTarget(self, action: #selector(blockQuicChanged(_:)))
        statusCard.addRouteModeTarget(self, action: #selector(routeModeChanged(_:)))
        content.addArrangedSubview(statusCard)
        statusCard.heightAnchor.constraint(greaterThanOrEqualToConstant: 286).isActive = true

        profileListView.onApplyProfile = { [weak self] profile in
            self?.selectProfile(profile)
        }
        profileListView.onEditProfile = { [weak self] profile in
            self?.editProfile(profile)
        }
        profileListView.onShareProfile = { [weak self] profile in
            self?.shareProfile(profile)
        }
        profileListView.onTogglePinnedProfile = { [weak self] profile in
            self?.togglePinnedProfile(profile)
        }
        profileListView.onAddProfile = { [weak self] in
            self?.addProfile()
        }
        profileListView.onImportFromFile = { [weak self] in
            self?.importFromFile()
        }
        profileListView.onImportSubscription = { [weak self] in
            self?.importSubscription()
        }
        content.addArrangedSubview(profileListView)

        diagnosticLabel.backgroundColor = AppTheme.primarySoft
        diagnosticLabel.textColor = .secondaryLabel
        diagnosticLabel.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        diagnosticLabel.numberOfLines = 0
        diagnosticLabel.layer.cornerRadius = 12
        diagnosticLabel.clipsToBounds = true
        diagnosticLabel.isHidden = true
        content.addArrangedSubview(diagnosticLabel)

        errorLabel.backgroundColor = .systemRed.withAlphaComponent(0.12)
        errorLabel.textColor = .systemRed
        errorLabel.font = .preferredFont(forTextStyle: .footnote)
        errorLabel.numberOfLines = 0
        errorLabel.layer.cornerRadius = 12
        errorLabel.clipsToBounds = true
        content.addArrangedSubview(errorLabel)
    }

    @objc private func refreshUI() {
        if let json = TunnelSharedState.readRuntimeSnapshotJsonIfAlive() {
            do {
                let snapshot = try TunnelRuntimeBridge.decodeSnapshot(json)
                if runtimeStore.apply(snapshot) {
                    traffic = RuntimeTrafficRate.between(previousTrafficSample, snapshot)
                    if RuntimeTrafficRate.advancesTrafficBaseline(
                        previousTrafficSample,
                        snapshot
                    ) {
                        previousTrafficSample = snapshot
                    }
                }
                runtimeDecodeError = nil
            } catch {
                runtimeDecodeError = error.localizedDescription
                if let ordering = try? TunnelRuntimeBridge.decodeOrdering(json) {
                    runtimeStore.applyUnknown(
                        generation: ordering.generation,
                        monotonicMs: ordering.monotonicMs
                    )
                }
            }
        } else {
            traffic = .empty
            previousTrafficSample = nil
            if runtimeStore.state.phase != .idle {
                runtimeStore.markUnknown()
            }
        }
        if let generation = pendingStartGeneration,
           runtimeStore.state.generation > generation ||
           runtimeStore.state.phase == .unknown ||
           runtimeStore.state.phase == .failed {
            pendingStartGeneration = nil
        }
        if let generation = pendingStopGeneration,
           runtimeStore.state.generation > generation ||
           runtimeStore.state.phase == .idle ||
           runtimeStore.state.phase == .failed ||
           vpn.status == .disconnected ||
           vpn.status == .invalid {
            pendingStopGeneration = nil
        }
        let debugPanelEnabled = store.debugPanelEnabled()
        let profile = store.activeProfile()
        let launchOptions = store.launchOptions()
        updateStopPresentationTimer()
        let stopTakingTooLong = stopStartedAt.map {
            Date().timeIntervalSince($0) >= 15
        } ?? false
        var controls = controlsFor(
            runtimeStore.state.phase,
            stopTakingTooLong: stopTakingTooLong
        )
        if pendingStartGeneration != nil || pendingStopGeneration != nil {
            controls.buttonEnabled = false
            controls.configEditable = false
        }
        let statusText = L10n.tr(controls.statusTitleKey)
        var statusDetail = controls.detailKey.isEmpty ? "" : L10n.tr(controls.detailKey)

        if controls.isConnected {
            updateElapsedText()
            statusDetail = elapsedText
            if !runtimeStore.state.effectiveMuxMode.isEmpty {
                statusDetail += " · VMUX: \(runtimeStore.state.effectiveMuxDisplayName)"
            }
            statusDetail += " · Path: \(runtimeStore.state.effectivePathDisplayName)"
            stopConnectWatchdog()
            startTimer()
        } else {
            timer?.invalidate()
            timer = nil
        }

        switch controls.action {
        case .cancel, .stop:
            startPolling()
            if controls.action == .cancel && connectStartedAt == nil {
                startConnectWatchdog()
            }
        default:
            pollTimer?.invalidate()
            pollTimer = nil
            stopConnectWatchdog()
        }

        statusCard.apply(
            status: statusText,
            detail: statusDetail,
            isConnected: controls.isConnected,
            isBusy: controls.isBusy,
            buttonTitle: L10n.tr(controls.buttonTitleKey),
            buttonEnabled: controls.buttonEnabled,
            configEditable: controls.configEditable,
            upload: "\(formatBytes(Int(traffic.txBytesPerSecond)))/s",
            download: "\(formatBytes(Int(traffic.rxBytesPerSecond)))/s",
            options: launchOptions
        )
        profileListView.apply(
            profiles: store.profiles(),
            activeId: profile?.id,
            configEditable: controls.configEditable
        )

        if debugPanelEnabled {
            let diagnosticText = vpn.diagnostics.summaryText(
                fallbackLinkState: linkState,
                fallbackNetworkPath: vpn.networkPath
            )
            let muxText = runtimeStore.state.muxDiagnosticLines.joined(separator: "\n")
            let p2pText = runtimeStore.state.p2pDiagnosticLines.joined(separator: "\n")
            diagnosticLabel.text = [diagnosticText, muxText.isEmpty ? nil : muxText, p2pText]
                .compactMap { $0 }
                .joined(separator: "\n")
            diagnosticLabel.isHidden = diagnosticLabel.text?.isEmpty != false
        } else {
            diagnosticLabel.text = nil
            diagnosticLabel.isHidden = true
        }
        errorLabel.text = runtimeDecodeError ?? vpn.lastError
        errorLabel.isHidden = errorLabel.text == nil
    }

    private func startTimer() {
        updateElapsedText()
        guard timer == nil else { return }
        timer?.invalidate()
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            guard let self else { return }
            self.updateElapsedText()
            self.refreshUI()
        }
    }

    private func updateStopPresentationTimer() {
        guard runtimeStore.state.phase == .stopping else {
            stopStartedAt = nil
            stopPresentationTimer?.invalidate()
            stopPresentationTimer = nil
            return
        }
        stopStartedAt = stopStartedAt ?? Date()
        guard stopPresentationTimer == nil else { return }
        stopPresentationTimer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) {
            [weak self] _ in self?.refreshUI()
        }
    }

    /// Elapsed connect time comes from the runtime snapshot's own clock, so it
    /// stays correct after the app process is recreated while the tunnel keeps
    /// running.
    private func updateElapsedText() {
        guard runtimeStore.state.connectedMonotonicMs != 0 else {
            elapsedText = ""
            return
        }
        let duration = Int(connectedElapsedMs(runtimeStore.state) / 1000)
        let h = duration / 3600
        let m = (duration / 60) % 60
        let s = duration % 60
        elapsedText = String(format: "%02d:%02d:%02d", h, m, s)
    }

    private func startPolling() {
        guard pollTimer == nil else { return }
        pollTimer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            self?.pollTunnel()
        }
        pollTunnel()
    }

    private func pollTunnel() {
        let status = vpn.status
        guard status == .connected || status == .connecting || status == .reasserting else {
            traffic = .empty
            previousTrafficSample = nil
            linkState = 6
            pollTimer?.invalidate()
            pollTimer = nil
            refreshUI()
            return
        }

        vpn.fetchLinkState { [weak self] state in
            guard let self else { return }
            self.linkState = state
            self.refreshUI()
        }

        if store.debugPanelEnabled() {
            vpn.fetchDiagnostics { [weak self] _ in
                guard let self else { return }
                self.refreshUI()
            }
        }

    }

    private func startConnectWatchdog() {
        connectStartedAt = Date()
        connectWatchdogTimer?.invalidate()
        connectWatchdogTimer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in
            self?.evaluateConnectWatchdog()
        }
    }

    private func stopConnectWatchdog() {
        connectWatchdogTimer?.invalidate()
        connectWatchdogTimer = nil
        connectStartedAt = nil
    }

    private func evaluateConnectWatchdog() {
        guard let startedAt = connectStartedAt else { return }

        let stillConnecting = pendingStartGeneration != nil ||
            controlsFor(runtimeStore.state.phase).action == .cancel
        guard stillConnecting else {
            stopConnectWatchdog()
            return
        }

        let totalSeconds = Int(Date().timeIntervalSince(startedAt))
        if totalSeconds >= TunnelSharedState.connectWatchdogMaxSeconds {
            pendingStartGeneration = nil
            stopConnectWatchdog()
            vpn.disconnect()
            presentError(L10n.format("home.timeout", TunnelSharedState.connectWatchdogMaxSeconds))
            refreshUI()
            return
        }

        if TunnelSharedState.shouldUseSharedHeartbeat {
            let heartbeatAge = TunnelSharedState.heartbeatAgeMs()
            if heartbeatAge >= 0 && heartbeatAge > TunnelSharedState.heartbeatStaleMilliseconds {
                pendingStartGeneration = nil
                stopConnectWatchdog()
                vpn.disconnect()
                presentError(L10n.format("home.heartbeatTimeout", Double(heartbeatAge) / 1000))
                refreshUI()
            }
        }
    }

    @objc private func toggleConnection() {
        switch controlsFor(runtimeStore.state.phase).action {
        case .cancel, .stop, .forceStop:
            let generation = runtimeStore.state.generation
            guard pendingStopGeneration != generation else { return }
            pendingStartGeneration = nil
            pendingStopGeneration = generation
            vpn.disconnect()
            refreshUI()
            return
        case .none:
            return
        case .start, .retry:
            guard pendingStartGeneration == nil else { return }
            break
        }

        guard let profile = store.activeProfile(), !profile.json.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            openProfiles()
            return
        }

        pendingStartGeneration = runtimeStore.state.generation
        refreshUI()
        vpn.connect(profile: profile) { [weak self] result in
            guard let self else { return }
            if case let .failure(error) = result {
                self.pendingStartGeneration = nil
                self.stopConnectWatchdog()
                self.presentError(error.localizedDescription)
            } else {
                self.startPolling()
                self.startConnectWatchdog()
            }
            self.refreshUI()
        }
    }

    @objc private func openProfiles() {
        let selector = SelectProfileViewController()
        let nav = UINavigationController(rootViewController: selector)
        nav.modalPresentationStyle = .pageSheet
        if let sheet = nav.sheetPresentationController {
            sheet.detents = [.medium(), .large()]
            sheet.prefersGrabberVisible = true
            sheet.preferredCornerRadius = 22
            sheet.selectedDetentIdentifier = .medium
        }
        present(nav, animated: true)
    }

    private func selectProfile(_ profile: ConfigProfile) {
        guard profile.id != store.activeProfile()?.id else { return }
        store.setActive(profile.id)
        promptRestartForActiveTunnelIfNeeded(
            profile: profile,
            message: L10n.format("profiles.switched.message", profile.name),
            noRestartMessage: nil
        ) { [weak self] in
            self?.refreshUI()
        }
    }

    private func editProfile(_ profile: ConfigProfile) {
        navigationController?.pushViewController(ProfileEditViewController(profile: profile), animated: true)
    }

    private func addProfile() {
        navigationController?.pushViewController(ProfileEditViewController(profile: nil), animated: true)
    }

    private func togglePinnedProfile(_ profile: ConfigProfile) {
        var updated = profile
        updated.favorite.toggle()
        store.update(updated, snapshot: false)
        refreshUI()
    }

    private func shareProfile(_ profile: ConfigProfile) {
        do {
            let bundle = try store.exportProfile(id: profile.id)
            let data = try ProfileImportExportCodec.encode(bundle)
            let filename = ProfileImportExportCodec.singleProfileFilename(name: bundle.profiles[0].name)
            let url = FileManager.default.temporaryDirectory.appendingPathComponent(filename)
            try? FileManager.default.removeItem(at: url)
            try data.write(to: url, options: [.atomic])
            if let temporaryShareURL {
                try? FileManager.default.removeItem(at: temporaryShareURL)
            }
            temporaryShareURL = url

            let activity = UIActivityViewController(activityItems: [url], applicationActivities: nil)
            activity.completionWithItemsHandler = { [weak self] _, _, _, _ in
                if let url = self?.temporaryShareURL {
                    try? FileManager.default.removeItem(at: url)
                }
                self?.temporaryShareURL = nil
            }
            if let popover = activity.popoverPresentationController {
                popover.sourceView = view
                popover.sourceRect = CGRect(x: view.bounds.midX, y: view.bounds.midY, width: 1, height: 1)
                popover.permittedArrowDirections = []
            }
            present(activity, animated: true)
        } catch {
            presentMessage(title: L10n.tr("profiles.exportFailed"), message: error.localizedDescription)
        }
    }

    private func importFromFile() {
        documentPicker.presentImport(from: self) { [weak self] event in
            guard let self else { return }
            switch event {
            case let .imported(bundle):
                self.presentProfileImportModeChoice(
                    profileCount: bundle.profiles.count,
                    onMerge: {
                        self.applyImport(bundle, mode: .merge)
                    },
                    onReplace: {
                        self.applyImport(bundle, mode: .replace)
                    }
                )
            case .cancelled, .exportFinished:
                break
            case let .failed(error):
                self.presentMessage(title: L10n.tr("profiles.importFailed"), message: error.localizedDescription)
            }
        }
    }

    private func applyImport(_ bundle: ProfileExportBundle, mode: ProfileImportMode) {
        do {
            let result = try store.importBundle(bundle, mode: mode)
            refreshUI()
            presentProfileImportResult(result)
        } catch {
            presentMessage(title: L10n.tr("profiles.importFailed"), message: error.localizedDescription)
        }
    }

    private func importSubscription() {
        let alert = UIAlertController(title: L10n.tr("profiles.importSubscription"), message: nil, preferredStyle: .alert)
        alert.addTextField { field in
            field.placeholder = "https://example.com/openppp2.json"
            field.keyboardType = .URL
            field.autocapitalizationType = .none
            field.autocorrectionType = .no
        }
        alert.addAction(UIAlertAction(title: L10n.tr("common.cancel"), style: .cancel))
        alert.addAction(UIAlertAction(title: L10n.tr("profiles.import"), style: .default) { [weak self, weak alert] _ in
            guard let self,
                  let urlText = alert?.textFields?.first?.text?.trimmingCharacters(in: .whitespacesAndNewlines),
                  !urlText.isEmpty
            else {
                return
            }
            self.fetchSubscription(urlText)
        })
        present(alert, animated: true)
    }

    private func fetchSubscription(_ urlText: String) {
        guard let url = URL(string: urlText), isSecureSubscriptionURL(url) else {
            presentMessage(title: L10n.tr("profiles.invalidSubscription"), message: L10n.tr("profiles.invalidSubscription.message"))
            return
        }

        let progress = UIAlertController(title: nil, message: L10n.tr("profiles.fetching"), preferredStyle: .alert)
        present(progress, animated: true)

        var request = URLRequest(url: url, timeoutInterval: 15)
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("OpenPPP2/iOS", forHTTPHeaderField: "User-Agent")

        secureSubscriptionSession.dataTask(with: request) { [weak self] data, response, error in
            DispatchQueue.main.async {
                progress.dismiss(animated: true) {
                    guard let self else { return }
                    if let error {
                        self.presentMessage(title: L10n.tr("profiles.subscriptionFailed"), message: error.localizedDescription)
                        return
                    }
                    if let http = response as? HTTPURLResponse,
                       http.statusCode < 200 || http.statusCode >= 300 {
                        self.presentMessage(title: L10n.tr("profiles.subscriptionFailed"), message: "HTTP \(http.statusCode)")
                        return
                    }
                    guard let data, data.count <= 2 * 1024 * 1024,
                          let text = String(data: data, encoding: .utf8)
                    else {
                        self.presentMessage(title: L10n.tr("profiles.subscriptionFailed"), message: L10n.tr("profiles.subscriptionBadResponse"))
                        return
                    }

                    do {
                        let subscription = try RemoteSubscriptionParser.parse(text)
                        let count = self.store.upsertSubscription(url: urlText, subscription: subscription)
                        self.refreshUI()
                        self.presentToast(L10n.format("profiles.importedNodes", count))
                    } catch {
                        self.presentMessage(title: L10n.tr("profiles.subscriptionFailed"), message: error.localizedDescription)
                    }
                }
            }
        }.resume()
    }

    @objc private func allowLanChanged(_ sender: UISwitch) {
        updateLaunchOptions(noRestartMessage: L10n.tr("home.lanUpdated")) { options in
            options.allowLan = sender.isOn
        }
    }

    @objc private func blockQuicChanged(_ sender: UISwitch) {
        updateLaunchOptions(noRestartMessage: L10n.tr("home.blockQuicUpdated")) { options in
            options.blockQuic = sender.isOn
        }
    }

    @objc private func routeModeChanged(_ sender: UISegmentedControl) {
        updateLaunchOptions(noRestartMessage: L10n.tr("home.routeUpdated")) { options in
            let modes = LaunchRouteMode.allCases
            let index = max(0, min(sender.selectedSegmentIndex, modes.count - 1))
            options.setRouteMode(modes[index])
        }
    }

    private func updateLaunchOptions(
        noRestartMessage: String,
        mutate: (inout LaunchOptions) -> Void
    ) {
        var options = store.launchOptions()
        let previousOptions = options
        mutate(&options)
        guard options != previousOptions else {
            refreshUI()
            return
        }

        store.setLaunchOptions(options)
        guard let profile = store.activeProfile() else {
            presentToast(noRestartMessage)
            refreshUI()
            return
        }

        promptRestartForActiveTunnelIfNeeded(
            profile: profile,
            message: L10n.tr("home.quickSaved"),
            noRestartMessage: noRestartMessage
        ) { [weak self] in
            self?.refreshUI()
        }
    }

    private func presentError(_ message: String) {
        let alert = UIAlertController(title: L10n.tr("home.connectFailed"), message: message, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: L10n.tr("common.close"), style: .default))
        present(alert, animated: true)
    }

    private func connectingText(for state: Int, debugPanelEnabled: Bool) -> String {
        guard debugPanelEnabled else { return L10n.tr("home.connecting") }

        switch state {
        case 0: return L10n.tr("home.connected")
        case 2: return L10n.tr("home.state.initializingClient")
        case 3: return L10n.tr("home.state.initializingExchanger")
        case 4: return L10n.tr("home.reconnecting")
        case 5: return L10n.tr("home.state.handshaking")
        case 6: return L10n.tr("home.state.startingEngine")
        default: return L10n.tr("home.connecting")
        }
    }

    private func formatBytes(_ bytes: Int) -> String {
        let value = Double(max(0, bytes))
        if value < 1024 { return "\(Int(value)) B" }
        if value < 1024 * 1024 { return String(format: "%.1f KB", value / 1024) }
        if value < 1024 * 1024 * 1024 { return String(format: "%.1f MB", value / (1024 * 1024)) }
        return String(format: "%.2f GB", value / (1024 * 1024 * 1024))
    }
}

private final class HomeStatusCard: UIView {
    private let dot = UIView()
    private let statusLabel = UILabel()
    private let detailLabel = UILabel()
    private let actionButton = UIButton(type: .system)
    private let uploadValue = UILabel()
    private let downloadValue = UILabel()
    private let allowLanSwitch = UISwitch()
    private let blockQuicSwitch = UISwitch()
    private let routeModeControl = UISegmentedControl(items: LaunchRouteMode.allCases.map(\.localizedDisplayName))

    override init(frame: CGRect) {
        super.init(frame: frame)
        setup()
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    private func setup() {
        backgroundColor = .secondarySystemGroupedBackground
        layer.cornerRadius = 24
        translatesAutoresizingMaskIntoConstraints = false

        dot.translatesAutoresizingMaskIntoConstraints = false
        dot.layer.cornerRadius = 6
        dot.setContentHuggingPriority(.required, for: .horizontal)

        statusLabel.font = .systemFont(ofSize: 19, weight: .semibold)
        statusLabel.textColor = .label
        statusLabel.adjustsFontSizeToFitWidth = true
        statusLabel.minimumScaleFactor = 0.82

        detailLabel.font = .monospacedDigitSystemFont(ofSize: 13, weight: .medium)
        detailLabel.textColor = .secondaryLabel
        detailLabel.adjustsFontSizeToFitWidth = true
        detailLabel.minimumScaleFactor = 0.78

        let labels = UIStackView(arrangedSubviews: [statusLabel, detailLabel])
        labels.axis = .vertical
        labels.spacing = 4

        let left = UIStackView(arrangedSubviews: [dot, labels])
        left.axis = .horizontal
        left.alignment = .center
        left.spacing = 12
        left.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)

        actionButton.titleLabel?.font = .systemFont(ofSize: 15, weight: .bold)
        actionButton.heightAnchor.constraint(equalToConstant: 42).isActive = true
        actionButton.widthAnchor.constraint(greaterThanOrEqualToConstant: 96).isActive = true

        let statusRow = UIStackView(arrangedSubviews: [left, actionButton])
        statusRow.axis = .horizontal
        statusRow.alignment = .center
        statusRow.spacing = 14

        let speedRow = UIStackView(arrangedSubviews: [
            makeSpeedColumn(title: L10n.tr("home.upload"), valueLabel: uploadValue, color: .systemOrange),
            makeVerticalDivider(),
            makeSpeedColumn(title: L10n.tr("home.download"), valueLabel: downloadValue, color: AppTheme.primary)
        ])
        speedRow.axis = .horizontal
        speedRow.alignment = .center
        speedRow.distribution = .fill
        speedRow.spacing = 14
        speedRow.arrangedSubviews[0].widthAnchor.constraint(equalTo: speedRow.arrangedSubviews[2].widthAnchor).isActive = true

        let quickTitle = UILabel()
        quickTitle.text = L10n.tr("home.quickSwitches")
        quickTitle.font = .systemFont(ofSize: 13, weight: .semibold)
        quickTitle.textColor = .secondaryLabel

        [allowLanSwitch, blockQuicSwitch].forEach { control in
            control.onTintColor = AppTheme.primary
        }
        routeModeControl.selectedSegmentTintColor = AppTheme.primary
        routeModeControl.setTitleTextAttributes([.foregroundColor: UIColor.white, .font: UIFont.systemFont(ofSize: 12, weight: .semibold)], for: .selected)
        routeModeControl.setTitleTextAttributes([.foregroundColor: UIColor.label, .font: UIFont.systemFont(ofSize: 12, weight: .regular)], for: .normal)
        routeModeControl.heightAnchor.constraint(equalToConstant: 34).isActive = true

        let stack = UIStackView(arrangedSubviews: [
            statusRow,
            makeHorizontalDivider(),
            speedRow,
            makeHorizontalDivider(),
            quickTitle,
            makeSwitchRow(title: L10n.tr("home.lanProxy"), subtitle: L10n.tr("home.lanProxy.subtitle"), control: allowLanSwitch),
            makeSwitchRow(title: L10n.tr("home.blockQuic"), subtitle: L10n.tr("options.blockQuic.detail"), control: blockQuicSwitch),
            makeRouteRow()
        ])
        stack.axis = .vertical
        stack.spacing = 12
        stack.translatesAutoresizingMaskIntoConstraints = false
        addSubview(stack)

        NSLayoutConstraint.activate([
            dot.widthAnchor.constraint(equalToConstant: 12),
            dot.heightAnchor.constraint(equalTo: dot.widthAnchor),
            stack.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 18),
            stack.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -18),
            stack.topAnchor.constraint(equalTo: topAnchor, constant: 18),
            stack.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -18)
        ])
        setTraffic(upload: "0 B/s", download: "0 B/s")
    }

    func addConnectionTarget(_ target: Any?, action: Selector) {
        actionButton.addTarget(target, action: action, for: .touchUpInside)
    }

    func addAllowLanTarget(_ target: Any?, action: Selector) {
        allowLanSwitch.addTarget(target, action: action, for: .valueChanged)
    }

    func addBlockQuicTarget(_ target: Any?, action: Selector) {
        blockQuicSwitch.addTarget(target, action: action, for: .valueChanged)
    }

    func addRouteModeTarget(_ target: Any?, action: Selector) {
        routeModeControl.addTarget(target, action: action, for: .valueChanged)
    }

    func apply(
        status: String,
        detail: String,
        isConnected: Bool,
        isBusy: Bool,
        buttonTitle: String,
        buttonEnabled: Bool,
        configEditable: Bool,
        upload: String,
        download: String,
        options: LaunchOptions
    ) {
        let color = color(isConnected: isConnected, isBusy: isBusy)
        statusLabel.text = status
        detailLabel.text = detail
        dot.backgroundColor = color
        dot.layer.shadowColor = color.cgColor
        dot.layer.shadowOpacity = isConnected || isBusy ? 0.42 : 0.18
        dot.layer.shadowRadius = 10
        dot.layer.shadowOffset = .zero
        actionButton.isEnabled = buttonEnabled
        actionButton.alpha = buttonEnabled ? 1 : 0.58
        allowLanSwitch.isEnabled = configEditable
        blockQuicSwitch.isEnabled = configEditable
        routeModeControl.isEnabled = configEditable

        var configuration = UIButton.Configuration.filled()
        configuration.cornerStyle = .capsule
        configuration.baseBackgroundColor = color
        configuration.baseForegroundColor = .white
        configuration.contentInsets = NSDirectionalEdgeInsets(top: 9, leading: 18, bottom: 9, trailing: 18)
        configuration.title = buttonTitle
        actionButton.configuration = configuration
        setTraffic(upload: upload, download: download)
        apply(options: options)
        updatePulse(isConnected: isConnected, isBusy: isBusy)
    }

    private func apply(options: LaunchOptions) {
        allowLanSwitch.isOn = options.allowLan
        blockQuicSwitch.isOn = options.blockQuic
        routeModeControl.selectedSegmentIndex = LaunchRouteMode.allCases.firstIndex(of: options.routeMode) ?? 0
    }

    private func setTraffic(upload: String, download: String) {
        uploadValue.text = upload
        downloadValue.text = download
    }

    private func color(isConnected: Bool, isBusy: Bool) -> UIColor {
        if isConnected || isBusy { return AppTheme.primary }
        return UIColor { trait in
            trait.userInterfaceStyle == .dark
                ? UIColor(red: 0.22, green: 0.30, blue: 0.40, alpha: 1)
                : UIColor(red: 0.26, green: 0.32, blue: 0.40, alpha: 1)
        }
    }

    private func updatePulse(isConnected: Bool, isBusy: Bool) {
        let key = "openppp2.home.status.pulse"
        guard !isConnected && !isBusy else {
            dot.layer.removeAnimation(forKey: key)
            return
        }
        guard dot.layer.animation(forKey: key) == nil else { return }

        let animation = CABasicAnimation(keyPath: "opacity")
        animation.fromValue = 0.38
        animation.toValue = 1.0
        animation.duration = 1.6
        animation.autoreverses = true
        animation.repeatCount = .infinity
        animation.timingFunction = CAMediaTimingFunction(name: .easeInEaseOut)
        dot.layer.add(animation, forKey: key)
    }

    private func makeSpeedColumn(title: String, valueLabel: UILabel, color: UIColor) -> UIView {
        let titleLabel = UILabel()
        titleLabel.text = title
        titleLabel.font = .preferredFont(forTextStyle: .caption1)
        titleLabel.textColor = color
        titleLabel.textAlignment = .center

        valueLabel.font = .monospacedDigitSystemFont(ofSize: 20, weight: .bold)
        valueLabel.textColor = .label
        valueLabel.textAlignment = .center
        valueLabel.adjustsFontSizeToFitWidth = true
        valueLabel.minimumScaleFactor = 0.65
        valueLabel.numberOfLines = 1

        let stack = UIStackView(arrangedSubviews: [titleLabel, valueLabel])
        stack.axis = .vertical
        stack.alignment = .fill
        stack.spacing = 6
        return stack
    }

    private func makeSwitchRow(title: String, subtitle: String, control: UISwitch) -> UIView {
        let titleLabel = UILabel()
        titleLabel.text = title
        titleLabel.font = .preferredFont(forTextStyle: .body)
        titleLabel.textColor = .label

        let subtitleLabel = UILabel()
        subtitleLabel.text = subtitle
        subtitleLabel.font = .preferredFont(forTextStyle: .caption1)
        subtitleLabel.textColor = .secondaryLabel
        subtitleLabel.numberOfLines = 1
        subtitleLabel.adjustsFontSizeToFitWidth = true
        subtitleLabel.minimumScaleFactor = 0.78

        let labels = UIStackView(arrangedSubviews: [titleLabel, subtitleLabel])
        labels.axis = .vertical
        labels.spacing = 2
        labels.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)

        let row = UIStackView(arrangedSubviews: [labels, control])
        row.axis = .horizontal
        row.alignment = .center
        row.spacing = 12
        return row
    }

    private func makeRouteRow() -> UIView {
        let label = UILabel()
        label.text = L10n.tr("home.routeMode")
        label.font = .preferredFont(forTextStyle: .body)
        label.textColor = .label
        label.setContentHuggingPriority(.required, for: .horizontal)

        routeModeControl.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        let row = UIStackView(arrangedSubviews: [label, routeModeControl])
        row.axis = .horizontal
        row.alignment = .center
        row.spacing = 12
        return row
    }

    private func makeHorizontalDivider() -> UIView {
        let divider = UIView()
        divider.backgroundColor = .separator.withAlphaComponent(0.55)
        divider.heightAnchor.constraint(equalToConstant: 1 / UIScreen.main.scale).isActive = true
        return divider
    }

    private func makeVerticalDivider() -> UIView {
        let divider = UIView()
        divider.backgroundColor = .separator.withAlphaComponent(0.55)
        divider.widthAnchor.constraint(equalToConstant: 1 / UIScreen.main.scale).isActive = true
        divider.heightAnchor.constraint(equalToConstant: 42).isActive = true
        return divider
    }
}

private final class HomeProfileListView: UIView {
    var onApplyProfile: ((ConfigProfile) -> Void)?
    var onEditProfile: ((ConfigProfile) -> Void)?
    var onShareProfile: ((ConfigProfile) -> Void)?
    var onTogglePinnedProfile: ((ConfigProfile) -> Void)?
    var onAddProfile: (() -> Void)?
    var onImportFromFile: (() -> Void)?
    var onImportSubscription: (() -> Void)?

    private struct ProfileGroup {
        var title: String
        var profiles: [ConfigProfile]
    }

    private let titleLabel = UILabel()
    private let addButton = UIButton(type: .system)
    private let tableView = UITableView(frame: .zero, style: .plain)
    private var tableHeightConstraint: NSLayoutConstraint?
    private var groups: [ProfileGroup] = []
    private var activeId: String?
    private var configEditable = true
    private var maxTableHeight: CGFloat {
        min(360, max(240, UIScreen.main.bounds.height * 0.38))
    }

    override init(frame: CGRect) {
        super.init(frame: frame)
        setup()
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    private func setup() {
        translatesAutoresizingMaskIntoConstraints = false

        titleLabel.text = L10n.tr("tab.profiles")
        titleLabel.font = .systemFont(ofSize: 15, weight: .semibold)
        titleLabel.textColor = .secondaryLabel

        var addConfiguration = UIButton.Configuration.plain()
        addConfiguration.image = UIImage(systemName: "plus.circle")
        addConfiguration.baseForegroundColor = AppTheme.primary
        addConfiguration.contentInsets = NSDirectionalEdgeInsets(top: 2, leading: 6, bottom: 2, trailing: 0)
        addButton.configuration = addConfiguration
        addButton.showsMenuAsPrimaryAction = true
        addButton.menu = makeAddMenu()

        let header = UIStackView(arrangedSubviews: [titleLabel, addButton])
        header.axis = .horizontal
        header.alignment = .center
        header.spacing = 10

        tableView.backgroundColor = .clear
        tableView.dataSource = self
        tableView.delegate = self
        tableView.isScrollEnabled = false
        tableView.showsVerticalScrollIndicator = true
        tableView.separatorStyle = .none
        tableView.rowHeight = UITableView.automaticDimension
        tableView.estimatedRowHeight = 70
        tableView.estimatedSectionHeaderHeight = 28
        tableView.estimatedSectionFooterHeight = 8
        tableView.register(ProfileCell.self, forCellReuseIdentifier: ProfileCell.reuseIdentifier)
        tableView.register(ProfileSectionHeaderView.self, forHeaderFooterViewReuseIdentifier: ProfileSectionHeaderView.reuseIdentifier)
        tableView.translatesAutoresizingMaskIntoConstraints = false
        if #available(iOS 15.0, *) {
            tableView.sectionHeaderTopPadding = 0
        }

        let stack = UIStackView(arrangedSubviews: [header, tableView])
        stack.axis = .vertical
        stack.spacing = 8
        stack.translatesAutoresizingMaskIntoConstraints = false
        addSubview(stack)

        tableHeightConstraint = tableView.heightAnchor.constraint(equalToConstant: 1)
        tableHeightConstraint?.isActive = true

        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: leadingAnchor),
            stack.trailingAnchor.constraint(equalTo: trailingAnchor),
            stack.topAnchor.constraint(equalTo: topAnchor),
            stack.bottomAnchor.constraint(equalTo: bottomAnchor)
        ])
    }

    func apply(profiles: [ConfigProfile], activeId: String?, configEditable: Bool) {
        self.activeId = activeId
        self.configEditable = configEditable
        addButton.isEnabled = configEditable
        groups = Self.groupProfiles(profiles)
        tableView.reloadData()
        tableView.layoutIfNeeded()
        let contentHeight = max(44, tableView.contentSize.height)
        let cappedHeight = min(contentHeight, maxTableHeight)
        tableView.isScrollEnabled = contentHeight > maxTableHeight
        tableHeightConstraint?.constant = cappedHeight
        invalidateIntrinsicContentSize()
    }

    private func makeAddMenu() -> UIMenu {
        UIMenu(children: [
            UIAction(title: L10n.tr("profiles.addMenu.new"), image: UIImage(systemName: "plus")) { [weak self] _ in
                self?.onAddProfile?()
            },
            UIAction(title: L10n.tr("profiles.importSubscription"), image: UIImage(systemName: "icloud.and.arrow.down")) { [weak self] _ in
                self?.onImportSubscription?()
            },
            UIAction(title: L10n.tr("profiles.importFile"), image: UIImage(systemName: "doc.badge.plus")) { [weak self] _ in
                self?.onImportFromFile?()
            }
        ])
    }

    private static func groupProfiles(_ profiles: [ConfigProfile]) -> [ProfileGroup] {
        var result: [ProfileGroup] = []
        let pinned = profiles.filter(\.favorite)
        if !pinned.isEmpty {
            result.append(ProfileGroup(title: L10n.tr("profiles.group.pinned"), profiles: pinned))
        }

        for profile in profiles where !profile.favorite {
            let title = groupTitle(for: profile)
            if let index = result.firstIndex(where: { $0.title == title }) {
                result[index].profiles.append(profile)
            } else {
                result.append(ProfileGroup(title: title, profiles: [profile]))
            }
        }
        return result
    }

    private static func groupTitle(for profile: ConfigProfile) -> String {
        guard let urlText = profile.subscriptionUrl?.trimmingCharacters(in: .whitespacesAndNewlines),
              !urlText.isEmpty
        else {
            return L10n.tr("profiles.group.local")
        }
        let host = URL(string: urlText)?.host ?? urlText
        return L10n.format("profiles.group.subscription", host)
    }

    private func profile(at indexPath: IndexPath) -> ConfigProfile {
        groups[indexPath.section].profiles[indexPath.row]
    }
}

extension HomeProfileListView: UITableViewDataSource, UITableViewDelegate {
    func numberOfSections(in tableView: UITableView) -> Int {
        groups.count
    }

    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        groups[section].profiles.count
    }

    func tableView(_ tableView: UITableView, heightForHeaderInSection section: Int) -> CGFloat {
        28
    }

    func tableView(_ tableView: UITableView, viewForHeaderInSection section: Int) -> UIView? {
        let header = tableView.dequeueReusableHeaderFooterView(withIdentifier: ProfileSectionHeaderView.reuseIdentifier) as? ProfileSectionHeaderView
        header?.configure(title: groups[section].title)
        return header
    }

    func tableView(_ tableView: UITableView, heightForFooterInSection section: Int) -> CGFloat {
        section == groups.count - 1 ? 4 : 10
    }

    func tableView(_ tableView: UITableView, viewForFooterInSection section: Int) -> UIView? {
        UIView()
    }

    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: ProfileCell.reuseIdentifier, for: indexPath) as! ProfileCell
        let profile = profile(at: indexPath)
        cell.configure(profile: profile, isActive: profile.id == activeId, showsDisclosure: false)
        cell.applyGroupPosition(ProfilesViewController.groupPosition(row: indexPath.row, count: groups[indexPath.section].profiles.count))
        cell.selectionStyle = .default
        return cell
    }

    func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        tableView.deselectRow(at: indexPath, animated: true)
        guard configEditable else { return }
        onApplyProfile?(profile(at: indexPath))
    }

    func tableView(_ tableView: UITableView, leadingSwipeActionsConfigurationForRowAt indexPath: IndexPath) -> UISwipeActionsConfiguration? {
        guard configEditable else { return nil }
        let profile = profile(at: indexPath)
        let pinTitle = profile.favorite ? L10n.tr("profiles.unpin") : L10n.tr("profiles.pin")
        let pin = UIContextualAction(style: .normal, title: pinTitle) { [weak self] _, _, done in
            self?.onTogglePinnedProfile?(profile)
            done(true)
        }
        pin.backgroundColor = .systemYellow

        var actions = [pin]
        if profile.id != activeId {
            let apply = UIContextualAction(style: .normal, title: L10n.tr("profiles.apply")) { [weak self] _, _, done in
                self?.onApplyProfile?(profile)
                done(true)
            }
            apply.backgroundColor = AppTheme.primary
            actions.append(apply)
        }

        let configuration = UISwipeActionsConfiguration(actions: actions)
        configuration.performsFirstActionWithFullSwipe = false
        return configuration
    }

    func tableView(_ tableView: UITableView, trailingSwipeActionsConfigurationForRowAt indexPath: IndexPath) -> UISwipeActionsConfiguration? {
        let profile = profile(at: indexPath)
        let edit = UIContextualAction(style: .normal, title: L10n.tr("common.edit")) { [weak self] _, _, done in
            self?.onEditProfile?(profile)
            done(true)
        }
        edit.backgroundColor = AppTheme.primary

        let share = UIContextualAction(style: .normal, title: L10n.tr("profiles.share")) { [weak self] _, _, done in
            self?.onShareProfile?(profile)
            done(true)
        }
        share.backgroundColor = .systemPurple
        share.image = UIImage(systemName: "square.and.arrow.up")

        let actions = configEditable ? [share, edit] : [share]
        let configuration = UISwipeActionsConfiguration(actions: actions)
        configuration.performsFirstActionWithFullSwipe = false
        return configuration
    }
}

private final class TagLabel: UILabel {
    var insets = UIEdgeInsets(top: 5, left: 9, bottom: 5, right: 9) {
        didSet { invalidateIntrinsicContentSize() }
    }
    var tint: UIColor = AppTheme.primary {
        didSet {
            textColor = tint
            backgroundColor = tint.withAlphaComponent(0.12)
        }
    }

    override init(frame: CGRect) {
        super.init(frame: frame)
        font = .systemFont(ofSize: 12, weight: .semibold)
        textAlignment = .center
        layer.cornerRadius = 8
        clipsToBounds = true
        tint = AppTheme.primary
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    override func drawText(in rect: CGRect) {
        super.drawText(in: rect.inset(by: insets))
    }

    override var intrinsicContentSize: CGSize {
        let size = super.intrinsicContentSize
        return CGSize(width: size.width + insets.left + insets.right, height: size.height + insets.top + insets.bottom)
    }
}
