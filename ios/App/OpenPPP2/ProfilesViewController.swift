import UIKit

// MARK: - Profiles

final class ProfilesViewController: UIViewController, UITableViewDataSource, UITableViewDelegate {
    private let store = ProfileStore.shared
    private let tableView = UITableView(frame: .zero, style: .plain)
    private var profiles: [ConfigProfile] = []
    private var groups: [ProfileGroup] = []
    private var activeId: String?
    private let documentPicker = ProfileDocumentPicker()
    private var temporaryShareURL: URL?

    private struct ProfileGroup {
        var title: String
        var profiles: [ConfigProfile]
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        title = L10n.tr("profiles.title")
        view.backgroundColor = .systemGroupedBackground
        tableView.backgroundColor = .systemGroupedBackground
        tableView.tintColor = AppTheme.primary
        tableView.dataSource = self
        tableView.delegate = self
        tableView.separatorStyle = .none
        tableView.rowHeight = UITableView.automaticDimension
        tableView.estimatedRowHeight = 70
        tableView.estimatedSectionHeaderHeight = 34
        tableView.estimatedSectionFooterHeight = 14
        tableView.register(ProfileCell.self, forCellReuseIdentifier: ProfileCell.reuseIdentifier)
        tableView.register(ProfileSectionHeaderView.self, forHeaderFooterViewReuseIdentifier: ProfileSectionHeaderView.reuseIdentifier)
        tableView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(tableView)
        NSLayoutConstraint.activate([
            tableView.leadingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.leadingAnchor, constant: 18),
            tableView.trailingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.trailingAnchor, constant: -18),
            tableView.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            tableView.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor)
        ])
        tableView.contentInset = UIEdgeInsets(top: 14, left: 0, bottom: 24, right: 0)
        tableView.scrollIndicatorInsets = tableView.contentInset
        let menuButton = UIBarButtonItem(
            image: UIImage(systemName: "ellipsis.circle"),
            style: .plain,
            target: nil,
            action: nil
        )
        menuButton.menu = makeProfileMenu()
        navigationItem.rightBarButtonItems = [
            menuButton,
            makeAddButtonItem()
        ]
        NotificationCenter.default.addObserver(self, selector: #selector(reload), name: ProfileStore.didChangeNotification, object: nil)
        reload()
    }

    deinit {
        NotificationCenter.default.removeObserver(self)
    }

    @objc private func reload() {
        profiles = store.profiles()
        groups = Self.groupProfiles(profiles)
        activeId = store.activeProfile()?.id
        tableView.reloadData()
    }

    @objc private func addProfile() {
        let editor = ProfileEditViewController(profile: nil)
        navigationController?.pushViewController(editor, animated: true)
    }

    private func makeAddButtonItem() -> UIBarButtonItem {
        UIBarButtonItem(
            barButtonSystemItem: .add,
            target: self,
            action: #selector(addProfile)
        )
    }

    private func makeProfileMenu() -> UIMenu {
        UIMenu(children: [
            UIAction(
                title: L10n.tr("profiles.importSubscription"),
                image: UIImage(systemName: "icloud.and.arrow.down")
            ) { [weak self] _ in
                self?.importSubscription()
            },
            UIAction(
                title: L10n.tr("profiles.importFile"),
                image: UIImage(systemName: "doc.badge.plus")
            ) { [weak self] _ in
                self?.importFromFile()
            },
            UIAction(
                title: L10n.tr("profiles.exportAll"),
                image: UIImage(systemName: "square.and.arrow.up")
            ) { [weak self] _ in
                self?.exportAllProfiles()
            }
        ])
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
            case .cancelled:
                break
            case .exportFinished:
                break
            case let .failed(error):
                self.presentMessage(title: L10n.tr("profiles.importFailed"), message: error.localizedDescription)
            }
        }
    }

    private func applyImport(_ bundle: ProfileExportBundle, mode: ProfileImportMode) {
        do {
            let result = try store.importBundle(bundle, mode: mode)
            reload()
            presentProfileImportResult(result)
        } catch {
            presentMessage(title: L10n.tr("profiles.importFailed"), message: error.localizedDescription)
        }
    }

    private func exportAllProfiles() {
        confirmProfileSecretsWarning(title: L10n.tr("profiles.exportAll")) { [weak self] in
            guard let self else { return }
            do {
                let bundle = self.store.exportBundle()
                let data = try ProfileImportExportCodec.encode(bundle)
                let filename = ProfileImportExportCodec.allProfilesFilename()
                self.documentPicker.presentExport(data: data, filename: filename, from: self) { event in
                    switch event {
                    case .exportFinished:
                        self.presentToast(L10n.tr("profiles.exported"))
                    case let .failed(error):
                        self.presentMessage(title: L10n.tr("profiles.exportFailed"), message: error.localizedDescription)
                    case .cancelled, .imported:
                        break
                    }
                }
            } catch {
                self.presentMessage(title: L10n.tr("profiles.exportFailed"), message: error.localizedDescription)
            }
        }
    }

    @objc private func importSubscription() {
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
                        self.reload()
                        self.presentToast(L10n.format("profiles.importedNodes", count))
                    } catch {
                        self.presentMessage(title: L10n.tr("profiles.subscriptionFailed"), message: error.localizedDescription)
                    }
                }
            }
        }.resume()
    }

    func numberOfSections(in tableView: UITableView) -> Int {
        groups.count
    }

    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        groups[section].profiles.count
    }

    func tableView(_ tableView: UITableView, heightForHeaderInSection section: Int) -> CGFloat {
        34
    }

    func tableView(_ tableView: UITableView, viewForHeaderInSection section: Int) -> UIView? {
        let header = tableView.dequeueReusableHeaderFooterView(withIdentifier: ProfileSectionHeaderView.reuseIdentifier) as? ProfileSectionHeaderView
        header?.configure(title: groups[section].title)
        return header
    }

    func tableView(_ tableView: UITableView, heightForFooterInSection section: Int) -> CGFloat {
        section == groups.count - 1 ? 18 : 14
    }

    func tableView(_ tableView: UITableView, viewForFooterInSection section: Int) -> UIView? {
        UIView()
    }

    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: ProfileCell.reuseIdentifier, for: indexPath) as! ProfileCell
        let profile = profile(at: indexPath)
        cell.configure(profile: profile, isActive: profile.id == activeId)
        cell.applyGroupPosition(Self.groupPosition(row: indexPath.row, count: groups[indexPath.section].profiles.count))
        return cell
    }

    func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        tableView.deselectRow(at: indexPath, animated: true)
        navigationController?.pushViewController(ProfileEditViewController(profile: profile(at: indexPath)), animated: true)
    }

    func tableView(_ tableView: UITableView, leadingSwipeActionsConfigurationForRowAt indexPath: IndexPath) -> UISwipeActionsConfiguration? {
        let profile = profile(at: indexPath)
        let pinTitle = profile.favorite ? L10n.tr("profiles.unpin") : L10n.tr("profiles.pin")
        let pin = UIContextualAction(style: .normal, title: pinTitle) { [weak self] _, _, done in
            self?.togglePinnedProfile(profile)
            done(true)
        }
        pin.backgroundColor = .systemYellow

        var actions = [pin]
        if profile.id != activeId {
            let apply = UIContextualAction(style: .normal, title: L10n.tr("profiles.apply")) { [weak self] _, _, done in
                self?.applyProfile(profile)
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
            self?.navigationController?.pushViewController(ProfileEditViewController(profile: profile), animated: true)
            done(true)
        }
        edit.backgroundColor = AppTheme.primary

        let share = UIContextualAction(style: .normal, title: L10n.tr("profiles.share")) { [weak self] _, _, done in
            self?.shareProfile(profile)
            done(true)
        }
        share.backgroundColor = .systemPurple
        share.image = UIImage(systemName: "square.and.arrow.up")

        let delete = UIContextualAction(style: .destructive, title: L10n.tr("common.delete")) { [weak self] _, _, done in
            self?.confirmDelete(profile)
            done(true)
        }

        let configuration = UISwipeActionsConfiguration(actions: [delete, share, edit])
        configuration.performsFirstActionWithFullSwipe = false
        return configuration
    }

    private func applyProfile(_ profile: ConfigProfile) {
        store.setActive(profile.id)
        promptRestartForActiveTunnelIfNeeded(
            profile: profile,
            message: L10n.format("profiles.switched.message", profile.name),
            noRestartMessage: nil
        )
    }

    private func togglePinnedProfile(_ profile: ConfigProfile) {
        var updated = profile
        updated.favorite.toggle()
        store.update(updated, snapshot: false)
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

    private func profile(at indexPath: IndexPath) -> ConfigProfile {
        groups[indexPath.section].profiles[indexPath.row]
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

    static func groupPosition(row: Int, count: Int) -> ProfileCell.GroupPosition {
        if count <= 1 { return .single }
        if row == 0 { return .first }
        if row == count - 1 { return .last }
        return .middle
    }

    private func confirmDelete(_ profile: ConfigProfile) {
        let alert = UIAlertController(title: L10n.tr("profiles.deleteProfile"), message: L10n.format("profiles.deleteProfile.message", profile.name), preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: L10n.tr("common.cancel"), style: .cancel))
        alert.addAction(UIAlertAction(title: L10n.tr("common.delete"), style: .destructive) { [weak self] _ in
            self?.store.remove(profile.id)
        })
        present(alert, animated: true)
    }
}

final class ProfileCell: UITableViewCell {
    enum GroupPosition {
        case single
        case first
        case middle
        case last
    }

    static let reuseIdentifier = "ProfileCell"

    private let cardBackground = UIView()
    private let selectedCardBackground = UIView()
    private let leftIndicator = UIView()
    private let divider = UIView()
    private let badge = UILabel()
    private let nameLabel = UILabel()
    private let subtitleLabel = UILabel()
    private let activeBadge = UILabel()
    private var currentIsActive = false
    private var currentGroupPosition: GroupPosition = .single

    override init(style: UITableViewCell.CellStyle, reuseIdentifier: String?) {
        super.init(style: style, reuseIdentifier: reuseIdentifier)
        accessoryType = .disclosureIndicator
        backgroundColor = .clear
        contentView.backgroundColor = .clear
        cardBackground.backgroundColor = .secondarySystemGroupedBackground
        selectedCardBackground.backgroundColor = .tertiarySystemGroupedBackground
        cardBackground.layer.borderWidth = 0
        selectedCardBackground.layer.borderWidth = 0
        backgroundView = cardBackground
        selectedBackgroundView = selectedCardBackground

        leftIndicator.backgroundColor = AppTheme.primary
        leftIndicator.layer.cornerRadius = 1.5
        leftIndicator.isHidden = true
        leftIndicator.translatesAutoresizingMaskIntoConstraints = false
        contentView.addSubview(leftIndicator)

        divider.backgroundColor = .separator.withAlphaComponent(0.55)
        divider.translatesAutoresizingMaskIntoConstraints = false
        contentView.addSubview(divider)

        badge.textAlignment = .center
        badge.font = .systemFont(ofSize: 20, weight: .semibold)
        badge.textColor = .secondaryLabel
        badge.backgroundColor = .tertiarySystemGroupedBackground
        badge.layer.cornerRadius = 18
        badge.clipsToBounds = true

        nameLabel.font = .systemFont(ofSize: 16, weight: .semibold)
        subtitleLabel.font = .preferredFont(forTextStyle: .footnote)
        subtitleLabel.textColor = .secondaryLabel
        subtitleLabel.numberOfLines = 1

        activeBadge.text = L10n.tr("profiles.active")
        activeBadge.font = .systemFont(ofSize: 10, weight: .bold)
        activeBadge.textColor = .white
        activeBadge.backgroundColor = AppTheme.primary
        activeBadge.layer.cornerRadius = 7
        activeBadge.clipsToBounds = true
        activeBadge.textAlignment = .center

        let titleRow = UIStackView(arrangedSubviews: [nameLabel, activeBadge])
        titleRow.axis = .horizontal
        titleRow.spacing = 8
        titleRow.alignment = .center
        let textStack = UIStackView(arrangedSubviews: [titleRow, subtitleLabel])
        textStack.axis = .vertical
        textStack.spacing = 3
        let row = UIStackView(arrangedSubviews: [badge, textStack])
        row.axis = .horizontal
        row.spacing = 12
        row.alignment = .center
        row.translatesAutoresizingMaskIntoConstraints = false
        contentView.addSubview(row)

        NSLayoutConstraint.activate([
            badge.widthAnchor.constraint(equalToConstant: 36),
            badge.heightAnchor.constraint(equalToConstant: 36),
            activeBadge.widthAnchor.constraint(equalToConstant: 50),
            activeBadge.heightAnchor.constraint(equalToConstant: 18),
            row.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 14),
            row.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -8),
            row.topAnchor.constraint(equalTo: contentView.topAnchor, constant: 12),
            row.bottomAnchor.constraint(equalTo: contentView.bottomAnchor, constant: -12),
            leftIndicator.leadingAnchor.constraint(equalTo: contentView.leadingAnchor),
            leftIndicator.centerYAnchor.constraint(equalTo: contentView.centerYAnchor),
            leftIndicator.widthAnchor.constraint(equalToConstant: 3),
            leftIndicator.heightAnchor.constraint(equalTo: contentView.heightAnchor, multiplier: 0.58),
            divider.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 62),
            divider.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -16),
            divider.bottomAnchor.constraint(equalTo: contentView.bottomAnchor),
            divider.heightAnchor.constraint(equalToConstant: 1 / UIScreen.main.scale)
        ])
        applyGroupPosition(.single)
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    override func prepareForReuse() {
        super.prepareForReuse()
        currentIsActive = false
        applyGroupPosition(.single)
    }

    func configure(profile: ConfigProfile, isActive: Bool, showsDisclosure: Bool = true) {
        currentIsActive = isActive
        accessoryType = showsDisclosure ? .disclosureIndicator : .none
        badge.text = isActive ? "✓" : (profile.flag.isEmpty ? "◎" : profile.flag)
        nameLabel.text = profile.name
        activeBadge.text = L10n.tr("profiles.active")
        subtitleLabel.text = profile.subtitle.isEmpty ? (profile.serverEndpoint ?? L10n.tr("profiles.noServer")) : profile.subtitle
        activeBadge.isHidden = false
        activeBadge.alpha = isActive ? 1 : 0
        updateChrome()
    }

    func applyGroupPosition(_ position: GroupPosition) {
        currentGroupPosition = position
        updateChrome()
    }

    private func updateChrome() {
        let corners: CACornerMask
        switch currentGroupPosition {
        case .single:
            corners = [.layerMinXMinYCorner, .layerMaxXMinYCorner, .layerMinXMaxYCorner, .layerMaxXMaxYCorner]
        case .first:
            corners = [.layerMinXMinYCorner, .layerMaxXMinYCorner]
        case .middle:
            corners = []
        case .last:
            corners = [.layerMinXMaxYCorner, .layerMaxXMaxYCorner]
        }

        let active = currentIsActive
        divider.isHidden = active || currentGroupPosition == .single || currentGroupPosition == .last
        leftIndicator.isHidden = !active
        nameLabel.textColor = active ? AppTheme.primary : .label
        badge.textColor = active ? .white : .secondaryLabel
        badge.backgroundColor = active ? AppTheme.primary : .tertiarySystemGroupedBackground
        cardBackground.backgroundColor = active ? AppTheme.primarySoft : .secondarySystemGroupedBackground
        selectedCardBackground.backgroundColor = active ? AppTheme.primaryMuted : .tertiarySystemGroupedBackground
        [cardBackground, selectedCardBackground].forEach { view in
            view.layer.cornerRadius = corners.isEmpty ? 0 : 16
            view.layer.cornerCurve = .continuous
            view.layer.maskedCorners = corners
            view.layer.borderWidth = 0
            view.layer.borderColor = UIColor.clear.cgColor
            view.clipsToBounds = true
        }
    }
}

final class ProfileSectionHeaderView: UITableViewHeaderFooterView {
    static let reuseIdentifier = "ProfileSectionHeaderView"

    private let titleLabel = UILabel()

    override init(reuseIdentifier: String?) {
        super.init(reuseIdentifier: reuseIdentifier)
        contentView.backgroundColor = .clear
        backgroundView = UIView()
        backgroundView?.backgroundColor = .clear

        titleLabel.font = .systemFont(ofSize: 15, weight: .semibold)
        titleLabel.textColor = .secondaryLabel
        titleLabel.translatesAutoresizingMaskIntoConstraints = false
        contentView.addSubview(titleLabel)

        NSLayoutConstraint.activate([
            titleLabel.leadingAnchor.constraint(equalTo: contentView.leadingAnchor),
            titleLabel.trailingAnchor.constraint(lessThanOrEqualTo: contentView.trailingAnchor),
            titleLabel.bottomAnchor.constraint(equalTo: contentView.bottomAnchor, constant: -6)
        ])
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    func configure(title: String) {
        titleLabel.text = title
    }
}
