import SwiftUI
import AppKit
import ClaudeGuardCore

@main
struct ClaudeGuardApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @ObservedObject private var model = StatusModel.shared

    var body: some Scene {
        MenuBarExtra {
            MenuContentView(model: model)
        } label: {
            Image(systemName: model.menuIcon)
        }
        .menuBarExtraStyle(.window)
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        Task { @MainActor in StatusModel.shared.start() }
    }
}

// MARK: - Model

@MainActor
final class StatusModel: ObservableObject {
    static let shared = StatusModel()
    static let cli = "/Library/PrivilegedHelperTools/claudeguardd"

    @Published private(set) var status: GuardStatus?
    @Published private(set) var refreshing = false
    @Published private(set) var now = Date()
    @Published private(set) var claudeCodeProxy: String?
    @Published private(set) var busy = false

    private var refreshStartedAt: Date?
    private var timer: Timer?
    private var started = false

    func start() {
        guard !started else { return }
        started = true
        reload()
        GuardNotify.observe(GuardNotify.statusChanged, queue: .main) {
            Task { @MainActor in StatusModel.shared.reload() }
        }
        timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { _ in
            Task { @MainActor in
                StatusModel.shared.now = Date()
                StatusModel.shared.reload()
            }
        }
        if isAlarm(status) { BlockedWindowController.shared.show() }
    }

    var serviceRunning: Bool {
        guard let s = status else { return false }
        return now.timeIntervalSince(s.updatedAt) < GuardStatus.staleAfter
    }

    var menuIcon: String {
        guard serviceRunning, let s = status else { return "exclamationmark.shield" }
        switch s.state {
        case .allowed: return "checkmark.shield.fill"
        case .proxyOnly: return "checkmark.shield"
        case .blocked: return "xmark.shield.fill"
        case .checking: return "shield.lefthalf.filled"
        }
    }

    /// In Iran with no safe route at all.
    func isAlarm(_ s: GuardStatus?) -> Bool { s?.inIran == true && s?.state == .blocked }

    func reload() {
        let new = GuardStatus.load()
        let old = status
        if new != old { status = new }
        let cc = ClaudeSettings.proxy()
        if cc != claudeCodeProxy { claudeCodeProxy = cc }

        if refreshing, let started = refreshStartedAt {
            if let s = new, s.state != .checking, let c = s.checkedAt, c >= started.addingTimeInterval(-0.5) {
                refreshing = false
            } else if Date().timeIntervalSince(started) > 30 {
                refreshing = false
            }
        }

        if isAlarm(new) && !isAlarm(old) {
            BlockedWindowController.shared.show()
        }
    }

    func refresh() {
        refreshing = true
        refreshStartedAt = Date()
        GuardNotify.post(GuardNotify.refresh)
    }

    /// Turns "route Claude Code through the system proxy" on/off via the CLI.
    func toggleClaudeCodeProxy() {
        let turnOn = claudeCodeProxy == nil
        let proxy = status?.proxy?.system.http
        busy = true
        DispatchQueue.global().async {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: Self.cli)
            p.arguments = turnOn ? ["claude-proxy", "on"] + (proxy.map { [$0] } ?? []) : ["claude-proxy", "off"]
            let pipe = Pipe()
            p.standardOutput = pipe
            p.standardError = pipe
            var output = ""
            do {
                try p.run()
                output = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
                p.waitUntilExit()
            } catch {
                output = "\(error)"
            }
            DispatchQueue.main.async {
                StatusModel.shared.busy = false
                StatusModel.shared.reload()
                let alert = NSAlert()
                alert.messageText = "ClaudeGuard"
                alert.informativeText = output.trimmingCharacters(in: .whitespacesAndNewlines)
                NSApp.activate(ignoringOtherApps: true)
                alert.runModal()
            }
        }
    }
}

// MARK: - Menu bar popover

struct MenuContentView: View {
    @ObservedObject var model: StatusModel

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            StatusHeader(model: model)

            if let s = model.status, model.serviceRunning {
                Text(s.message)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                Divider()
                DetailsGrid(status: s, now: model.now, claudeCodeProxy: model.claudeCodeProxy)
                ClaudeCodeProxyRow(model: model, status: s)
            } else {
                Text("The ClaudeGuard protection service isn't running, so your location can't be verified. Run install.sh again.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Divider()

            HStack {
                RefreshButton(model: model)
                Spacer()
                Button("Quit") { NSApp.terminate(nil) }
                    .help("Quits the menu bar app only. Protection keeps running in the background.")
            }
        }
        .padding(16)
        .frame(width: 360)
    }
}

struct StatusHeader: View {
    @ObservedObject var model: StatusModel

    var body: some View {
        let (title, color, icon) = look
        HStack(spacing: 10) {
            Image(systemName: icon)
                .font(.system(size: 26))
                .foregroundStyle(color)
            VStack(alignment: .leading, spacing: 2) {
                Text("ClaudeGuard").font(.caption).foregroundStyle(.secondary)
                Text(title).font(.headline)
            }
        }
    }

    private var look: (String, Color, String) {
        guard model.serviceRunning, let s = model.status else {
            return ("Service not running", .orange, "exclamationmark.shield.fill")
        }
        switch s.state {
        case .allowed: return ("Claude allowed", .green, "checkmark.shield.fill")
        case .proxyOnly: return ("Allowed via proxy only", .blue, "checkmark.shield.fill")
        case .checking: return ("Checking your IP…", .yellow, "shield.lefthalf.filled")
        case .blocked:
            return s.inIran
                ? ("Blocked: Iranian IP", .red, "xmark.shield.fill")
                : ("Blocked: location not verified", .orange, "xmark.shield.fill")
        }
    }
}

struct DetailsGrid: View {
    let status: GuardStatus
    let now: Date
    let claudeCodeProxy: String?

    var body: some View {
        Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 6) {
            if let n = status.network { row("VPN", n.summary) }
            ForEach(status.apps ?? [], id: \.source) { a in
                row(a.sendsClaudeDirect ? "⚠️ \(a.name)" : a.name,
                    a.describe.replacingOccurrences(of: "\(a.name): ", with: ""))
            }
            row(status.network?.bound == true ? "Anthropic path" : (status.network?.tunnelActive == true ? "Via TUN" : "Direct"), "\(CountryInfo.flag(status.country)) \(CountryInfo.name(status.country))  \(status.ipv4 ?? status.ipv6 ?? "-")")
            if let p = status.proxy {
                row("Desktop route", p.describe)
                if let pac = p.pacResult { row("  PAC answer", pac) }
                row("  exits in", p.ok
                    ? "\(CountryInfo.flag(p.country)) \(CountryInfo.name(p.country))  \(p.ipv4 ?? p.ipv6 ?? "")"
                    : (p.kind == "iran" ? "🇮🇷 Iran" : "not verified"))
            } else {
                row("System proxy", "off")
            }
            row("Claude Code", claudeCodeLine)
            row("Claude Desktop", status.desktopBlocked == true ? "Blocked"
                : (status.state == .blocked ? "Blocked" : "Allowed"))
            row("Checked", checkedText)
        }
        .font(.callout)
    }

    private var claudeCodeLine: String {
        if let cc = claudeCodeProxy { return "via \(cc)" }
        return status.enforcing ? "Blocked (direct)" : "Allowed (direct)"
    }

    private var checkedText: String {
        guard let c = status.checkedAt else { return "never" }
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .full
        return f.localizedString(for: c, relativeTo: max(now, c))
    }

    private func row(_ k: String, _ v: String) -> some View {
        GridRow {
            Text(k).foregroundStyle(.secondary)
            Text(v).textSelection(.enabled).lineLimit(1).truncationMode(.middle)
        }
    }
}

/// Claude Code ignores the system proxy; offer to route it through v2ray's HTTP port.
struct ClaudeCodeProxyRow: View {
    @ObservedObject var model: StatusModel
    let status: GuardStatus

    var body: some View {
        if let cc = model.claudeCodeProxy {
            Button("Stop routing Claude Code through \(cc)") { model.toggleClaudeCodeProxy() }
                .disabled(model.busy)
        } else if let http = status.proxy?.system.http {
            VStack(alignment: .leading, spacing: 4) {
                Button("Route Claude Code through \(http)") { model.toggleClaudeCodeProxy() }
                    .disabled(model.busy)
                if status.state == .proxyOnly {
                    Text("Claude Code ignores the system proxy, so it's blocked until you do this (then restart Claude Code).")
                        .font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }
}

struct RefreshButton: View {
    @ObservedObject var model: StatusModel

    var body: some View {
        Button {
            model.refresh()
        } label: {
            HStack(spacing: 6) {
                if model.refreshing {
                    ProgressView().controlSize(.small)
                } else {
                    Image(systemName: "arrow.clockwise")
                }
                Text(model.refreshing ? "Checking…" : "Refresh")
            }
        }
        .keyboardShortcut("r")
        .disabled(model.refreshing || !model.serviceRunning)
    }
}

// MARK: - "You are in Iran" window

@MainActor
final class BlockedWindowController {
    static let shared = BlockedWindowController()
    private var window: NSWindow?

    func show() {
        if window == nil {
            let host = NSHostingController(rootView: BlockedView(model: .shared))
            let w = NSWindow(contentViewController: host)
            w.title = "ClaudeGuard"
            w.styleMask = [.titled, .closable]
            w.isReleasedWhenClosed = false
            w.level = .floating
            window = w
        }
        window?.center()
        NSApp.activate(ignoringOtherApps: true)
        window?.makeKeyAndOrderFront(nil)
    }

    func close() { window?.close() }
}

struct BlockedView: View {
    @ObservedObject var model: StatusModel

    private var state: GuardStatus.State? { model.status?.state }
    private var resolved: Bool { state == .allowed || state == .proxyOnly }

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: resolved ? "checkmark.shield.fill" : "xmark.shield.fill")
                .font(.system(size: 56))
                .foregroundStyle(state == .allowed ? .green : (state == .proxyOnly ? .blue : .red))

            if state == .allowed {
                Text("You're no longer on an Iranian IP").font(.title2.bold())
                Text("Claude Code and Claude Desktop are unblocked.")
                    .foregroundStyle(.secondary)
            } else if state == .proxyOnly, let p = model.status?.proxy {
                Text("Your v2ray proxy exits in \(CountryInfo.name(p.country))").font(.title2.bold())
                Text(model.claudeCodeProxy == nil && p.system.http != nil
                     ? "Claude Desktop is unblocked. Direct connections stay blocked. Claude Code ignores the system proxy, so route it through \(p.system.http!) from the menu bar icon, then restart Claude Code."
                     : "Claude Desktop and Claude Code (via the proxy) can connect. Direct connections stay blocked.")
                    .multilineTextAlignment(.center)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                Text("You are in Iran").font(.title2.bold())
                Text("Your IP address is located in Iran, so Claude Code and Claude Desktop are blocked and can't connect. Your Iranian IP is not sent to Anthropic.")
                    .multilineTextAlignment(.center)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if let s = model.status {
                    Text("IP: \(s.ipv4 ?? s.ipv6 ?? "unknown")  ·  \(CountryInfo.flag(s.country)) \(CountryInfo.name(s.country))")
                        .font(.callout.monospaced())
                        .textSelection(.enabled)
                    if let p = s.proxy, !p.detail.isEmpty {
                        Text("System proxy: \(p.detail)")
                            .font(.caption).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                Text("Connect your VPN (TUN, system-proxy or PAC mode), then press Refresh.")
                    .font(.callout)
                    .multilineTextAlignment(.center)
            }

            HStack {
                if resolved {
                    Button("Close") { BlockedWindowController.shared.close() }
                        .keyboardShortcut(.defaultAction)
                } else {
                    Button("Close") { BlockedWindowController.shared.close() }
                    RefreshButton(model: model)
                        .keyboardShortcut(.defaultAction)
                }
            }
        }
        .padding(28)
        .frame(width: 440)
        .onChange(of: state) { newState in
            if newState == .allowed {
                DispatchQueue.main.asyncAfter(deadline: .now() + 2.5) {
                    if StatusModel.shared.status?.state == .allowed { BlockedWindowController.shared.close() }
                }
            }
        }
    }
}
