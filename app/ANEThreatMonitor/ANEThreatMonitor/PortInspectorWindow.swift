import SwiftUI
import AppKit
import Combine
import QuartzCore

struct PortInspectorData {
    var transport: String = "TCP"
    var port: Int = 0
    var pid: String = "-"
    var processName: String = "-"
    var statusText: String = "Select a port to inspect."
    var commandText: String = "-"
    var isInspecting: Bool = false
}

final class PortInspectorStore: ObservableObject {
    @Published var data = PortInspectorData()
}

struct PortInspectorWindowView: View {
    @ObservedObject var store: PortInspectorStore

    var body: some View {
        ZStack {
            LinearGradient(
                colors: [
                    Color(red: 0.07, green: 0.08, blue: 0.12),
                    Color(red: 0.09, green: 0.10, blue: 0.15)
                ],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
            .ignoresSafeArea()

            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Shows which local process is using the selected port")
                            .font(.system(size: 12, weight: .regular))
                            .foregroundStyle(Color.white.opacity(0.68))
                    }

                    infoCard {
                        detailRow("Protocol", store.data.transport)
                        detailRow("Port", String(store.data.port))
                        detailRow("PID", store.data.pid)
                        detailRow("Process", store.data.processName)
                    }

                    infoCard {
                        VStack(alignment: .leading, spacing: 6) {
                            Text("Status")
                                .font(.caption)
                                .foregroundStyle(Color.white.opacity(0.68))

                            if store.data.isInspecting {
                                ProgressView()
                                    .controlSize(.small)
                            }

                            Text(store.data.statusText)
                                .font(.system(size: 13, weight: .regular))
                                .foregroundStyle(.white)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }

                    infoCard {
                        VStack(alignment: .leading, spacing: 6) {
                            Text("Command")
                                .font(.caption)
                                .foregroundStyle(Color.white.opacity(0.68))

                            Text(store.data.commandText)
                                .font(.system(size: 12, weight: .regular, design: .monospaced))
                                .foregroundStyle(.white)
                                .textSelection(.enabled)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                }
                .padding(18)
                .frame(maxWidth: .infinity, alignment: .topLeading)
            }
        }
        .frame(minWidth: 460, minHeight: 420)
    }

    private func infoCard<Content: View>(@ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            content()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(12)
        .background(Color(red: 0.17, green: 0.19, blue: 0.26))
        .overlay(
            RoundedRectangle(cornerRadius: 12)
                .stroke(Color.white.opacity(0.08), lineWidth: 1)
        )
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }

    private func detailRow(_ title: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title)
                .font(.caption)
                .foregroundStyle(Color.white.opacity(0.68))

            Text(value)
                .font(.system(size: 15, weight: .semibold))
                .foregroundStyle(.white)
        }
    }
}

final class PortInspectorWindowController {
    static let shared = PortInspectorWindowController()

    private var window: NSWindow?
    private var hasPresentedOnce = false
    private let presentedFrameSize = NSSize(width: 520, height: 520)
    let store = PortInspectorStore()

    func show() {
        if let window {
            present(window: window, animated: false)
            return
        }

        let contentView = PortInspectorWindowView(store: store)
        let hostingController = NSHostingController(rootView: contentView)

        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 520, height: 520),
            styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )

        window.title = "Port Inspector"
        window.center()
        window.isReleasedWhenClosed = false
        window.contentViewController = hostingController
        window.setFrameAutosaveName("PortInspectorWindow")

        let finalFrame = window.frame
        let startWidth = finalFrame.width * 0.94
        let startHeight = finalFrame.height * 0.94
        let startOrigin = NSPoint(
            x: finalFrame.origin.x + (finalFrame.width - startWidth) / 2,
            y: finalFrame.origin.y + (finalFrame.height - startHeight) / 2
        )
        let startFrame = NSRect(
            origin: startOrigin,
            size: NSSize(width: startWidth, height: startHeight)
        )

        window.setFrame(startFrame, display: false)
        window.alphaValue = 0.0

        self.window = window
        present(window: window, animated: true)
    }

    private func present(window: NSWindow, animated: Bool) {
        let finalFrame = NSRect(
            x: window.frame.origin.x - (presentedFrameSize.width - window.frame.width) / 2,
            y: window.frame.origin.y - (presentedFrameSize.height - window.frame.height) / 2,
            width: presentedFrameSize.width,
            height: presentedFrameSize.height
        )

        if animated && !window.isVisible {
            let startWidth = finalFrame.width * 0.94
            let startHeight = finalFrame.height * 0.94
            let startOrigin = NSPoint(
                x: finalFrame.origin.x + (finalFrame.width - startWidth) / 2,
                y: finalFrame.origin.y + (finalFrame.height - startHeight) / 2
            )
            let startFrame = NSRect(
                origin: startOrigin,
                size: NSSize(width: startWidth, height: startHeight)
            )

            window.setFrame(finalFrame, display: false)
            window.alphaValue = 0.0
            window.makeKeyAndOrderFront(nil)
            window.setFrame(startFrame, display: true)

            NSAnimationContext.runAnimationGroup { context in
                context.duration = 0.20
                context.timingFunction = CAMediaTimingFunction(name: .easeOut)
                window.animator().alphaValue = 1.0
                window.animator().setFrame(finalFrame, display: true)
            }
            hasPresentedOnce = true
        } else {
            window.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)

            if !hasPresentedOnce {
                hasPresentedOnce = true
            }

            NSAnimationContext.runAnimationGroup { context in
                context.duration = 0.14
                context.timingFunction = CAMediaTimingFunction(name: .easeOut)
                window.animator().alphaValue = 1.0
            }
        }
    }

    func update(data: PortInspectorData) {
        store.data = data
        show()
    }

    func close() {
        window?.close()
        window = nil
    }
}
