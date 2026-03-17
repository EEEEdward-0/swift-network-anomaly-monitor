import SwiftUI

struct ContentView: View {
    // MARK: - 页面状态与主题
    @StateObject var viewModel = InferenceViewModel()
    
    @State var isLogExpanded: Bool = false
    @State var viewportWidth: CGFloat = 1400
    @State var showTCPPortsPopover: Bool = false
    @State var showUDPPortsPopover: Bool = false
    // 主机信息弹出面板显示状态
    @State var isHostInfoPopoverPresented: Bool = false
    
    // 公网信息弹出面板显示状态
    @State var isPublicNetworkPopoverPresented: Bool = false
    // 端口归属缓存：当前重构阶段先使用字符串占位，避免依赖未接入的 PortOwnerSummary 类型。
    @State var portOwnerCache: [String: String] = [:]
    @State var isInspectingPortOwner: Bool = false
    @State var inspectedPortTransport: String = "TCP"
    @State var inspectedPortNumber: Int = 0
    @State var inspectedPortPID: String = "-"
    @State var inspectedPortProcessName: String = "-"
    @State var inspectedPortStatusText: String = "Select a port to inspect."
    @State var inspectedPortRawCommand: String = ""
    @State var loadingDotsPhase: Int = 0
    @State var loadingDotsTimer: Timer? = nil
    // 风险列表排序与分页状态：供 ContentSections.swift 访问，不能设为 private。
    @State var riskSortDescending: Bool = true
    @State var riskPageIndex: Int = 0
    let riskPageSize: Int = 5
    @Environment(\.colorScheme) private var systemColorScheme
    
    
    var isPrideTheme: Bool {
        viewModel.themeMode == .pride
    }
    
    var isLightTheme: Bool {
        switch viewModel.themeMode {
        case .light:
            return true
        case .dark:
            return false
        case .pride:
            return true
        case .system:
            return systemColorScheme == .light
        }
    }
    
    var pageBackground: LinearGradient {
        if isPrideTheme {
            return LinearGradient(
                colors: [
                    Color(red: 1.00, green: 0.42, blue: 0.42),
                    Color(red: 1.00, green: 0.67, blue: 0.30),
                    Color(red: 1.00, green: 0.86, blue: 0.34),
                    Color(red: 0.39, green: 0.82, blue: 0.47),
                    Color(red: 0.34, green: 0.66, blue: 1.00),
                    Color(red: 0.62, green: 0.48, blue: 0.98)
                ],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
        }
        
        if isLightTheme {
            return LinearGradient(
                colors: [
                    Color(red: 0.95, green: 0.97, blue: 1.00),
                    Color(red: 0.92, green: 0.95, blue: 0.99)
                ],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
        }
        
        return LinearGradient(
            colors: [
                Color(red: 0.07, green: 0.08, blue: 0.12),
                Color(red: 0.09, green: 0.10, blue: 0.15)
            ],
            startPoint: .topLeading,
            endPoint: .bottomTrailing
        )
    }
    
    var surfacePrimary: Color {
        if isPrideTheme {
            return Color.white.opacity(0.88)
        }
        
        return isLightTheme
        ? Color(red: 0.98, green: 0.99, blue: 1.00)
        : Color(red: 0.14, green: 0.16, blue: 0.22)
    }
    
    var surfaceSecondary: Color {
        if isPrideTheme {
            return Color.white.opacity(0.72)
        }
        
        return isLightTheme
        ? Color(red: 0.94, green: 0.96, blue: 0.99)
        : Color(red: 0.17, green: 0.19, blue: 0.26)
    }
    
    var borderSoft: Color {
        if isPrideTheme {
            return Color.white.opacity(0.42)
        }
        
        return isLightTheme ? Color.black.opacity(0.08) : Color.white.opacity(0.08)
    }
    
    var mutedText: Color {
        if isPrideTheme {
            return Color.black.opacity(0.62)
        }
        
        return isLightTheme ? Color.black.opacity(0.60) : Color.white.opacity(0.68)
    }
    
    var primaryText: Color {
        if isPrideTheme {
            return Color.black.opacity(0.92)
        }
        
        return isLightTheme ? Color.black.opacity(0.88) : .white
    }
    
    // MARK: - 页面入口布局
    var body: some View {
        GeometryReader { proxy in
            ZStack {
                pageBackground
                    .ignoresSafeArea()
                
                ScrollView {
                    VStack(alignment: .leading, spacing: 18) {
                        headerSection
                        captureSettingsSection
                        analysisLogSection
                        hostSummarySection
                        realtimeSection
                        whitelistManagerSection
                        historySection
                        demoSection
                    }
                    .padding(20)
                    .frame(maxWidth: .infinity, alignment: .topLeading)
                }
                .scrollContentBackground(.hidden)
            }
            .onAppear {
                viewportWidth = proxy.size.width
                startLoadingDotsTimer()
            }
            .onDisappear {
                stopLoadingDotsTimer()
            }
            .onChange(of: proxy.size.width) { _, newValue in
                viewportWidth = newValue
            }
        }
        .frame(minWidth: 920, minHeight: 700)
        .preferredColorScheme(viewModel.themeMode.colorScheme)
        .onChange(of: viewModel.themeMode) { _, _ in
            viewModel.saveThemeMode()
        }
    }
    
    var whitelistManagerSection: some View {
        let valuePlaceholder: String = {
            switch viewModel.whitelistInputKind {
            case "host":
                return "example.com"
            case "ip":
                return "8.8.8.8"
            case "ip_port":
                return "8.8.8.8:53"
            default:
                return "Value"
            }
        }()
        
        return GroupBox {
            VStack(alignment: .leading, spacing: 12) {
                HStack(alignment: .center, spacing: 12) {
                    sectionTitle("Whitelist Manager", systemImage: "checkmark.shield")
                    
                    Spacer(minLength: 16)
                    
                    Button("Refresh") {
                        viewModel.refreshWhitelist()
                    }
                    .frame(width: 132, height: 34)
                    .buttonStyle(.bordered)
                }
                
                HStack(alignment: .center, spacing: 10) {
                    Picker("Type", selection: $viewModel.whitelistInputKind) {
                        Text("Host").tag("host")
                        Text("IP").tag("ip")
                        Text("IP:Port").tag("ip_port")
                    }
                    .frame(width: 120)
                    
                    TextField(valuePlaceholder, text: $viewModel.whitelistInputValue)
                        .textFieldStyle(.roundedBorder)
                    
                    TextField("Note", text: $viewModel.whitelistInputNote)
                        .textFieldStyle(.roundedBorder)
                    
                    Button("Add") {
                        viewModel.addWhitelistEntry()
                    }
                    .frame(width: 112, height: 34)
                    .buttonStyle(.borderedProminent)
                }
                
                whitelistIPMatchSection
                whitelistBatchMatchSection
                
                if viewModel.whitelistRecords.isEmpty {
                    Text("No whitelist rules yet.")
                        .font(.system(size: 13, weight: .regular))
                        .foregroundStyle(mutedText)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.vertical, 6)
                } else {
                    LazyVStack(spacing: 8) {
                        ForEach(Array(viewModel.whitelistRecords.enumerated()), id: \.offset) { _, item in
                            whitelistRow(item)
                        }
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(14)
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(surfacePrimary)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 16)
                .stroke(borderSoft, lineWidth: 1)
        )
        .shadow(color: Color.black.opacity(0.14), radius: 16, x: 0, y: 8)
        .alert("Invalid Input", isPresented: $viewModel.showWhitelistValidationAlert) {
            Button("OK", role: .cancel) { }
        } message: {
            Text(viewModel.whitelistValidationMessage)
        }
    }
    var whitelistIPMatchSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            Divider()

            Text("IP Match")
                .font(.system(size: 14, weight: .semibold))
                .foregroundStyle(primaryText)

            whitelistIPMatchInputRow

            if !viewModel.whitelistQueryError.isEmpty {
                Text(viewModel.whitelistQueryError)
                    .font(.system(size: 12, weight: .regular))
                    .foregroundStyle(.red)
            }

            whitelistIPMatchResultCard
        }
    }

    var whitelistIPMatchInputRow: some View {
        HStack(alignment: .center, spacing: 10) {
            TextField("Query IP, e.g. 82.156.1.1", text: $viewModel.whitelistQueryIP)
                .textFieldStyle(.roundedBorder)

            Button(viewModel.whitelistQueryInProgress ? "Querying..." : "Match") {
                viewModel.matchWhitelistIP()
            }
            .frame(width: 112, height: 34)
            .buttonStyle(.borderedProminent)
            .disabled(viewModel.whitelistQueryInProgress)
        }
    }

    var whitelistIPMatchResultCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            whitelistIPMatchSummary
            whitelistIPMatchMetricsGrid
            whitelistIPMatchCountRow
            whitelistIPMatchRawJSON
        }
        .padding(12)
        .background(surfaceSecondary)
        .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .stroke(borderSoft, lineWidth: 1)
        )
    }

    var whitelistIPMatchSummary: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(viewModel.whitelistQuerySummaryTitle)
                .font(.system(size: 15, weight: .semibold))
                .foregroundStyle(primaryText)

            Text(viewModel.whitelistQuerySummarySubtitle)
                .font(.system(size: 12, weight: .regular))
                .foregroundStyle(mutedText)
        }
    }

    var whitelistIPMatchMetricsGrid: some View {
        LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], alignment: .leading, spacing: 10) {
            whitelistMatchMetricCard(title: "Exact IP", value: viewModel.whitelistQueryExactValue)
            whitelistMatchMetricCard(title: "Best CIDR", value: viewModel.whitelistQueryBestCIDRValue)
            whitelistMatchMetricCard(title: "Category", value: viewModel.whitelistQueryCategory)
            whitelistMatchMetricCard(title: "Source", value: viewModel.whitelistQuerySource)
        }
    }

    var whitelistIPMatchCountRow: some View {
        HStack(spacing: 8) {
            Text("CIDR Matches")
                .font(.system(size: 12, weight: .medium))
                .foregroundStyle(mutedText)

            Text("\(viewModel.whitelistQueryCIDRMatchCount)")
                .font(.system(size: 12, weight: .semibold, design: .monospaced))
                .foregroundStyle(primaryText)
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .background(surfacePrimary.opacity(0.55))
                .clipShape(Capsule())
        }
    }

    var whitelistIPMatchRawJSON: some View {
        DisclosureGroup("Raw JSON Result") {
            ScrollView {
                Text(viewModel.whitelistQueryResultText)
                    .font(.system(size: 11, weight: .regular, design: .monospaced))
                    .foregroundStyle(primaryText)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(10)
            }
            .frame(minHeight: 100, maxHeight: 180)
            .background(surfacePrimary.opacity(0.35))
            .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .stroke(borderSoft, lineWidth: 1)
            )
        }
        .font(.system(size: 12, weight: .medium))
        .foregroundStyle(primaryText)
    }

    var whitelistBatchMatchSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Divider()

            Text("Batch IP Match")
                .font(.system(size: 14, weight: .semibold))
                .foregroundStyle(primaryText)

            Text("Enter one IP address per line. IPv4 and IPv6 are both supported.")
                .font(.system(size: 12, weight: .regular))
                .foregroundStyle(mutedText)

            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Text("Input")
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundStyle(primaryText)

                    Spacer()

                    Text("One IP per line")
                        .font(.system(size: 11, weight: .medium))
                        .foregroundStyle(mutedText)
                }

                ZStack(alignment: .topLeading) {
                    RoundedRectangle(cornerRadius: 12, style: .continuous)
                        .fill(surfaceSecondary.opacity(0.9))

                    if viewModel.whitelistBatchInput.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines).isEmpty {
                        Text("8.8.8.8\n1.1.1.1\n240e::1\nff02::fb")
                            .font(.system(size: 12, weight: .regular, design: .monospaced))
                            .foregroundStyle(mutedText.opacity(0.75))
                            .padding(.horizontal, 12)
                            .padding(.vertical, 12)
                            .allowsHitTesting(false)
                    }

                    TextEditor(text: $viewModel.whitelistBatchInput)
                        .font(.system(size: 12, weight: .regular, design: .monospaced))
                        .scrollContentBackground(.hidden)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 8)
                        .frame(minHeight: 96, maxHeight: 132)
                        .background(Color.clear)
                }
                .overlay(
                    RoundedRectangle(cornerRadius: 12, style: .continuous)
                        .stroke(borderSoft, lineWidth: 1)
                )
            }
            .padding(12)
            .background(surfacePrimary.opacity(0.35))
            .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .stroke(borderSoft, lineWidth: 1)
            )

            HStack(spacing: 10) {
                Button(viewModel.whitelistBatchInProgress ? "Querying..." : "Batch Match") {
                    viewModel.batchMatchWhitelistIPs()
                }
                .frame(width: 128, height: 34)
                .buttonStyle(.borderedProminent)
                .disabled(viewModel.whitelistBatchInProgress)

                Button("Clear") {
                    viewModel.whitelistBatchInput = ""
                    viewModel.whitelistBatchError = ""
                    viewModel.whitelistBatchSummaryText = "Paste IPs above and click Batch Match to view the summary."
                    viewModel.whitelistBatchResultText = "[]"
                }
                .frame(width: 88, height: 34)
                .buttonStyle(.bordered)
                .disabled(viewModel.whitelistBatchInProgress)

                Spacer()
            }

            if !viewModel.whitelistBatchError.isEmpty {
                Text(viewModel.whitelistBatchError)
                    .font(.system(size: 12, weight: .regular))
                    .foregroundStyle(.red)
            }

            VStack(alignment: .leading, spacing: 10) {
                Text("Summary")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(primaryText)

                Text(viewModel.whitelistBatchSummaryText)
                    .font(.system(size: 12, weight: .regular))
                    .foregroundStyle(mutedText)

                DisclosureGroup("Raw Batch Result") {
                    ScrollView {
                        Text(viewModel.whitelistBatchResultText)
                            .font(.system(size: 11, weight: .regular, design: .monospaced))
                            .foregroundStyle(primaryText)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(10)
                    }
                    .frame(minHeight: 100, maxHeight: 220)
                    .background(surfacePrimary.opacity(0.35))
                    .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
                    .overlay(
                        RoundedRectangle(cornerRadius: 10, style: .continuous)
                            .stroke(borderSoft, lineWidth: 1)
                    )
                }
                .font(.system(size: 12, weight: .medium))
                .foregroundStyle(primaryText)
            }
            .padding(12)
            .background(surfaceSecondary)
            .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .stroke(borderSoft, lineWidth: 1)
            )
        }
    }
    @ViewBuilder
    func whitelistMatchMetricCard(title: String, value: String) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title)
                .font(.system(size: 11, weight: .medium))
                .foregroundStyle(mutedText)
            
            Text(value)
                .font(.system(size: 13, weight: .semibold, design: .monospaced))
                .foregroundStyle(primaryText)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(10)
        .background(surfacePrimary.opacity(0.55))
        .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .stroke(borderSoft, lineWidth: 1)
        )
    }

    // MARK: - 共享视图辅助
    
    // 通用分区标题：供 ContentSections.swift 中的各个 section 复用。
    @ViewBuilder
    func sectionTitle(_ title: String, systemImage: String) -> some View {
        HStack(spacing: 8) {
            Image(systemName: systemImage)
                .font(.system(size: 16, weight: .semibold))
                .foregroundStyle(Color.accentColor)
            
            Text(title)
                .font(.system(size: 17, weight: .semibold))
                .foregroundStyle(primaryText)
        }
    }
    
    // macOS 风格的三点加载提示：供主机摘要加载态复用。
    @ViewBuilder
    func macOSLoadingDots(phase: Int) -> some View {
        HStack(spacing: 6) {
            ForEach(0..<3, id: \.self) { index in
                Circle()
                    .fill(index == phase ? Color.accentColor : mutedText.opacity(0.35))
                    .frame(width: index == phase ? 8 : 6, height: index == phase ? 8 : 6)
                    .offset(y: index == phase ? -1.5 : 0)
                    .animation(.easeInOut(duration: 0.18), value: phase)
            }
        }
    }
    
    // 启动三点加载动画计时器。
    func startLoadingDotsTimer() {
        loadingDotsTimer?.invalidate()
        loadingDotsPhase = 0
        
        loadingDotsTimer = Timer.scheduledTimer(withTimeInterval: 0.38, repeats: true) { _ in
            loadingDotsPhase = (loadingDotsPhase + 1) % 3
        }
    }
    
    // 停止三点加载动画计时器。
    func stopLoadingDotsTimer() {
        loadingDotsTimer?.invalidate()
        loadingDotsTimer = nil
    }
}
