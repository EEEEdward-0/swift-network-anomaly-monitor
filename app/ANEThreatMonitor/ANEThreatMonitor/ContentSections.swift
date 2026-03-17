import SwiftUI
import Foundation
import AppKit
extension ContentView {
    // MARK: - Primary view sections
    struct PortKindGroup {
        let title: String
        let ports: [Int]
    }
    // 按端口范围分组：系统级、用户级、动态/临时。
    func groupedPortsByKind(_ ports: [Int]) -> [PortKindGroup] {
        let systemPorts = ports.filter { 0...1023 ~= $0 }
        let userPorts = ports.filter { 1024...49151 ~= $0 }
        let dynamicPorts = ports.filter { 49152...65535 ~= $0 }
        
        return [
            PortKindGroup(title: "System Ports", ports: systemPorts),
            PortKindGroup(title: "User Ports", ports: userPorts),
            PortKindGroup(title: "Dynamic / Ephemeral Ports", ports: dynamicPorts)
        ]
    }
    
    func portKindSection(title: String, transport: String, ports: [Int]) -> some View {
        let gridColumns = [GridItem(.adaptive(minimum: 84), spacing: 8)]
        
        return VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(.system(size: 12, weight: .medium))
                .foregroundStyle(mutedText)
            
            LazyVGrid(columns: gridColumns, alignment: .leading, spacing: 8) {
                ForEach(ports, id: \.self) { port in
                    portTag(transport: transport, port: port)
                }
            }
            .padding(10)
            .background(surfaceSecondary.opacity(0.7))
            .overlay(
                RoundedRectangle(cornerRadius: 12)
                    .stroke(borderSoft, lineWidth: 1)
            )
            .clipShape(RoundedRectangle(cornerRadius: 12))
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
    // 顶部概览区域：显示当前状态、模式与进度。
    var headerSection: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 14) {
                HStack(alignment: .center, spacing: 12) {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("ANE Threat Monitor")
                            .font(.system(size: 26, weight: .bold))
                            .foregroundStyle(primaryText)
                        
                        Text("Apple ANE based local network anomaly detection and visualization")
                            .font(.system(size: 13, weight: .regular))
                            .foregroundStyle(mutedText)
                    }
                    
                    Spacer(minLength: 16)
                    
                    VStack(alignment: .trailing, spacing: 8) {
                        HStack(spacing: 8) {
                            statusBadge(viewModel.appStatusText)
                            
                            Menu {
                                ForEach(ThemeMode.allCases) { mode in
                                    Button {
                                        viewModel.themeMode = mode
                                    } label: {
                                        Label(mode.rawValue, systemImage: mode.systemImage)
                                    }
                                }
                            } label: {
                                HStack(spacing: 6) {
                                    Image(systemName: viewModel.themeMode.systemImage)
                                        .font(.system(size: 12, weight: .semibold))
                                    
                                    Text(viewModel.themeMode.rawValue)
                                        .font(.system(size: 12, weight: .semibold))
                                    
                                    Image(systemName: "chevron.down")
                                        .font(.system(size: 10, weight: .semibold))
                                }
                                .foregroundStyle(primaryText)
                                .padding(.horizontal, 10)
                                .padding(.vertical, 6)
                                .background(surfaceSecondary)
                                .overlay(
                                    RoundedRectangle(cornerRadius: 10)
                                        .stroke(borderSoft, lineWidth: 1)
                                )
                                .clipShape(RoundedRectangle(cornerRadius: 10))
                            }
                            .menuStyle(.borderlessButton)
                            .fixedSize()
                        }
                        
                        Text("Mode: \(String(describing: viewModel.selectedMode))")
                            .font(.caption)
                            .foregroundStyle(mutedText)
                    }
                }
                
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Text("Analysis Progress")
                            .font(.system(size: 12, weight: .semibold))
                            .foregroundStyle(mutedText)
                        Spacer()
                        Text("\(Int(viewModel.analysisProgress * 100))%")
                            .font(.system(size: 12, weight: .semibold))
                            .foregroundStyle(primaryText)
                    }
                    
                    ProgressView(value: viewModel.analysisProgress)
                        .tint(Color.accentColor)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(14)
        .background(
            ZStack {
                RoundedRectangle(cornerRadius: 16)
                    .fill(surfacePrimary)

                if isPrideTheme {
                    RoundedRectangle(cornerRadius: 16)
                        .fill(.ultraThinMaterial)
                        .opacity(0.55)
                }
            }
        )
        .overlay(
            RoundedRectangle(cornerRadius: 16)
                .stroke(
                    isPrideTheme ? Color.white.opacity(0.32) : borderSoft,
                    lineWidth: 1
                )
        )
        .shadow(
            color: isPrideTheme ? Color.black.opacity(0.10) : Color.black.opacity(0.14),
            radius: isPrideTheme ? 22 : 16,
            x: 0,
            y: isPrideTheme ? 12 : 8
        )
        .overlay {
            if isPrideTheme {
                RoundedRectangle(cornerRadius: 16)
                    .stroke(Color.white.opacity(0.18), lineWidth: 0.8)
                    .blur(radius: 0.5)
            }
        }
    }

    // 抓包设置区域：选择网卡并开始/结束分析。
    var captureSettingsSection: some View {
            GroupBox {
                VStack(alignment: .leading, spacing: 12) {
                    sectionTitle("Capture Settings", systemImage: "antenna.radiowaves.left.and.right")
                    
                    HStack(alignment: .center, spacing: 12) {
                        VStack(alignment: .leading, spacing: 6) {
                            Text("Interface")
                                .font(.caption.weight(.semibold))
                                .foregroundStyle(mutedText)
                            
                            Picker("Interface", selection: $viewModel.selectedInterface) {
                                ForEach(viewModel.interfaceOptions, id: \.self) { item in
                                    Text(item).tag(item)
                                }
                            }
                            .pickerStyle(.menu)
                            .frame(width: 160)
                        }
                        
                        VStack(alignment: .leading, spacing: 6) {
                            Text("Capture State")
                                .font(.caption.weight(.semibold))
                                .foregroundStyle(mutedText)
                            
                            Text(viewModel.isCapturing ? "Capturing" : "Idle")
                                .font(.system(size: 13, weight: .semibold))
                                .foregroundStyle(viewModel.isCapturing ? Color.green : mutedText)
                        }
                        
                        VStack(alignment: .leading, spacing: 6) {
                            Text("Elapsed")
                                .font(.caption.weight(.semibold))
                                .foregroundStyle(mutedText)
                            
                            Text("\(viewModel.captureElapsedSeconds) s")
                                .font(.system(size: 13, weight: .semibold))
                                .foregroundStyle(primaryText)
                        }
                        
                        Spacer(minLength: 12)
                        
                        if viewModel.isCapturing {
                            Button("Stop & Analyze") {
                                viewModel.stopCaptureAndAnalyze()
                            }
                            .frame(width: 140, height: 36)
                            .buttonStyle(.borderedProminent)
                        } else {
                            Button("Start Capture") {
                                viewModel.startCapture()
                            }
                            .frame(width: 140, height: 36)
                            .buttonStyle(.borderedProminent)
                        }
                    }
                    
                    HStack(spacing: 10) {
                        Button("Analyze Saved PCAP") {
                            viewModel.chooseAndAnalyzeSavedPCAP()
                        }
                        .frame(width: 160, height: 34)
                        .buttonStyle(.bordered)
                        
                        Button("Choose PCAP Save Location") {
                            viewModel.choosePCAPSaveLocation()
                        }
                        .frame(width: 190, height: 34)
                        .buttonStyle(.bordered)
                        
                        Button("Export Log") {
                            viewModel.exportLog()
                        }
                        .frame(width: 110, height: 34)
                        .buttonStyle(.bordered)
                        
                        Button("Refresh Host Info") {
                            viewModel.reloadHostSummary()
                        }
                        .frame(width: 140, height: 34)
                        .buttonStyle(.bordered)
                        
                        Spacer()
                    }
                    
                    let throughputPoints = parseThroughputPoints(from: viewModel.throughputLogText)
                    if !throughputPoints.isEmpty {
                        let latestPoint = throughputPoints.last
                        
                        VStack(alignment: .leading, spacing: 8) {
                            HStack(alignment: .center, spacing: 12) {
                                Text("Realtime Throughput")
                                    .font(.caption.weight(.semibold))
                                    .foregroundStyle(mutedText)
                                
                                Spacer()
                                
                                if let latestPoint {
                                    HStack(spacing: 12) {
                                        Label("RX \(formatByteRate(latestPoint.rx))", systemImage: "arrow.down.circle")
                                            .font(.caption)
                                            .foregroundStyle(Color.blue)
                                        
                                        Label("TX \(formatByteRate(latestPoint.tx))", systemImage: "arrow.up.circle")
                                            .font(.caption)
                                            .foregroundStyle(Color.green)
                                    }
                                }
                                
                                Text("Unit: B/s")
                                    .font(.caption)
                                    .foregroundStyle(mutedText)
                            }
                            
                            ThroughputLineChartView(points: throughputPoints)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.top, 4)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .padding(14)
            .background(
                ZStack {
                    RoundedRectangle(cornerRadius: 16)
                        .fill(surfacePrimary)
                    
                    if isPrideTheme {
                        RoundedRectangle(cornerRadius: 16)
                            .fill(.ultraThinMaterial)
                            .opacity(0.55)
                    }
                }
            )
            .overlay(
                RoundedRectangle(cornerRadius: 16)
                    .stroke(
                        isPrideTheme ? Color.white.opacity(0.32) : borderSoft,
                        lineWidth: 1
                    )
            )
            .shadow(
                color: isPrideTheme ? Color.black.opacity(0.10) : Color.black.opacity(0.14),
                radius: isPrideTheme ? 22 : 16,
                x: 0,
                y: isPrideTheme ? 12 : 8
            )
            .overlay {
                if isPrideTheme {
                    RoundedRectangle(cornerRadius: 16)
                        .stroke(Color.white.opacity(0.18), lineWidth: 0.8)
                        .blur(radius: 0.5)
                }
            }
    }

    // 日志区域：显示分析日志并支持复制、清空。
    @ViewBuilder
    var analysisLogSection: some View {
                if !viewModel.appLogText.isEmpty {
                    DisclosureGroup(isExpanded: $isLogExpanded) {
                        GroupBox {
                            VStack(alignment: .leading, spacing: 10) {
                                HStack {
                                    Spacer()
                                    
                                    Button("Copy") {
                                        viewModel.copyLogToClipboard()
                                    }
                                    .frame(width: 88, height: 32)
                                    .buttonStyle(.bordered)
                                    
                                    Button("Clear") {
                                        viewModel.clearLogView()
                                    }
                                    .frame(width: 88, height: 32)
                                    .buttonStyle(.bordered)
                                }
                                
                                ScrollView {
                                    Text(viewModel.appLogText)
                                        .font(.system(size: 12, weight: .regular, design: .monospaced))
                                        .foregroundStyle(primaryText)
                                        .textSelection(.enabled)
                                        .frame(maxWidth: .infinity, alignment: .leading)
                                        .lineSpacing(3)
                                        .padding(12)
                                        .background(isLightTheme ? Color.black.opacity(0.04) : Color.black.opacity(0.20))
                                        .clipShape(RoundedRectangle(cornerRadius: 12))
                                }
                                .frame(minHeight: 90, maxHeight: 150)
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
                        .padding(.top, 8)
                    } label: {
                        sectionTitle("Analysis Log", systemImage: "doc.text.magnifyingglass")
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
                }
            }
    
    var hostSummarySection: some View {
                Group {
                    if let hostSummary = viewModel.hostSummary {
                        GroupBox {
                            VStack(alignment: .leading, spacing: 14) {
                                sectionTitle("Host Summary", systemImage: "desktopcomputer")
                                
                                Text("Click a card to view detailed information in a floating panel.")
                                    .font(.system(size: 13, weight: .regular))
                                    .foregroundStyle(mutedText)
                                
                                let columns = [
                                    GridItem(.flexible(), spacing: 12),
                                    GridItem(.flexible(), spacing: 12)
                                ]
                                
                                LazyVGrid(columns: columns, alignment: .leading, spacing: 12) {
                                    summaryEntryCard(
                                        title: "Host Information",
                                        subtitle: "Local device and system network",
                                        icon: "desktopcomputer",
                                        tint: Color.blue,
                                        detailLines: [
                                            "Interface: \(hostSummary.interface.isEmpty ? "-" : hostSummary.interface)",
                                            "IPv4: \(hostSummary.local_ip.isEmpty ? "-" : hostSummary.local_ip)",
                                            "IPv6: \(hostSummary.local_ipv6.isEmpty ? "-" : hostSummary.local_ipv6)"
                                        ]
                                    ) {
                                        isHostInfoPopoverPresented = true
                                    }
                                    .popover(
                                        isPresented: $isHostInfoPopoverPresented,
                                        attachmentAnchor: PopoverAttachmentAnchor.rect(.bounds),
                                        arrowEdge: Edge.bottom
                                    ) {
                                        hostInfoPopoverContent(hostSummary)
                                    }

                                    summaryEntryCard(
                                        title: "Public Network",
                                        subtitle: "External IP and geolocation",
                                        icon: "location.viewfinder",
                                        tint: Color.green,
                                        detailLines: [
                                            "Public IPv4: \(hostSummary.public_ip.isEmpty ? "-" : hostSummary.public_ip)",
                                            "Public IPv6: \(hostSummary.public_ipv6.isEmpty ? "-" : hostSummary.public_ipv6)",
                                            "Location: \(hostSummary.public_ip_location.isEmpty ? "-" : hostSummary.public_ip_location)"
                                        ],
                                        showsViewDetails: false
                                    ) {
                                        isPublicNetworkPopoverPresented = true
                                    }
                                    .popover(
                                        isPresented: $isPublicNetworkPopoverPresented,
                                        attachmentAnchor: PopoverAttachmentAnchor.rect(.bounds),
                                        arrowEdge: Edge.bottom
                                    ) {
                                        networkInfoPopoverContent(hostSummary)
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
                    } else {
                        GroupBox {
                            HStack(spacing: 10) {
                                Text("Loading host summary")
                                    .foregroundStyle(mutedText)
                                macOSLoadingDots(phase: loadingDotsPhase)
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
                    }
                }
            }
            
    @ViewBuilder
    var realtimeSection: some View {
                let allRisks = realtimeRiskItems()
                let totalPages = max(1, Int(ceil(Double(allRisks.count) / Double(riskPageSize))))
                let safePageIndex = min(max(riskPageIndex, 0), max(totalPages - 1, 0))
                let pageStart = safePageIndex * riskPageSize
                let pageItems = Array(allRisks.dropFirst(pageStart).prefix(riskPageSize))
                
                GroupBox {
                    VStack(alignment: .leading, spacing: 12) {
                        HStack(alignment: .center, spacing: 12) {
                            sectionTitle("Realtime Analysis", systemImage: "waveform.path.ecg")
                            
                            Spacer(minLength: 12)
                            
                            Menu {
                                Button("High to Low") {
                                    riskSortDescending = true
                                    riskPageIndex = 0
                                }
                                
                                Button("Low to High") {
                                    riskSortDescending = false
                                    riskPageIndex = 0
                                }
                            } label: {
                                HStack(spacing: 6) {
                                    Image(systemName: "arrow.up.arrow.down")
                                        .font(.system(size: 12, weight: .semibold))
                                    
                                    Text(riskSortDescending ? "High to Low" : "Low to High")
                                        .font(.system(size: 13, weight: .semibold))
                                    
                                    Image(systemName: "chevron.down")
                                        .font(.system(size: 10, weight: .semibold))
                                        .foregroundStyle(mutedText)
                                }
                                .foregroundStyle(primaryText)
                                .padding(.horizontal, 10)
                                .padding(.vertical, 6)
                                .background(surfaceSecondary)
                                .overlay(
                                    RoundedRectangle(cornerRadius: 10)
                                        .stroke(borderSoft, lineWidth: 1)
                                )
                                .clipShape(RoundedRectangle(cornerRadius: 10))
                            }
                            .menuStyle(.borderlessButton)
                            .fixedSize()
                            
                            Toggle(
                                "Include Internal IP",
                                isOn: Binding(
                                    get: { !viewModel.excludeInternalTraffic },
                                    set: { newValue in
                                        viewModel.excludeInternalTraffic = !newValue
                                        riskPageIndex = 0
                                    }
                                )
                            )
                            .toggleStyle(.switch)
                            .frame(width: 190)
                        }
                        
                        realtimeBlock(title: "Result", text: viewModel.resultText)
                        
                        if !viewModel.detailText.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines).isEmpty {
                            realtimeBlock(title: "Detail", text: viewModel.detailText)
                        }
                        
                        if !viewModel.errorText.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines).isEmpty {
                            
                            realtimeBlock(title: "Error", text: viewModel.errorText, tint: Color.red)
                        }
                        
                        if allRisks.isEmpty {
                            Text("No detailed risk items available.")
                                .font(.system(size: 13, weight: .regular))
                                .foregroundStyle(mutedText)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        } else {
                            VStack(alignment: .leading, spacing: 10) {
                                HStack {
                                    Text("Top Risk Details")
                                        .font(.caption.weight(.semibold))
                                        .foregroundStyle(mutedText)

                                    Spacer()

                                    Text("Page \(safePageIndex + 1) / \(totalPages)")
                                        .font(.caption)
                                        .foregroundStyle(mutedText)
                                }

                                if pageItems.count == 1 {
                                    riskItemRow(
                                        displayIndex: pageStart + 1,
                                        item: pageItems[0]
                                    )
                                } else {
                                    ForEach(0..<max(pageItems.count - 1, 0), id: \.self) { index in
                                        HStack(alignment: .top, spacing: 12) {
                                            riskItemRow(
                                                displayIndex: pageStart + index + 1,
                                                item: pageItems[index]
                                            )
                                            .frame(maxWidth: .infinity)

                                            riskItemRow(
                                                displayIndex: pageStart + index + 2,
                                                item: pageItems[index + 1]
                                            )
                                            .frame(maxWidth: .infinity)
                                        }
                                    }
                                }

                                HStack(spacing: 10) {
                                    Button("Previous") {
                                        riskPageIndex = max(riskPageIndex - 1, 0)
                                    }
                                    .disabled(safePageIndex == 0)

                                    Button("Next") {
                                        riskPageIndex = min(riskPageIndex + 1, totalPages - 1)
                                    }
                                    .disabled(safePageIndex >= totalPages - 1)

                                    Spacer()
                                }
                            }
                            .frame(maxWidth: .infinity, alignment: .topLeading)
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
                .overlayPreferenceValue(RiskCardBoundsPreferenceKey.self) { preferences in
                    GeometryReader { proxy in
                        if let selected = viewModel.selectedRiskItem,
                           let anchor = preferences[String(describing: selected.id)] {
                            let rect = proxy[anchor]
                            let panelWidth: CGFloat = 320
                            let panelHeight: CGFloat = 220
                            let horizontalSpacing: CGFloat = 14
                            let verticalPadding: CGFloat = 10
                            let halfWidth = panelWidth / 2
                            let halfHeight = panelHeight / 2
                            let fitsOnRight = rect.maxX + horizontalSpacing + panelWidth <= proxy.size.width - 12
                            let preferredCenterX = fitsOnRight
                                ? rect.maxX + horizontalSpacing + halfWidth
                                : rect.minX - horizontalSpacing - halfWidth
                            let clampedCenterX = min(
                                max(preferredCenterX, halfWidth + 12),
                                proxy.size.width - halfWidth - 12
                            )
                            let preferredCenterY = rect.midY
                            let clampedCenterY = min(
                                max(preferredCenterY, halfHeight + verticalPadding),
                                proxy.size.height - halfHeight - verticalPadding
                            )

                            selectedRiskFloatingPanel(selected)
                                .frame(width: panelWidth)
                                .scaleEffect(viewModel.selectedRiskItem?.id == selected.id ? 1 : 0.94)
                                .animation(.interpolatingSpring(stiffness: 250, damping: 20), value: viewModel.selectedRiskItem?.id)
                                .position(x: clampedCenterX, y: clampedCenterY)
                                .shadow(color: Color.black.opacity(0.18), radius: 18, x: 0, y: 10)
                                .zIndex(10)
                        }
                    }
                }
                .shadow(color: Color.black.opacity(0.14), radius: 16, x: 0, y: 8)
            }
            
    var historySection: some View {
                GroupBox {
                    VStack(alignment: .leading, spacing: 12) {
                        HStack(alignment: .center, spacing: 12) {
                            sectionTitle("History", systemImage: "clock.arrow.circlepath")
                            
                            Spacer(minLength: 16)
                            
                            HStack(spacing: 8) {
                                Button("Delete Selected") {
                                    viewModel.deleteSelectedHistory()
                                }
                                .frame(width: 92, height: 28)
                                .buttonStyle(.borderedProminent)
                                .tint(.red)
                                .disabled(viewModel.selectedHistoryIDs.isEmpty)
                                
                                Button("Clear All") {
                                    viewModel.clearAllHistory()
                                }
                                .frame(width: 92, height: 28)
                                .buttonStyle(.borderedProminent)
                                .tint(.red)
                                .disabled(viewModel.historyItems.isEmpty)
                            }
                        }
                        
                        if viewModel.historyItems.isEmpty {
                            Text("No capture history yet.")
                                .foregroundStyle(mutedText)
                        } else {
                            LazyVStack(spacing: 10) {
                                ForEach(viewModel.historyItems.prefix(20)) { item in
                                    VStack(alignment: .leading, spacing: 10) {
                                        HStack(alignment: .top, spacing: 12) {
                                            Button {
                                                viewModel.toggleHistorySelection(item.session_id)
                                            } label: {
                                                Image(systemName: viewModel.selectedHistoryIDs.contains(item.session_id) ? "checkmark.circle.fill" : "circle")
                                                    .font(.title3)
                                                    .foregroundStyle(primaryText)
                                            }
                                            .buttonStyle(.plain)
                                            .padding(.top, 2)
                                            
                                            VStack(alignment: .leading, spacing: 6) {
                                                Text(item.session_id)
                                                    .font(.headline)
                                                    .foregroundStyle(primaryText)
                                                
                                                Text("Interface: \(item.interface ?? "-")")
                                                    .font(.subheadline)
                                                    .foregroundStyle(mutedText)
                                                
                                                Text("Duration: \(item.capture_window_seconds.map { "\($0) s" } ?? "-")")
                                                    .font(.subheadline)
                                                    .foregroundStyle(primaryText.opacity(0.9))
                                                
                                                Text("Started: \(item.started_at)")
                                                    .font(.caption)
                                                    .foregroundStyle(mutedText)
                                                
                                                Text("Risk Counts: \(riskCountsText(item.risk_level_counts))")
                                                    .font(.caption)
                                                    .foregroundStyle(mutedText)
                                            }
                                            .frame(maxWidth: .infinity, alignment: .leading)
                                            
                                            Button(role: .destructive) {
                                                viewModel.deleteHistoryItem(item)
                                            } label: {
                                                Label("Delete", systemImage: "trash")
                                            }
                                            .buttonStyle(.borderedProminent)
                                            .tint(.red)
                                        }
                                    }
                                    .padding(12)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .background(surfaceSecondary)
                                    .overlay(
                                        RoundedRectangle(cornerRadius: 14)
                                            .stroke(borderSoft, lineWidth: 1)
                                    )
                                    .clipShape(RoundedRectangle(cornerRadius: 14))
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
            }
            
    var demoSection: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 16) {
                HStack(alignment: .center, spacing: 10) {
                    sectionTitle("Model Status", systemImage: "cpu")
                    Spacer()
                }

                HStack(alignment: .top, spacing: 16) {
                    rotatingDotGlobeCard(
                        isAnalyzing: viewModel.isAnalyzing,
                        isCapturing: viewModel.isCapturing,
                        compact: false
                    )
                    .frame(width: 260, alignment: .leading)

                    modelStatusContent(compact: false)
                        .frame(maxWidth: .infinity, alignment: .leading)
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
    }

    func modelStatusContent(compact: Bool) -> some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Core ML inference pipeline")
                .font(.system(size: 12, weight: .medium))
                .foregroundStyle(mutedText)

            LazyVGrid(
                columns: [
                    GridItem(.flexible(), spacing: 12),
                    GridItem(.flexible(), spacing: 12),
                    GridItem(.flexible(), spacing: 12)
                ],
                alignment: .leading,
                spacing: 12
            ) {
                modelStatusInfoCard(title: "Backend", value: "Core ML / ANE", accent: .blue)
                modelStatusStateCard(
                    title: "Mode",
                    value: String(describing: viewModel.selectedMode),
                    tint: .purple,
                    icon: "slider.horizontal.3"
                )
                modelStatusStateCard(
                    title: "Inference",
                    value: viewModel.isAnalyzing ? "Running" : "Ready",
                    tint: viewModel.isAnalyzing ? .orange : .green,
                    icon: viewModel.isAnalyzing ? "waveform.path.ecg" : "checkmark.circle"
                )
                modelStatusInfoCard(title: "Risk Items", value: "\(viewModel.realtimeResult?.top_risks.count ?? 0)", accent: .red)
                modelStatusInfoCard(title: "Whitelist", value: "\(viewModel.whitelistRecords.count)", accent: .green)
                modelStatusStateCard(
                    title: "Capture",
                    value: viewModel.isCapturing ? "Live" : "Idle",
                    tint: viewModel.isCapturing ? .cyan : .gray,
                    icon: viewModel.isCapturing ? "dot.radiowaves.left.and.right" : "pause.circle"
                )
            }

            VStack(alignment: .leading, spacing: 8) {
                Text("Pipeline")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(primaryText)

                Text("Realtime packet features are extracted locally, evaluated by the current inference pipeline, and linked to host summary, risk ranking, and whitelist matching.")
                    .font(.system(size: 13, weight: .regular))
                    .foregroundStyle(mutedText)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(12)
            .background(surfaceSecondary)
            .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: 14, style: .continuous)
                    .stroke(borderSoft, lineWidth: 1)
            )

            HStack(spacing: 8) {
                Circle()
                    .fill(viewModel.isAnalyzing ? Color.orange : Color.green)
                    .frame(width: 8, height: 8)

                Text(
                    viewModel.isAnalyzing
                    ? "Model is currently processing realtime analysis."
                    : "Model is ready. Current state remains synchronized with the main analysis pipeline."
                )
                .font(.system(size: 12, weight: .medium))
                .foregroundStyle(mutedText)

                Spacer()
            }
            .padding(.top, 2)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
            
    func rotatingDotGlobeCard(isAnalyzing: Bool, isCapturing: Bool, compact: Bool) -> some View {
        VStack(spacing: 0) {
            Spacer(minLength: 0)

            RotatingDotGlobeView(isAnalyzing: isAnalyzing, isCapturing: isCapturing)
                .frame(width: 220, height: 220)
                .frame(maxWidth: .infinity, alignment: .center)

            Spacer(minLength: 0)
        }
        .padding(16)
        .frame(maxWidth: .infinity, minHeight: 300, alignment: .center)
        .background(surfaceSecondary)
        .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 14, style: .continuous)
                .stroke(borderSoft, lineWidth: 1)
        )
    }
    
    func modelStatusInfoCard(title: String, value: String, accent: Color) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 6) {
                Circle()
                    .fill(accent.opacity(0.85))
                    .frame(width: 7, height: 7)

                Text(title)
                    .font(.system(size: 12, weight: .medium))
                    .foregroundStyle(mutedText)
            }

            Text(value)
                .font(.system(size: 17, weight: .bold))
                .foregroundStyle(primaryText)
                .lineLimit(1)
                .minimumScaleFactor(0.82)
        }
        .frame(maxWidth: .infinity, minHeight: 104, alignment: .topLeading)
        .padding(.horizontal, 16)
        .padding(.vertical, 14)
        .background(surfaceSecondary)
        .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 14, style: .continuous)
                .stroke(borderSoft, lineWidth: 1)
        )
    }

    func modelStatusStateCard(title: String, value: String, tint: Color, icon: String) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(title)
                .font(.system(size: 12, weight: .medium))
                .foregroundStyle(mutedText)

            HStack(spacing: 8) {
                Image(systemName: icon)
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(tint)

                Text(value)
                    .font(.system(size: 14, weight: .bold))
                    .foregroundStyle(tint)
                    .lineLimit(1)
                    .minimumScaleFactor(0.65)
                    .allowsTightening(true)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 12)
            .padding(.vertical, 9)
            .background(
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .fill(tint.opacity(0.12))
            )
        }
        .frame(maxWidth: .infinity, minHeight: 104, alignment: .topLeading)
        .padding(.horizontal, 16)
        .padding(.vertical, 14)
        .background(surfaceSecondary)
        .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 14, style: .continuous)
                .stroke(borderSoft, lineWidth: 1)
        )
    }

    struct RotatingDotGlobeView: View {
        let isAnalyzing: Bool
        let isCapturing: Bool

        private let points: [SIMD3<Double>] = {
            var result: [SIMD3<Double>] = []
            let latSteps = 18
            let lonSteps = 36

            for latIndex in 0...latSteps {
                let lat = -Double.pi / 2 + Double(latIndex) / Double(latSteps) * Double.pi
                for lonIndex in 0..<lonSteps {
                    let lon = Double(lonIndex) / Double(lonSteps) * 2 * Double.pi
                    let x = cos(lat) * cos(lon)
                    let y = sin(lat)
                    let z = cos(lat) * sin(lon)
                    result.append(SIMD3<Double>(x, y, z))
                }
            }
            return result
        }()

        var body: some View {
            TimelineView(.animation) { timeline in
                let t = timeline.date.timeIntervalSinceReferenceDate
                let rotationSpeed = isAnalyzing ? 1.15 : (isCapturing ? 0.8 : 0.48)
                let angle = t * rotationSpeed
                let tilt = isAnalyzing ? 0.45 : 0.34
                let pulse = isAnalyzing ? (0.92 + 0.12 * sin(t * 3.2)) : (isCapturing ? (0.96 + 0.06 * sin(t * 1.8)) : 1.0)
                let primaryColor: Color = isAnalyzing ? .orange : (isCapturing ? .cyan : .blue)
                let secondaryColor: Color = isAnalyzing ? .yellow : (isCapturing ? .blue : .cyan)

                Canvas { context, size in
                    let center = CGPoint(x: size.width / 2, y: size.height / 2)
                    let radius = min(size.width, size.height) * 0.34 * pulse

                    let haloRect = CGRect(
                        x: center.x - radius - 30,
                        y: center.y - radius - 30,
                        width: (radius + 30) * 2,
                        height: (radius + 30) * 2
                    )

                    context.fill(
                        Path(ellipseIn: haloRect),
                        with: .radialGradient(
                            Gradient(colors: [
                                primaryColor.opacity(isAnalyzing ? 0.18 : 0.12),
                                secondaryColor.opacity(0.06),
                                .clear
                            ]),
                            center: center,
                            startRadius: 8,
                            endRadius: radius + 30
                        )
                    )

                    let ringRect = CGRect(
                        x: center.x - radius - 8,
                        y: center.y - radius - 8,
                        width: (radius + 8) * 2,
                        height: (radius + 8) * 2
                    )

                    context.stroke(
                        Path(ellipseIn: ringRect),
                        with: .color(primaryColor.opacity(0.16)),
                        lineWidth: 1.1
                    )

                    let midRingRect = CGRect(
                        x: center.x - radius + 12,
                        y: center.y - radius * 0.72,
                        width: (radius - 12) * 2,
                        height: (radius * 0.72) * 2
                    )

                    context.stroke(
                        Path(ellipseIn: midRingRect),
                        with: .color(secondaryColor.opacity(0.14)),
                        lineWidth: 0.9
                    )

                    for point in points {
                        let tilted = rotateX(point, angle: tilt)
                        let rotated = rotateY(tilted, angle: angle)
                        let depth = (rotated.z + 1.0) / 2.0
                        let alpha = 0.18 + depth * 0.82
                        let dotSize = 1.1 + depth * 3.6
                        let projectedX = center.x + rotated.x * radius
                        let projectedY = center.y + rotated.y * radius * 0.9

                        let rect = CGRect(
                            x: projectedX - dotSize / 2,
                            y: projectedY - dotSize / 2,
                            width: dotSize,
                            height: dotSize
                        )

                        let dotColor = depth > 0.6 ? primaryColor : secondaryColor

                        context.fill(
                            Path(ellipseIn: rect),
                            with: .color(dotColor.opacity(alpha))
                        )
                    }

                    if isAnalyzing {
                        let sweepWidth = radius * 1.45
                        let sweepX = center.x + CGFloat(sin(t * 2.4)) * radius * 0.46
                        let sweepRect = CGRect(
                            x: sweepX - sweepWidth / 2,
                            y: center.y - radius - 18,
                            width: sweepWidth,
                            height: (radius + 18) * 2
                        )

                        context.fill(
                            Path(roundedRect: sweepRect, cornerRadius: sweepWidth / 2),
                            with: .linearGradient(
                                Gradient(colors: [
                                    .clear,
                                    primaryColor.opacity(0.10),
                                    .clear
                                ]),
                                startPoint: CGPoint(x: sweepRect.minX, y: sweepRect.midY),
                                endPoint: CGPoint(x: sweepRect.maxX, y: sweepRect.midY)
                            )
                        )
                    }
                }
            }
            .background(
                RadialGradient(
                    colors: [
                        (isAnalyzing ? Color.orange : (isCapturing ? Color.cyan : Color.blue)).opacity(0.12),
                        (isAnalyzing ? Color.yellow : Color.cyan).opacity(0.05),
                        Color.clear
                    ],
                    center: .center,
                    startRadius: 10,
                    endRadius: 132
                )
            )
            .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
        }

        private func rotateY(_ p: SIMD3<Double>, angle: Double) -> SIMD3<Double> {
            let cosA = cos(angle)
            let sinA = sin(angle)
            return SIMD3<Double>(
                p.x * cosA + p.z * sinA,
                p.y,
                -p.x * sinA + p.z * cosA
            )
        }

        private func rotateX(_ p: SIMD3<Double>, angle: Double) -> SIMD3<Double> {
            let cosA = cos(angle)
            let sinA = sin(angle)
            return SIMD3<Double>(
                p.x,
                p.y * cosA - p.z * sinA,
                p.y * sinA + p.z * cosA
            )
        }
    }

    // MARK: - Reusable section helpers
            
    func whitelistRow(_ item: [String: String]) -> some View {
        let rawSource = (item["source"] ?? "")
            .trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
            .lowercased()
        let value = item["value"] ?? "-"
        let ruleType = item["rule_type"] ?? "unknown"
        let note = item["note"] ?? ""
        let normalizedNote = note.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines).lowercased()
        let inferredSystem = normalizedNote.contains("system") || normalizedNote.contains("seeded")
        let effectiveSource = rawSource.isEmpty ? (inferredSystem ? "system" : "user") : rawSource
        let isSystemEntry = effectiveSource == "system" || effectiveSource == "api"

        return HStack(alignment: .center, spacing: 12) {
            VStack(alignment: .leading, spacing: 8) {
                Text(value)
                    .font(.system(size: 16, weight: .semibold))
                    .foregroundStyle(isSystemEntry ? Color.gray : primaryText)
                    .textSelection(.enabled)

                HStack(spacing: 8) {
                    smallTag(ruleType)
                        .opacity(isSystemEntry ? 0.55 : 1.0)

                    if !note.isEmpty {
                        smallTag(note)
                            .opacity(isSystemEntry ? 0.55 : 1.0)
                    }

                    if isSystemEntry {
                        Text(effectiveSource)
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(.gray)
                            .padding(.horizontal, 8)
                            .padding(.vertical, 4)
                            .background(Color.gray.opacity(0.12))
                            .clipShape(Capsule())
                    }
                }

                if ruleType == "host" {
                    Text("Resolved IP: \(item["resolved_ips_display"] ?? "unavailable")")
                        .font(.system(size: 12, weight: .regular))
                        .foregroundStyle(isSystemEntry ? Color.gray.opacity(0.9) : mutedText)
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)

            if isSystemEntry {
                Text("Locked")
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundStyle(Color.gray)
                    .padding(.horizontal, 18)
                    .padding(.vertical, 10)
                    .background(Color.gray.opacity(0.18))
                    .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
            } else {
                Button {
                    let alert = NSAlert()
                    alert.messageText = "Delete whitelist entry?"
                    alert.informativeText = "This will remove \(value) from the whitelist."
                    alert.alertStyle = .warning
                    alert.addButton(withTitle: "Delete")
                    alert.addButton(withTitle: "Cancel")

                    let response = alert.runModal()
                    if response == .alertFirstButtonReturn {
                        viewModel.removeWhitelistEntry(kind: ruleType, value: value)
                    }
                } label: {
                    Text("Delete")
                        .font(.system(size: 14, weight: .semibold))
                        .foregroundStyle(Color.white)
                        .padding(.horizontal, 18)
                        .padding(.vertical, 10)
                        .background(Color.red.opacity(0.9))
                        .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
                }
                .buttonStyle(.plain)
            }
        }
        .padding(12)
        .background(isSystemEntry ? Color.gray.opacity(0.08) : surfaceSecondary)
        .overlay(
            RoundedRectangle(cornerRadius: 14)
                .stroke(isSystemEntry ? Color.gray.opacity(0.22) : borderSoft, lineWidth: 1)
        )
        .clipShape(RoundedRectangle(cornerRadius: 14))
        .grayscale(isSystemEntry ? 0.55 : 0)
        .opacity(isSystemEntry ? 0.72 : 1.0)
    }
            
            // 主机信息悬浮面板内容：
            // 这里不再做向下展开，而是作为 popover 的主体内容显示。
    func hostInfoPopoverContent(_ hostSummary: HostSummaryResult) -> some View {
                VStack(alignment: .leading, spacing: 14) {
                    HStack(spacing: 10) {
                        SectionTitleIcon(systemName: "desktopcomputer", tint: Color.blue)
                        
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Host Information")
                                .font(.system(size: 17, weight: .semibold))
                                .foregroundStyle(primaryText)
                            
                            Text("Local device and system network")
                                .font(.system(size: 12, weight: .regular))
                                .foregroundStyle(mutedText)
                        }
                        
                        Spacer()
                    }
                    
                    Divider()
                        .overlay(borderSoft)
                    
                    VStack(alignment: .leading, spacing: 12) {
                        infoRow(title: "Interface", value: hostSummary.interface)
                        infoRow(title: "Local IPv4", value: hostSummary.local_ip)
                        infoRow(title: "Local IPv6", value: hostSummary.local_ipv6)
                        
                        portSummarySection(
                            title: "Open TCP Ports",
                            transport: "TCP",
                            ports: hostSummary.open_tcp_ports
                        )
                        
                        portSummarySection(
                            title: "Open UDP Ports",
                            transport: "UDP",
                            ports: hostSummary.open_udp_ports
                        )
                    }
                }
                .padding(16)
                .frame(width: 420)
                .background(surfacePrimary)
            }
            
            // 公网信息悬浮面板内容：
            // 点击卡片后以浮层形式显示，避免原先内容从顶部滑入的不自然动画。
    func networkInfoPopoverContent(_ hostSummary: HostSummaryResult) -> some View {
                VStack(alignment: .leading, spacing: 14) {
                    HStack(spacing: 10) {
                        SectionTitleIcon(systemName: "location.viewfinder", tint: Color.green)
                        
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Public Network")
                                .font(.system(size: 17, weight: .semibold))
                                .foregroundStyle(primaryText)
                            
                            Text("External IP and geolocation")
                                .font(.system(size: 12, weight: .regular))
                                .foregroundStyle(mutedText)
                        }
                        
                        Spacer()
                    }
                    
                    Divider()
                        .overlay(borderSoft)
                    
                    VStack(alignment: .leading, spacing: 12) {
                        infoRow(title: "Public IPv4", value: hostSummary.public_ip)
                        infoRow(title: "Public IPv6", value: hostSummary.public_ipv6)
                        infoRow(title: "IPv4 Location", value: hostSummary.public_ip_location)
                        infoRow(title: "IPv6 Location", value: hostSummary.public_ipv6_location)
                    }
                }
                .padding(16)
                .frame(width: 420)
                .background(surfacePrimary)
            }
            
    // 紧凑信息入口卡片：
    // 用于替代原来的大号展开框，点击后弹出悬浮窗口。
    func summaryEntryCard(
        title: String,
        subtitle: String,
        icon: String,
        tint: Color,
        detailLines: [String],
        showsViewDetails: Bool = true,
        action: @escaping () -> Void
    ) -> some View {
        Button(
            action: action,
            label: {
                VStack(alignment: .leading, spacing: 12) {
                    HStack(alignment: .center, spacing: 10) {
                        ZStack {
                            RoundedRectangle(cornerRadius: 10)
                                .fill(tint.opacity(0.14))
                                .frame(width: 34, height: 34)

                            Image(systemName: icon)
                                .font(.system(size: 15, weight: .semibold))
                                .foregroundStyle(tint)
                        }

                        VStack(alignment: .leading, spacing: 2) {
                            Text(title)
                                .font(.system(size: 15, weight: .semibold))
                                .foregroundStyle(primaryText)

                            Text(subtitle)
                                .font(.system(size: 12, weight: .regular))
                                .foregroundStyle(mutedText)
                                .lineLimit(1)
                        }

                        Spacer(minLength: 8)
                    }

                    VStack(alignment: .leading, spacing: 6) {
                        ForEach(detailLines.prefix(3), id: \.self) { line in
                            Text(line)
                                .font(.system(size: 12, weight: .regular))
                                .foregroundStyle(mutedText)
                                .lineLimit(1)
                        }
                    }

                    Spacer(minLength: 0)

                    HStack {
                        if showsViewDetails {
                            Text("View details")
                                .font(.system(size: 12, weight: .semibold))
                                .foregroundStyle(tint)
                        } else {
                            Text("View details")
                                .font(.system(size: 12, weight: .semibold))
                                .opacity(0)
                        }

                        Spacer()
                    }
                }
                .frame(maxWidth: .infinity, minHeight: 172, maxHeight: 172, alignment: .topLeading)
                .padding(14)
                .background(surfaceSecondary)
                .overlay(
                    RoundedRectangle(cornerRadius: 16)
                        .stroke(borderSoft, lineWidth: 1)
                )
                .clipShape(RoundedRectangle(cornerRadius: 16))
                .contentShape(RoundedRectangle(cornerRadius: 16))
            }
        )
        .buttonStyle(.plain)
    }
            
    func infoRow(title: String, value: String) -> some View {
                VStack(alignment: .leading, spacing: 4) {
                    Text(title)
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(mutedText)
                    Text(value.isEmpty ? "-" : value)
                        .font(.system(size: 13, weight: .regular))
                        .foregroundStyle(primaryText)
                        .textSelection(.enabled)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            
    func realtimeBlock(title: String, text: String, tint: Color? = nil) -> some View {
                VStack(alignment: .leading, spacing: 6) {
                    Text(title)
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(mutedText)
                    
                    Text(text)
                        .font(.system(size: 13, weight: .regular))
                        .foregroundStyle(tint ?? primaryText)
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(12)
                        .background(surfaceSecondary)
                        .overlay(
                            RoundedRectangle(cornerRadius: 12)
                                .stroke(borderSoft, lineWidth: 1)
                        )
                        .clipShape(RoundedRectangle(cornerRadius: 12))
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                
            }
            
            // 风险等级颜色：用于高/中/低风险标签和选中态描边。
    func riskLevelColor(_ value: String) -> Color {
                switch value.lowercased() {
                case "high":
                    return .red
                case "medium":
                    return .orange
                case "low":
                    return .green
                default:
                    return .secondary
                }
            }
            
            // 详情行：用于展示选中风险的关键字段。
    func detailRow(title: String, value: String) -> some View {
                HStack(alignment: .top, spacing: 10) {
                    Text(title)
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(mutedText)
                        .frame(width: 96, alignment: .leading)
                    
                    Text(value)
                        .font(.system(size: 13, weight: .regular))
                        .foregroundStyle(primaryText)
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            
            // 风险严重度排序值。
    func riskSeverityValue(_ value: String) -> Int {
                switch value.lowercased() {
                case "high":
                    return 3
                case "medium":
                    return 2
                case "low":
                    return 1
                default:
                    return 0
                }
            }
            
    // 生成风险列表：按内网过滤、按目标 IP 去重，再按严重度排序。
    func realtimeRiskItems() -> [RiskItem] {
        guard let realtime = viewModel.realtimeResult else { return [] }
        
        var items = realtime.top_risks
        
        if viewModel.excludeInternalTraffic {
            items = items.filter { item in
                let geo = item.geo_label.lowercased()
                let host = item.resolved_host.lowercased()
                let dst = item.dst_ip.lowercased()
                
                let isInternal =
                geo.contains("local") ||
                geo.contains("private") ||
                geo.contains("lan") ||
                host.hasPrefix("192.168.") ||
                host.hasPrefix("10.") ||
                host.hasPrefix("172.") ||
                dst.hasPrefix("192.168.") ||
                dst.hasPrefix("10.") ||
                dst.hasPrefix("172.")
                
                return !isInternal
            }
        }
        
        var deduplicated: [String: RiskItem] = [:]
        
        for item in items {
            let key = item.dst_ip.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines).lowercased()
            
            guard !key.isEmpty else { continue }
            
            if let existing = deduplicated[key] {
                let currentSeverity = riskSeverityValue(item.risk_level)
                let existingSeverity = riskSeverityValue(existing.risk_level)
                
                if currentSeverity > existingSeverity {
                    deduplicated[key] = item
                } else if currentSeverity == existingSeverity {
                    let currentCompleteness =
                        (item.service_hint.isEmpty ? 0 : 1) +
                        (item.resolved_host.isEmpty ? 0 : 1) +
                        (item.geo_label.isEmpty ? 0 : 1)
                    
                    let existingCompleteness =
                        (existing.service_hint.isEmpty ? 0 : 1) +
                        (existing.resolved_host.isEmpty ? 0 : 1) +
                        (existing.geo_label.isEmpty ? 0 : 1)
                    
                    if currentCompleteness > existingCompleteness {
                        deduplicated[key] = item
                    } else if currentCompleteness == existingCompleteness, item.dst_port < existing.dst_port {
                        deduplicated[key] = item
                    }
                }
            } else {
                deduplicated[key] = item
            }
        }
        
        var result = Array(deduplicated.values)
        
        result.sort { lhs, rhs in
            let left = riskSeverityValue(lhs.risk_level)
            let right = riskSeverityValue(rhs.risk_level)
            
            if left == right {
                return riskSortDescending ? lhs.dst_ip < rhs.dst_ip : lhs.dst_ip > rhs.dst_ip
            }
            
            return riskSortDescending ? left > right : left < right
        }
        
        return result
    }
            
    // 左侧风险项卡片：点击后通过浮层显示详情，而不是在右侧单独占一列。
    func riskItemRow(displayIndex: Int, item: RiskItem) -> some View {
        let isSelected = viewModel.selectedRiskItem?.id == item.id

        return Button {
            if isSelected {
                viewModel.selectedRiskItem = nil
            } else {
                viewModel.selectRiskItem(item)
            }
        } label: {
            VStack(alignment: .leading, spacing: 12) {
                HStack(alignment: .top, spacing: 10) {
                    Text("#\(displayIndex)")
                        .font(.system(size: 18, weight: .bold, design: .rounded))
                        .foregroundStyle(primaryText)

                    Spacer(minLength: 8)

                    Text(item.risk_level)
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(riskLevelColor(item.risk_level))
                        .padding(.horizontal, 10)
                        .padding(.vertical, 5)
                        .background(riskLevelColor(item.risk_level).opacity(0.12))
                        .clipShape(Capsule())
                }

                VStack(alignment: .leading, spacing: 10) {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("IP")
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(mutedText)

                        Text(item.dst_ip)
                            .font(.system(size: 15, weight: .semibold))
                            .foregroundStyle(primaryText)
                            .lineLimit(1)
                            .minimumScaleFactor(0.9)

                        if let ipType = item.dst_ip_type, !ipType.isEmpty {
                            Text("IP Type: \(ipTypeDisplayName(ipType))")
                                .font(.system(size: 11, weight: .medium))
                                .foregroundStyle(mutedText)
                                .lineLimit(1)
                        }
                    }

                    VStack(alignment: .leading, spacing: 6) {
                        Text("Service")
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(mutedText)

                        Text(item.service_hint.isEmpty ? "-" : item.service_hint)
                            .font(.system(size: 13, weight: .regular))
                            .foregroundStyle(primaryText)
                            .lineLimit(1)
                    }

                    VStack(alignment: .leading, spacing: 6) {
                        Text("Port")
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(mutedText)

                        Text(String(item.dst_port))
                            .font(.system(size: 13, weight: .regular))
                            .foregroundStyle(primaryText)
                            .lineLimit(1)
                    }
                }

                HStack {
                    Text("View details")
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundStyle(riskLevelColor(item.risk_level))

                    Spacer()
                }
            }
            .frame(maxWidth: .infinity, minHeight: 170, alignment: .topLeading)
            .padding(14)
            .background(
                isSelected
                ? surfaceSecondary.opacity(0.95)
                : surfaceSecondary
            )
            .overlay(
                RoundedRectangle(cornerRadius: 16)
                    .stroke(
                        isSelected
                        ? riskLevelColor(item.risk_level).opacity(0.65)
                        : borderSoft,
                        lineWidth: isSelected ? 1.4 : 1
                    )
            )
            .clipShape(RoundedRectangle(cornerRadius: 16))
            .contentShape(RoundedRectangle(cornerRadius: 16))
        }
        .buttonStyle(.plain)
        .anchorPreference(
            key: RiskCardBoundsPreferenceKey.self,
            value: .bounds,
            transform: { anchor in
                [String(describing: item.id): anchor]
            }
        )
    }
            
            // 右侧浮窗：显示当前选中的风险详情。
    func selectedRiskFloatingPanel(_ selected: RiskItem) -> some View {
                VStack(alignment: .leading, spacing: 12) {
                    HStack(alignment: .top, spacing: 12) {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Selected Risk")
                                .font(.caption.weight(.semibold))
                                .foregroundStyle(mutedText)
                            
                            Text("\(selected.dst_ip):\(String(selected.dst_port))")
                                .font(.system(size: 16, weight: .semibold))
                                .foregroundStyle(primaryText)
                                .textSelection(.enabled)
                        }
                        
                        Spacer()
                        
                        Button {
                            viewModel.selectedRiskItem = nil
                        } label: {
                            Image(systemName: "xmark")
                                .font(.system(size: 11, weight: .bold))
                                .foregroundStyle(mutedText)
                                .frame(width: 24, height: 24)
                                .background(surfaceSecondary)
                                .clipShape(Circle())
                        }
                        .buttonStyle(.plain)
                        
                        Text(selected.risk_level)
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(riskLevelColor(selected.risk_level))
                            .padding(.horizontal, 10)
                            .padding(.vertical, 5)
                            .background(riskLevelColor(selected.risk_level).opacity(0.12))
                            .clipShape(Capsule())
                    }
                    
                    Divider()
                        .overlay(borderSoft)
                    
                    detailRow(title: "Host", value: selected.resolved_host.isEmpty ? "-" : selected.resolved_host)
                    detailRow(title: "Service", value: selected.service_hint.isEmpty ? "-" : selected.service_hint)
                    detailRow(title: "Geo", value: selected.geo_label.isEmpty ? "-" : selected.geo_label)
                    detailRow(title: "Destination", value: "\(selected.dst_ip):\(String(selected.dst_port))")
                    detailRow(title: "IP Type", value: selected.dst_ip_type.map { ipTypeDisplayName($0) } ?? "-")
                    detailRow(title: "Port", value: String(selected.dst_port))
                }
                .padding(16)
                .background(surfacePrimary)
                .overlay(
                    RoundedRectangle(cornerRadius: 16)
                        .stroke(borderSoft, lineWidth: 1)
                )
                .clipShape(RoundedRectangle(cornerRadius: 16))
            }
            
    func ipTypeDisplayName(_ value: String) -> String {
        switch value.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines).lowercased() {
        case "public":
            return "Public"
        case "private":
            return "Private / LAN"
        case "loopback":
            return "Loopback"
        case "broadcast":
            return "Broadcast"
        case "multicast":
            return "Multicast"
        case "link_local":
            return "Link Local"
        case "reserved":
            return "Reserved"
        case "documentation":
            return "Documentation"
        case "carrier_nat":
            return "Carrier NAT"
        case "unspecified":
            return "Unspecified"
        case "invalid":
            return "Invalid"
        default:
            return value
        }
    }

    func smallTag(_ text: String) -> some View {
                Text(text)
                    .font(.caption)
                    .foregroundStyle(primaryText)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background(surfacePrimary)
                    .overlay(
                        Capsule()
                            .stroke(borderSoft, lineWidth: 1)
                    )
                    .clipShape(Capsule())
            }
            
    func statusBadge(_ text: String) -> some View {
                Text(text)
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(.white)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 6)
                    .background(
                        Capsule()
                            .fill(Color.accentColor)
                    )
            }
            
    func summaryChip(title: String, value: String) -> some View {
                VStack(alignment: .leading, spacing: 4) {
                    Text(title)
                        .font(.caption)
                        .foregroundStyle(mutedText)
                    Text(value)
                        .font(.system(size: 14, weight: .semibold))
                        .foregroundStyle(primaryText)
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 10)
                .background(surfaceSecondary)
                .overlay(
                    RoundedRectangle(cornerRadius: 12)
                        .stroke(borderSoft, lineWidth: 1)
                )
                .clipShape(RoundedRectangle(cornerRadius: 12))
            }
            
    func portsText(_ ports: [Int]) -> String {
                if ports.isEmpty { return "None" }
                return ports.map(String.init).joined(separator: ", ")
            }
            
    func riskCountsText(_ value: [String: Int]) -> String {
                if value.isEmpty { return "-" }
                return value
                    .map { "\($0.key): \($0.value)" }
                    .sorted()
                    .joined(separator: ", ")
            }
            
            // 吞吐量数值格式化：优先显示更易读的 B/s、KB/s、MB/s。
    func formatByteRate(_ value: Double) -> String {
                let absValue = abs(value)
                
                if absValue >= 1024 * 1024 {
                    return String(format: "%.2f MB/s", value / (1024 * 1024))
                } else if absValue >= 1024 {
                    return String(format: "%.1f KB/s", value / 1024)
                } else {
                    return String(format: "%.0f B/s", value)
                }
            }
            
    // MARK: - Throughput chart helpers
            
    // 从日志文本中解析吞吐量点，用于绘制实时折线图。
    private func parseThroughputPoints(from text: String) -> [ThroughputPoint] {
                let lines = text.components(separatedBy: .newlines)
                var bucket: [String: (rx: Double?, tx: Double?)] = [:]
                
                for line in lines {
                    guard let timeStart = line.firstIndex(of: "["),
                          let timeEnd = line.firstIndex(of: "]") else {
                        continue
                    }
                    
                    let timestamp = String(line[line.index(after: timeStart)..<timeEnd])
                    
                    if let rxRange = line.range(of: "rx_bytes_per_second=") {
                        let valueText = String(line[rxRange.upperBound...]).trimmingCharacters(in: .whitespaces)
                        if let value = Double(valueText) {
                            var item = bucket[timestamp] ?? (nil, nil)
                            item.rx = value
                            bucket[timestamp] = item
                        }
                    }
                    
                    if let txRange = line.range(of: "tx_bytes_per_second=") {
                        let valueText = String(line[txRange.upperBound...]).trimmingCharacters(in: .whitespaces)
                        if let value = Double(valueText) {
                            var item = bucket[timestamp] ?? (nil, nil)
                            item.tx = value
                            bucket[timestamp] = item
                        }
                    }
                }
                
                return bucket
                    .sorted { $0.key < $1.key }
                    .map { key, value in
                        ThroughputPoint(
                            timestamp: key,
                            rx: value.rx ?? 0,
                            tx: value.tx ?? 0
                        )
                    }
            }
            
    // MARK: - Port summary helpers
            
    func portSummarySection(title: String, transport: String, ports: [Int]) -> some View {
                let grouped = groupedPortsByKind(ports)
                
                return VStack(alignment: .leading, spacing: 10) {
                    HStack(alignment: .firstTextBaseline, spacing: 10) {
                        Text(title)
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(mutedText)
                        
                        Text("Count: \(ports.count)")
                            .font(.system(size: 13, weight: .semibold))
                            .foregroundStyle(primaryText)
                    }
                    
                    if ports.isEmpty {
                        Text("No open ports")
                            .font(.system(size: 13, weight: .regular))
                            .foregroundStyle(mutedText)
                    } else {
                        ForEach(grouped, id: \.title) { group in
                            if !group.ports.isEmpty {
                                portKindSection(
                                    title: group.title,
                                    transport: transport,
                                    ports: group.ports
                                )
                            }
                        }
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            
            
    func portTag(transport: String, port: Int) -> some View {
                let isSelected = isInspectingPortOwner &&
                inspectedPortTransport == transport &&
                inspectedPortNumber == port
                
                return HStack(spacing: 6) {
                    Text(verbatim: String(port))
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(primaryText)
                    
                    if isSelected {
                        Image(systemName: "checkmark.circle.fill")
                            .font(.system(size: 11, weight: .semibold))
                            .foregroundStyle(Color.accentColor)
                    }
                }
                .frame(minWidth: 64)
                .padding(.horizontal, 10)
                .padding(.vertical, 8)
                .background(isSelected ? surfacePrimary : surfaceSecondary)
                .overlay(
                    Capsule()
                        .stroke(
                            isSelected ? Color.accentColor.opacity(0.7) : borderSoft,
                            lineWidth: isSelected ? 1.4 : 1
                        )
                )
                .clipShape(Capsule())
                .contentShape(Capsule())
                .onTapGesture {
                    inspectPort(transport: transport, port: port)
                }
            }
            
            // 端口详情状态：当前先显示基础信息，后续再接真实归属查询。
    func inspectPort(transport: String, port: Int) {
                inspectedPortTransport = transport
                inspectedPortNumber = port
                inspectedPortPID = "Loading..."
                inspectedPortProcessName = "Loading..."
                inspectedPortRawCommand = ""
                inspectedPortStatusText = "Looking up local owner for \(transport) port \(port)..."
                isInspectingPortOwner = true
                
                PortInspectorWindowController.shared.update(
                    data: PortInspectorData(
                        transport: transport,
                        port: port,
                        pid: "Loading...",
                        processName: "Loading...",
                        statusText: "Looking up local owner for \(transport) port \(port)...",
                        commandText: "-",
                        isInspecting: true
                    )
                )
                
                let selectedTransport = transport.uppercased()
                let selectedPort = port
                
                DispatchQueue.global(qos: .userInitiated).async {
                    let process = Process()
                    let outputPipe = Pipe()
                    let errorPipe = Pipe()
                    
                    process.executableURL = URL(fileURLWithPath: "/usr/sbin/lsof")
                    
                    if selectedTransport == "TCP" {
                        process.arguments = ["-nP", "-iTCP:\(selectedPort)", "-sTCP:LISTEN"]
                    } else {
                        process.arguments = ["-nP", "-iUDP:\(selectedPort)"]
                    }
                    
                    process.standardOutput = outputPipe
                    process.standardError = errorPipe
                    
                    do {
                        try process.run()
                        process.waitUntilExit()
                        
                        let stdout = String(data: outputPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
                        let stderr = String(data: errorPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
                        
                        let lookup = parsePortOwnerLookupOutput(stdout)
                        
                        DispatchQueue.main.async {
                            if let lookup {
                                inspectedPortPID = lookup.pid
                                inspectedPortProcessName = lookup.process
                                inspectedPortRawCommand = lookup.raw
                                inspectedPortStatusText = lookup.status
                                
                                PortInspectorWindowController.shared.update(
                                    data: PortInspectorData(
                                        transport: transport,
                                        port: port,
                                        pid: lookup.pid,
                                        processName: lookup.process,
                                        statusText: lookup.status,
                                        commandText: lookup.raw,
                                        isInspecting: false
                                    )
                                )
                            } else {
                                let fallbackText = stderr.isEmpty ? stdout : stderr
                                
                                inspectedPortPID = "-"
                                inspectedPortProcessName = "-"
                                inspectedPortRawCommand = fallbackText
                                inspectedPortStatusText = "No active local owner was found for \(selectedTransport) port \(selectedPort). This may be a system socket, a short-lived socket, or require elevated permission to inspect."
                                
                                PortInspectorWindowController.shared.update(
                                    data: PortInspectorData(
                                        transport: transport,
                                        port: port,
                                        pid: "-",
                                        processName: "-",
                                        statusText: "No active local owner was found for \(selectedTransport) port \(selectedPort). This may be a system socket, a short-lived socket, or require elevated permission to inspect.",
                                        commandText: fallbackText.isEmpty ? "-" : fallbackText,
                                        isInspecting: false
                                    )
                                )
                            }
                        }
                    } catch {
                        DispatchQueue.main.async {
                            inspectedPortPID = "-"
                            inspectedPortProcessName = "-"
                            inspectedPortRawCommand = error.localizedDescription
                            inspectedPortStatusText = "Port owner lookup failed: \(error.localizedDescription)"
                            
                            PortInspectorWindowController.shared.update(
                                data: PortInspectorData(
                                    transport: transport,
                                    port: port,
                                    pid: "-",
                                    processName: "-",
                                    statusText: "Port owner lookup failed: \(error.localizedDescription)",
                                    commandText: error.localizedDescription,
                                    isInspecting: false
                                )
                            )
                        }
                    }
                }
            }
            
            // 解析 lsof 输出，提取进程名、PID 和状态信息。
    func parsePortOwnerLookupOutput(_ output: String) -> (pid: String, process: String, status: String, raw: String)? {
                let lines = output
                    .components(separatedBy: .newlines)
                    .map { $0.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines) }
                    .filter { !$0.isEmpty }
                
                guard lines.count >= 2 else { return nil }
                
                let firstDataLine = lines[1]
                let columns = firstDataLine.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
                guard columns.count >= 2 else { return nil }
                
                let processName = columns[0]
                let pid = columns[1]
                let status = columns.last ?? "Socket found"
                
                return (
                    pid: pid,
                    process: processName,
                    status: status,
                    raw: firstDataLine
                )
            }
            
    }

    // 折线图点：同一时间戳聚合 RX / TX 两条序列。
    private struct ThroughputPoint: Identifiable {
        let id = UUID()
        let timestamp: String
        let rx: Double
        let tx: Double
    }

    // 轻量吞吐量折线图：蓝色表示 RX，红色表示 TX。
    private struct ThroughputLineChartView: View {
        let points: [ThroughputPoint]

        var body: some View {
            GeometryReader { geometry in
                let maxValue = max(points.map { max($0.rx, $0.tx) }.max() ?? 1, 1)
                let width = geometry.size.width
                let height = geometry.size.height

                ZStack {
                    RoundedRectangle(cornerRadius: 12)
                        .fill(Color.black.opacity(0.03))

                    gridLines(width: width, height: height)
                        .stroke(
                            Color.gray.opacity(0.18),
                            style: StrokeStyle(lineWidth: 1, dash: [4, 4])
                        )

                    buildPath(
                        values: points.map(\.rx),
                        width: width,
                        height: height,
                        maxValue: maxValue
                    )
                    .stroke(
                        Color.blue,
                        style: StrokeStyle(
                            lineWidth: 2.2,
                            lineCap: .round,
                            lineJoin: .round
                        )
                    )

                    buildPath(
                        values: points.map(\.tx),
                        width: width,
                        height: height,
                        maxValue: maxValue
                    )
                    .stroke(
                        Color.red,
                        style: StrokeStyle(
                            lineWidth: 2.2,
                            lineCap: .round,
                            lineJoin: .round
                        )
                    )
                }
            }
            .frame(height: 180)
            .animation(.easeInOut(duration: 0.22), value: points.map(\.rx))
            .animation(.easeInOut(duration: 0.22), value: points.map(\.tx))
        }

        private func buildPath(values: [Double], width: CGFloat, height: CGFloat, maxValue: Double) -> Path {
            var path = Path()
            guard values.count > 1 else { return path }

            let normalizedPoints: [CGPoint] = values.enumerated().map { index, value in
                let x = CGFloat(index) / CGFloat(values.count - 1) * width
                let y = height - CGFloat(value / maxValue) * height
                return CGPoint(x: x, y: y)
            }

            guard let first = normalizedPoints.first else { return path }
            path.move(to: first)

            if normalizedPoints.count == 2 {
                path.addLine(to: normalizedPoints[1])
                return path
            }

            for index in 0..<(normalizedPoints.count - 1) {
                let current = normalizedPoints[index]
                let next = normalizedPoints[index + 1]
                let midPoint = CGPoint(
                    x: (current.x + next.x) / 2,
                    y: (current.y + next.y) / 2
                )

                path.addQuadCurve(to: midPoint, control: current)

                if index == normalizedPoints.count - 2 {
                    path.addQuadCurve(to: next, control: next)
                }
            }

            return path
        }

        private func gridLines(width: CGFloat, height: CGFloat) -> Path {
            var path = Path()
            let rows = 4

            for index in 1...rows {
                let y = height * CGFloat(index) / CGFloat(rows + 1)
                path.move(to: CGPoint(x: 0, y: y))
                path.addLine(to: CGPoint(x: width, y: y))
            }

            return path
        }
    }

    private struct RiskCardBoundsPreferenceKey: PreferenceKey {
        static var defaultValue: [String: Anchor<CGRect>] = [:]

        static func reduce(value: inout [String: Anchor<CGRect>], nextValue: () -> [String: Anchor<CGRect>]) {
            value.merge(nextValue(), uniquingKeysWith: { _, new in new })
        }
    }

    private struct SectionTitleIcon: View {
        let systemName: String
        let tint: Color

        var body: some View {
            ZStack {
                RoundedRectangle(cornerRadius: 12)
                    .fill(tint.opacity(0.14))
                    .frame(width: 46, height: 46)
                Image(systemName: systemName)
                    .font(.system(size: 20, weight: .semibold))
                    .foregroundStyle(tint)
            }
        }
    }
