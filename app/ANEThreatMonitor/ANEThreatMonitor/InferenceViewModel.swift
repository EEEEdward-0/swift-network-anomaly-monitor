import SwiftUI
import CoreML
import Combine
import Foundation
import AppKit
import UniformTypeIdentifiers
import Darwin

enum ThemeMode: String, CaseIterable, Identifiable, Codable {
    case light = "Light"
    case dark = "Dark"
    case pride = "Pride"
    case system = "System"

    var id: String { rawValue }

    var colorScheme: ColorScheme? {
        switch self {
        case .light:
            return .light
        case .dark:
            return .dark
        case .pride:
            return .light
        case .system:
            return nil
        }
    }

    var systemImage: String {
        switch self {
        case .light:
            return "sun.max"
        case .dark:
            return "moon"
        case .pride:
            return "paintpalette"
        case .system:
            return "gearshape.2"
        }
    }
}

final class InferenceViewModel: ObservableObject {
    // MARK: - Alert state
    
    // 白名单输入非法时用于弹窗提示。
    @Published var showWhitelistValidationAlert: Bool = false
    @Published var whitelistValidationMessage: String = ""
    
    // MARK: - Core state
    @Published var whitelistQueryContextText: String = ""
    @Published var selectedMode: DetectionMode = .balanced
    @Published var demoCases: [DetectionMode.DemoCase] = []
    @Published var selectedCase: DetectionMode.DemoCase?
    @Published var resultText: String = "No prediction yet."
    @Published var detailText: String = ""
    @Published var errorText: String = ""
    @Published var whitelistRecords: [[String: String]] = []
    @Published var whitelistInputValue: String = ""
    @Published var whitelistInputNote: String = ""
    @Published var whitelistInputKind: String = "host"
    @Published var whitelistQueryIP: String = ""
    @Published var whitelistQueryInProgress: Bool = false
    @Published var whitelistQueryError: String = ""
    @Published var whitelistQueryResultText: String = "No IP query yet."
    @Published var whitelistQuerySummaryTitle: String = "No IP query yet."
    @Published var whitelistQuerySummarySubtitle: String = "Enter an IP address to check exact-IP and CIDR matches."
    @Published var whitelistBatchInput: String = ""
    @Published var whitelistBatchInProgress: Bool = false
    @Published var whitelistBatchError: String = ""
    @Published var whitelistBatchSummaryText: String = "Paste IPs above and click Batch Match to view the summary."
    @Published var whitelistBatchResultText: String = "[]"
    @Published var whitelistQueryExactValue: String = "-"
    @Published var whitelistQueryBestCIDRValue: String = "-"
    @Published var whitelistQueryCategory: String = "-"
    @Published var whitelistQuerySource: String = "-"
    @Published var whitelistQueryCIDRMatchCount: Int = 0
    @Published var hostSummary: HostSummaryResult?
    @Published var realtimeResult: RealtimeResult?
    @Published var consumerSummary: DetectionMode.ConsumerSummary?
    @Published var appStatusText: String = "Ready"
    @Published var isAnalyzing: Bool = false
    @Published var appLogText: String = ""
    @Published var throughputLogText: String = ""
    
    @Published var selectedInterface: String = "en0"
    @Published var analysisProgress: Double = 0.0
    
    @Published var isCapturing: Bool = false
    @Published var captureElapsedSeconds: Int = 0
    @Published var historyItems: [DetectionMode.HistoryRecord] = []
    @Published var selectedHistoryIDs: Set<String> = []
    @Published var selectedPCAPSavePath: String = NSHomeDirectory() + "/Desktop/captured_traffic.pcap"
    @Published var selectedRiskFilter: DetectionMode.RiskFilter = .all
    @Published var selectedRiskSort: DetectionMode.RiskSortOption = .severity
    @Published var selectedRiskItem: RiskItem?
    @Published var excludeInternalTraffic: Bool = false
    @Published var themeMode: ThemeMode = .system
    let interfaceOptions = ["en0", "awdl0", "utun0", "utun1", "bridge0", "lo0"]
    
    private let projectRoot = "/Users/zhengzhuohao/Documents/基于 Apple ANE 的本地网络异常检测与可视化系统_0307"
    private let pythonPath = "/Users/zhengzhuohao/Documents/基于 Apple ANE 的本地网络异常检测与可视化系统_0307/.venv/bin/python"
    private let hostScriptPath = "/Users/zhengzhuohao/Documents/基于 Apple ANE 的本地网络异常检测与可视化系统_0307/src/get_host_summary.py"
    private let analysisScriptPath = "/Users/zhengzhuohao/Documents/基于 Apple ANE 的本地网络异常检测与可视化系统_0307/src/local_realtime_analyzer.py"
    private let hostJsonPath = "/Users/zhengzhuohao/Documents/基于 Apple ANE 的本地网络异常检测与可视化系统_0307/reports/local_analysis/host_summary.json"
    private let analysisJsonPath = "/Users/zhengzhuohao/Documents/基于 Apple ANE 的本地网络异常检测与可视化系统_0307/reports/local_analysis/realtime_result.json"
    private let historyJsonPath = "/Users/zhengzhuohao/Documents/基于 Apple ANE 的本地网络异常检测与可视化系统_0307/reports/local_analysis/history/history_index.json"
    private let historyDirPath = "/Users/zhengzhuohao/Documents/基于 Apple ANE 的本地网络异常检测与可视化系统_0307/reports/local_analysis/history"
    private let logFilePath = "/Users/zhengzhuohao/Documents/基于 Apple ANE 的本地网络异常检测与可视化系统_0307/reports/local_analysis/realtime_analysis.log"
    private let capturedPcapSourcePath = NSHomeDirectory() + "/Desktop/local_test.pcap"
    
    private var progressTimer: Timer?
    private var captureTimer: Timer?
    private var logRefreshTimer: Timer?
    private let threatIntelService = AbuseIPDBThreatIntelService()
    @Published var threatIntelAPIKey: String = UserDefaults.standard.string(forKey: "abuseipdb_api_key") ?? ""
    @Published var threatIntelSyncInProgress: Bool = false
    
    func saveThreatIntelAPIKey(_ key: String) {
        let trimmed = key.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
        threatIntelAPIKey = trimmed
        UserDefaults.standard.set(trimmed, forKey: "abuseipdb_api_key")
    }
    
    private func addOrUpdateSystemWhitelistIP(ip: String, note: String, confidence: Double) async -> Bool {
        await withCheckedContinuation { continuation in
            runWhitelistScript(
                arguments: [
                    "--action", "add",
                    "--kind", "ip",
                    "--value", ip,
                    "--note", note,
                    "--source", "system",
                    "--category", "external_threat_intel",
                    "--confidence", String(format: "%.2f", confidence)
                ]
            ) { success, _ in
                continuation.resume(returning: success)
            }
        }
    }
    
    private func realtimeRiskItemsForIntel() -> [RiskItem] {
        guard let realtime = realtimeResult else { return [] }

        var items = realtime.top_risks

        if excludeInternalTraffic {
            items = items.filter { item in
                let dst = item.dst_ip.lowercased()
                let geo = item.geo_label.lowercased()
                let host = item.resolved_host.lowercased()

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

        var unique: [String: RiskItem] = [:]
        for item in items {
            let key = item.dst_ip.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines).lowercased()
            guard !key.isEmpty else { continue }

            if let existing = unique[key] {
                let currentSeverity = riskRank(item.risk_level)
                let existingSeverity = riskRank(existing.risk_level)
                if currentSeverity < existingSeverity {
                    unique[key] = item
                }
            } else {
                unique[key] = item
            }
        }

        return Array(unique.values)
    }

    func syncTopRiskIPsFromAbuseIPDB() {
        guard !threatIntelAPIKey.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines).isEmpty else {
            appStatusText = "Threat intel API key missing"
            appLogText = "Please set AbuseIPDB API key first"
            return
        }
                
        let riskItems = realtimeRiskItemsForIntel()
        guard !riskItems.isEmpty else {
            appStatusText = "No public IPs to sync"
            appLogText = "Realtime result has no routable IP candidates"
            return
        }

        threatIntelSyncInProgress = true
        appStatusText = "Threat intel sync running"
        appLogText = "Checking \(riskItems.count) IPs via AbuseIPDB..."

        Task {
            var logs: [String] = []
            var addedCount = 0

            for item in riskItems {
                do {
                    let intel = try await threatIntelService.checkIP(item.dst_ip, apiKey: threatIntelAPIKey)

                    let score = intel.abuseConfidenceScore
                    let reports = intel.totalReports ?? 0
                    let isp = intel.isp ?? "-"
                    let usage = intel.usageType ?? "-"
                    let country = intel.countryCode ?? "-"

                    logs.append("[CHECK] \(item.dst_ip) score=\(score) reports=\(reports) isp=\(isp) usage=\(usage) country=\(country)")

                    // 仅高风险自动写入 system whitelist
                    if score >= 75 {
                        let note = "AbuseIPDB score=\(score), reports=\(reports), isp=\(isp), usage=\(usage), country=\(country)"
                        let confidence = min(max(Double(score) / 100.0, 0.0), 1.0)

                        let success = await addOrUpdateSystemWhitelistIP(
                            ip: item.dst_ip,
                            note: note,
                            confidence: confidence
                        )

                        if success {
                            addedCount += 1
                            logs.append("[SYNCED] \(item.dst_ip) -> system whitelist")
                        } else {
                            logs.append("[FAILED] \(item.dst_ip) -> whitelist write failed")
                        }
                    } else {
                        logs.append("[SKIP] \(item.dst_ip) score below threshold")
                    }
                } catch {
                    logs.append("[ERROR] \(item.dst_ip) \(error.localizedDescription)")
                }
            }

            await MainActor.run {
                self.threatIntelSyncInProgress = false
                self.appStatusText = "Threat intel sync finished"
                self.appLogText = logs.joined(separator: "\n")
                self.refreshWhitelist()
                if addedCount > 0 {
                    self.appStatusText = "Synced \(addedCount) system entries"
                }
            }
        }
    }
    
    init() {
        loadSavedPCAPPath()
        loadSavedThemeMode()
        loadDemoCases()
        loadHistory()
        loadHostSummaryOnLaunch()
        refreshWhitelist()
    }
    
    // MARK: - Prediction
    
    func runSelectedPrediction() {
        errorText = ""
        
        guard let selectedCase else {
            errorText = "No demo case selected."
            resultText = "Prediction failed."
            detailText = ""
            return
        }
        
        do {
            let result = try runModel(sample: selectedCase.features, mode: selectedMode)
            
            resultText = "Prediction: \(result.predictedLabel)"
            detailText =
            """
            Case: \(selectedCase.displayName)
            True label: \(selectedCase.trueLabelText)
            Reference attack probability: \(String(format: "%.4f", selectedCase.attackProbability))
            
            Mode: \(selectedMode.rawValue)
            Threshold: \(String(format: "%.2f", result.threshold))
            Attack probability: \(String(format: "%.4f", result.attackProbability))
            Normal probability: \(String(format: "%.4f", result.normalProbability))
            Latency: \(String(format: "%.3f", result.latencyMs)) ms
            """
        } catch {
            errorText = error.localizedDescription
            resultText = "Prediction failed."
            detailText = ""
        }
    }
    
    // MARK: - Capture
    
    // 启动抓包：先清理上一轮残留状态，只有在启动命令成功后才进入抓包状态。
    func startCapture() {
        isCapturing = false
        captureElapsedSeconds = 0
        analysisProgress = 0.0
        appStatusText = "Starting capture..."
        appLogText = ""
        throughputLogText = ""
        realtimeResult = nil
        consumerSummary = nil
        stopCaptureTimer()
        stopLogRefreshTimer()
        clearCaptureArtifactsForNewSession()
        startLogRefreshTimer()
        
        DispatchQueue.global(qos: .userInitiated).async {
            let process = Process()
            let outputPipe = Pipe()
            let errorPipe = Pipe()
            
            var stdoutBuffer = Data()
            var stderrBuffer = Data()
            
            outputPipe.fileHandleForReading.readabilityHandler = { handle in
                let data = handle.availableData
                if !data.isEmpty {
                    stdoutBuffer.append(data)
                }
            }
            
            errorPipe.fileHandleForReading.readabilityHandler = { handle in
                let data = handle.availableData
                if !data.isEmpty {
                    stderrBuffer.append(data)
                }
            }
            
            process.currentDirectoryURL = URL(fileURLWithPath: self.projectRoot)
            process.executableURL = URL(fileURLWithPath: self.pythonPath)
            process.arguments = [
                self.analysisScriptPath,
                "--start-capture",
                "--interface", self.selectedInterface
            ]
            process.standardOutput = outputPipe
            process.standardError = errorPipe
            
            process.terminationHandler = { proc in
                outputPipe.fileHandleForReading.readabilityHandler = nil
                errorPipe.fileHandleForReading.readabilityHandler = nil
                
                let remainingOut = outputPipe.fileHandleForReading.readDataToEndOfFile()
                let remainingErr = errorPipe.fileHandleForReading.readDataToEndOfFile()
                if !remainingOut.isEmpty { stdoutBuffer.append(remainingOut) }
                if !remainingErr.isEmpty { stderrBuffer.append(remainingErr) }
                
                let stdoutText = String(data: stdoutBuffer, encoding: .utf8) ?? ""
                let stderrText = String(data: stderrBuffer, encoding: .utf8) ?? ""
                
                DispatchQueue.main.async {
                    if proc.terminationStatus == 0 {
                        self.isCapturing = true
                        self.startCaptureTimer()
                        self.appStatusText = "Capture in progress"
                        let text = stdoutText.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
                        if !text.isEmpty {
                            self.appLogText = self.stripThroughputLines(from: text)
                            let throughputText = self.extractThroughputText(from: text)
                            if !throughputText.isEmpty {
                                self.throughputLogText = throughputText
                            }
                        } else {
                            self.refreshLogTextFromFile()
                        }
                    } else {
                        self.isCapturing = false
                        self.stopCaptureTimer()
                        self.stopLogRefreshTimer()
                        self.throughputLogText = ""
                        let message = (stderrText.isEmpty ? stdoutText : stderrText)
                            .trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
                        self.appStatusText = "Start capture failed (code \(proc.terminationStatus))"
                        self.appLogText = message.isEmpty ? "Unknown start capture error." : message
                    }
                }
            }
            
            do {
                try process.run()
            } catch {
                DispatchQueue.main.async {
                    self.isCapturing = false
                    self.stopCaptureTimer()
                    self.stopLogRefreshTimer()
                    self.throughputLogText = ""
                    self.appStatusText = "Start capture error: \(error.localizedDescription)"
                    self.appLogText = error.localizedDescription
                }
            }
        }
    }
    
    func stopCaptureAndAnalyze() {
        isCapturing = false
        stopCaptureTimer()
        startLogRefreshTimer()
        appStatusText = "Stopping capture and analyzing..."
        analysisProgress = 0.05
        isAnalyzing = true
        startFakeProgress()
        
        DispatchQueue.global(qos: .userInitiated).async {
            let process = Process()
            let outputPipe = Pipe()
            let errorPipe = Pipe()
            
            var stdoutBuffer = Data()
            var stderrBuffer = Data()
            
            outputPipe.fileHandleForReading.readabilityHandler = { handle in
                let data = handle.availableData
                if !data.isEmpty {
                    stdoutBuffer.append(data)
                }
            }
            
            errorPipe.fileHandleForReading.readabilityHandler = { handle in
                let data = handle.availableData
                if !data.isEmpty {
                    stderrBuffer.append(data)
                }
            }
            
            process.currentDirectoryURL = URL(fileURLWithPath: self.projectRoot)
            process.executableURL = URL(fileURLWithPath: self.pythonPath)
            process.arguments = [
                self.analysisScriptPath,
                "--stop-capture",
                "--scope", "external_only"
            ]
            process.standardOutput = outputPipe
            process.standardError = errorPipe
            
            process.terminationHandler = { proc in
                outputPipe.fileHandleForReading.readabilityHandler = nil
                errorPipe.fileHandleForReading.readabilityHandler = nil
                
                let remainingOut = outputPipe.fileHandleForReading.readDataToEndOfFile()
                let remainingErr = errorPipe.fileHandleForReading.readDataToEndOfFile()
                if !remainingOut.isEmpty { stdoutBuffer.append(remainingOut) }
                if !remainingErr.isEmpty { stderrBuffer.append(remainingErr) }
                
                let stdoutText = String(data: stdoutBuffer, encoding: .utf8) ?? ""
                let stderrText = String(data: stderrBuffer, encoding: .utf8) ?? ""
                
                DispatchQueue.main.async {
                    self.isCapturing = false
                    self.isAnalyzing = false
                    self.stopFakeProgress(success: proc.terminationStatus == 0)
                    self.stopLogRefreshTimer()
                    
                    if proc.terminationStatus == 0 {
                        self.loadRealtimeResult()
                        self.loadHostSummary()
                        self.loadHistory()
                        self.persistCapturedPCAPIfNeeded()
                        self.selectedRiskItem = self.sortedAndFilteredRisks().first
                        self.appStatusText = "Capture analysis complete"
                        
                        let stdout = stdoutText.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
                        if !stdout.isEmpty {
                            self.appLogText = self.stripThroughputLines(from: stdout)
                            let throughputText = self.extractThroughputText(from: stdout)
                            if !throughputText.isEmpty {
                                self.throughputLogText = throughputText
                            }
                        } else {
                            self.refreshLogTextFromFile()
                            if self.throughputLogText.isEmpty {
                                let throughputText = self.extractThroughputText(from: self.appLogText)
                                if !throughputText.isEmpty {
                                    self.throughputLogText = throughputText
                                }
                            }
                        }
                    } else {
                        let message = (stderrText.isEmpty ? stdoutText : stderrText)
                            .trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
                        self.appStatusText = "Stop & analyze failed (code \(proc.terminationStatus))"
                        self.appLogText = message.isEmpty ? "Unknown stop/analyze error." : message
                    }
                }
            }
            
            do {
                try process.run()
            } catch {
                DispatchQueue.main.async {
                    self.isCapturing = false
                    self.isAnalyzing = false
                    self.stopFakeProgress(success: false)
                    self.stopLogRefreshTimer()
                    self.appStatusText = "Stop capture error: \(error.localizedDescription)"
                    self.appLogText = error.localizedDescription
                }
            }
        }
    }
    
    // MARK: - Log helpers
    
    private func extractThroughputText(from text: String) -> String {
        let lines = text.components(separatedBy: .newlines)
        let filtered = lines.filter {
            $0.localizedCaseInsensitiveContains("rx_bytes_per_second=") ||
            $0.localizedCaseInsensitiveContains("tx_bytes_per_second=") ||
            $0.localizedCaseInsensitiveContains("bytes_per_second=") ||
            $0.localizedCaseInsensitiveContains("KB/s") ||
            $0.localizedCaseInsensitiveContains("MB/s") ||
            $0.localizedCaseInsensitiveContains("B/s")
        }
        return Array(filtered.suffix(120)).joined(separator: "\n")
    }
    
    private func stripThroughputLines(from text: String) -> String {
        let lines = text.components(separatedBy: .newlines)
        let filtered = lines.filter {
            !$0.localizedCaseInsensitiveContains("rx_bytes_per_second=") &&
            !$0.localizedCaseInsensitiveContains("tx_bytes_per_second=") &&
            !$0.localizedCaseInsensitiveContains("bytes_per_second=") &&
            !$0.localizedCaseInsensitiveContains("packets_per_second=")
        }
        return Array(filtered.suffix(300)).joined(separator: "\n")
    }
    
    func exportLog() {
        let panel = NSSavePanel()
        panel.title = "Export Analysis Log"
        panel.nameFieldStringValue = "ane_monitor_log.txt"
        panel.allowedContentTypes = [.plainText]
        panel.canCreateDirectories = true
        
        guard panel.runModal() == .OK, let destinationURL = panel.url else {
            appStatusText = "Log export cancelled"
            return
        }
        
        let sourceURL = URL(fileURLWithPath: logFilePath)
        
        do {
            guard FileManager.default.fileExists(atPath: sourceURL.path) else {
                appStatusText = "No log file found"
                return
            }
            
            if FileManager.default.fileExists(atPath: destinationURL.path) {
                try FileManager.default.removeItem(at: destinationURL)
            }
            try FileManager.default.copyItem(at: sourceURL, to: destinationURL)
            appStatusText = "Log exported"
            appLogText = "Saved log to: \(destinationURL.path)"
        } catch {
            appStatusText = "Export log error: \(error.localizedDescription)"
        }
    }
    
    func chooseAndAnalyzeSavedPCAP() {
        let panel = NSOpenPanel()
        panel.title = "Choose Saved PCAP"
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.allowedContentTypes = [UTType(filenameExtension: "pcap") ?? .data]
        
        guard panel.runModal() == .OK, let selectedURL = panel.url else {
            appStatusText = "Saved PCAP analysis cancelled"
            return
        }
        
        let pcapPath = selectedURL.path
        appStatusText = "Analyzing saved PCAP..."
        isAnalyzing = true
        analysisProgress = 0.05
        startFakeProgress()
        startLogRefreshTimer()
        
        DispatchQueue.global(qos: .userInitiated).async {
            let process = Process()
            let outputPipe = Pipe()
            let errorPipe = Pipe()
            
            process.currentDirectoryURL = URL(fileURLWithPath: self.projectRoot)
            process.executableURL = URL(fileURLWithPath: self.pythonPath)
            process.arguments = [
                self.analysisScriptPath,
                "--input-pcap", pcapPath,
                "--scope", "external_only"
            ]
            process.standardOutput = outputPipe
            process.standardError = errorPipe
            
            do {
                try process.run()
                process.waitUntilExit()
                
                let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
                let errorData = errorPipe.fileHandleForReading.readDataToEndOfFile()
                let stdoutText = String(data: outputData, encoding: .utf8) ?? ""
                let stderrText = String(data: errorData, encoding: .utf8) ?? ""
                
                DispatchQueue.main.async {
                    self.isAnalyzing = false
                    self.stopFakeProgress(success: process.terminationStatus == 0)
                    self.stopLogRefreshTimer()
                    
                    if process.terminationStatus == 0 {
                        self.loadRealtimeResult()
                        self.loadHostSummary()
                        self.loadHistory()
                        self.selectedRiskItem = self.sortedAndFilteredRisks().first
                        self.appStatusText = "Saved PCAP analysis complete"
                        
                        let stdout = stdoutText.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
                        if !stdout.isEmpty {
                            self.appLogText = self.stripThroughputLines(from: stdout)
                            let throughputText = self.extractThroughputText(from: stdout)
                            if !throughputText.isEmpty {
                                self.throughputLogText = throughputText
                            }
                        } else {
                            self.refreshLogTextFromFile()
                        }
                    } else {
                        let message = (stderrText.isEmpty ? stdoutText : stderrText)
                            .trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
                        self.appStatusText = "Analyze saved PCAP failed (code \(process.terminationStatus))"
                        self.appLogText = message
                    }
                }
            } catch {
                DispatchQueue.main.async {
                    self.isAnalyzing = false
                    self.stopFakeProgress(success: false)
                    self.stopLogRefreshTimer()
                    self.appStatusText = "Analyze saved PCAP error: \(error.localizedDescription)"
                }
            }
        }
    }
    
    func choosePCAPSaveLocation() {
        let panel = NSSavePanel()
        panel.title = "Choose PCAP Save Location"
        panel.nameFieldStringValue = URL(fileURLWithPath: selectedPCAPSavePath).lastPathComponent
        panel.allowedContentTypes = [UTType(filenameExtension: "pcap") ?? .data]
        panel.canCreateDirectories = true
        
        guard panel.runModal() == .OK, let destinationURL = panel.url else {
            appStatusText = "PCAP location selection cancelled"
            return
        }
        
        selectedPCAPSavePath = destinationURL.path
        saveSelectedPCAPPath()
        appStatusText = "PCAP save location updated"
    }
    
    func copyLogToClipboard() {
        guard !appLogText.isEmpty else {
            appStatusText = "No log content to copy"
            return
        }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(appLogText, forType: .string)
        appStatusText = "Log copied"
    }
    
    func clearLogView() {
        appLogText = ""
        throughputLogText = ""
        stopLogRefreshTimer()
        appStatusText = "Log cleared from view"
    }
    
    private func startLogRefreshTimer() {
        logRefreshTimer?.invalidate()
        refreshLogTextFromFile()
        logRefreshTimer = Timer.scheduledTimer(withTimeInterval: 0.8, repeats: true) { _ in
            self.refreshLogTextFromFile()
        }
    }
    
    private func stopLogRefreshTimer() {
        logRefreshTimer?.invalidate()
        logRefreshTimer = nil
    }
    
    // 为新一轮抓包清理旧日志与旧分析结果，避免失败时仍显示上一轮曲线和状态。
    private func clearCaptureArtifactsForNewSession() {
        let fileManager = FileManager.default
        let cleanupPaths = [logFilePath, analysisJsonPath]
        
        for path in cleanupPaths {
            if fileManager.fileExists(atPath: path) {
                try? fileManager.removeItem(atPath: path)
            }
        }
    }
    
    private func refreshLogTextFromFile() {
        let url = URL(fileURLWithPath: logFilePath)
        guard FileManager.default.fileExists(atPath: url.path) else { return }
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return }
        
        let trimmed = text.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
        if !trimmed.isEmpty {
            let throughputOnly = self.extractThroughputText(from: trimmed)
            let cleanedLog = self.stripThroughputLines(from: trimmed)
            
            DispatchQueue.main.async {
                self.appLogText = cleanedLog.isEmpty ? "Capture is running. Throughput samples are updating in the chart." : cleanedLog
                if !throughputOnly.isEmpty {
                    self.throughputLogText = throughputOnly
                }
            }
        }
    }
    
    // MARK: - Host summary / history
    
    private func loadHostSummaryOnLaunch() {
        appStatusText = "Loading host Info..."
        
        DispatchQueue.global(qos: .userInitiated).async {
            let process = Process()
            let outputPipe = Pipe()
            let errorPipe = Pipe()
            
            var stdoutBuffer = Data()
            var stderrBuffer = Data()
            
            outputPipe.fileHandleForReading.readabilityHandler = { handle in
                let data = handle.availableData
                if !data.isEmpty {
                    stdoutBuffer.append(data)
                }
            }
            
            errorPipe.fileHandleForReading.readabilityHandler = { handle in
                let data = handle.availableData
                if !data.isEmpty {
                    stderrBuffer.append(data)
                }
            }
            
            process.currentDirectoryURL = URL(fileURLWithPath: self.projectRoot)
            process.executableURL = URL(fileURLWithPath: self.pythonPath)
            process.arguments = [self.hostScriptPath, "--interface", self.selectedInterface]
            process.standardOutput = outputPipe
            process.standardError = errorPipe
            
            process.terminationHandler = { proc in
                outputPipe.fileHandleForReading.readabilityHandler = nil
                errorPipe.fileHandleForReading.readabilityHandler = nil
                
                let remainingOut = outputPipe.fileHandleForReading.readDataToEndOfFile()
                let remainingErr = errorPipe.fileHandleForReading.readDataToEndOfFile()
                if !remainingOut.isEmpty { stdoutBuffer.append(remainingOut) }
                if !remainingErr.isEmpty { stderrBuffer.append(remainingErr) }
                
                let stdoutText = String(data: stdoutBuffer, encoding: .utf8) ?? ""
                let stderrText = String(data: stderrBuffer, encoding: .utf8) ?? ""
                
                DispatchQueue.main.async {
                    if proc.terminationStatus == 0 {
                        self.loadHostSummary()
                        self.appStatusText = "Ready"
                        let text = stdoutText.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
                        if !text.isEmpty {
                            self.appLogText = text
                        }
                    } else {
                        let message = (stderrText.isEmpty ? stdoutText : stderrText)
                            .trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
                        self.appStatusText = "Failed to load host summary (code \(proc.terminationStatus))"
                        self.appLogText = message.isEmpty ? "Unknown host summary error." : message
                    }
                }
            }
            
            do {
                try process.run()
            } catch {
                DispatchQueue.main.async {
                    self.appStatusText = "Host summary error: \(error.localizedDescription)"
                    self.appLogText = error.localizedDescription
                }
            }
        }
    }
    
    func reloadHostSummary() {
        hostSummary = nil
        loadHostSummaryOnLaunch()
    }
    
    private func loadHostSummary() {
        do {
            let url = URL(fileURLWithPath: hostJsonPath)
            let data = try Data(contentsOf: url)
            let decoded = try JSONDecoder().decode(HostSummaryResult.self, from: data)
            hostSummary = decoded
        } catch {
            appStatusText = "Load host summary error: \(error.localizedDescription)"
        }
    }
    
    private func loadRealtimeResult() {
        let url = URL(fileURLWithPath: analysisJsonPath)
        
        guard FileManager.default.fileExists(atPath: url.path) else {
            realtimeResult = nil
            consumerSummary = nil
            selectedRiskItem = nil
            resultText = "No prediction yet."
            detailText = ""
            errorText = ""
            return
        }
        
        do {
            let data = try Data(contentsOf: url)
            
            guard !data.isEmpty else {
                realtimeResult = nil
                consumerSummary = nil
                selectedRiskItem = nil
                resultText = "No prediction yet."
                detailText = ""
                errorText = ""
                return
            }
            
            let decoded = try JSONDecoder().decode(RealtimeResult.self, from: data)
            realtimeResult = decoded
            consumerSummary = parseConsumerSummary(from: data)
            
            let filteredRisks = sortedAndFilteredRisks()
            selectedRiskItem = filteredRisks.first
            errorText = ""
            
            // 优先使用 consumer_summary
            if let summary = consumerSummary {
                resultText = summary.headline.isEmpty ? "Analysis completed." : summary.headline
                
                let nextStepsText: String
                if summary.next_steps.isEmpty {
                    nextStepsText = "Next steps: none"
                } else {
                    nextStepsText = "Next steps:\n- " + summary.next_steps.joined(separator: "\n- ")
                }
                
                detailText =
                """
                Status: \(summary.status)
                Priority: \(summary.priority)
                
                \(summary.summary)
                
                \(nextStepsText)
                """
                return
            }
            
            // 如果没有 consumer_summary，就退回到 top_risks 展示
            if filteredRisks.isEmpty {
                resultText = "Analysis completed."
                detailText = "No significant external risk was detected in this capture."
                return
            }
            
            let topRisk = filteredRisks[0]
            
            resultText = "Analysis completed: \(topRisk.risk_level) risk detected"
            
            detailText =
            """
            Total risks: \(filteredRisks.count)
            
            Top destination IP: \(topRisk.dst_ip)
            Top port: \(topRisk.dst_port)
            Top host: \(topRisk.resolved_host.isEmpty ? "-" : topRisk.resolved_host)
            Service: \(topRisk.service_hint.isEmpty ? "-" : topRisk.service_hint)
            Geo: \(topRisk.geo_label.isEmpty ? "-" : topRisk.geo_label)
            Risk level: \(topRisk.risk_level)
            """
        } catch {
            realtimeResult = nil
            consumerSummary = nil
            selectedRiskItem = nil
            resultText = "No prediction yet."
            detailText = ""
            
            if isCapturing || isAnalyzing {
                errorText = ""
            } else {
                errorText = "Waiting for analysis result..."
            }
        }
    }
    
    private func parseConsumerSummary(from data: Data) -> DetectionMode.ConsumerSummary? {
        guard let raw = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let summary = raw["consumer_summary"] as? [String: Any],
              let status = summary["status"] as? String,
              let priority = summary["priority"] as? String,
              let headline = summary["headline"] as? String,
              let text = summary["summary"] as? String else {
            return nil
        }
        
        let nextSteps = summary["next_steps"] as? [String] ?? []
        return DetectionMode.ConsumerSummary(
            status: status,
            priority: priority,
            headline: headline,
            summary: text,
            next_steps: nextSteps
        )
    }
    
    private func loadHistory() {
        do {
            let url = URL(fileURLWithPath: historyJsonPath)
            guard FileManager.default.fileExists(atPath: historyJsonPath) else {
                historyItems = []
                return
            }
            let data = try Data(contentsOf: url)
            let decoded = try JSONDecoder().decode([DetectionMode.HistoryRecord].self, from: data)
            historyItems = decoded
        } catch {
            historyItems = []
            appStatusText = "Load history error: \(error.localizedDescription)"
        }
    }
    
    func toggleHistorySelection(_ sessionID: String) {
        if selectedHistoryIDs.contains(sessionID) {
            selectedHistoryIDs.remove(sessionID)
        } else {
            selectedHistoryIDs.insert(sessionID)
        }
    }
    
    func deleteHistoryItem(_ item: DetectionMode.HistoryRecord) {
        do {
            try removeHistoryArtifacts(for: item)
            historyItems.removeAll { $0.session_id == item.session_id }
            selectedHistoryIDs.remove(item.session_id)
            try persistHistoryIndex()
            appStatusText = "History item deleted"
        } catch {
            appStatusText = "Delete history error: \(error.localizedDescription)"
            appLogText = error.localizedDescription
        }
    }
    
    func deleteSelectedHistory() {
        guard !selectedHistoryIDs.isEmpty else {
            appStatusText = "No history selected"
            return
        }
        
        let targets = historyItems.filter { selectedHistoryIDs.contains($0.session_id) }
        
        do {
            for item in targets {
                try removeHistoryArtifacts(for: item)
            }
            
            historyItems.removeAll { selectedHistoryIDs.contains($0.session_id) }
            selectedHistoryIDs.removeAll()
            try persistHistoryIndex()
            appStatusText = "Selected history deleted"
        } catch {
            appStatusText = "Batch delete error: \(error.localizedDescription)"
            appLogText = error.localizedDescription
        }
    }
    
    func clearAllHistory() {
        guard !historyItems.isEmpty else {
            appStatusText = "No history to delete"
            return
        }
        
        do {
            for item in historyItems {
                try removeHistoryArtifacts(for: item)
            }
            historyItems = []
            selectedHistoryIDs.removeAll()
            try persistHistoryIndex()
            appStatusText = "All history deleted"
        } catch {
            appStatusText = "Clear history error: \(error.localizedDescription)"
        }
    }
    
    private func persistHistoryIndex() throws {
        let url = URL(fileURLWithPath: historyJsonPath)
        let data = try JSONEncoder().encode(historyItems)
        try data.write(to: url)
    }
    
    private func removeHistoryArtifacts(for item: DetectionMode.HistoryRecord) throws {
        let fm = FileManager.default
        
        if let files = item.files, let anyPath = files.values.first {
            let sessionDir = URL(fileURLWithPath: anyPath).deletingLastPathComponent()
            if fm.fileExists(atPath: sessionDir.path) {
                try fm.removeItem(at: sessionDir)
                return
            }
        }
        
        let fallbackDir = URL(fileURLWithPath: historyDirPath)
            .appendingPathComponent("session_\(item.session_id)")
        
        if fm.fileExists(atPath: fallbackDir.path) {
            try fm.removeItem(at: fallbackDir)
        }
    }
    
    private func persistCapturedPCAPIfNeeded() {
        let sourceURL = URL(fileURLWithPath: capturedPcapSourcePath)
        let destinationURL = URL(fileURLWithPath: selectedPCAPSavePath)
        
        guard FileManager.default.fileExists(atPath: sourceURL.path) else {
            return
        }
        
        do {
            let folderURL = destinationURL.deletingLastPathComponent()
            try FileManager.default.createDirectory(at: folderURL, withIntermediateDirectories: true)
            if FileManager.default.fileExists(atPath: destinationURL.path) {
                try FileManager.default.removeItem(at: destinationURL)
            }
            try FileManager.default.copyItem(at: sourceURL, to: destinationURL)
        } catch {
            appStatusText = "PCAP save error: \(error.localizedDescription)"
        }
    }
    
    private func saveSelectedPCAPPath() {
        UserDefaults.standard.set(selectedPCAPSavePath, forKey: "selectedPCAPSavePath")
    }
    
    private func loadSavedPCAPPath() {
        if let saved = UserDefaults.standard.string(forKey: "selectedPCAPSavePath"), !saved.isEmpty {
            selectedPCAPSavePath = saved
        }
    }
    
    func saveThemeMode() {
        UserDefaults.standard.set(themeMode.rawValue, forKey: "themeMode")
    }
    
    private func loadSavedThemeMode() {
        if let saved = UserDefaults.standard.string(forKey: "themeMode"),
           let mode = ThemeMode(rawValue: saved) {
            themeMode = mode
        }
    }
    
    // MARK: - Whitelist
    
    private var whitelistScriptPath: String {
        URL(fileURLWithPath: projectRoot)
            .appendingPathComponent("src")
            .appendingPathComponent("manage_whitelist.py")
            .path
    }
    
    private func runWhitelistScript(arguments: [String], completion: @escaping (Bool, String) -> Void) {
        DispatchQueue.global(qos: .userInitiated).async {
            let process = Process()
            let outputPipe = Pipe()
            let errorPipe = Pipe()
            
            process.currentDirectoryURL = URL(fileURLWithPath: self.projectRoot)
            process.executableURL = URL(fileURLWithPath: self.pythonPath)
            process.arguments = [self.whitelistScriptPath] + arguments
            process.standardOutput = outputPipe
            process.standardError = errorPipe
            
            do {
                try process.run()
                process.waitUntilExit()
                
                let stdout = String(data: outputPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
                let stderr = String(data: errorPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
                
                DispatchQueue.main.async {
                    if process.terminationStatus == 0 {
                        completion(true, stdout.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines))
                    } else {
                        completion(false, stderr.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines))
                    }
                }
            } catch {
                DispatchQueue.main.async {
                    completion(false, error.localizedDescription)
                }
            }
        }
    }
    
    func refreshWhitelist() {
        runWhitelistScript(arguments: ["--action", "list", "--include-disabled"]) { success, message in
            guard success else {
                self.appStatusText = "Whitelist load failed"
                self.appLogText = message
                return
            }
            
            guard let data = message.data(using: .utf8),
                  let records = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] else {
                self.whitelistRecords = []
                return
            }
            
            self.whitelistRecords = records.map { raw in
                var mapped: [String: String] = [:]
                raw.forEach { key, value in
                    mapped[key] = String(describing: value)
                }
                
                if let resolved = raw["resolved_ips"] as? [String] {
                    mapped["resolved_ips_display"] = resolved.isEmpty
                    ? "unavailable"
                    : resolved.joined(separator: ", ")
                } else {
                    mapped["resolved_ips_display"] = "unavailable"
                }
                
                return mapped
            }
        }
    }

    // 新增白名单前的统一校验入口。
    private func validateWhitelistInput(kind: String, value: String) -> String? {
        let trimmedKind = kind.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines).lowercased()
        let trimmedValue = value.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)

        guard !trimmedValue.isEmpty else {
            return "Whitelist value cannot be empty."
        }

        switch trimmedKind {
        case "host":
            return isValidHost(trimmedValue) ? nil : "Invalid host format. Example: example.com"
        case "ip":
            return isValidIPAddress(trimmedValue) ? nil : "Invalid IP address format."
        case "ip_port":
            return isValidIPPort(trimmedValue) ? nil : "Invalid IP:Port format. Example: 8.8.8.8:443"
        case "cidr":
            if let slashIndex = trimmedValue.firstIndex(of: "/") {
                let ipPart = String(trimmedValue[..<slashIndex])
                let prefixPart = String(trimmedValue[trimmedValue.index(after: slashIndex)...])
                guard isValidIPAddress(ipPart), let prefix = Int(prefixPart), (0...32).contains(prefix) else {
                    return "Invalid CIDR format. Example: 1.2.3.0/24"
                }
                return nil
            }
            return "Invalid CIDR format. Example: 1.2.3.0/24"
        default:
            return "Unsupported whitelist kind: \(trimmedKind)"
        }
    }

    func matchWhitelistIP() {
        let ip = whitelistQueryIP.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
        guard !ip.isEmpty else {
            whitelistQueryError = "Please enter an IP address."
            whitelistQueryResultText = "No IP query yet."
            whitelistQuerySummaryTitle = "No IP query yet."
            whitelistQuerySummarySubtitle = "Enter an IP address to check exact-IP and CIDR matches."
            whitelistQueryExactValue = "-"
            whitelistQueryBestCIDRValue = "-"
            whitelistQueryCategory = "-"
            whitelistQuerySource = "-"
            whitelistQueryCIDRMatchCount = 0
            if whitelistQueryContextText.isEmpty {
                whitelistQueryContextText = "Current query source: manual input"
            }
            return
        }

        guard isValidIPAddress(ip) else {
            whitelistQueryError = "Invalid IP address. Please enter a valid IPv4 or IPv6 address."
            whitelistQueryResultText = "No IP query yet."
            whitelistQuerySummaryTitle = "Invalid IP address"
            whitelistQuerySummarySubtitle = "Please enter a valid IPv4 or IPv6 address."
            whitelistQueryExactValue = "-"
            whitelistQueryBestCIDRValue = "-"
            whitelistQueryCategory = "-"
            whitelistQuerySource = "-"
            whitelistQueryCIDRMatchCount = 0
            return
        }

        whitelistQueryInProgress = true
        whitelistQueryError = ""
        whitelistQueryResultText = "Querying..."
        whitelistQuerySummaryTitle = "Querying..."
        whitelistQuerySummarySubtitle = "Checking exact-IP and CIDR whitelist rules."
        whitelistQueryExactValue = "-"
        whitelistQueryBestCIDRValue = "-"
        whitelistQueryCategory = "-"
        whitelistQuerySource = "-"
        whitelistQueryCIDRMatchCount = 0

        runWhitelistScript(
            arguments: [
                "--action", "match",
                "--query-ip", ip,
                "--include-disabled"
            ]
        ) { [weak self] success, output in
            DispatchQueue.main.async {
                guard let self = self else { return }
                self.whitelistQueryInProgress = false

                if success {
                    self.whitelistQueryResultText = output.isEmpty ? "No result." : output
                    self.applyWhitelistMatchPresentation(from: output, queryIP: ip)
                } else {
                    self.whitelistQueryError = output.isEmpty ? "IP query failed." : output
                    self.whitelistQueryResultText = "No IP query yet."
                    self.whitelistQuerySummaryTitle = "Query failed"
                    self.whitelistQuerySummarySubtitle = self.whitelistQueryError
                    self.whitelistQueryExactValue = "-"
                    self.whitelistQueryBestCIDRValue = "-"
                    self.whitelistQueryCategory = "-"
                    self.whitelistQuerySource = "-"
                    self.whitelistQueryCIDRMatchCount = 0
                }
            }
        }
    }

    private func applyWhitelistMatchPresentation(from output: String, queryIP: String) {
        guard let data = output.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            whitelistQuerySummaryTitle = "IP query completed"
            whitelistQuerySummarySubtitle = "Unable to parse structured result."
            whitelistQueryExactValue = "-"
            whitelistQueryBestCIDRValue = "-"
            whitelistQueryCategory = "-"
            whitelistQuerySource = "-"
            whitelistQueryCIDRMatchCount = 0
            return
        }

        let exact = json["exact_ip_match"] as? [String: Any]
        let bestCIDR = json["best_cidr_match"] as? [String: Any]
        let cidrCount = json["cidr_match_count"] as? Int ?? 0

        whitelistQueryExactValue = (exact?["value"] as? String) ?? "-"
        whitelistQueryBestCIDRValue = (bestCIDR?["value"] as? String) ?? "-"
        whitelistQueryCIDRMatchCount = cidrCount
        whitelistQueryCategory = (exact?["category"] as? String)
            ?? (bestCIDR?["category"] as? String)
            ?? "-"
        whitelistQuerySource = (exact?["source"] as? String)
            ?? (bestCIDR?["source"] as? String)
            ?? "-"

        if let exactValue = exact?["value"] as? String {
            whitelistQuerySummaryTitle = "Exact IP match found"
            whitelistQuerySummarySubtitle = "\(queryIP) exactly matches whitelist entry \(exactValue)."
            return
        }

        if let bestCIDRValue = bestCIDR?["value"] as? String {
            whitelistQuerySummaryTitle = "CIDR match found"
            whitelistQuerySummarySubtitle = "\(queryIP) falls inside whitelist network \(bestCIDRValue)."
            return
        }

        whitelistQuerySummaryTitle = "No whitelist match"
        whitelistQuerySummarySubtitle = "\(queryIP) does not match any exact-IP or CIDR whitelist rule."
    }

    func batchMatchWhitelistIPs() {
        let rawInput = whitelistBatchInput.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
        guard !rawInput.isEmpty else {
            whitelistBatchError = "Please enter at least one IP address."
            whitelistBatchSummaryText = "Paste IPs above and click Batch Match to view the summary."
            whitelistBatchResultText = "[]"
            return
        }

        let ips = rawInput
            .components(separatedBy: CharacterSet.newlines)
            .map { $0.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines) }
            .filter { !$0.isEmpty }

        guard !ips.isEmpty else {
            whitelistBatchError = "Please enter at least one valid line of input."
            whitelistBatchSummaryText = "Paste IPs above and click Batch Match to view the summary."
            whitelistBatchResultText = "[]"
            return
        }

        whitelistBatchInProgress = true
        whitelistBatchError = ""
        whitelistBatchSummaryText = "Querying \(ips.count) IPs..."
        whitelistBatchResultText = "[]"

        let joinedIPs = ips.joined(separator: ",")

        runWhitelistScript(
            arguments: [
                "--action", "batch-match",
                "--ips", joinedIPs,
                "--include-disabled"
            ]
        ) { [weak self] success, output in
            DispatchQueue.main.async {
                guard let self = self else { return }
                self.whitelistBatchInProgress = false

                if success {
                    self.whitelistBatchResultText = output.isEmpty ? "[]" : output
                    self.applyWhitelistBatchPresentation(from: output)
                } else {
                    self.whitelistBatchError = output.isEmpty ? "Batch IP query failed." : output
                    self.whitelistBatchSummaryText = "Batch query failed"
                    self.whitelistBatchResultText = "[]"
                }
            }
        }
    }

    private func applyWhitelistBatchPresentation(from output: String) {
        guard let data = output.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let summary = json["summary"] as? [String: Any] else {
            whitelistBatchSummaryText = "Batch query completed"
            return
        }

        let total = summary["total"] as? Int ?? 0
        let ipv4 = summary["ipv4_count"] as? Int ?? 0
        let ipv6 = summary["ipv6_count"] as? Int ?? 0
        let exact = summary["exact_match_count"] as? Int ?? 0
        let cidr = summary["cidr_match_count"] as? Int ?? 0
        let unmatched = summary["unmatched_count"] as? Int ?? 0
        let errors = summary["error_count"] as? Int ?? 0

        whitelistBatchSummaryText = "Total: \(total) | IPv4: \(ipv4) | IPv6: \(ipv6) | Exact: \(exact) | CIDR: \(cidr) | Unmatched: \(unmatched) | Errors: \(errors)"
    }
    
    // 新增白名单前的统一校验入口。
    
    // 域名校验：不允许 ?, 空格, 单独符号, 非法主机名。
    private func isValidHost(_ value: String) -> Bool {
        if value.count > 253 { return false }
        if value.contains(" ") { return false }
        if value.contains("?") { return false }
        if value.hasPrefix(".") || value.hasSuffix(".") { return false }
        if value.contains("..") { return false }
        
        let pattern = #"^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"#
        return value.range(of: pattern, options: .regularExpression) != nil
    }
    
    // IP 校验：同时支持 IPv4 / IPv6。
    private func isValidIPAddress(_ value: String) -> Bool {
        var ipv4 = in_addr()
        var ipv6 = in6_addr()
        
        let ipv4Result = value.withCString { inet_pton(AF_INET, $0, &ipv4) }
        if ipv4Result == 1 { return true }
        
        let ipv6Result = value.withCString { inet_pton(AF_INET6, $0, &ipv6) }
        return ipv6Result == 1
    }
    
    // IP:Port 校验：当前要求 host 部分必须是 IP。
    private func isValidIPPort(_ value: String) -> Bool {
        let parts = value.split(separator: ":", omittingEmptySubsequences: false)
        guard parts.count == 2 else { return false }
        
        let hostPart = String(parts[0]).trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
        let portPart = String(parts[1]).trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
        
        guard isValidIPAddress(hostPart) else { return false }
        guard let port = Int(portPart), (1...65535).contains(port) else { return false }
        
        return true
    }
    
    // 手动新增白名单：先校验，失败则弹窗，不写数据库。
    func addWhitelistEntry() {
        let trimmedKind = whitelistInputKind.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
        let trimmedValue = whitelistInputValue.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
        
        if let message = validateWhitelistInput(kind: trimmedKind, value: trimmedValue) {
            whitelistValidationMessage = message
            showWhitelistValidationAlert = true
            return
        }
        
        runWhitelistScript(
            arguments: [
                "--action", "add",
                "--kind", trimmedKind,
                "--value", trimmedValue
            ]
        ) { success, message in
            self.appStatusText = success ? "Whitelist entry added" : message
            self.appLogText = message
            
            if success {
                self.whitelistInputValue = ""
                self.whitelistInputNote = ""
                self.refreshWhitelist()
            }
        }
    }
    
    func removeWhitelistEntry(kind: String, value: String) {
        let normalizedKind = kind.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
        let normalizedValue = value.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)

        if let record = whitelistRecords.first(where: {
            ($0["rule_type"] ?? "") == normalizedKind &&
            ($0["value"] ?? "") == normalizedValue
        }) {
            let source = (record["source"] ?? "user").trimmingCharacters(in: CharacterSet.whitespacesAndNewlines).lowercased()
            if source != "user" {
                self.appStatusText = "System entry is locked"
                self.appLogText = "Only user entries can be removed. Current source: \(source)"
                return
            }
        }

        runWhitelistScript(
            arguments: [
                "--action", "remove",
                "--kind", normalizedKind,
                "--value", normalizedValue
            ]
        ) { success, message in
            self.appStatusText = success ? "Whitelist entry removed" : "Whitelist remove failed"
            self.appLogText = message
            if success {
                self.refreshWhitelist()
            }
        }
    }
    
    func updateWhitelistNote(kind: String, value: String, note: String) {
        runWhitelistScript(
            arguments: [
                "--action", "update",
                "--kind", kind,
                "--value", value,
                "--note", note
            ]
        ) { success, message in
            self.appStatusText = success ? "Whitelist entry updated" : "Whitelist update failed"
            self.appLogText = message
            if success {
                self.refreshWhitelist()
            }
        }
    }
    
    func addTrustedIP(_ ip: String) {
        whitelistInputKind = "ip"
        whitelistInputValue = ip
        addWhitelistEntry()
    }
    
    func addTrustedHost(_ host: String) {
        whitelistInputKind = "host"
        whitelistInputValue = host
        addWhitelistEntry()
    }
    
    func addTrustedIPPort(ip: String, port: Int) {
        whitelistInputKind = "ip_port"
        whitelistInputValue = "\(ip):\(port)"
        addWhitelistEntry()
    }
    
    // MARK: - Risk list
    
    func sortedAndFilteredRisks() -> [RiskItem] {
        guard let realtimeResult else { return [] }
        
        let filtered = uniqueTopRisks(realtimeResult.top_risks).filter { item in
            let matchesRiskFilter: Bool
            switch selectedRiskFilter {
            case .all:
                matchesRiskFilter = true
            case .high:
                matchesRiskFilter = item.risk_level.caseInsensitiveCompare("High") == .orderedSame
            case .medium:
                matchesRiskFilter = item.risk_level.caseInsensitiveCompare("Medium") == .orderedSame
            case .low:
                matchesRiskFilter = item.risk_level.caseInsensitiveCompare("Low") == .orderedSame
            }
            
            if !matchesRiskFilter {
                return false
            }
            
            if excludeInternalTraffic {
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
                
                if isInternal {
                    return false
                }
            }
            
            return true
        }
        
        return filtered.sorted { lhs, rhs in
            switch selectedRiskSort {
            case .severity:
                let leftRank = riskRank(lhs.risk_level)
                let rightRank = riskRank(rhs.risk_level)
                if leftRank == rightRank {
                    return lhs.dst_ip < rhs.dst_ip
                }
                return leftRank < rightRank
            case .endpoint:
                if lhs.dst_ip == rhs.dst_ip {
                    return lhs.dst_port < rhs.dst_port
                }
                return lhs.dst_ip < rhs.dst_ip
            case .service:
                if lhs.service_hint == rhs.service_hint {
                    return lhs.dst_ip < rhs.dst_ip
                }
                return lhs.service_hint < rhs.service_hint
            }
        }
    }
    
    func selectRiskItem(_ item: RiskItem) {
        selectedRiskItem = item

        let ip = item.dst_ip.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
        guard !ip.isEmpty else { return }
        guard isValidIPAddress(ip) else { return }

        whitelistQueryIP = ip
        whitelistQueryContextText = "Current query source: selected risk item \(ip)"
        matchWhitelistIP()
    }
    
    private func riskRank(_ level: String) -> Int {
        switch level.lowercased() {
        case "high": return 0
        case "medium": return 1
        default: return 2
        }
    }
    
    private func uniqueTopRisks(_ items: [RiskItem]) -> [RiskItem] {
        var seen: Set<String> = []
        var result: [RiskItem] = []
        
        for item in items {
            let key = [
                item.ip_version,
                item.dst_ip,
                String(item.dst_port),
                item.resolved_host,
                item.service_hint
            ].joined(separator: "|")
            
            if !seen.contains(key) {
                seen.insert(key)
                result.append(item)
            }
        }
        
        return result
    }
    
    // MARK: - Demo cases / model inference
    
    private func loadDemoCases() {
        do {
            guard let url = Bundle.main.url(forResource: "demo_cases", withExtension: "json") else {
                throw NSError(
                    domain: "DemoCases",
                    code: 1,
                    userInfo: [NSLocalizedDescriptionKey: "demo_cases.json not found in app bundle."]
                )
            }
            
            let data = try Data(contentsOf: url)
            let cases = try JSONDecoder().decode([DetectionMode.DemoCase].self, from: data)
            
            demoCases = cases
            selectedCase = cases.first
        } catch {
            errorText = error.localizedDescription
        }
    }
    
    private func runModel(sample: [Double], mode: DetectionMode) throws -> DetectionMode.PredictionResult {
        let config = MLModelConfiguration()
        config.computeUnits = .cpuAndNeuralEngine
        let wrappedModel = try IDSClassifier(configuration: config)
        let model = wrappedModel.model
        
        let inputArray = try MLMultiArray(
            shape: [1, NSNumber(value: sample.count)],
            dataType: .float32
        )
        
        for i in 0..<sample.count {
            inputArray[i] = NSNumber(value: Float(sample[i]))
        }
        
        let inputFeatures = try MLDictionaryFeatureProvider(dictionary: [
            "flow_features": MLFeatureValue(multiArray: inputArray)
        ])
        
        let start = CFAbsoluteTimeGetCurrent()
        let prediction = try model.prediction(from: inputFeatures)
        let end = CFAbsoluteTimeGetCurrent()
        
        guard let outputName = model.modelDescription.outputDescriptionsByName.keys.first,
              let outputValue = prediction.featureValue(for: outputName)?.multiArrayValue else {
            throw NSError(domain: "ModelOutput", code: 2, userInfo: [NSLocalizedDescriptionKey: "Model output not found."])
        }
        
        let logits = multiArrayToDoubleArray(outputValue)
        let probs = softmax(logits)
        
        guard probs.count >= 2 else {
            throw NSError(domain: "ModelOutput", code: 3, userInfo: [NSLocalizedDescriptionKey: "Unexpected output dimension."])
        }
        
        let attackProbability = probs[1]
        let normalProbability = probs[0]
        let predictedLabel = attackProbability >= mode.threshold ? "Attack" : "Normal"
        let latencyMs = (end - start) * 1000.0
        
        return DetectionMode.PredictionResult(
            attackProbability: attackProbability,
            normalProbability: normalProbability,
            predictedLabel: predictedLabel,
            threshold: mode.threshold,
            latencyMs: latencyMs
        )
    }
    
    private func multiArrayToDoubleArray(_ array: MLMultiArray) -> [Double] {
        let count = array.count
        var values: [Double] = []
        values.reserveCapacity(count)
        
        for i in 0..<count {
            values.append(array[i].doubleValue)
        }
        
        return values
    }
    
    private func softmax(_ values: [Double]) -> [Double] {
        guard let maxValue = values.max() else { return values }
        let expValues = values.map { Foundation.exp($0 - maxValue) }
        let sumExp = expValues.reduce(0, +)
        return expValues.map { $0 / sumExp }
    }
    
    // MARK: - Timer helpers
    
    private func startFakeProgress() {
        progressTimer?.invalidate()
        analysisProgress = 0.02
        
        progressTimer = Timer.scheduledTimer(withTimeInterval: 0.08, repeats: true) { _ in
            if self.analysisProgress < 0.9 {
                self.analysisProgress += 0.02
            }
        }
    }
    
    private func startCaptureTimer() {
        captureTimer?.invalidate()
        captureTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { _ in
            self.captureElapsedSeconds += 1
        }
    }
    
    private func stopCaptureTimer() {
        captureTimer?.invalidate()
        captureTimer = nil
    }
    
    private func stopFakeProgress(success: Bool) {
        progressTimer?.invalidate()
        progressTimer = nil
        analysisProgress = success ? 1.0 : 0.0
    }
}
