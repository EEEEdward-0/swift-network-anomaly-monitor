import SwiftUI
import CoreML
import Combine
import Foundation
import AppKit
import UniformTypeIdentifiers

enum DetectionMode: String, CaseIterable, Identifiable {
    case balanced = "Balanced"
    case securityFirst = "Security-first"
    case lowNoise = "Low-noise"
    
    var id: String { rawValue }
    
    var threshold: Double {
        switch self {
        case .balanced: return 0.50
        case .securityFirst: return 0.36
        case .lowNoise: return 0.60
        }
    }
    
    struct DemoCase: Codable, Identifiable, Hashable {
        let name: String
        let index: Int
        let trueLabel: Int
        let attackProbability: Double
        let features: [Double]
        
        enum CodingKeys: String, CodingKey {
            case name
            case index
            case trueLabel = "true_label"
            case attackProbability = "attack_probability"
            case features
        }
        
        var id: String { name }
        
        var displayName: String {
            switch name {
            case "normal_case": return "Normal Case"
            case "borderline_case": return "Borderline Case"
            case "attack_case": return "Attack Case"
            default: return name
            }
        }
        
        var trueLabelText: String {
            trueLabel == 1 ? "Attack" : "Normal"
        }
    }
    
    struct PredictionResult {
        let attackProbability: Double
        let normalProbability: Double
        let predictedLabel: String
        let threshold: Double
        let latencyMs: Double
    }
    
    struct HistoryRecord: Codable, Identifiable {
        let session_id: String
        let started_at: String
        let stopped_at: String
        let interface: String?
        let capture_window_seconds: Int?
        let risk_level_counts: [String: Int]
        let files: [String: String]?
        
        var id: String { session_id }
    }
    
    
    struct ConsumerSummary: Codable {
        let status: String
        let priority: String
        let headline: String
        let summary: String
        let next_steps: [String]
    }
    
    enum RiskFilter: String, CaseIterable, Identifiable {
        case all = "All"
        case high = "High"
        case medium = "Medium"
        case low = "Low"
        
        var id: String { rawValue }
    }
    
    enum RiskSortOption: String, CaseIterable, Identifiable {
        case severity = "Severity"
        case endpoint = "Endpoint"
        case service = "Service"
        
        var id: String { rawValue }
    }
    
    final class InferenceViewModel: ObservableObject {
        @Published var showWhitelistValidationAlert: Bool = false
        @Published var whitelistValidationMessage: String = ""
        @Published var selectedMode: DetectionMode = .balanced
        @Published var demoCases: [DemoCase] = []
        @Published var selectedCase: DemoCase?
        @Published var resultText: String = "No prediction yet."
        @Published var detailText: String = ""
        @Published var errorText: String = ""
        @Published var whitelistRecords: [[String: String]] = []
        @Published var whitelistInputValue: String = ""
        @Published var whitelistInputNote: String = ""
        @Published var whitelistInputKind: String = "host"
        @Published var hostSummary: HostSummaryResult?
        @Published var realtimeResult: RealtimeResult?
        @Published var consumerSummary: ConsumerSummary?
        @Published var appStatusText: String = "Ready"
        @Published var isAnalyzing: Bool = false
        @Published var appLogText: String = ""
        @Published var throughputLogText: String = ""
        
        @Published var selectedInterface: String = "en0"
        @Published var analysisProgress: Double = 0.0
        
        @Published var isCapturing: Bool = false
        @Published var captureElapsedSeconds: Int = 0
        @Published var historyItems: [HistoryRecord] = []
        @Published var selectedHistoryIDs: Set<String> = []
        @Published var selectedPCAPSavePath: String = NSHomeDirectory() + "/Desktop/captured_traffic.pcap"
        @Published var selectedRiskFilter: RiskFilter = .all
        @Published var selectedRiskSort: RiskSortOption = .severity
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
        
        init() {
            loadSavedPCAPPath()
            loadSavedThemeMode()
            loadDemoCases()
            loadHistory()
            loadHostSummaryOnLaunch()
            refreshWhitelist()
        }
        
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
        
        // 启动抓包：先清理上一轮残留状态，只有在启动命令成功后才进入“抓包中”状态。
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
                            let text = stdoutText.trimmingCharacters(in: .whitespacesAndNewlines)
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
                                .trimmingCharacters(in: .whitespacesAndNewlines)
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
                            
                            let stdout = stdoutText.trimmingCharacters(in: .whitespacesAndNewlines)
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
                                .trimmingCharacters(in: .whitespacesAndNewlines)
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
                            
                            let stdout = stdoutText.trimmingCharacters(in: .whitespacesAndNewlines)
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
                                .trimmingCharacters(in: .whitespacesAndNewlines)
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
            
            let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
            if !trimmed.isEmpty {
                let throughputOnly = self.extractThroughputText(from: trimmed)
                let cleanedLog = self.stripThroughputLines(from: trimmed)
                
                DispatchQueue.main.async {
                    self.appLogText = cleanedLog.isEmpty ? "Capture is running. Throughput samples are updating in the chart." : cleanedLog
                    if self.isCapturing {
                        self.throughputLogText = throughputOnly
                    } else if throughputOnly.isEmpty {
                        self.throughputLogText = ""
                    }
                }
            }
        }
        
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
                            let text = stdoutText.trimmingCharacters(in: .whitespacesAndNewlines)
                            if !text.isEmpty {
                                self.appLogText = text
                            }
                        } else {
                            let message = (stderrText.isEmpty ? stdoutText : stderrText)
                                .trimmingCharacters(in: .whitespacesAndNewlines)
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
            do {
                let url = URL(fileURLWithPath: analysisJsonPath)
                let data = try Data(contentsOf: url)
                let decoded = try JSONDecoder().decode(RealtimeResult.self, from: data)
                realtimeResult = decoded
                consumerSummary = parseConsumerSummary(from: data)
                selectedRiskItem = sortedAndFilteredRisks().first
            } catch {
                appStatusText = "Load analysis error: \(error.localizedDescription)"
            }
        }
        private func parseConsumerSummary(from data: Data) -> ConsumerSummary? {
            guard let raw = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let summary = raw["consumer_summary"] as? [String: Any],
                  let status = summary["status"] as? String,
                  let priority = summary["priority"] as? String,
                  let headline = summary["headline"] as? String,
                  let text = summary["summary"] as? String else {
                return nil
            }
            
            let nextSteps = summary["next_steps"] as? [String] ?? []
            return ConsumerSummary(
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
                let decoded = try JSONDecoder().decode([HistoryRecord].self, from: data)
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
        
        func deleteHistoryItem(_ item: HistoryRecord) {
            do {
                try removeHistoryArtifacts(for: item)
                historyItems.removeAll { $0.session_id == item.session_id }
                selectedHistoryIDs.remove(item.session_id)
                try persistHistoryIndex()
                appStatusText = "History item deleted"
            } catch {
                appStatusText = "Delete history error: \(error.localizedDescription)"
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
        
        private func removeHistoryArtifacts(for item: HistoryRecord) throws {
            let fm = FileManager.default
            
            if let files = item.files, let anyPath = files.values.first {
                let sessionDir = URL(fileURLWithPath: anyPath).deletingLastPathComponent()
                if fm.fileExists(atPath: sessionDir.path) {
                    try fm.removeItem(at: sessionDir)
                    return
                }
            }
            
            let fallbackDir = URL(fileURLWithPath: historyDirPath).appendingPathComponent("session_\(item.session_id)")
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
        
        // 白名单脚本路径，所有增删改查都通过 Python 脚本完成，Swift 不直接写数据库。
        private var whitelistScriptPath: String {
            URL(fileURLWithPath: projectRoot)
                .appendingPathComponent("src")
                .appendingPathComponent("manage_whitelist.py")
                .path
        }
        
        // 统一调用白名单脚本。
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
                            completion(true, stdout.trimmingCharacters(in: .whitespacesAndNewlines))
                        } else {
                            completion(false, stderr.trimmingCharacters(in: .whitespacesAndNewlines))
                        }
                    }
                } catch {
                    DispatchQueue.main.async {
                        completion(false, error.localizedDescription)
                    }
                }
            }
        }
        
        // 刷新白名单列表，用于前端展示当前规则。
        func refreshWhitelist() {
            runWhitelistScript(arguments: ["--action", "list", "--include-disabled"]) { success, message in
                guard success else {
                    self.appStatusText = "Whitelist load failed"
                    self.appLogText = message
                    return
                }
                
                guard let data = message.data(using: .utf8),
                      let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                      let records = json["records"] as? [[String: Any]] else {
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
        
        // 手动新增白名单。
        func addWhitelistEntry() {
            let value = whitelistInputValue.trimmingCharacters(in: .whitespacesAndNewlines)
            
            guard !value.isEmpty else {
                appStatusText = "Whitelist value cannot be empty."
                return
            }
            
            runWhitelistScript(
                arguments: [
                    "--action", "add",
                    "--kind", whitelistInputKind,
                    "--value", value
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
        
        // 删除白名单。
        func removeWhitelistEntry(kind: String, value: String) {
            runWhitelistScript(
                arguments: [
                    "--action", "remove",
                    "--kind", kind,
                    "--value", value
                ]
            ) { success, message in
                self.appStatusText = success ? "Whitelist entry removed" : "Whitelist remove failed"
                self.appLogText = message
                if success {
                    self.refreshWhitelist()
                }
            }
        }
        
        // 更新单条规则备注。
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
        
        // 风险详情里的快捷加白名单按钮仍然保留，但底层改为调用 SQLite 脚本。
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
                let cases = try JSONDecoder().decode([DemoCase].self, from: data)
                
                demoCases = cases
                selectedCase = cases.first
            } catch {
                errorText = error.localizedDescription
            }
        }
        
        private func runModel(sample: [Double], mode: DetectionMode) throws -> PredictionResult {
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
            
            return PredictionResult(
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
    
    enum ThemeMode: String, CaseIterable, Identifiable, Codable {
        case light = "Light"
        case dark = "Dark"
        case system = "System"
        
        var id: String { rawValue }
        
        var colorScheme: ColorScheme? {
            switch self {
            case .light:
                return .light
            case .dark:
                return .dark
            case .system:
                return nil
            }
        }
    }
    
    struct ContentView: View {
        @StateObject private var viewModel = InferenceViewModel()
        @State private var isLogExpanded: Bool = false
        @State private var viewportWidth: CGFloat = 1400
        @State private var showTCPPortsPopover: Bool = false
        @State private var showUDPPortsPopover: Bool = false
        @State private var isHostInfoExpanded: Bool = true
        @State private var isPublicNetworkExpanded: Bool = false
        @State private var portOwnerCache: [String: PortOwnerSummary] = [:]
        @State private var isInspectingPortOwner: Bool = false
        @State private var inspectedPortTransport: String = "TCP"
        @State private var inspectedPortNumber: Int = 0
        @State private var inspectedPortPID: String = "-"
        @State private var inspectedPortProcessName: String = "-"
        @State private var inspectedPortStatusText: String = "Select a port to inspect."
        @State private var inspectedPortRawCommand: String = ""
        @State private var loadingDotsPhase: Int = 0
        @State private var loadingDotsTimer: Timer? = nil
        @Environment(\.colorScheme) private var systemColorScheme
        
        private var isLightTheme: Bool {
            switch viewModel.themeMode {
            case .light:
                return true
            case .dark:
                return false
            case .system:
                return systemColorScheme == .light
            }
        }
        
        private var pageBackground: LinearGradient {
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
        
        private var surfacePrimary: Color {
            isLightTheme
            ? Color(red: 0.98, green: 0.99, blue: 1.00)
            : Color(red: 0.14, green: 0.16, blue: 0.22)
        }
        
        private var surfaceSecondary: Color {
            isLightTheme
            ? Color(red: 0.94, green: 0.96, blue: 0.99)
            : Color(red: 0.17, green: 0.19, blue: 0.26)
        }
        
        private var borderSoft: Color {
            isLightTheme ? Color.black.opacity(0.08) : Color.white.opacity(0.08)
        }
        
        private var mutedText: Color {
            isLightTheme ? Color.black.opacity(0.60) : Color.white.opacity(0.68)
        }
        
        private var primaryText: Color {
            isLightTheme ? Color.black.opacity(0.88) : .white
        }
        
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
                }
                .onChange(of: proxy.size.width) { _, newValue in
                    viewportWidth = newValue
                }
            }
            .frame(minWidth: 920, minHeight: 700)
            .preferredColorScheme(viewModel.themeMode.colorScheme)
        }
        
        // 白名单管理面板：支持手动新增、查看、删除和修改备注。
        private var whitelistManagerSection: some View {
            GroupBox {
                VStack(alignment: .leading, spacing: 12) {
                    // 顶部标题行：标题在左，刷新按钮在右。
                    HStack(alignment: .center, spacing: 12) {
                        sectionTitle("Whitelist Manager", systemImage: "checkmark.shield")
                        
                        Spacer(minLength: 16)
                        
                        Button("Refresh") {
                            viewModel.refreshWhitelist()
                        }
                        .frame(width: 132, height: 34)
                        .buttonStyle(SecondaryAnimatedButtonStyle())
                    }
                    
                    // 输入行：类型、值、备注、添加按钮。
                    HStack(alignment: .center, spacing: 10) {
                        Picker("Type", selection: $viewModel.whitelistInputKind) {
                            Text("Host").tag("host")
                            Text("IP").tag("ip")
                            Text("IP:Port").tag("ip_port")
                        }
                        .frame(width: 120)
                        
                        TextField("Value", text: $viewModel.whitelistInputValue)
                            .textFieldStyle(.roundedBorder)
                        
                        TextField("Note", text: $viewModel.whitelistInputNote)
                            .textFieldStyle(.roundedBorder)
                        
                        Button("Add") {
                            viewModel.addWhitelistEntry()
                        }
                        .frame(width: 112, height: 34)
                        .buttonStyle(PrimaryAnimatedButtonStyle())
                    }
                    
                    // 列表区域：空状态或规则列表。
                    if viewModel.whitelistRecords.isEmpty {
                        Text("No whitelist rules yet.")
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
            .groupBoxStyle(CleanGroupBoxStyle(fill: surfacePrimary, stroke: borderSoft))
        }
            
            @ViewBuilder
            private func whitelistRow(_ item: [String: String]) -> some View {
                HStack(alignment: .center, spacing: 12) {
                    Text(item["rule_type"] ?? "-")
                        .frame(width: 80, alignment: .leading)
                        .foregroundStyle(mutedText)
                    
                    VStack(alignment: .leading, spacing: 4) {
                        Text(item["value"] ?? "-")
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .foregroundStyle(primaryText)
                            .textSelection(.enabled)
                        
                        if (item["rule_type"] ?? "") == "host" {
                            Text("Resolved IP: \(item["resolved_ips_display"] ?? "unavailable")")
                                .font(.system(size: 12, weight: .regular))
                                .foregroundStyle(mutedText)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .textSelection(.enabled)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    
                    TextField(
                        "Note",
                        text: Binding(
                            get: { item["note"] ?? "" },
                            set: { newValue in
                                let kind = item["rule_type"] ?? ""
                                let value = item["value"] ?? ""
                                viewModel.updateWhitelistNote(kind: kind, value: value, note: newValue)
                            }
                        )
                    )
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 220)
                    
                    Text(item["source"] ?? "-")
                        .frame(width: 70, alignment: .leading)
                        .foregroundStyle(mutedText)
                    
                    Button("Delete") {
                        let kind = item["rule_type"] ?? ""
                        let value = item["value"] ?? ""
                        viewModel.removeWhitelistEntry(kind: kind, value: value)
                    }
                    .frame(width: 118, height: 34, alignment: .center)
                    .buttonStyle(DangerAnimatedButtonStyle())
                }
                .padding(10)
                .background(surfaceSecondary)
                .overlay(
                    RoundedRectangle(cornerRadius: 12)
                        .stroke(borderSoft, lineWidth: 1)
                )
                .clipShape(RoundedRectangle(cornerRadius: 12))
            }
            
            private var headerSection: some View {
                HStack(alignment: .center, spacing: 12) {
                    Image(systemName: "shield.lefthalf.filled.badge.checkmark")
                        .font(.system(size: 22, weight: .semibold))
                        .foregroundStyle(Color(red: 0.34, green: 0.62, blue: 1.0))
                        .frame(width: 46, height: 46)
                        .background(
                            RoundedRectangle(cornerRadius: 14)
                                .fill(Color.blue.opacity(0.14))
                        )
                    
                    VStack(alignment: .leading, spacing: 4) {
                        Text("ANE Threat Monitor")
                            .font(.system(size: 28, weight: .bold))
                            .foregroundStyle(primaryText)
                        
                        Text("On-device network anomaly detection")
                            .font(.system(size: 13, weight: .regular))
                            .foregroundStyle(mutedText)
                    }
                    
                    Spacer()
                    
                    themeModePicker
                }
                .padding(.horizontal, 4)
            }
            
            @ViewBuilder
            private var themeModePicker: some View {
                HStack(spacing: 0) {
                    ForEach(ThemeMode.allCases) { mode in
                        Button {
                            viewModel.themeMode = mode
                            viewModel.saveThemeMode()
                        } label: {
                            Text(mode.rawValue)
                                .font(.system(size: 13, weight: .semibold))
                                .foregroundStyle(viewModel.themeMode == mode ? Color.white : Color.blue)
                                .frame(width: 72, height: 34)
                                .background(viewModel.themeMode == mode ? Color.blue : Color.clear)
                        }
                        .buttonStyle(.plain)
                        
                        if mode != ThemeMode.allCases.last {
                            Rectangle()
                                .fill(Color.blue.opacity(0.35))
                                .frame(width: 1, height: 34)
                        }
                    }
                }
                .background(
                    RoundedRectangle(cornerRadius: 10)
                        .fill(isLightTheme ? Color.white.opacity(0.90) : Color.white.opacity(0.06))
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 10)
                        .stroke(Color.blue.opacity(0.65), lineWidth: 1)
                )
                .clipShape(RoundedRectangle(cornerRadius: 10))
            }
            
            private var captureSettingsSection: some View {
                GroupBox {
                    VStack(alignment: .leading, spacing: 14) {
                        sectionTitle("Capture Settings", systemImage: "slider.horizontal.3")
                        
                        VStack(alignment: .leading, spacing: 14) {
                            HStack(alignment: .top, spacing: 12) {
                                VStack(alignment: .leading, spacing: 8) {
                                    Text("Network Interface")
                                        .font(.caption)
                                        .foregroundStyle(mutedText)
                                    
                                    Picker("Network Interface", selection: $viewModel.selectedInterface) {
                                        ForEach(viewModel.interfaceOptions, id: \.self) { item in
                                            Text(item).tag(item)
                                        }
                                    }
                                    .pickerStyle(.menu)
                                    .frame(width: 180)
                                    .onChange(of: viewModel.selectedInterface) { _, _ in
                                        viewModel.reloadHostSummary()
                                    }
                                }
                                .padding(12)
                                .frame(width: 220, alignment: .leading)
                                .background(surfaceSecondary)
                                .overlay(
                                    RoundedRectangle(cornerRadius: 12)
                                        .stroke(borderSoft, lineWidth: 1)
                                )
                                .clipShape(RoundedRectangle(cornerRadius: 12))
                                
                                VStack(alignment: .leading, spacing: 8) {
                                    Text("Capture Timer")
                                        .font(.caption)
                                        .foregroundStyle(mutedText)
                                    
                                    Text(formatElapsed(viewModel.captureElapsedSeconds))
                                        .font(.system(size: 20, weight: .bold, design: .monospaced))
                                    .foregroundStyle(viewModel.isCapturing ? Color(red: 1.0, green: 0.42, blue: 0.42) : primaryText)                        }
                                .padding(12)
                                .frame(width: 180, alignment: .leading)
                                .background(surfaceSecondary)
                                .overlay(
                                    RoundedRectangle(cornerRadius: 12)
                                        .stroke(borderSoft, lineWidth: 1)
                                )
                                .clipShape(RoundedRectangle(cornerRadius: 12))
                                
                                Spacer(minLength: 0)
                            }
                            
                            LazyVGrid(
                                columns: [
                                    GridItem(.adaptive(minimum: 170, maximum: 240), spacing: 10)
                                ],
                                alignment: .leading,
                                spacing: 10
                            ) {
                                Button("Choose PCAP Location") {
                                    viewModel.choosePCAPSaveLocation()
                                }
                                .buttonStyle(SecondaryAnimatedButtonStyle())
                                .frame(height: 44)
                                
                                Button("Refresh Host Info") {
                                    viewModel.reloadHostSummary()
                                }
                                .buttonStyle(SecondaryAnimatedButtonStyle())
                                .frame(height: 44)
                                
                                Button("Export Log") {
                                    viewModel.exportLog()
                                }
                                .buttonStyle(SecondaryAnimatedButtonStyle())
                                .frame(height: 44)
                                
                                Button("Analyze Saved PCAP") {
                                    viewModel.chooseAndAnalyzeSavedPCAP()
                                }
                                .buttonStyle(SecondaryAnimatedButtonStyle())
                                .frame(height: 44)
                            }
                            
                            Text(viewModel.selectedPCAPSavePath)
                                .font(.caption2)
                                .foregroundStyle(mutedText)
                                .lineLimit(2)
                                .textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        
                        HStack(spacing: 10) {
                            Button(viewModel.isCapturing ? "Capturing..." : "Start Capture") {
                                viewModel.startCapture()
                            }
                            .buttonStyle(PrimaryAnimatedButtonStyle())
                            .frame(maxWidth: .infinity, minHeight: 44)
                            .disabled(viewModel.isCapturing || viewModel.isAnalyzing)
                            
                            Button("Stop & Analyze") {
                                viewModel.stopCaptureAndAnalyze()
                            }
                            .buttonStyle(SecondaryAnimatedButtonStyle())
                            .frame(maxWidth: .infinity, minHeight: 44)
                            .disabled(!viewModel.isCapturing)
                        }
                        
                        HStack {
                            if viewModel.isCapturing || viewModel.isAnalyzing {
                                VStack(alignment: .leading, spacing: 8) {
                                    ProgressView(value: viewModel.analysisProgress)
                                        .progressViewStyle(.linear)
                                        .tint(.blue)
                                    
                                    Text(viewModel.isCapturing ? "Capture in progress..." : "Analyzing captured traffic...")
                                        .font(.caption)
                                        .foregroundStyle(mutedText)
                                }
                                .frame(maxWidth: .infinity, alignment: .leading)
                            } else {
                                Spacer(minLength: 0)
                            }
                            
                            Text(viewModel.appStatusText)
                                .font(.caption.weight(.medium))
                                .foregroundStyle(primaryText.opacity(0.88))
                                .padding(.horizontal, 12)
                                .padding(.vertical, 8)
                                .background(surfaceSecondary)
                                .overlay(
                                    Capsule()
                                        .stroke(borderSoft, lineWidth: 1)
                                )
                                .clipShape(Capsule())
                        }
                        
                        captureThroughputPanel
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .groupBoxStyle(CleanGroupBoxStyle(fill: surfacePrimary, stroke: borderSoft))
            }
            
            @ViewBuilder
            private var analysisLogSection: some View {
                if !viewModel.appLogText.isEmpty {
                    DisclosureGroup(isExpanded: $isLogExpanded) {
                        GroupBox {
                            VStack(alignment: .leading, spacing: 10) {
                                HStack {
                                    Spacer()
                                    Button("Copy") {
                                        viewModel.copyLogToClipboard()
                                    }
                                    .buttonStyle(SecondaryAnimatedButtonStyle())
                                    
                                    Button("Clear") {
                                        viewModel.clearLogView()
                                    }
                                    .buttonStyle(SecondaryAnimatedButtonStyle())
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
                                .frame(minHeight: 90, maxHeight: 140)
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        .groupBoxStyle(CleanGroupBoxStyle(fill: surfacePrimary, stroke: borderSoft))
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
            
            private var hostSummarySection: some View {
                Group {
                    if let hostSummary = viewModel.hostSummary {
                        if viewportWidth < 1180 {
                            VStack(alignment: .leading, spacing: 12) {
                                hostInfoPanel(hostSummary, isExpanded: $isHostInfoExpanded)
                                networkInfoPanel(hostSummary, isExpanded: $isPublicNetworkExpanded)
                            }
                        } else {
                            HStack(alignment: .top, spacing: 12) {
                                hostInfoPanel(hostSummary, isExpanded: $isHostInfoExpanded)
                                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                                
                                networkInfoPanel(hostSummary, isExpanded: $isPublicNetworkExpanded)
                                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                            }
                            .fixedSize(horizontal: false, vertical: true)
                        }
                    } else {
                        GroupBox {
                            HStack(spacing: 10) {
                                Text("Loading host summary")
                                    .foregroundStyle(mutedText)
                                
                                macOSLoadingDots(phase: loadingDotsPhase)
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .onAppear {
                                if loadingDotsTimer == nil {
                                    loadingDotsPhase = 0
                                    loadingDotsTimer = Timer.scheduledTimer(withTimeInterval: 0.28, repeats: true) { timer in
                                        if viewModel.hostSummary != nil {
                                            timer.invalidate()
                                            loadingDotsTimer = nil
                                            loadingDotsPhase = 0
                                        } else {
                                            loadingDotsPhase = (loadingDotsPhase + 1) % 3
                                        }
                                    }
                                }
                            }
                            .onDisappear {
                                loadingDotsTimer?.invalidate()
                                loadingDotsTimer = nil
                                loadingDotsPhase = 0
                            }
                        }
                        .groupBoxStyle(CleanGroupBoxStyle(fill: surfacePrimary, stroke: borderSoft))
                    }
                }
            }
            
            @ViewBuilder
            private func hostInfoPanel(_ hostSummary: HostSummaryResult, isExpanded: Binding<Bool>) -> some View {
                VStack(alignment: .leading, spacing: 0) {
                    Button {
                        withAnimation(.easeInOut(duration: 0.22)) {
                            isExpanded.wrappedValue.toggle()
                        }
                    } label: {
                        HStack(spacing: 10) {
                            ZStack {
                                RoundedRectangle(cornerRadius: 12)
                                    .fill(Color.blue.opacity(0.14))
                                    .frame(width: 46, height: 46)
                                Image(systemName: "desktopcomputer")
                                    .font(.system(size: 20, weight: .semibold))
                                    .foregroundStyle(Color(red: 0.18, green: 0.56, blue: 1.0))
                            }
                            
                            VStack(alignment: .leading, spacing: 3) {
                                Text("Host Information")
                                    .font(.system(size: 16, weight: .semibold))
                                    .foregroundStyle(primaryText)
                                Text("Local device and system network")
                                    .font(.system(size: 12, weight: .regular))
                                    .foregroundStyle(mutedText)
                            }
                            
                            Spacer()
                            
                            Image(systemName: isExpanded.wrappedValue ? "chevron.up" : "chevron.down")
                                .font(.system(size: 13, weight: .semibold))
                                .foregroundStyle(mutedText)
                        }
                        .contentShape(Rectangle())
                        .padding(.horizontal, 16)
                        .padding(.vertical, 14)
                    }
                    .buttonStyle(.plain)
                    
                    if isExpanded.wrappedValue {
                        Divider().overlay(borderSoft)
                        VStack(spacing: 0) {
                            infoRow("Interface", hostSummary.interface)
                            dividerLine
                            infoRow("Local IPv4", hostSummary.local_ip)
                            dividerLine
                            infoRow("Local IPv6", hostSummary.local_ipv6)
                            dividerLine
                            portInfoRow(
                                title: "Open TCP Ports",
                                transport: "TCP",
                                ports: hostSummary.open_tcp_ports,
                                isPresented: $showTCPPortsPopover
                            )
                            dividerLine
                            portInfoRow(
                                title: "Open UDP Ports",
                                transport: "UDP",
                                ports: hostSummary.open_udp_ports,
                                isPresented: $showUDPPortsPopover
                            )
                        }
                        .padding(.horizontal, 16)
                        .padding(.vertical, 8)
                        .transition(.move(edge: .top))
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                .background(
                    RoundedRectangle(cornerRadius: 18)
                        .fill(surfacePrimary)
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 18)
                        .stroke(borderSoft, lineWidth: 1)
                )
                .shadow(color: Color.black.opacity(0.18), radius: 18, x: 0, y: 10)
            }
            
            @ViewBuilder
            
            private func networkInfoPanel(_ hostSummary: HostSummaryResult, isExpanded: Binding<Bool>) -> some View {
                VStack(alignment: .leading, spacing: 0) {
                    Button {
                        withAnimation(.easeInOut(duration: 0.22)) {
                            isExpanded.wrappedValue.toggle()
                        }
                    } label: {
                        HStack(spacing: 10) {
                            ZStack {
                                RoundedRectangle(cornerRadius: 12)
                                    .fill(Color.green.opacity(0.14))
                                    .frame(width: 46, height: 46)
                                Image(systemName: "location.viewfinder")
                                    .font(.system(size: 20, weight: .semibold))
                                    .foregroundStyle(Color(red: 0.25, green: 0.92, blue: 0.42))
                            }
                            
                            VStack(alignment: .leading, spacing: 3) {
                                Text("Public Network")
                                    .font(.system(size: 16, weight: .semibold))
                                    .foregroundStyle(primaryText)
                                Text("External IP and geolocation")
                                    .font(.system(size: 12, weight: .regular))
                                    .foregroundStyle(mutedText)
                            }
                            
                            Spacer()
                            
                            Image(systemName: isExpanded.wrappedValue ? "chevron.up" : "chevron.down")
                                .font(.system(size: 13, weight: .semibold))
                                .foregroundStyle(mutedText)
                        }
                        .contentShape(Rectangle())
                        .padding(.horizontal, 16)
                        .padding(.vertical, 14)
                    }
                    .buttonStyle(.plain)
                    
                    if isExpanded.wrappedValue {
                        Divider().overlay(borderSoft)
                        VStack(spacing: 0) {
                            infoRow("Public IPv4", hostSummary.public_ip)
                            dividerLine
                            infoRow("Public IPv6", hostSummary.public_ipv6)
                            dividerLine
                            infoRow("IPv4 Location", hostSummary.public_ip_location)
                            dividerLine
                            infoRow("IPv6 Location", hostSummary.public_ipv6_location)
                        }
                        .padding(.horizontal, 16)
                        .padding(.vertical, 8)
                        .transition(.move(edge: .top))
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                .background(
                    RoundedRectangle(cornerRadius: 18)
                        .fill(surfacePrimary)
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 18)
                        .stroke(borderSoft, lineWidth: 1)
                )
                .shadow(color: Color.black.opacity(0.18), radius: 18, x: 0, y: 10)
            }
            
            @ViewBuilder
            private func infoRow(_ title: String, _ value: String) -> some View {
                HStack(alignment: .firstTextBaseline, spacing: 14) {
                    Text(title)
                        .font(.system(size: 14, weight: .regular))
                        .foregroundStyle(mutedText)
                        .frame(width: 120, alignment: .leading)
                    
                    Text(value.isEmpty || value == "unknown" ? "-" : value)
                        .font(.system(size: 14, weight: .medium))
                        .foregroundStyle(primaryText)                .textSelection(.enabled)
                        .multilineTextAlignment(.leading)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.vertical, 11)
            }
            
            @ViewBuilder
            private func portInfoRow(title: String, transport: String, ports: [Int], isPresented: Binding<Bool>) -> some View {
                let sorted = ports.sorted()
                let countText = sorted.isEmpty ? "None" : "Count: \(sorted.count) ports"
                let previewPorts = Array(sorted.prefix(5))
                let remainingCount = max(sorted.count - previewPorts.count, 0)
                let needsFullList = sorted.count > 5
                let categorized = categorizedPorts(for: sorted, transport: transport)
                
                HStack(alignment: .top, spacing: 14) {
                    Text(title)
                        .font(.system(size: 14, weight: .regular))
                        .foregroundStyle(mutedText)
                        .frame(width: 120, alignment: .leading)
                    
                    VStack(alignment: .leading, spacing: 6) {
                        Text(countText)
                            .font(.system(size: 14, weight: .semibold))
                            .foregroundStyle(primaryText)
                        if !sorted.isEmpty {
                            Text(categorySummaryText(for: sorted, transport: transport))
                                .font(.system(size: 12, weight: .regular))
                                .foregroundStyle(mutedText)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        
                        if sorted.isEmpty {
                            Text("No open ports detected")
                                .font(.system(size: 13, weight: .regular))
                                .foregroundStyle(mutedText)
                        } else {
                            LazyVGrid(
                                columns: [GridItem(.adaptive(minimum: 62), spacing: 8)],
                                alignment: .leading,
                                spacing: 8
                            ) {
                                ForEach(previewPorts, id: \.self) { port in
                                    portChip(port, transport: transport)
                                }
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                            
                            if remainingCount > 0 {
                                Text("More: \(remainingCount) ports")
                                    .font(.system(size: 12, weight: .regular))
                                    .foregroundStyle(mutedText)
                            }
                        }
                        
                        if needsFullList {
                            Button("Show all ports") {
                                isPresented.wrappedValue = true
                            }
                            .buttonStyle(.plain)
                            .font(.system(size: 12, weight: .semibold))
                            .foregroundStyle(Color.blue)
                            .popover(isPresented: isPresented) {
                                VStack(alignment: .leading, spacing: 12) {
                                    HStack(alignment: .center) {
                                        VStack(alignment: .leading, spacing: 4) {
                                            Text(title)
                                                .font(.system(size: 17, weight: .semibold))
                                                .foregroundStyle(primaryText)
                                            
                                            Text("All detected ports: \(sorted.count)")
                                                .font(.system(size: 12, weight: .regular))
                                                .foregroundStyle(mutedText)
                                        }
                                        
                                        Spacer()
                                    }
                                    
                                    ScrollView {
                                        VStack(alignment: .leading, spacing: 12) {
                                            ForEach(categorized) { section in
                                                VStack(alignment: .leading, spacing: 8) {
                                                    Text("\(section.title): \(section.items.count) ports")
                                                        .font(.system(size: 13, weight: .semibold))
                                                        .foregroundStyle(primaryText)
                                                    
                                                    LazyVGrid(
                                                        columns: [GridItem(.adaptive(minimum: 70), spacing: 8)],
                                                        alignment: .leading,
                                                        spacing: 8
                                                    ) {
                                                        ForEach(section.items) { item in
                                                            portChip(item.port, transport: transport)
                                                        }
                                                    }
                                                    .frame(maxWidth: .infinity, alignment: .leading)
                                                }
                                                .padding(12)
                                                .background(surfaceSecondary)
                                                .overlay(
                                                    RoundedRectangle(cornerRadius: 12)
                                                        .stroke(borderSoft, lineWidth: 1)
                                                )
                                                .clipShape(RoundedRectangle(cornerRadius: 12))
                                            }
                                        }
                                    }
                                    .frame(width: 360, height: 220)
                                }
                                .padding(16)
                                .frame(width: 392)
                                .background(surfacePrimary)
                            }
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .onAppear {
                        resolvePortOwners(for: sorted, transport: transport)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.vertical, 11)
            }
            
            @ViewBuilder
            private func portChip(_ port: Int, transport: String) -> some View {
                Button {
                    inspectPortOwner(port: port, transport: transport)
                } label: {
                    Text(String(port))
                        .font(.system(size: 12, weight: .semibold, design: .monospaced))
                        .foregroundStyle(primaryText)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 7)
                        .frame(minWidth: 58)
                        .background(Color.blue.opacity(0.10))
                        .overlay(
                            Capsule()
                                .stroke(Color.blue.opacity(0.22), lineWidth: 1)
                        )
                        .clipShape(Capsule())
                }
                .buttonStyle(.plain)
                .help("Inspect process using port \(port)")
            }
            
            private func inspectPortOwner(port: Int, transport: String) {
                inspectedPortTransport = transport.uppercased()
                inspectedPortNumber = port
                inspectedPortPID = "-"
                inspectedPortProcessName = "-"
                inspectedPortStatusText = "Inspecting port owner..."
                inspectedPortRawCommand = "-"
                isInspectingPortOwner = true
                
                PortInspectorWindowController.shared.update(
                    data: PortInspectorData(
                        transport: inspectedPortTransport,
                        port: inspectedPortNumber,
                        pid: "-",
                        processName: "-",
                        statusText: "Inspecting port owner...",
                        commandText: "-",
                        isInspecting: true
                    )
                )
                
                DispatchQueue.global(qos: .userInitiated).async {
                    let process = Process()
                    let outputPipe = Pipe()
                    let errorPipe = Pipe()
                    
                    process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
                    if transport.uppercased() == "TCP" {
                        process.arguments = ["lsof", "-nP", "-iTCP:\(port)", "-sTCP:LISTEN"]
                    } else {
                        process.arguments = ["lsof", "-nP", "-iUDP:\(port)"]
                    }
                    process.standardOutput = outputPipe
                    process.standardError = errorPipe
                    
                    do {
                        try process.run()
                        process.waitUntilExit()
                        
                        let stdout = String(decoding: outputPipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
                        let stderr = String(decoding: errorPipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
                        let commandText = (["lsof"] + Array((process.arguments ?? []).dropFirst())).joined(separator: " ")
                        
                        let lines = stdout
                            .split(separator: "\n", omittingEmptySubsequences: true)
                            .map(String.init)
                        
                        var pid = "-"
                        var processName = "-"
                        var status = "No listening process found for this port."
                        
                        if lines.count >= 2 {
                            let columns = lines[1]
                                .split(whereSeparator: { $0 == " " || $0 == "\t" })
                                .map(String.init)
                            
                            if columns.count >= 2 {
                                processName = columns[0]
                                pid = columns[1]
                                status = "Port owner detected successfully."
                            }
                        } else if !stderr.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                            status = stderr.trimmingCharacters(in: .whitespacesAndNewlines)
                        }
                        
                        DispatchQueue.main.async {
                            self.inspectedPortPID = pid
                            self.inspectedPortProcessName = processName
                            self.inspectedPortStatusText = status
                            self.inspectedPortRawCommand = commandText
                            self.isInspectingPortOwner = false
                            
                            PortInspectorWindowController.shared.update(
                                data: PortInspectorData(
                                    transport: self.inspectedPortTransport,
                                    port: self.inspectedPortNumber,
                                    pid: pid,
                                    processName: processName,
                                    statusText: status,
                                    commandText: commandText,
                                    isInspecting: false
                                )
                            )
                        }
                    } catch {
                        DispatchQueue.main.async {
                            let status = error.localizedDescription
                            self.inspectedPortStatusText = status
                            self.inspectedPortRawCommand = "lsof"
                            self.isInspectingPortOwner = false
                            
                            PortInspectorWindowController.shared.update(
                                data: PortInspectorData(
                                    transport: self.inspectedPortTransport,
                                    port: self.inspectedPortNumber,
                                    pid: "-",
                                    processName: "-",
                                    statusText: status,
                                    commandText: "lsof",
                                    isInspecting: false
                                )
                            )
                        }
                    }
                }
            }
            
            @ViewBuilder
            private var realtimeSection: some View {
                if let realtimeResult = viewModel.realtimeResult {
                    VStack(alignment: .leading, spacing: 12) {
                        if let summary = viewModel.consumerSummary {
                            consumerSummaryPanel(summary)
                        }
                        GroupBox {
                            VStack(alignment: .leading, spacing: 10) {
                                HStack {
                                    sectionTitle("Traffic Summary", systemImage: "waveform.path.ecg")
                                    Spacer()
                                    riskScoreBadge(score: sessionRiskScore(from: realtimeResult.traffic_summary.risk_level_counts))
                                }
                                
                                LazyVGrid(columns: [
                                    GridItem(.flexible(), spacing: 10),
                                    GridItem(.flexible(), spacing: 10),
                                    GridItem(.flexible(), spacing: 10),
                                    GridItem(.flexible(), spacing: 10)
                                ], alignment: .leading, spacing: 10) {
                                    summaryCard(title: "Connections Captured", value: "\(realtimeResult.traffic_summary.total_flows)")
                                    // 将协议版本键转成大写后再格式化显示，避免依赖已删除的 mapKeys 扩展。
                                    summaryCard(
                                        title: "Network Types",
                                        value: formatDict(
                                            Dictionary(
                                                uniqueKeysWithValues: realtimeResult.traffic_summary.ip_version_counts.map {
                                                    ($0.key.uppercased(), $0.value)
                                                }
                                            )
                                        )
                                    )
                                    summaryCard(title: "Risk Overview", value: formatRiskCountsMultiline(realtimeResult.traffic_summary.risk_level_counts), isCompactValue: true)
                                    summaryCard(title: "Most Active Ports", value: formatTopPorts(realtimeResult.traffic_summary.top_ports), isCompactValue: true)
                                }
                                
                                recommendationPanel(from: realtimeResult.traffic_summary.risk_level_counts)
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        .groupBoxStyle(CleanGroupBoxStyle(fill: surfacePrimary, stroke: borderSoft))
                        
                        VStack(alignment: .leading, spacing: 10) {
                            HStack(alignment: .center, spacing: 10) {
                                sectionTitle("Top Risks", systemImage: "exclamationmark.shield")
                                Spacer()
                                
                                Picker("Filter", selection: $viewModel.selectedRiskFilter) {
                                    ForEach(RiskFilter.allCases) { filter in
                                        Text(filter.rawValue).tag(filter)
                                    }
                                }
                                .pickerStyle(.menu)
                                .frame(width: 110)
                                
                                Picker("Sort", selection: $viewModel.selectedRiskSort) {
                                    ForEach(RiskSortOption.allCases) { option in
                                        Text(option.rawValue).tag(option)
                                    }
                                }
                                .pickerStyle(.menu)
                                .frame(width: 120)
                                
                                Text("Exclude LAN")
                                    .font(.caption)
                                    .foregroundStyle(mutedText)
                                
                                Toggle("", isOn: $viewModel.excludeInternalTraffic)
                                    .toggleStyle(.switch)
                                    .frame(width: 44)
                                
                                Text(viewModel.excludeInternalTraffic ? "LAN excluded" : "Include LAN")
                                    .font(.caption.weight(.semibold))
                                    .padding(.horizontal, 10)
                                    .padding(.vertical, 5)
                                    .background((viewModel.excludeInternalTraffic ? Color.green : Color.orange).opacity(0.14))
                                    .foregroundStyle(viewModel.excludeInternalTraffic ? Color.green : Color.orange)
                                    .clipShape(Capsule())
                                
                                Text("Deduplicated endpoint view")
                                    .font(.caption.weight(.semibold))
                                    .padding(.horizontal, 10)
                                    .padding(.vertical, 5)
                                    .background(Color.orange.opacity(0.14))
                                    .foregroundStyle(.orange)
                                    .clipShape(Capsule())
                            }
                            if viewportWidth < 1320 {
                                VStack(alignment: .leading, spacing: 12) {
                                    risksListPanel
                                    
                                    riskDetailPanel
                                        .frame(maxWidth: .infinity, alignment: .topLeading)
                                }
                            } else {
                                HStack(alignment: .top, spacing: 12) {
                                    risksListPanel
                                        .frame(maxWidth: .infinity, alignment: .topLeading)
                                    
                                    riskDetailPanel
                                        .frame(width: 320, alignment: .topLeading)
                                }
                            }
                            
                            
                        }
                    }
                }
            }
            @ViewBuilder
            private var risksListPanel: some View {
                VStack(alignment: .leading, spacing: 10) {
                    if viewModel.sortedAndFilteredRisks().isEmpty {
                        Text(viewModel.excludeInternalTraffic ? "No external/public risks match the current filter." : "No risks match the current filter.")
                            .foregroundStyle(mutedText)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(16)
                            .background(surfaceSecondary)
                            .overlay(
                                RoundedRectangle(cornerRadius: 14)
                                    .stroke(borderSoft, lineWidth: 1)
                            )
                            .clipShape(RoundedRectangle(cornerRadius: 14))
                    } else {
                        LazyVStack(spacing: 10) {
                            ForEach(viewModel.sortedAndFilteredRisks()) { item in
                                Button {
                                    viewModel.selectRiskItem(item)
                                } label: {
                                    VStack(alignment: .leading, spacing: 9) {
                                        HStack(alignment: .firstTextBaseline) {
                                            Text(verbatim: "\(item.dst_ip):\(String(item.dst_port))")
                                                .font(.system(size: 15, weight: .semibold))
                                                .foregroundStyle(primaryText)
                                            Spacer()
                                            riskBadge(item.risk_level)
                                        }
                                        
                                        Text(verbatim: "\(item.ip_version.uppercased()) · \(item.resolved_host)")
                                            .font(.system(size: 12, weight: .regular))
                                            .foregroundStyle(mutedText)
                                        
                                        if !item.user_label.isEmpty {
                                            Text(item.user_label)
                                                .font(.system(size: 11, weight: .semibold))
                                                .padding(.horizontal, 10)
                                                .padding(.vertical, 5)
                                                .background(Color.blue.opacity(0.14))
                                                .clipShape(Capsule())
                                        }
                                    }
                                    .padding(12)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .background(
                                        LinearGradient(
                                            colors: [
                                                Color.red.opacity(item.risk_level.lowercased() == "high" ? 0.18 : 0.08),
                                                surfaceSecondary
                                            ],
                                            startPoint: .topLeading,
                                            endPoint: .bottomTrailing
                                        )
                                    )
                                    .overlay(
                                        RoundedRectangle(cornerRadius: 16)
                                            .stroke(
                                                isSelectedRisk(item)
                                                ? Color.blue.opacity(0.70)
                                                : (item.risk_level.lowercased() == "high" ? Color.red.opacity(0.45) : borderSoft),
                                                lineWidth: isSelectedRisk(item) ? 1.5 : 1
                                            )
                                    )
                                    .clipShape(RoundedRectangle(cornerRadius: 16))
                                    .shadow(color: .black.opacity(0.08), radius: 8, x: 0, y: 4)
                                }
                                .buttonStyle(.plain)
                            }
                        }
                    }
                }
            }
            @ViewBuilder
            private func consumerSummaryPanel(_ summary: ConsumerSummary) -> some View {
                GroupBox {
                    VStack(alignment: .leading, spacing: 12) {
                        HStack(alignment: .center) {
                            sectionTitle("Network Health Summary", systemImage: "stethoscope")
                            Spacer()
                            consumerPriorityBadge(summary.priority)
                        }
                        
                        VStack(alignment: .leading, spacing: 6) {
                            Text(summary.headline)
                                .font(.system(size: 18, weight: .semibold))
                                .foregroundStyle(primaryText)
                            Text(summary.summary)
                                .font(.system(size: 13, weight: .regular))
                                .foregroundStyle(mutedText)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        
                        if !summary.next_steps.isEmpty {
                            VStack(alignment: .leading, spacing: 8) {
                                Text("Next Steps")
                                    .font(.caption.weight(.semibold))
                                    .foregroundStyle(mutedText)
                                
                                ForEach(summary.next_steps, id: \.self) { item in
                                    HStack(alignment: .top, spacing: 8) {
                                        Image(systemName: "arrow.right.circle.fill")
                                            .foregroundStyle(Color.blue)
                                        Text(item)
                                            .font(.system(size: 13, weight: .regular))
                                            .foregroundStyle(primaryText)
                                            .fixedSize(horizontal: false, vertical: true)
                                    }
                                }
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(12)
                            .background(surfaceSecondary)
                            .overlay(
                                RoundedRectangle(cornerRadius: 12)
                                    .stroke(borderSoft, lineWidth: 1)
                            )
                            .clipShape(RoundedRectangle(cornerRadius: 12))
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .groupBoxStyle(CleanGroupBoxStyle(fill: surfacePrimary, stroke: borderSoft))
            }
            
            @ViewBuilder
            private func consumerPriorityBadge(_ priority: String) -> some View {
                let lower = priority.lowercased()
                let color: Color = lower == "high" ? .red : (lower == "medium" ? .orange : .green)
                
                Text(priority)
                    .font(.caption.weight(.semibold))
                    .padding(.horizontal, 10)
                    .padding(.vertical, 6)
                    .background(color.opacity(0.15))
                    .foregroundStyle(color)
                    .clipShape(Capsule())
            }
            @ViewBuilder
            private var riskDetailPanel: some View {
                GroupBox {
                    VStack(alignment: .leading, spacing: 10) {
                        sectionTitle("Risk Details", systemImage: "info.circle")
                        
                        if let item = viewModel.selectedRiskItem {
                            VStack(alignment: .leading, spacing: 10) {
                                detailRow("Destination", "\(item.dst_ip):\(item.dst_port)")
                                detailRow("IP Version", item.ip_version.uppercased())
                                detailRow("Host", item.resolved_host)
                                detailRow("Geo Label", item.geo_label)
                                detailRow("Service", item.service_hint)
                                detailRow("Risk Level", item.risk_level)
                                
                                if !item.user_label.isEmpty {
                                    detailRow("User Label", item.user_label)
                                }
                                
                                VStack(alignment: .leading, spacing: 8) {
                                    Text("Trust / Whitelist")
                                        .font(.caption)
                                        .foregroundStyle(mutedText)
                                    
                                    HStack(spacing: 8) {
                                        Button("Trust IP") {
                                            viewModel.whitelistInputKind = "ip"
                                            viewModel.whitelistInputValue = item.dst_ip
                                            viewModel.whitelistInputNote = "用户手动添加"
                                            viewModel.addWhitelistEntry()
                                        }
                                        .buttonStyle(SecondaryAnimatedButtonStyle())
                                        
                                        Button("Trust Host") {
                                            viewModel.whitelistInputKind = "host"
                                            viewModel.whitelistInputValue = item.resolved_host
                                            viewModel.whitelistInputNote = "用户手动添加"
                                            viewModel.addWhitelistEntry()
                                        }
                                        .buttonStyle(SecondaryAnimatedButtonStyle())
                                        .disabled(item.resolved_host.isEmpty || item.resolved_host == "unresolved")
                                        
                                        Button("Trust IP:Port") {
                                            viewModel.whitelistInputKind = "ip_port"
                                            viewModel.whitelistInputValue = "\(item.dst_ip):\(item.dst_port)"
                                            viewModel.whitelistInputNote = "用户手动添加"
                                            viewModel.addWhitelistEntry()
                                        }
                                        .buttonStyle(SecondaryAnimatedButtonStyle())
                                    }
                                }
                                
                                VStack(alignment: .leading, spacing: 6) {
                                    Text("Why flagged")
                                        .font(.caption)
                                        .foregroundStyle(mutedText)
                                    Text(item.reason)
                                        .font(.system(size: 13, weight: .regular))
                                        .foregroundStyle(primaryText)
                                        .fixedSize(horizontal: false, vertical: true)
                                }
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .padding(10)
                                .background(surfaceSecondary)
                                .overlay(
                                    RoundedRectangle(cornerRadius: 12)
                                        .stroke(borderSoft, lineWidth: 1)
                                )
                                .clipShape(RoundedRectangle(cornerRadius: 12))
                            }
                        } else {
                            Text("Select a risk item to inspect its details.")
                                .foregroundStyle(mutedText)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .groupBoxStyle(CleanGroupBoxStyle(fill: surfacePrimary, stroke: borderSoft))
            }
            
            @ViewBuilder
            private var captureThroughputPanel: some View {
                let series = parsedThroughputSeries(from: viewModel.throughputLogText)
                let rxSamples = series.rx
                let txSamples = series.tx
                let hasSeries = rxSamples.count >= 2 || txSamples.count >= 2
                
                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        sectionTitle("Capture Throughput", systemImage: "chart.line.uptrend.xyaxis")
                        Spacer()
                        
                        HStack(spacing: 10) {
                            legendChip(color: .cyan, label: "Receive")
                            legendChip(color: .green, label: "Send")
                        }
                        
                        Text(viewModel.isCapturing ? "Live" : "Frozen")
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(viewModel.isCapturing ? Color.green : mutedText)
                            .padding(.horizontal, 10)
                            .padding(.vertical, 5)
                            .background((viewModel.isCapturing ? Color.green : Color.white).opacity(0.10))
                            .clipShape(Capsule())
                    }
                    
                    if hasSeries {
                        DualMiniLineChart(rxValues: rxSamples, txValues: txSamples)
                            .frame(height: 170)
                            .background(surfaceSecondary)
                            .overlay(
                                RoundedRectangle(cornerRadius: 12)
                                    .stroke(borderSoft, lineWidth: 1)
                            )
                            .clipShape(RoundedRectangle(cornerRadius: 12))
                        
                        HStack {
                            Text("RX Latest: \(formatRate(rxSamples.last ?? 0))")
                            Spacer()
                            Text("TX Latest: \(formatRate(txSamples.last ?? 0))")
                            Spacer()
                            Text("Peak: \(formatRate(max(rxSamples.max() ?? 0, txSamples.max() ?? 0)))")
                        }
                        .font(.caption)
                        .foregroundStyle(mutedText)
                    } else {
                        VStack(alignment: .leading, spacing: 6) {
                            Text("Waiting for receive/send throughput metrics from capture logs...")
                                .font(.system(size: 13, weight: .medium))
                                .foregroundStyle(primaryText)
                            Text("The chart freezes when capture stops. During capture it listens for rx_bytes_per_second / tx_bytes_per_second values from the analyzer log.")
                                .font(.caption)
                                .foregroundStyle(mutedText)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(12)
                        .background(surfaceSecondary)
                        .overlay(
                            RoundedRectangle(cornerRadius: 12)
                                .stroke(borderSoft, lineWidth: 1)
                        )
                        .clipShape(RoundedRectangle(cornerRadius: 12))
                    }
                }
            }
            
            @ViewBuilder
            private func legendChip(color: Color, label: String) -> some View {
                HStack(spacing: 6) {
                    Circle()
                        .fill(color)
                        .frame(width: 8, height: 8)
                    Text(label)
                        .font(.caption)
                        .foregroundStyle(mutedText)
                }
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .background(Color.white.opacity(0.04))
                .clipShape(Capsule())
            }
            
            @ViewBuilder
            private func recommendationPanel(from counts: [String: Int]) -> some View {
                let items = recommendations(from: counts, selectedRisk: viewModel.selectedRiskItem)
                
                VStack(alignment: .leading, spacing: 6) {
                    Text("Suggested Actions")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(mutedText)
                    
                    ForEach(items, id: \.self) { item in
                        HStack(alignment: .top, spacing: 8) {
                            Image(systemName: "checkmark.circle")
                                .foregroundStyle(.blue)
                            Text(item)
                                .font(.system(size: 13, weight: .regular))
                                .foregroundStyle(primaryText)
                        }
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(12)
                .background(surfaceSecondary)
                .overlay(
                    RoundedRectangle(cornerRadius: 12)
                        .stroke(borderSoft, lineWidth: 1)
                )
                .clipShape(RoundedRectangle(cornerRadius: 12))
            }
            @ViewBuilder
            private func detailRow(_ title: String, _ value: String) -> some View {
                VStack(alignment: .leading, spacing: 3) {
                    Text(title)
                        .font(.caption)
                        .foregroundStyle(mutedText)
                    Text(value.isEmpty ? "-" : value)
                        .font(.system(size: 13, weight: .medium))
                        .foregroundStyle(primaryText)
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            
            @ViewBuilder
            private func macOSLoadingDots(phase: Int) -> some View {
                HStack(spacing: 6) {
                    ForEach(0..<3, id: \.self) { index in
                        Circle()
                            .fill(dotColor(for: index, phase: phase))
                            .frame(width: 7, height: 7)
                            .scaleEffect(phase == index ? 1.0 : 0.82)
                            .animation(.easeInOut(duration: 0.18), value: phase)
                    }
                }
            }
            
            private func dotColor(for index: Int, phase: Int) -> Color {
                if phase == index {
                    return isLightTheme ? Color.black.opacity(0.68) : Color.white.opacity(0.90)
                }
                return isLightTheme ? Color.black.opacity(0.18) : Color.white.opacity(0.22)
            }
            private struct PortOwnerSummary: Identifiable {
                let id: String
                let port: Int
                let transport: String
                let pid: String
                let processName: String
                let category: String
            }
            
            private struct PortCategorySection: Identifiable {
                let id: String
                let title: String
                let items: [PortOwnerSummary]
            }
            
            private func portLookupKey(port: Int, transport: String) -> String {
                "\(transport.uppercased()):\(port)"
            }
            
            private func categoryForProcess(_ processName: String) -> String {
                let lower = processName.lowercased()
                
                if lower.isEmpty || lower == "-" || lower == "unknown" {
                    return "Unknown"
                }
                
                let systemProcesses: Set<String> = [
                    "homed", "rapportd", "identityservicesd", "identityservices",
                    "sharingd", "controlce", "controlcenter", "mdnsresponder",
                    "airportd", "configd", "coreaudiod", "nehelper",
                    "locationd", "distnoted"
                ]
                
                if systemProcesses.contains(lower) || lower.hasSuffix("d") {
                    return "System Service"
                }
                
                if lower.contains("clash") || lower.contains("mihomo") || lower.contains("proxy")
                    || lower.contains("surge") || lower.contains("vpn") || lower.contains("v2ray")
                    || lower.contains("xray") || lower.contains("sing-box") || lower.contains("tailscale") {
                    return "Proxy / Network Tool"
                }
                
                if lower.contains("code") || lower.contains("python") || lower.contains("node")
                    || lower.contains("docker") || lower.contains("java") || lower.contains("go") {
                    return "Developer Tool"
                }
                
                if lower.contains("wechat") || lower == "qq" || lower.contains("qqexdoc")
                    || lower.contains("telegram") || lower.contains("discord")
                    || lower.contains("chrome") || lower.contains("safari") {
                    return "User App"
                }
                
                return "Unknown"
            }
            
            private func resolvePortOwners(for ports: [Int], transport: String) {
                let unresolved = ports.filter {
                    portOwnerCache[portLookupKey(port: $0, transport: transport)] == nil
                }
                guard !unresolved.isEmpty else { return }
                
                DispatchQueue.global(qos: .userInitiated).async {
                    var resolved: [String: PortOwnerSummary] = [:]
                    
                    for port in unresolved {
                        let key = portLookupKey(port: port, transport: transport)
                        let process = Process()
                        let outputPipe = Pipe()
                        let errorPipe = Pipe()
                        
                        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
                        if transport.uppercased() == "TCP" {
                            process.arguments = ["lsof", "-nP", "-iTCP:\(port)", "-sTCP:LISTEN"]
                        } else {
                            process.arguments = ["lsof", "-nP", "-iUDP:\(port)"]
                        }
                        process.standardOutput = outputPipe
                        process.standardError = errorPipe
                        
                        var pid = "-"
                        var processName = "-"
                        
                        do {
                            try process.run()
                            process.waitUntilExit()
                            
                            let stdout = String(
                                decoding: outputPipe.fileHandleForReading.readDataToEndOfFile(),
                                as: UTF8.self
                            )
                            
                            let lines = stdout
                                .split(separator: "\n", omittingEmptySubsequences: true)
                                .map(String.init)
                            
                            if lines.count >= 2 {
                                let columns = lines[1]
                                    .split(whereSeparator: { $0 == " " || $0 == "\t" })
                                    .map(String.init)
                                
                                if columns.count >= 2 {
                                    processName = columns[0]
                                    pid = columns[1]
                                }
                            }
                        } catch {
                            _ = errorPipe.fileHandleForReading.readDataToEndOfFile()
                        }
                        
                        resolved[key] = PortOwnerSummary(
                            id: key,
                            port: port,
                            transport: transport.uppercased(),
                            pid: pid,
                            processName: processName,
                            category: categoryForProcess(processName)
                        )
                    }
                    
                    DispatchQueue.main.async {
                        for (key, value) in resolved {
                            portOwnerCache[key] = value
                        }
                    }
                }
            }
            
            private func categorizedPorts(for ports: [Int], transport: String) -> [PortCategorySection] {
                let order = ["System Service", "User App", "Proxy / Network Tool", "Developer Tool", "Unknown"]
                
                let items = ports.sorted().map { port -> PortOwnerSummary in
                    let key = portLookupKey(port: port, transport: transport)
                    return portOwnerCache[key] ?? PortOwnerSummary(
                        id: key,
                        port: port,
                        transport: transport.uppercased(),
                        pid: "-",
                        processName: "-",
                        category: "Unknown"
                    )
                }
                
                let grouped = Dictionary(grouping: items, by: { $0.category })
                
                return order.compactMap { title in
                    guard let groupItems = grouped[title], !groupItems.isEmpty else { return nil }
                    return PortCategorySection(
                        id: title,
                        title: title,
                        items: groupItems.sorted { $0.port < $1.port }
                    )
                }
            }
            
            private func categorySummaryText(for ports: [Int], transport: String) -> String {
                let sections = categorizedPorts(for: ports, transport: transport)
                guard !sections.isEmpty else { return "Category: resolving" }
                
                return sections
                    .prefix(3)
                    .map { "\($0.title): \($0.items.count)" }
                    .joined(separator: "    ")
            }
            private var historySection: some View {
                GroupBox {
                    VStack(alignment: .leading, spacing: 12) {
                        HStack(alignment: .center, spacing: 12) {
                            sectionTitle("History", systemImage: "clock.arrow.circlepath")
                            
                            Spacer(minLength: 16)
                            
                            HStack(spacing: 8) {
                                Button("Delete Selected") {
                                    viewModel.deleteSelectedHistory()
                                }
                                .frame(width: 96, height: 30)
                                .buttonStyle(DangerAnimatedButtonStyle())
                                .disabled(viewModel.selectedHistoryIDs.isEmpty)
                                
                                Button("Clear All") {
                                    viewModel.clearAllHistory()
                                }
                                .frame(width: 96, height: 30)
                                .buttonStyle(DangerAnimatedButtonStyle())
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
                                                
                                                Text("Risk Counts: \(formatRiskCounts(item.risk_level_counts))")
                                                    .font(.caption)
                                                    .foregroundStyle(mutedText)
                                            }
                                            .frame(maxWidth: .infinity, alignment: .leading)
                                            
                                            Button(role: .destructive) {
                                                viewModel.deleteHistoryItem(item)
                                            } label: {
                                                Label("Delete", systemImage: "trash")
                                            }
                                            .buttonStyle(CompactDangerAnimatedButtonStyle())
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
                .groupBoxStyle(CleanGroupBoxStyle(fill: surfacePrimary, stroke: borderSoft))
            }
            
            private var demoSection: some View {
                GroupBox {
                    VStack(alignment: .leading, spacing: 12) {
                        sectionTitle("Core ML Demo", systemImage: "cpu")
                        
                        HStack(alignment: .top, spacing: 20) {
                            VStack(alignment: .leading, spacing: 8) {
                                Text("Demo Case")
                                    .font(.headline)
                                    .foregroundStyle(primaryText)
                                Picker("Demo Case", selection: $viewModel.selectedCase) {
                                    ForEach(viewModel.demoCases, id: \.self) { item in
                                        Text(item.displayName).tag(Optional(item))
                                    }
                                }
                                .pickerStyle(.menu)
                                .frame(width: 220)
                            }
                            
                            VStack(alignment: .leading, spacing: 8) {
                                Text("Detection Mode")
                                    .font(.headline)
                                    .foregroundStyle(primaryText)
                                
                                Picker("Detection Mode", selection: $viewModel.selectedMode) {
                                    ForEach(DetectionMode.allCases) { mode in
                                        Text(mode.rawValue).tag(mode)
                                    }
                                }
                                .pickerStyle(.menu)
                                .frame(width: 220)
                            }
                        }
                        
                        Button("Run Selected Case") {
                            viewModel.runSelectedPrediction()
                        }
                        .buttonStyle(SecondaryAnimatedButtonStyle())
                        
                        VStack(alignment: .leading, spacing: 8) {
                            Text(viewModel.resultText)
                                .font(.title3)
                                .bold()
                                .foregroundStyle(primaryText)
                            
                            Text(viewModel.detailText)
                                .font(.body)
                                .foregroundStyle(mutedText)
                                .textSelection(.enabled)
                        }
                        
                        if !viewModel.errorText.isEmpty {
                            Text("Error: \(viewModel.errorText)")
                                .foregroundStyle(.red)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .groupBoxStyle(CleanGroupBoxStyle(fill: surfacePrimary, stroke: borderSoft))
            }
            
            @ViewBuilder
            private func sectionTitle(_ title: String, systemImage: String) -> some View {
                HStack(spacing: 6) {
                    Image(systemName: systemImage)
                        .font(.system(size: 14, weight: .semibold))
                        .foregroundStyle(Color(red: 0.25, green: 0.60, blue: 1.0))
                    Text(title)
                        .font(.title3.weight(.semibold))
                        .foregroundStyle(primaryText)
                }
            }
            
            private func sessionRiskScore(from counts: [String: Int]) -> Int {
                let high = counts["High", default: 0]
                let medium = counts["Medium", default: 0]
                let low = counts["Low", default: 0]
                return min(100, high * 18 + medium * 7 + low)
            }
            
            @ViewBuilder
            private func riskScoreBadge(score: Int) -> some View {
                let badge = riskScoreAppearance(score: score)
                
                Text(badge.label)
                    .font(.caption.weight(.semibold))
                    .padding(.horizontal, 10)
                    .padding(.vertical, 6)
                    .background(badge.color.opacity(0.15))
                    .foregroundStyle(badge.color)
                    .clipShape(Capsule())
            }
            
            private func riskScoreAppearance(score: Int) -> (label: String, color: Color) {
                switch score {
                case 0..<31:
                    return ("Safe \(score)", .green)
                case 31..<61:
                    return ("Notice \(score)", .blue)
                case 61..<81:
                    return ("Warning \(score)", .orange)
                default:
                    return ("Critical \(score)", .red)
                }
            }
            
            private func recommendations(from counts: [String: Int], selectedRisk: RiskItem?) -> [String] {
                if let risk = selectedRisk {
                    var result: [String] = []
                    
                    if risk.risk_level.lowercased() == "high" {
                        result.append("Prioritize this high-risk endpoint first and confirm whether the destination is expected.")
                    } else if risk.risk_level.lowercased() == "medium" {
                        result.append("Review this medium-risk endpoint and verify whether the connection pattern matches normal behavior.")
                    } else {
                        result.append("This endpoint is lower risk, but you can still keep it as a baseline reference.")
                    }
                    
                    let reason = risk.reason.lowercased()
                    let service = risk.service_hint.lowercased()
                    let host = risk.resolved_host.lowercased()
                    
                    if reason.contains("rare port") || service.contains("custom") {
                        result.append("Check whether this custom or uncommon service port is intentionally exposed or belongs to a trusted application.")
                    }
                    
                    if reason.contains("long-lived") {
                        result.append("Inspect whether this long-lived connection is from a VPN, remote access tool, browser sync, or background cloud software.")
                    }
                    
                    if reason.contains("private-to-public") {
                        result.append("Verify whether this private-to-public communication is expected for the current host and network environment.")
                    }
                    
                    if reason.contains("high bytes") || reason.contains("high packets") {
                        result.append("Review bandwidth-heavy behavior and confirm whether file sync, streaming, updates, or tunneling software is active.")
                    }
                    
                    if host.contains("vpn") || host.contains("static") || host.contains("cloud") {
                        result.append("The resolved host suggests infrastructure or hosted service traffic. Cross-check this destination with your known VPN or cloud providers.")
                    }
                    
                    result.append("Export the current log and PCAP if you need a deeper offline investigation of this selected endpoint.")
                    return Array(result.prefix(4))
                }
                
                let high = counts["High", default: 0]
                let medium = counts["Medium", default: 0]
                
                if high > 0 {
                    return [
                        "Review high-risk public endpoints first and verify whether they belong to known services.",
                        "Check whether VPN, proxy, browser sync, or background cloud software is expected on this host.",
                        "Export the current log and PCAP if you need a deeper offline investigation."
                    ]
                }
                
                if medium > 0 {
                    return [
                        "Inspect medium-risk endpoints and confirm whether long-lived or uncommon public connections are expected.",
                        "Use the risk detail panel to review the flagged service and reason before taking action.",
                        "Consider adding trusted destinations to a future whitelist to reduce repeated noise."
                    ]
                }
                
                return [
                    "No major anomalies were highlighted in this capture window.",
                    "You can still review saved history to compare future sessions against this baseline.",
                    "Use a longer capture duration or another interface if you want broader coverage."
                ]
            }
            
            private func isSelectedRisk(_ item: RiskItem) -> Bool {
                guard let selected = viewModel.selectedRiskItem else { return false }
                return selected.dst_ip == item.dst_ip
                && selected.dst_port == item.dst_port
                && selected.ip_version == item.ip_version
                && selected.service_hint == item.service_hint
            }
            
            private func formatElapsed(_ seconds: Int) -> String {
                let minutes = seconds / 60
                let remain = seconds % 60
                return String(format: "%02d:%02d", minutes, remain)
            }
            
            @ViewBuilder
            private func summaryCard(title: String, value: String, isCompactValue: Bool = false) -> some View {
                VStack(alignment: .leading, spacing: 8) {
                    Text(title)
                        .font(.system(size: 12, weight: .regular))
                        .foregroundStyle(mutedText)
                    
                    Text((value.isEmpty || value == "unknown") ? "-" : value)
                        .font(isCompactValue ? .system(size: 13, weight: .medium) : .system(size: 14, weight: .medium))
                        .foregroundStyle(primaryText)                .textSelection(.enabled)
                        .multilineTextAlignment(.leading)
                        .lineLimit(nil)
                        .fixedSize(horizontal: false, vertical: true)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(maxWidth: .infinity, minHeight: 96, alignment: .topLeading)
                .padding(14)
                .background(
                    RoundedRectangle(cornerRadius: 12)
                        .fill(surfaceSecondary)
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 12)
                        .stroke(borderSoft, lineWidth: 1)
                )
            }
            
            private func formatDict<T>(_ dict: [String: T]) -> String {
                if dict.isEmpty { return "-" }
                return dict
                    .sorted { $0.key < $1.key }
                    .map { "\($0.key): \($0.value)" }
                    .joined(separator: "  ·  ")
            }
            
            private func formatDict<T>(_ dict: [String: T], preferredOrder: [String]) -> String {
                if dict.isEmpty { return "-" }
                
                let ordered = preferredOrder.compactMap { key in
                    dict[key].map { (key, $0) }
                }
                let remaining = dict
                    .filter { !preferredOrder.contains($0.key) }
                    .sorted { $0.key < $1.key }
                
                return (ordered + remaining)
                    .map { "\($0.0): \($0.1)" }
                    .joined(separator: "  ·  ")
            }
            
            private func formatRiskCounts(_ dict: [String: Int]) -> String {
                formatDict(dict, preferredOrder: ["High", "Medium", "Low"])
            }
            
            private func formatRiskCountsMultiline(_ dict: [String: Int]) -> String {
                if dict.isEmpty { return "-" }
                
                let high = dict["High", default: 0]
                let medium = dict["Medium", default: 0]
                let low = dict["Low", default: 0]
                
                return "High: \(high)\nMedium: \(medium)\nLow: \(low)"
            }
            
            private func formatTopPorts(_ dict: [String: Int]) -> String {
                if dict.isEmpty { return "-" }
                
                let sorted = dict
                    .compactMap { (key, value) -> (Int, Int)? in
                        guard let port = Int(key) else { return nil }
                        return (port, value)
                    }
                    .sorted {
                        if $0.1 == $1.1 {
                            return $0.0 < $1.0
                        }
                        return $0.1 > $1.1
                    }
                    .prefix(5)
                
                return sorted.map { "\($0.0): \($0.1)" }.joined(separator: "\n")
            }
            
            private func parsedThroughputSeries(from logText: String) -> (rx: [Double], tx: [Double]) {
                let lines = logText.components(separatedBy: .newlines).filter { !$0.isEmpty }
                var rxValues: [Double] = []
                var txValues: [Double] = []
                
                func extractValue(_ pattern: String, from line: String) -> Double? {
                    guard let regex = try? NSRegularExpression(pattern: pattern),
                          let match = regex.firstMatch(in: line, range: NSRange(line.startIndex..., in: line)),
                          let valueRange = Range(match.range(at: 1), in: line),
                          let value = Double(line[valueRange]) else {
                        return nil
                    }
                    return value
                }
                
                for line in lines {
                    var matchedRX = false
                    var matchedTX = false
                    
                    if let rx = extractValue(#"(?i)rx_bytes_per_second\s*=\s*(\d+(?:\.\d+)?)"#, from: line) {
                        rxValues.append(rx)
                        matchedRX = true
                    }
                    
                    if let tx = extractValue(#"(?i)tx_bytes_per_second\s*=\s*(\d+(?:\.\d+)?)"#, from: line) {
                        txValues.append(tx)
                        matchedTX = true
                    }
                    
                    if !matchedRX, !matchedTX,
                       let legacy = extractValue(#"(?i)bytes_per_second\s*=\s*(\d+(?:\.\d+)?)"#, from: line) {
                        rxValues.append(legacy)
                        txValues.append(0)
                    }
                    
                    if !matchedRX, !matchedTX,
                       let kb = extractValue(#"(?i)(\d+(?:\.\d+)?)\s*KB/s"#, from: line) {
                        rxValues.append(kb * 1_000)
                        txValues.append(0)
                    }
                    
                    if !matchedRX, !matchedTX,
                       let mb = extractValue(#"(?i)(\d+(?:\.\d+)?)\s*MB/s"#, from: line) {
                        rxValues.append(mb * 1_000_000)
                        txValues.append(0)
                    }
                    
                    if !matchedRX, !matchedTX,
                       let b = extractValue(#"(?i)(\d+(?:\.\d+)?)\s*B/s"#, from: line) {
                        rxValues.append(b)
                        txValues.append(0)
                    }
                }
                
                let count = min(rxValues.count, txValues.count)
                return (
                    Array(rxValues.prefix(count).suffix(24)),
                    Array(txValues.prefix(count).suffix(24))
                )
            }
            
            private func formatRate(_ value: Double) -> String {
                if value >= 1_000_000 {
                    return String(format: "%.2f MB/s", value / 1_000_000)
                }
                if value >= 1_000 {
                    return String(format: "%.1f KB/s", value / 1_000)
                }
                return String(format: "%.0f B/s", value)
            }
            
            private var dividerLine: some View {
                Rectangle()
                    .fill(Color.white.opacity(0.08))
                    .frame(height: 1)
            }
            
            private func compactPortText(_ ports: [Int]) -> String {
                guard !ports.isEmpty else { return "None" }
                
                let sorted = ports.sorted()
                let previewCount = 5
                let preview = sorted.prefix(previewCount).map(String.init).joined(separator: ", ")
                
                if sorted.count <= previewCount {
                    return preview
                }
                
                return preview
            }
            private func riskBadge(_ level: String) -> some View {
                let style = riskBadgeColor(level)
                
                return Text(level)
                    .font(.caption.weight(.semibold))
                    .padding(.horizontal, 10)
                    .padding(.vertical, 5)
                    .background(style.opacity(0.15))
                    .foregroundStyle(style)
                    .clipShape(Capsule())
            }
            
            private func riskBadgeColor(_ level: String) -> Color {
                switch level.lowercased() {
                case "high":
                    return .red
                case "medium":
                    return .orange
                default:
                    return .green
                }
            }
        }
        
        struct PrimaryAnimatedButtonStyle: ButtonStyle {
            func makeBody(configuration: Configuration) -> some View {
                AnimatedButtonBody(
                    configuration: configuration,
                    fill: Color(red: 0.18, green: 0.48, blue: 1.0),
                    stroke: Color.white.opacity(0.10),
                    foreground: .white,
                    shadowColor: Color.blue.opacity(0.30)
                )
            }
        }
        
        struct SecondaryAnimatedButtonStyle: ButtonStyle {
            func makeBody(configuration: Configuration) -> some View {
                AnimatedButtonBody(
                    configuration: configuration,
                    fill: Color(red: 0.19, green: 0.21, blue: 0.29),
                    stroke: Color.white.opacity(0.10),
                    foreground: .white,
                    shadowColor: Color.black.opacity(0.22)
                )
            }
        }
        
        struct DangerAnimatedButtonStyle: ButtonStyle {
            func makeBody(configuration: Configuration) -> some View {
                AnimatedButtonBody(
                    configuration: configuration,
                    fill: Color(red: 0.72, green: 0.25, blue: 0.24),
                    stroke: Color(red: 0.88, green: 0.44, blue: 0.40).opacity(0.34),
                    foreground: .white,
                    shadowColor: Color(red: 0.72, green: 0.25, blue: 0.24).opacity(0.20)
                )
            }
        }
        
        struct CompactDangerAnimatedButtonStyle: ButtonStyle {
            func makeBody(configuration: Configuration) -> some View {
                CompactAnimatedButtonBody(
                    configuration: configuration,
                    fill: Color(red: 0.72, green: 0.25, blue: 0.24),
                    stroke: Color(red: 0.88, green: 0.44, blue: 0.40).opacity(0.34),
                    foreground: .white,
                    shadowColor: Color(red: 0.72, green: 0.25, blue: 0.24).opacity(0.20)
                )
            }
        }
        
        private struct AnimatedButtonBody: View {
            let configuration: ButtonStyle.Configuration
            let fill: Color
            let stroke: Color
            let foreground: Color
            let shadowColor: Color
            
            @State private var isHovered = false
            
            var body: some View {
                configuration.label
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(foreground.opacity(configuration.isPressed ? 0.92 : 1.0))
                    .lineLimit(1)
                    .minimumScaleFactor(0.88)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .padding(.horizontal, 14)
                    .padding(.vertical, 9)
                    .background(
                        RoundedRectangle(cornerRadius: 12)
                            .fill(fill.opacity(configuration.isPressed ? 0.92 : (isHovered ? 1.0 : 0.96)))
                    )
                    .overlay(
                        RoundedRectangle(cornerRadius: 12)
                            .stroke(stroke.opacity(isHovered ? 1.0 : 0.85), lineWidth: 1)
                    )
                    .scaleEffect(configuration.isPressed ? 0.97 : (isHovered ? 1.02 : 1.0))
                    .shadow(color: shadowColor.opacity(isHovered ? 0.34 : 0.18), radius: isHovered ? 16 : 10, x: 0, y: isHovered ? 8 : 5)
                    .animation(.spring(response: 0.22, dampingFraction: 0.78), value: configuration.isPressed)
                    .animation(.easeOut(duration: 0.16), value: isHovered)
                    .onHover { hovering in
                        isHovered = hovering
                    }
            }
        }
        
        private struct CompactAnimatedButtonBody: View {
            let configuration: ButtonStyle.Configuration
            let fill: Color
            let stroke: Color
            let foreground: Color
            let shadowColor: Color
            
            @State private var isHovered = false
            
            var body: some View {
                configuration.label
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(foreground.opacity(configuration.isPressed ? 0.92 : 1.0))
                    .lineLimit(1)
                    .padding(.horizontal, 16)
                    .padding(.vertical, 9)
                    .background(
                        RoundedRectangle(cornerRadius: 12)
                            .fill(fill.opacity(configuration.isPressed ? 0.92 : (isHovered ? 1.0 : 0.96)))
                    )
                    .overlay(
                        RoundedRectangle(cornerRadius: 12)
                            .stroke(stroke.opacity(isHovered ? 1.0 : 0.85), lineWidth: 1)
                    )
                    .scaleEffect(configuration.isPressed ? 0.97 : (isHovered ? 1.02 : 1.0))
                    .shadow(color: shadowColor.opacity(isHovered ? 0.34 : 0.18), radius: isHovered ? 16 : 10, x: 0, y: isHovered ? 8 : 5)
                    .animation(.spring(response: 0.22, dampingFraction: 0.78), value: configuration.isPressed)
                    .animation(.easeOut(duration: 0.16), value: isHovered)
                    .onHover { hovering in
                        isHovered = hovering
                    }
                    .fixedSize()
            }
        }
        
        struct CleanGroupBoxStyle: GroupBoxStyle {
            let fill: Color
            let stroke: Color
            
            func makeBody(configuration: Configuration) -> some View {
                VStack(alignment: .leading, spacing: 12) {
                    configuration.label
                        .foregroundStyle(Color.primary.opacity(0.88))
                    configuration.content
                        .foregroundStyle(Color.primary.opacity(0.88))
                }
                .padding(16)
                .background(
                    RoundedRectangle(cornerRadius: 18)
                        .fill(fill)
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 18)
                        .stroke(stroke, lineWidth: 1)
                )
                .shadow(color: Color.black.opacity(0.14), radius: 16, x: 0, y: 8)
            }
        }
        
    struct DualMiniLineChart: View {
            let rxValues: [Double]
            let txValues: [Double]
            @Environment(\.colorScheme) private var colorScheme
            private let gridLineCount = 5
            
            var body: some View {
                GeometryReader { geo in
                    let allValues = rxValues + txValues
                    let maxValue = max(allValues.max() ?? 1, 1)
                    let minValue = min(allValues.min() ?? 0, 0)
                    let range = max(maxValue - minValue, 1)
                    
                    let leftLabelWidth: CGFloat = 64
                    let bottomPadding: CGFloat = 12
                    let topPadding: CGFloat = 10
                    let rightPadding: CGFloat = 10
                    
                    let chartWidth = max(geo.size.width - leftLabelWidth - rightPadding, 1)
                    let chartHeight = max(geo.size.height - topPadding - bottomPadding, 1)
                    
                    ZStack(alignment: .topLeading) {
                        ForEach(0..<gridLineCount, id: \.self) { index in
                            let ratio = CGFloat(index) / CGFloat(max(gridLineCount - 1, 1))
                            let y = topPadding + chartHeight * ratio
                            let value = maxValue - (Double(ratio) * range)
                            
                            Path { path in
                                path.move(to: CGPoint(x: leftLabelWidth, y: y))
                                path.addLine(to: CGPoint(x: leftLabelWidth + chartWidth, y: y))
                            }
                            .stroke(Color.white.opacity(0.10), style: StrokeStyle(lineWidth: 1, dash: [4, 4]))
                            
                            Text(formatAxisValue(value))
                                .font(.system(size: 10, weight: .medium))
                                .foregroundStyle(
                                    colorScheme == .light
                                    ? Color.black.opacity(0.62)
                                    : Color.white.opacity(0.62)
                                )
                                .frame(width: leftLabelWidth - 8, alignment: .trailing)
                                .position(x: (leftLabelWidth - 8) / 2, y: y)
                        }
                        
                        smoothLine(values: rxValues, color: .cyan, chartWidth: chartWidth, chartHeight: chartHeight, leftLabelWidth: leftLabelWidth, topPadding: topPadding, minValue: minValue, range: range)
                        
                        smoothLine(values: txValues, color: .green, chartWidth: chartWidth, chartHeight: chartHeight, leftLabelWidth: leftLabelWidth, topPadding: topPadding, minValue: minValue, range: range)
                    }
                    .padding(.vertical, 6)
                    .animation(.easeInOut(duration: 0.35), value: rxValues)
                    .animation(.easeInOut(duration: 0.35), value: txValues)
                }
            }
            
            @ViewBuilder
            private func smoothLine(
                values: [Double],
                color: Color,
                chartWidth: CGFloat,
                chartHeight: CGFloat,
                leftLabelWidth: CGFloat,
                topPadding: CGFloat,
                minValue: Double,
                range: Double
            ) -> some View {
                let points = makePoints(
                    values: values,
                    chartWidth: chartWidth,
                    chartHeight: chartHeight,
                    leftLabelWidth: leftLabelWidth,
                    topPadding: topPadding,
                    minValue: minValue,
                    range: range
                )
                
                smoothPath(points: points)
                    .stroke(color, style: StrokeStyle(lineWidth: 2.4, lineCap: .round, lineJoin: .round))
            }
            
            private func makePoints(
                values: [Double],
                chartWidth: CGFloat,
                chartHeight: CGFloat,
                leftLabelWidth: CGFloat,
                topPadding: CGFloat,
                minValue: Double,
                range: Double
            ) -> [CGPoint] {
                guard !values.isEmpty else { return [] }
                
                return values.indices.map { index in
                    let x = leftLabelWidth + chartWidth * CGFloat(index) / CGFloat(max(values.count - 1, 1))
                    let normalized = (values[index] - minValue) / range
                    let y = topPadding + chartHeight * (1 - CGFloat(normalized))
                    return CGPoint(x: x, y: y)
                }
            }
            
            private func smoothPath(points: [CGPoint]) -> Path {
                Path { path in
                    guard !points.isEmpty else { return }
                    guard points.count > 1 else {
                        path.move(to: points[0])
                        path.addLine(to: points[0])
                        return
                    }
                    
                    path.move(to: points[0])
                    
                    if points.count == 2 {
                        path.addLine(to: points[1])
                        return
                    }
                    
                    for index in 0..<(points.count - 1) {
                        let current = points[index]
                        let next = points[index + 1]
                        let previous = index > 0 ? points[index - 1] : current
                        let afterNext = index + 2 < points.count ? points[index + 2] : next
                        
                        let tension: CGFloat = 0.22
                        
                        let control1 = CGPoint(
                            x: current.x + (next.x - previous.x) * tension,
                            y: current.y + (next.y - previous.y) * tension
                        )
                        
                        let control2 = CGPoint(
                            x: next.x - (afterNext.x - current.x) * tension,
                            y: next.y - (afterNext.y - current.y) * tension
                        )
                        
                        path.addCurve(to: next, control1: control1, control2: control2)
                    }
                }
            }
            
            private func formatAxisValue(_ value: Double) -> String {
                if value >= 1_000_000 {
                    return String(format: "%.1f MB/s", value / 1_000_000)
                }
                if value >= 1_000 {
                    return String(format: "%.1f KB/s", value / 1_000)
                }
                return String(format: "%.0f B/s", value)
            }
        }
    }

