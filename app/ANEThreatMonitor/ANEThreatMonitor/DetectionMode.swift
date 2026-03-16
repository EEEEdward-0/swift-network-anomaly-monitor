import Foundation

enum DetectionMode: String, CaseIterable, Identifiable, Codable {
    case balanced = "Balanced"
    case sensitive = "Sensitive"
    case strict = "Strict"

    var id: String { rawValue }

    var threshold: Double {
        switch self {
        case .balanced:
            return 0.50
        case .sensitive:
            return 0.35
        case .strict:
            return 0.70
        }
    }

    struct DemoCase: Identifiable, Codable, Hashable {
        let id: UUID
        let displayName: String
        let trueLabelText: String
        let attackProbability: Double
        let features: [Double]

        init(
            id: UUID = UUID(),
            displayName: String,
            trueLabelText: String,
            attackProbability: Double,
            features: [Double]
        ) {
            self.id = id
            self.displayName = displayName
            self.trueLabelText = trueLabelText
            self.attackProbability = attackProbability
            self.features = features
        }
    }

    struct ConsumerSummary: Codable, Hashable {
        let status: String
        let priority: String
        let headline: String
        let summary: String
        let next_steps: [String]
    }

    struct HistoryRecord: Identifiable, Codable, Hashable {
        var id: String { session_id }
        let session_id: String
        let started_at: String
        let interface: String?
        let capture_window_seconds: Int?
        let risk_level_counts: [String: Int]
        let files: [String: String]?
    }

    enum RiskFilter: String, CaseIterable, Identifiable, Codable {
        case all = "All"
        case high = "High"
        case medium = "Medium"
        case low = "Low"

        var id: String { rawValue }
    }

    enum RiskSortOption: String, CaseIterable, Identifiable, Codable {
        case severity = "Severity"
        case endpoint = "Endpoint"
        case service = "Service"

        var id: String { rawValue }
    }

    struct PredictionResult: Codable, Hashable {
        let attackProbability: Double
        let normalProbability: Double
        let predictedLabel: String
        let threshold: Double
        let latencyMs: Double
    }
} 
