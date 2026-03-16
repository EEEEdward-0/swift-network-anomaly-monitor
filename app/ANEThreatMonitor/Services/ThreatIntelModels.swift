import Foundation

// 查询目标类型。
enum ThreatTargetType: String, Codable {
    case ip
    case domain
    case url
}

// 统一风险等级。
enum ThreatRiskLevel: String, Codable, CaseIterable {
    case low
    case medium
    case high
    case unknown
}

// 单个情报源返回的标准结果。
struct ThreatIntelRecord: Identifiable, Codable, Hashable {
    let id: UUID
    let source: String
    let target: String
    let targetType: ThreatTargetType
    let riskLevel: ThreatRiskLevel
    let confidence: Double
    let summary: String
    let tags: [String]
    let referenceURL: String?
    let rawScore: Double?
}

// 聚合后的统一结果。
struct ThreatIntelSummary: Codable, Hashable {
    let target: String
    let targetType: ThreatTargetType
    let overallRisk: ThreatRiskLevel
    let maxConfidence: Double
    let records: [ThreatIntelRecord]
}

// Provider 报错类型。
enum ThreatIntelError: LocalizedError {
    case invalidTarget
    case invalidURL
    case networkError(String)
    case decodeError(String)
    case providerUnavailable(String)
    case missingAPIKey(String)

    var errorDescription: String? {
        switch self {
        case .invalidTarget:
            return "Invalid target."
        case .invalidURL:
            return "Invalid request URL."
        case .networkError(let message):
            return "Network error: \(message)"
        case .decodeError(let message):
            return "Decode error: \(message)"
        case .providerUnavailable(let provider):
            return "Provider unavailable: \(provider)"
        case .missingAPIKey(let provider):
            return "Missing API key: \(provider)"
        }
    }
}
