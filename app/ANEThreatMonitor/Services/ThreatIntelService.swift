import Foundation
import Combine

// 统一情报查询服务。
@MainActor
final class ThreatIntelService: ObservableObject {
    @Published var isLoading: Bool = false
    @Published var lastSummary: ThreatIntelSummary?
    @Published var lastErrorMessage: String = ""
    
    private let providers: [ThreatIntelProvider]
    
    init(
        abuseIPDBKey: String = "",
        otxKey: String = ""
    ) {
        self.providers = [
            AbuseIPDBProvider(apiKey: abuseIPDBKey),
            OTXProvider(apiKey: otxKey)
        ]
    }
    
    // 查询入口：自动按目标类型调度。
    func query(target: String, type: ThreatTargetType) async {
        isLoading = true
        lastErrorMessage = ""
        lastSummary = nil
        
        defer {
            isLoading = false
        }
        
        do {
            let records = try await fetchAll(target: target, type: type)
            let summary = aggregate(target: target, type: type, records: records)
            lastSummary = summary
        } catch {
            lastErrorMessage = error.localizedDescription
        }
    }
    
    // 并发查询所有 provider。
    private func fetchAll(target: String, type: ThreatTargetType) async throws -> [ThreatIntelRecord] {
        try await withThrowingTaskGroup(of: ThreatIntelRecord?.self) { group in
            for provider in providers {
                group.addTask {
                    switch type {
                    case .ip:
                        return try await provider.lookupIP(target)
                    case .domain:
                        return try await provider.lookupDomain(target)
                    case .url:
                        return try await provider.lookupURL(target)
                    }
                }
            }
            
            var results: [ThreatIntelRecord] = []
            
            for try await record in group {
                if let record {
                    results.append(record)
                }
            }
            
            return results
        }
    }
    
    // 聚合 provider 结果，给前端统一展示。
    private func aggregate(
        target: String,
        type: ThreatTargetType,
        records: [ThreatIntelRecord]
    ) -> ThreatIntelSummary {
        let maxConfidence = records.map(\.confidence).max() ?? 0.0
        let overallRisk = deriveOverallRisk(from: records)
        
        return ThreatIntelSummary(
            target: target,
            targetType: type,
            overallRisk: overallRisk,
            maxConfidence: maxConfidence,
            records: records.sorted { $0.confidence > $1.confidence }
        )
    }
    
    private func deriveOverallRisk(from records: [ThreatIntelRecord]) -> ThreatRiskLevel {
        if records.contains(where: { $0.riskLevel == .high }) {
            return .high
        }
        if records.contains(where: { $0.riskLevel == .medium }) {
            return .medium
        }
        if records.contains(where: { $0.riskLevel == .low }) {
            return .low
        }
        return .unknown
    }
}

struct AbuseIPDBResponse: Decodable {
    let data: AbuseIPDBData
}

struct AbuseIPDBData: Decodable {
    let ipAddress: String
    let abuseConfidenceScore: Int
    let countryCode: String?
    let usageType: String?
    let isp: String?
    let domain: String?
    let totalReports: Int?
    let lastReportedAt: String?
    let isPublic: Bool?
}

final class AbuseIPDBThreatIntelService {
    private let session: URLSession
    private let baseURL = URL(string: "https://api.abuseipdb.com/api/v2/check")!
    
    init(session: URLSession = .shared) {
        self.session = session
    }
    
    func checkIP(_ ip: String, apiKey: String) async throws -> AbuseIPDBData {
        var components = URLComponents(url: baseURL, resolvingAgainstBaseURL: false)!
        components.queryItems = [
            URLQueryItem(name: "ipAddress", value: ip),
            URLQueryItem(name: "maxAgeInDays", value: "90"),
            URLQueryItem(name: "verbose", value: "")
        ]
        
        var request = URLRequest(url: components.url!)
        request.httpMethod = "GET"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue(apiKey, forHTTPHeaderField: "Key")
        request.timeoutInterval = 15
        
        let (data, response) = try await session.data(for: request)
        
        guard let http = response as? HTTPURLResponse else {
            throw NSError(domain: "AbuseIPDBThreatIntelService", code: -1, userInfo: [
                NSLocalizedDescriptionKey: "Invalid HTTP response"
            ])
        }
        
        guard (200...299).contains(http.statusCode) else {
            let body = String(data: data, encoding: .utf8) ?? ""
            throw NSError(domain: "AbuseIPDBThreatIntelService", code: http.statusCode, userInfo: [
                NSLocalizedDescriptionKey: "AbuseIPDB request failed: \(http.statusCode) \(body)"
            ])
        }
        
        let decoded = try JSONDecoder().decode(AbuseIPDBResponse.self, from: data)
        return decoded.data
    }
}
