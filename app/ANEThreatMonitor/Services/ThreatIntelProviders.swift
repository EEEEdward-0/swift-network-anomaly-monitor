import Foundation

// Provider 协议：所有情报源都实现这个接口。
protocol ThreatIntelProvider {
    var providerName: String { get }

    func lookupIP(_ ip: String) async throws -> ThreatIntelRecord?
    func lookupDomain(_ domain: String) async throws -> ThreatIntelRecord?
    func lookupURL(_ url: String) async throws -> ThreatIntelRecord?
}

// 统一的 URLSession 请求辅助。
enum ThreatIntelHTTP {
    static func getJSON(
        url: URL,
        headers: [String: String] = [:]
    ) async throws -> Data {
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.timeoutInterval = 12

        for (key, value) in headers {
            request.setValue(value, forHTTPHeaderField: key)
        }

        let (data, response) = try await URLSession.shared.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw ThreatIntelError.networkError("Invalid response.")
        }

        guard 200..<300 ~= httpResponse.statusCode else {
            throw ThreatIntelError.networkError("HTTP \(httpResponse.statusCode)")
        }

        return data
    }

    static func postJSON(
        url: URL,
        headers: [String: String] = [:],
        body: Data
    ) async throws -> Data {
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.timeoutInterval = 12
        request.httpBody = body

        for (key, value) in headers {
            request.setValue(value, forHTTPHeaderField: key)
        }

        let (data, response) = try await URLSession.shared.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw ThreatIntelError.networkError("Invalid response.")
        }

        guard 200..<300 ~= httpResponse.statusCode else {
            throw ThreatIntelError.networkError("HTTP \(httpResponse.statusCode)")
        }

        return data
    }
}

// MARK: - AbuseIPDB

final class AbuseIPDBProvider: ThreatIntelProvider {
    let providerName = "AbuseIPDB"
    private let apiKey: String

    init(apiKey: String) {
        self.apiKey = apiKey.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    func lookupIP(_ ip: String) async throws -> ThreatIntelRecord? {
        guard !apiKey.isEmpty else {
            throw ThreatIntelError.missingAPIKey(providerName)
        }

        var components = URLComponents(string: "https://api.abuseipdb.com/api/v2/check")
        components?.queryItems = [
            URLQueryItem(name: "ipAddress", value: ip),
            URLQueryItem(name: "maxAgeInDays", value: "90")
        ]

        guard let url = components?.url else {
            throw ThreatIntelError.invalidURL
        }

        let data = try await ThreatIntelHTTP.getJSON(
            url: url,
            headers: [
                "Key": apiKey,
                "Accept": "application/json"
            ]
        )

        let decoded = try JSONDecoder().decode(AbuseIPDBCheckResponse.self, from: data)
        let score = Double(decoded.data.abuseConfidenceScore)
        let risk = Self.mapRisk(score: score)

        let summary = "Confidence score: \(decoded.data.abuseConfidenceScore), reports: \(decoded.data.totalReports)"

        return ThreatIntelRecord(
    id: UUID(),
            source: providerName,
            target: ip,
            targetType: .ip,
            riskLevel: risk,
            confidence: min(max(score / 100.0, 0.0), 1.0),
            summary: summary,
            tags: decoded.data.usageType.map { [$0] } ?? [],
            referenceURL: nil,
            rawScore: score
        )
    }

    func lookupDomain(_ domain: String) async throws -> ThreatIntelRecord? {
        nil
    }

    func lookupURL(_ url: String) async throws -> ThreatIntelRecord? {
        nil
    }

    private static func mapRisk(score: Double) -> ThreatRiskLevel {
        if score >= 75 { return .high }
        if score >= 30 { return .medium }
        if score >= 0 { return .low }
        return .unknown
    }
}

private struct AbuseIPDBCheckResponse: Decodable {
    let data: AbuseIPDBCheckData
}

private struct AbuseIPDBCheckData: Decodable {
    let abuseConfidenceScore: Int
    let totalReports: Int
    let usageType: String?
}

// MARK: - OTX

final class OTXProvider: ThreatIntelProvider {
    let providerName = "AlienVault OTX"
    private let apiKey: String

    init(apiKey: String) {
        self.apiKey = apiKey.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    func lookupIP(_ ip: String) async throws -> ThreatIntelRecord? {
        let urlString = "https://otx.alienvault.com/api/v1/indicators/IPv4/\(ip)/general"
        guard let url = URL(string: urlString) else {
            throw ThreatIntelError.invalidURL
        }

        let data = try await ThreatIntelHTTP.getJSON(
            url: url,
            headers: apiKey.isEmpty ? [:] : ["X-OTX-API-KEY": apiKey]
        )

        let decoded = try JSONDecoder().decode(OTXGeneralResponse.self, from: data)
        return buildRecord(
            target: ip,
            targetType: .ip,
            pulseCount: decoded.pulseInfo?.count ?? 0,
            malwareCount: decoded.malwareCount ?? 0,
            sectionTitle: decoded.sectionTitle ?? "General indicator context"
        )
    }

    func lookupDomain(_ domain: String) async throws -> ThreatIntelRecord? {
        let urlString = "https://otx.alienvault.com/api/v1/indicators/domain/\(domain)/general"
        guard let url = URL(string: urlString) else {
            throw ThreatIntelError.invalidURL
        }

        let data = try await ThreatIntelHTTP.getJSON(
            url: url,
            headers: apiKey.isEmpty ? [:] : ["X-OTX-API-KEY": apiKey]
        )

        let decoded = try JSONDecoder().decode(OTXGeneralResponse.self, from: data)
        return buildRecord(
            target: domain,
            targetType: .domain,
            pulseCount: decoded.pulseInfo?.count ?? 0,
            malwareCount: decoded.malwareCount ?? 0,
            sectionTitle: decoded.sectionTitle ?? "Domain indicator context"
        )
    }

    func lookupURL(_ urlText: String) async throws -> ThreatIntelRecord? {
        guard let encoded = urlText.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) else {
            throw ThreatIntelError.invalidTarget
        }

        let urlString = "https://otx.alienvault.com/api/v1/indicators/url/\(encoded)/general"
        guard let url = URL(string: urlString) else {
            throw ThreatIntelError.invalidURL
        }

        let data = try await ThreatIntelHTTP.getJSON(
            url: url,
            headers: apiKey.isEmpty ? [:] : ["X-OTX-API-KEY": apiKey]
        )

        let decoded = try JSONDecoder().decode(OTXGeneralResponse.self, from: data)
        return buildRecord(
            target: urlText,
            targetType: .url,
            pulseCount: decoded.pulseInfo?.count ?? 0,
            malwareCount: decoded.malwareCount ?? 0,
            sectionTitle: decoded.sectionTitle ?? "URL indicator context"
        )
    }

    private func buildRecord(
        target: String,
        targetType: ThreatTargetType,
        pulseCount: Int,
        malwareCount: Int,
        sectionTitle: String
    ) -> ThreatIntelRecord {
        let score = Double(pulseCount * 10 + malwareCount * 20)
        let cappedScore = min(score, 100.0)
        let risk = Self.mapRisk(score: cappedScore)

        return ThreatIntelRecord(
    id: UUID(),
            source: providerName,
            target: target,
            targetType: targetType,
            riskLevel: risk,
            confidence: cappedScore / 100.0,
            summary: "\(sectionTitle). pulses=\(pulseCount), malware=\(malwareCount)",
            tags: pulseCount > 0 ? ["pulse"] : [],
            referenceURL: nil,
            rawScore: cappedScore
        )
    }

    private static func mapRisk(score: Double) -> ThreatRiskLevel {
        if score >= 70 { return .high }
        if score >= 25 { return .medium }
        if score >= 0 { return .low }
        return .unknown
    }
}

private struct OTXGeneralResponse: Decodable {
    let pulseInfo: OTXPulseInfo?
    let malwareCount: Int?
    let sectionTitle: String?

    enum CodingKeys: String, CodingKey {
        case pulseInfo = "pulse_info"
        case malwareCount = "malware_count"
        case sectionTitle = "section_title"
    }
}

private struct OTXPulseInfo: Decodable {
    let count: Int
}
