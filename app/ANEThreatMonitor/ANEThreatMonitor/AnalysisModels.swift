import Foundation

struct TrafficSummary: Codable {
    let total_flows: Int
    let risk_level_counts: [String: Int]
    let ip_version_counts: [String: Int]
    let top_ports: [String: Int]
    let top_dns: [String: Int]?
}

struct RiskItem: Codable, Identifiable, Hashable {
    let id = UUID()
    let ip_version: String
    let dst_ip: String
    let dst_port: Int
    let resolved_host: String
    let geo_label: String
    let service_hint: String
    let user_label: String
    let risk_level: String
    let reason: String

    enum CodingKeys: String, CodingKey {
        case ip_version
        case dst_ip
        case dst_port
        case resolved_host
        case geo_label
        case service_hint
        case user_label
        case risk_level
        case reason
    }
}

struct RealtimeResult: Codable {
    let traffic_summary: TrafficSummary
    let top_risks: [RiskItem]
}
