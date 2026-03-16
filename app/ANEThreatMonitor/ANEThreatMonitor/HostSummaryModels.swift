import Foundation

struct HostSummaryResult: Codable {
    let interface: String
    let local_ip: String
    let local_ipv6: String
    let public_ip: String
    let public_ipv6: String
    let public_ip_location: String
    let public_ipv6_location: String
    let open_tcp_ports: [Int]
    let open_udp_ports: [Int]
}
