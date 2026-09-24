import Foundation

/// Policy for remote subscription fetch URLs (HTTPS by default).
public enum SubscriptionUrlPolicy {
    public static let maxRedirects = 5

    /// Accepts https anywhere, or http only to loopback development hosts.
    public static func isSecure(_ url: URL) -> Bool {
        guard let scheme = url.scheme?.lowercased() else { return false }
        if scheme == "https" { return true }
        if scheme != "http" { return false }
        guard let host = url.host?.lowercased() else { return false }
        return host == "localhost" ||
            host == "127.0.0.1" ||
            host == "::1" ||
            host == "[::1]"
    }
}
