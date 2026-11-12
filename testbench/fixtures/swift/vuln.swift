import Foundation
func run(_ user: String) {
    let p = Process()
    p.launchPath = "/bin/sh"
    p.arguments = ["-c", user]
}
