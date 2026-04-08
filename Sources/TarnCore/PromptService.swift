import Foundation

/// Protocol abstracting the prompt and persist callbacks that the
/// DecisionEngine needs. In production, XPCService conforms; in
/// tests, MockPromptService conforms. This inversion lets the full
/// decision pipeline (deny → allow → cache → prompt → persist) be
/// tested via swift test without system frameworks.
public protocol PromptService: AnyObject {
    /// Send an asynchronous prompt request. The reply closure is
    /// called on an arbitrary thread with the user's response.
    func asyncPrompt(_ message: PromptRequestMessage,
                     reply: @escaping (PromptResponseMessage) -> Void)

    /// Ask the CLI to persist a learned entry. The reply closure
    /// returns true on success, false on failure.
    func asyncPersistEntry(request: AccessRequest,
                           reply: @escaping (Bool) -> Void)

    /// The profile path, used for diagnostics. May be nil if no
    /// session is active.
    var currentProfilePath: String? { get }
}
