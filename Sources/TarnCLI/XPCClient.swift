import Foundation
import TarnCore

/// Connects to the tarn supervisor system extension via XPC.
/// Sends session commands (start, end, register agent root) and
/// receives prompt and persist callbacks from the supervisor.
///
/// The supervisor sends prompt requests when it encounters unknown
/// file or network access. This client displays the prompt via
/// PromptUI and returns the user's decision. It also handles
/// persist requests by writing learned entries to the user's
/// profile file on disk (INV-XPC-4: the CLI, not the supervisor,
/// writes user files).
final class XPCClient: NSObject {
    private var connection: NSXPCConnection?
    private let profilePath: String
    private let promptLock = NSLock()

    init(profilePath: String) {
        self.profilePath = profilePath
        super.init()
    }

    /// Connect to the supervisor's Mach service. Returns false if
    /// the connection cannot be established (supervisor not active).
    func connect() -> Bool {
        let conn = NSXPCConnection(machServiceName: kTarnSupervisorMachServiceName)
        conn.remoteObjectInterface = NSXPCInterface(with: TarnSupervisorXPC.self)
        conn.exportedInterface = NSXPCInterface(with: TarnCLICallbackXPC.self)
        conn.exportedObject = self
        conn.invalidationHandler = {
            print("\ntarn: connection to supervisor lost")
        }
        conn.interruptionHandler = {
            print("\ntarn: supervisor interrupted, reconnecting...")
        }
        conn.resume()
        connection = conn
        return true
    }

    func disconnect() {
        connection?.invalidate()
        connection = nil
    }

    /// Start a supervised session. Returns the session response or nil on failure.
    func startSession(request: SessionStartRequest) -> SessionStartResponse? {
        guard let proxy = supervisorProxy() else { return nil }

        var result: SessionStartResponse?
        let semaphore = DispatchSemaphore(value: 0)

        guard let data = try? JSONEncoder().encode(request) else { return nil }
        proxy.startSession(data) { responseData, error in
            if let error = error {
                print("tarn: failed to start session: \(error)")
            } else if let responseData = responseData,
                      let response = try? JSONDecoder().decode(SessionStartResponse.self, from: responseData) {
                result = response
            }
            semaphore.signal()
        }
        semaphore.wait()
        return result
    }

    /// Register the agent's PID as the root of the supervised tree.
    func registerAgentRoot(sessionId: String, pid: pid_t) {
        guard let proxy = supervisorProxy() else { return }

        let semaphore = DispatchSemaphore(value: 0)
        proxy.registerAgentRoot(sessionId, pid: pid) { error in
            if let error = error {
                print("tarn: failed to register agent root: \(error)")
            }
            semaphore.signal()
        }
        semaphore.wait()
    }

    /// End the session and clean up supervisor state.
    func endSession(sessionId: String) {
        guard let proxy = supervisorProxy() else { return }

        let semaphore = DispatchSemaphore(value: 0)
        proxy.endSession(sessionId) {
            semaphore.signal()
        }
        semaphore.wait()
    }

    private func supervisorProxy() -> TarnSupervisorXPC? {
        connection?.remoteObjectProxyWithErrorHandler { error in
            print("tarn: XPC error: \(error)")
        } as? TarnSupervisorXPC
    }
}

// MARK: - Callbacks from the supervisor

extension XPCClient: TarnCLICallbackXPC {

    /// The supervisor paused a flow or held an ES event and needs
    /// a user decision. Display the prompt and return the response.
    func handlePromptRequest(_ requestData: Data, reply: @escaping (Data) -> Void) {
        guard let message = try? JSONDecoder().decode(PromptRequestMessage.self, from: requestData) else {
            let deny = PromptResponseMessage(flowId: "", action: "deny", remember: false)
            reply((try? JSONEncoder().encode(deny)) ?? Data())
            return
        }

        // Serialize prompts — only one on screen at a time
        promptLock.lock()
        let response = PromptUI.prompt(message: message)
        promptLock.unlock()

        reply((try? JSONEncoder().encode(response)) ?? Data())
    }

    /// The supervisor wants to persist a learned entry. The CLI
    /// writes to disk as the user (INV-XPC-4).
    func persistEntry(_ entryData: Data, reply: @escaping (Bool) -> Void) {
        guard let request = try? JSONDecoder().decode(PersistEntryRequest.self, from: entryData) else {
            reply(false)
            return
        }

        let path = request.path.isEmpty ? profilePath : request.path

        do {
            var config = try Config.load(from: path)
            switch request.mode {
            case "readonly":
                config.addReadonly(path: request.value)
            case "readwrite":
                config.addReadwrite(path: request.value)
            case "domain":
                config.addDomain(domain: request.value)
            default:
                reply(false)
                return
            }
            try config.save(to: path)
            reply(true)
        } catch {
            print("tarn: failed to save profile: \(error)")
            reply(false)
        }
    }
}
