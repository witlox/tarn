import XCTest
@testable import TarnCore

final class LockTests: XCTestCase {

    private func tmpLockPath() -> String {
        NSTemporaryDirectory() + "tarn-test-\(UUID())/tarn.lock"
    }

    func testAcquireCreatesFile() throws {
        let path = tmpLockPath()
        defer { try? FileManager.default.removeItem(atPath: (path as NSString).deletingLastPathComponent) }
        let lock = Lock(path: path)
        try lock.acquire()
        XCTAssertTrue(FileManager.default.fileExists(atPath: path))
    }

    func testReleaseRemovesFile() throws {
        let path = tmpLockPath()
        defer { try? FileManager.default.removeItem(atPath: (path as NSString).deletingLastPathComponent) }
        let lock = Lock(path: path)
        try lock.acquire()
        lock.release()
        XCTAssertFalse(FileManager.default.fileExists(atPath: path))
    }

    func testLockContainsPID() throws {
        let path = tmpLockPath()
        defer { try? FileManager.default.removeItem(atPath: (path as NSString).deletingLastPathComponent) }
        let lock = Lock(path: path)
        try lock.acquire()
        let content = try String(contentsOfFile: path, encoding: .utf8)
        let pid = content.trimmingCharacters(in: .whitespacesAndNewlines)
        XCTAssertEqual(pid, String(getpid()))
    }

    func testStaleLockIsRemoved() throws {
        let path = tmpLockPath()
        let dir = (path as NSString).deletingLastPathComponent
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: dir) }
        // Write a PID that doesn't exist
        try "999999".write(toFile: path, atomically: true, encoding: .utf8)
        let lock = Lock(path: path)
        XCTAssertNoThrow(try lock.acquire())
        // Now holds our PID
        let content = try String(contentsOfFile: path, encoding: .utf8)
        XCTAssertEqual(content.trimmingCharacters(in: .whitespacesAndNewlines), String(getpid()))
    }

    func testLiveLockThrows() throws {
        let path = tmpLockPath()
        let dir = (path as NSString).deletingLastPathComponent
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: dir) }
        // Write our own PID — kill(getpid(), 0) returns 0
        try String(getpid()).write(toFile: path, atomically: true, encoding: .utf8)
        let lock = Lock(path: path)
        XCTAssertThrowsError(try lock.acquire()) { error in
            guard case TarnError.lockHeld = error else {
                XCTFail("Expected lockHeld, got \(error)")
                return
            }
        }
    }
}
