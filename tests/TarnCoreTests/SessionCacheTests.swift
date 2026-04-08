import XCTest
@testable import TarnCore

final class SessionCacheTests: XCTestCase {

    func testRecordAndLookupAllow() {
        let cache = SessionCache()
        cache.record(key: "/etc/foo", action: .allow)
        XCTAssertEqual(cache.lookup(key: "/etc/foo"), .allow)
    }

    func testRecordAndLookupDeny() {
        let cache = SessionCache()
        cache.record(key: "/etc/private", action: .deny)
        XCTAssertEqual(cache.lookup(key: "/etc/private"), .deny)
    }

    func testLookupMissReturnsNil() {
        let cache = SessionCache()
        XCTAssertNil(cache.lookup(key: "/etc/never"))
    }

    func testRecordOverwritesPreviousDecision() {
        let cache = SessionCache()
        cache.record(key: "/etc/foo", action: .deny)
        cache.record(key: "/etc/foo", action: .allow)
        XCTAssertEqual(cache.lookup(key: "/etc/foo"), .allow)
    }

    func testClearRemovesAll() {
        let cache = SessionCache()
        cache.record(key: "/etc/foo", action: .allow)
        cache.record(key: "/etc/bar", action: .deny)
        XCTAssertEqual(cache.count, 2)
        cache.clear()
        XCTAssertEqual(cache.count, 0)
        XCTAssertNil(cache.lookup(key: "/etc/foo"))
    }

    func testNetworkKeyPrefixPreventCollision() {
        let cache = SessionCache()
        cache.record(key: "/some/path", action: .allow)
        cache.record(key: "host:github.com", action: .deny)
        XCTAssertEqual(cache.lookup(key: "/some/path"), .allow)
        XCTAssertEqual(cache.lookup(key: "host:github.com"), .deny)
    }

    func testCountReflectsEntries() {
        let cache = SessionCache()
        XCTAssertEqual(cache.count, 0)
        cache.record(key: "a", action: .allow)
        cache.record(key: "b", action: .deny)
        XCTAssertEqual(cache.count, 2)
    }
}
