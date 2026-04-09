import XCTest
@testable import TarnCore

final class ProcessTreeTests: XCTestCase {

    func testRootPIDIsSupervised() {
        let tree = ProcessTree()
        tree.addRoot(pid: 100)
        XCTAssertTrue(tree.isSupervised(pid: 100))
    }

    func testUnknownPIDIsNotSupervised() {
        let tree = ProcessTree()
        tree.addRoot(pid: 100)
        XCTAssertFalse(tree.isSupervised(pid: 999))
    }

    func testChildOfSupervisedIsSupervised() {
        let tree = ProcessTree()
        tree.addRoot(pid: 100)
        tree.addChild(pid: 101, parentPID: 100)
        XCTAssertTrue(tree.isSupervised(pid: 101))
    }

    func testChildOfUnsupervisedIsNotSupervised() {
        let tree = ProcessTree()
        tree.addRoot(pid: 100)
        tree.addChild(pid: 200, parentPID: 999)
        XCTAssertFalse(tree.isSupervised(pid: 200))
    }

    func testGrandchildIsSupervised() {
        let tree = ProcessTree()
        tree.addRoot(pid: 100)
        tree.addChild(pid: 101, parentPID: 100)
        tree.addChild(pid: 102, parentPID: 101)
        XCTAssertTrue(tree.isSupervised(pid: 102))
    }

    func testRemovePID() {
        let tree = ProcessTree()
        tree.addRoot(pid: 100)
        XCTAssertTrue(tree.isSupervised(pid: 100))
        tree.remove(pid: 100)
        XCTAssertFalse(tree.isSupervised(pid: 100))
    }

    func testCount() {
        let tree = ProcessTree()
        XCTAssertEqual(tree.count, 0)
        tree.addRoot(pid: 100)
        XCTAssertEqual(tree.count, 1)
        tree.addChild(pid: 101, parentPID: 100)
        XCTAssertEqual(tree.count, 2)
        tree.remove(pid: 100)
        XCTAssertEqual(tree.count, 1)
    }
}
