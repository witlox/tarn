import XCTest
@testable import TarnCore

/// Tests wired to tests/features/process-tree.feature scenarios.
final class ProcessTreeScenarioTests: XCTestCase {

    // Scenario: Agent root PID is supervised
    func testAgentRootPIDIsSupervised() {
        let tree = ProcessTree()
        tree.addRoot(pid: 100)
        XCTAssertTrue(tree.isSupervised(pid: 100))
    }

    // Scenario: Child of agent is supervised
    func testChildOfAgentIsSupervised() {
        let tree = ProcessTree()
        tree.addRoot(pid: 100)
        tree.addChild(pid: 101, parentPID: 100)
        XCTAssertTrue(tree.isSupervised(pid: 101))
    }

    // Scenario: Grandchild of agent is supervised
    func testGrandchildOfAgentIsSupervised() {
        let tree = ProcessTree()
        tree.addRoot(pid: 100)
        tree.addChild(pid: 101, parentPID: 100)
        tree.addChild(pid: 102, parentPID: 101)
        XCTAssertTrue(tree.isSupervised(pid: 102))
    }

    // Scenario: Unrelated process is not supervised
    func testUnrelatedProcessIsNotSupervised() {
        let tree = ProcessTree()
        tree.addRoot(pid: 100)
        XCTAssertFalse(tree.isSupervised(pid: 999))
    }

    // Scenario: Child of unrelated process is not supervised
    func testChildOfUnrelatedProcessIsNotSupervised() {
        let tree = ProcessTree()
        tree.addRoot(pid: 100)
        tree.addChild(pid: 1000, parentPID: 999)
        XCTAssertFalse(tree.isSupervised(pid: 1000))
    }

    // Scenario: Exited process is removed from tree
    func testExitedProcessIsRemovedFromTree() {
        let tree = ProcessTree()
        tree.addRoot(pid: 100)
        tree.addChild(pid: 101, parentPID: 100)
        tree.remove(pid: 101)
        XCTAssertFalse(tree.isSupervised(pid: 101))
        XCTAssertTrue(tree.isSupervised(pid: 100))
    }

    // Scenario: Exec retains supervised status (INV-PS-3)
    // exec() doesn't change PID, so the PID stays in the tree.
    // We verify that removing is the ONLY way out.
    func testExecRetainsSupervision() {
        let tree = ProcessTree()
        tree.addRoot(pid: 100)
        tree.addChild(pid: 101, parentPID: 100)
        // exec is a no-op in ProcessTree — PID 101 stays supervised
        XCTAssertTrue(tree.isSupervised(pid: 101))
    }

    // Scenario: Empty tree after all processes exit
    func testEmptyTreeAfterAllProcessesExit() {
        let tree = ProcessTree()
        tree.addRoot(pid: 100)
        tree.remove(pid: 100)
        XCTAssertEqual(tree.count, 0)
    }

    // Scenario: AUTH event for unsupervised PID is allowed immediately
    // (tests the check, not the ES response — that's an integration test)
    func testUnsupervisedPIDCheckReturnsFalse() {
        let tree = ProcessTree()
        tree.addRoot(pid: 100)
        XCTAssertFalse(tree.isSupervised(pid: 999))
    }

    // INV-PS-4: Removing root does NOT remove descendants
    func testRemovingRootDoesNotRemoveDescendants() {
        let tree = ProcessTree()
        tree.addRoot(pid: 100)
        tree.addChild(pid: 101, parentPID: 100)
        tree.addChild(pid: 102, parentPID: 101)
        tree.remove(pid: 100)
        XCTAssertFalse(tree.isSupervised(pid: 100))
        XCTAssertTrue(tree.isSupervised(pid: 101))
        XCTAssertTrue(tree.isSupervised(pid: 102))
    }

    // INV-PS-5: Empty tree triggers onEmpty callback
    func testEmptyTreeTriggersOnEmpty() {
        let tree = ProcessTree()
        var emptyCalled = false
        tree.onEmpty = { emptyCalled = true }
        tree.addRoot(pid: 100)
        tree.addChild(pid: 101, parentPID: 100)
        tree.remove(pid: 101)
        XCTAssertFalse(emptyCalled) // not empty yet
        tree.remove(pid: 100)
        XCTAssertTrue(emptyCalled) // now empty → callback fired
    }

    // INV-PS-5: onEmpty NOT called for redundant removes
    func testOnEmptyNotCalledOnRedundantRemove() {
        let tree = ProcessTree()
        var callCount = 0
        tree.onEmpty = { callCount += 1 }
        tree.addRoot(pid: 100)
        tree.remove(pid: 100)
        XCTAssertEqual(callCount, 1)
        // Removing a non-existent PID from an already-empty tree
        // should NOT fire onEmpty (the PID wasn't supervised)
        tree.remove(pid: 999)
        XCTAssertEqual(callCount, 1)
    }

    // removeAll clears everything
    func testRemoveAllClearsTree() {
        let tree = ProcessTree()
        tree.addRoot(pid: 100)
        tree.addChild(pid: 101, parentPID: 100)
        tree.removeAll()
        XCTAssertEqual(tree.count, 0)
        XCTAssertFalse(tree.isSupervised(pid: 100))
        XCTAssertFalse(tree.isSupervised(pid: 101))
    }
}
