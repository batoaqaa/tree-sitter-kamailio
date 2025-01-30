import XCTest
import SwiftTreeSitter
import TreeSitterKamailio

final class TreeSitterKamailioTests: XCTestCase {
    func testCanLoadGrammar() throws {
        let parser = Parser()
        let language = Language(language: tree_sitter_kamailio())
        XCTAssertNoThrow(try parser.setLanguage(language),
                         "Error loading Kamailio grammar")
    }
}
