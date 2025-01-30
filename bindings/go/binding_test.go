package tree_sitter_kamailio_test

import (
	"testing"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tree_sitter_kamailio "github.com/batoaqaa/tree-sitter-kamailio/bindings/go"
)

func TestCanLoadGrammar(t *testing.T) {
	language := tree_sitter.NewLanguage(tree_sitter_kamailio.Language())
	if language == nil {
		t.Errorf("Error loading Kamailio grammar")
	}
}
