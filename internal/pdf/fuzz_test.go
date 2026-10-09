package pdf

import (
	"reflect"
	"testing"
)

func FuzzParseMarkdown(f *testing.F) {
	for _, seed := range []string{
		"", "# Title\n\n**bold** and [link](https://example.com)",
		"| a | b |\n| --- | ---: |\n| c | d |", "|", "```\nunterminated",
		"> > quote\n\n- item\n  continuation\n1. numbered", "\ufeff# Title\r\n\xff\x00",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		doc := ParseMarkdown(data)
		if !reflect.DeepEqual(doc, ParseMarkdown(data)) {
			t.Fatal("Markdown parsing is not deterministic")
		}
	})
}
