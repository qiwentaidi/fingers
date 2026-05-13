package fingers

import (
	"net/url"
	"testing"
)

func TestResolveIconLink(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		pageURL  string
		iconLink string
		want     string
	}{
		{
			name:     "root absolute path",
			pageURL:  "http://localhost:3003/console/#/home/dashboard",
			iconLink: "/console/favicon.ico",
			want:     "http://localhost:3003/console/favicon.ico",
		},
		{
			name:     "relative path under nested route",
			pageURL:  "http://localhost:3003/console/",
			iconLink: "favicon.ico",
			want:     "http://localhost:3003/console/favicon.ico",
		},
		{
			name:     "scheme relative path",
			pageURL:  "https://example.com/app/",
			iconLink: "//cdn.example.com/favicon.ico",
			want:     "https://cdn.example.com/favicon.ico",
		},
		{
			name:     "absolute url",
			pageURL:  "https://example.com/app/",
			iconLink: "https://static.example.com/favicon.png",
			want:     "https://static.example.com/favicon.png",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			pageURL, err := url.Parse(tc.pageURL)
			if err != nil {
				t.Fatalf("parse page URL: %v", err)
			}

			got, err := resolveIconLink(pageURL, tc.iconLink)
			if err != nil {
				t.Fatalf("resolve icon link: %v", err)
			}

			if got != tc.want {
				t.Fatalf("resolveIconLink() = %q, want %q", got, tc.want)
			}
		})
	}
}
