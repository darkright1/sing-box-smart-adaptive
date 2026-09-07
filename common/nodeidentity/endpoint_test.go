package nodeidentity

import "testing"

func TestCanonicalEndpointOptionsStripsNestedCredentials(t *testing.T) {
	value, err := CanonicalEndpointOptions(map[string]any{
		"server":   "example.com",
		"password": "hidden",
		"tls":      map[string]any{"headers": map[string]any{"authorization": "hidden"}, "server_name": "example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	result := value.(map[string]any)
	if _, ok := result["password"]; ok {
		t.Fatal("top-level credential was retained")
	}
	tls := result["tls"].(map[string]any)
	if headers, ok := tls["headers"].(map[string]any); !ok || len(headers) != 0 {
		t.Fatalf("nested credential headers were retained: %#v", tls["headers"])
	}
	if tls["server_name"] != "example.com" {
		t.Fatalf("endpoint field changed: %#v", tls["server_name"])
	}
}

func TestCanonicalEndpointOptionsKeepsNonCredentialHeaders(t *testing.T) {
	value, err := CanonicalEndpointOptions(map[string]any{
		"server": "example.com",
		"headers": map[string]any{
			"Host":          "origin.example.com",
			"User-Agent":    "sing-box",
			"Authorization": "Bearer secret",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	headers := value.(map[string]any)["headers"].(map[string]any)
	if headers["Host"] != "origin.example.com" || headers["User-Agent"] != "sing-box" {
		t.Fatalf("non-credential headers were lost: %#v", headers)
	}
	if _, ok := headers["Authorization"]; ok {
		t.Fatal("authorization header was retained")
	}
}
