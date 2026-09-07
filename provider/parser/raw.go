package parser

import (
	"context"
	"encoding/base64"
	"strings"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func ParseRawSubscription(ctx context.Context, content string) ([]option.Outbound, []option.Endpoint, error) {
	providerTag := providerTagFromContext(ctx)
	if base64Content, err := DecodeBase64URLSafe(content); err == nil {
		servers, parseErr := parseRawSubscription(base64Content, providerTag)
		if len(servers) > 0 {
			return servers, nil, parseErr
		}
	}
	outbounds, err := parseRawSubscription(content, providerTag)
	return outbounds, nil, err
}

func parseRawSubscription(content, providerTag string) ([]option.Outbound, error) {
	var servers []option.Outbound
	var parseErrors []error
	content = strings.ReplaceAll(content, "\r\n", "\n")
	for index, linkLine := range strings.Split(content, "\n") {
		if strings.TrimSpace(linkLine) == "" {
			continue
		}
		server, err := ParseSubscriptionLink(linkLine)
		if err != nil {
			// Keep the source line out of errors: raw subscriptions can contain
			// passwords or signed query strings. The caller logs only this bounded
			// reason and line number.
			parseErrors = append(parseErrors, E.Cause(err, "line ", index+1))
			warnIgnoredProviderMember(providerTag, "raw", index, "", rawProtocol(linkLine), err)
			continue
		}
		servers = append(servers, server)
	}
	if len(servers) == 0 {
		return nil, E.Errors(E.New("no servers found"), E.Errors(parseErrors...))
	}
	return servers, E.Errors(parseErrors...)
}

func rawProtocol(line string) string {
	if protocol, _, ok := strings.Cut(strings.TrimSpace(line), "://"); ok {
		return protocol
	}
	return ""
}

func DecodeBase64URLSafe(content string) (string, error) {
	s := strings.ReplaceAll(content, " ", "-")
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "+", "-")
	s = strings.ReplaceAll(s, "=", "")
	result, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return content, nil
	}
	return string(result), nil
}
