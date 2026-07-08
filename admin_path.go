package fingers

import "strings"

const adminPathDetectName = "AdminPath"

var basicAdminBackendPaths = []string{
	"/console",
	"/console/",
	"/backend",
	"/backend/",
	"/admin",
	"/admin/",
	"/manager",
	"/manager/",
	"/manage",
	"/manage/",
	"/login",
	"/login/",
	"/report",
	"/report/",
}

func differentFingerprintMatches(fingerprints []FingerprintMatch, known []string) []FingerprintMatch {
	if len(fingerprints) == 0 {
		return nil
	}

	knownSet := make(map[string]struct{}, len(known))
	for _, name := range known {
		if name == "" {
			continue
		}
		knownSet[name] = struct{}{}
	}

	results := make([]FingerprintMatch, 0, len(fingerprints))
	for _, fp := range fingerprints {
		if _, ok := knownSet[fp.Name]; ok {
			continue
		}
		results = append(results, fp)
	}
	return results
}

func deduplicateAdminPathResult(result Result, seen map[string]struct{}) (Result, bool) {
	if len(result.Fingerprints) == 0 {
		return result, false
	}

	target := adminPathDedupeTarget(result)
	path := normalizeAdminPathForDedupe(result.Path)
	filtered := make([]FingerprintMatch, 0, len(result.Fingerprints))
	for _, fp := range result.Fingerprints {
		key := target + "\x00" + path + "\x00" + fp.Name
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		filtered = append(filtered, fp)
	}
	result.Fingerprints = filtered
	return result, len(result.Fingerprints) > 0
}

func adminPathDedupeTarget(result Result) string {
	normalizedPath := normalizeAdminPathForDedupe(result.Path)
	rawURL := strings.TrimRight(result.URL, "/")
	if normalizedPath != "" && normalizedPath != "/" && strings.HasSuffix(rawURL, normalizedPath) {
		return strings.TrimRight(strings.TrimSuffix(rawURL, normalizedPath), "/")
	}
	if result.Scheme != "" && result.Host != "" {
		return result.Scheme + "://" + result.Host
	}
	return rawURL
}

func normalizeAdminPathForDedupe(path string) string {
	path = strings.TrimSpace(path)
	if path == "" || path == "/" {
		return "/"
	}
	if normalized := strings.TrimRight(path, "/"); normalized != "" {
		return normalized
	}
	return "/"
}
