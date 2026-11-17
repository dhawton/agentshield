package gcp

import "strings"

// validSubscription accepts a Pub/Sub subscription ID or full name.
func validSubscription(value string) bool {
	id := value
	if strings.Contains(value, "/") {
		parts := strings.Split(value, "/")
		if len(parts) != 4 || parts[0] != "projects" || !validProjectID(parts[1]) || parts[2] != "subscriptions" {
			return false
		}
		id = parts[3]
	}
	if len(id) < 3 || len(id) > 255 || strings.HasPrefix(id, "goog") || id[0] < 'A' || (id[0] > 'Z' && id[0] < 'a') || id[0] > 'z' {
		return false
	}
	for _, character := range id {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') && !strings.ContainsRune("-_.~+%", character) {
			return false
		}
	}
	return true
}

func validProjectID(value string) bool {
	if value == "" || len(value) > 100 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && !strings.ContainsRune("-.:", character) {
			return false
		}
	}
	return true
}
