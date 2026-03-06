package policy

import (
	"fmt"
	"sort"
	"strings"

	"github.com/nelssec/iam-advisor/internal/cloudtrail"
)

// Document represents a valid IAM policy document.
type Document struct {
	Version   string      `json:"Version"`
	Statement []Statement `json:"Statement"`
}

// Statement represents a single IAM policy statement.
type Statement struct {
	Sid      string   `json:"Sid,omitempty"`
	Effect   string   `json:"Effect"`
	Action   []string `json:"Action"`
	Resource []string `json:"Resource"`
}

// Generate produces a least-privilege IAM policy Document from an EventCollection.
// It groups actions by their resource set so that actions sharing the same resources
// are combined into a single statement.
func Generate(events cloudtrail.EventCollection) Document {
	// resourceKey -> list of "service:Action"
	resourceToActions := make(map[string][]string)

	for actionKey, resources := range events {
		// Build a canonical resource key (sorted resource ARNs joined)
		resourceList := sortedKeys(resources)
		resourceKey := strings.Join(resourceList, "|")
		resourceToActions[resourceKey] = append(resourceToActions[resourceKey], actionKey)
	}

	var statements []Statement
	stmtIdx := 1

	// Sort resource keys for deterministic output
	sortedResourceKeys := make([]string, 0, len(resourceToActions))
	for k := range resourceToActions {
		sortedResourceKeys = append(sortedResourceKeys, k)
	}
	sort.Strings(sortedResourceKeys)

	for _, resourceKey := range sortedResourceKeys {
		actions := resourceToActions[resourceKey]
		sort.Strings(actions)

		resources := strings.Split(resourceKey, "|")
		// Capitalise the action names correctly: cloudtrail returns EventName
		// already in PascalCase; service prefix should be lowercase.
		normalised := make([]string, 0, len(actions))
		for _, a := range actions {
			normalised = append(normalised, normaliseAction(a))
		}

		stmt := Statement{
			Sid:      fmt.Sprintf("Stmt%d", stmtIdx),
			Effect:   "Allow",
			Action:   normalised,
			Resource: resources,
		}
		statements = append(statements, stmt)
		stmtIdx++
	}

	if len(statements) == 0 {
		// Return an empty but valid policy
		return Document{
			Version:   "2012-10-17",
			Statement: []Statement{},
		}
	}

	return Document{
		Version:   "2012-10-17",
		Statement: statements,
	}
}

// normaliseAction ensures the action is in "service:Action" format with lowercase service.
func normaliseAction(action string) string {
	parts := strings.SplitN(action, ":", 2)
	if len(parts) != 2 {
		return action
	}
	return strings.ToLower(parts[0]) + ":" + parts[1]
}

// sortedKeys returns the keys of a map[string]struct{} in sorted order.
func sortedKeys(m map[string]struct{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
