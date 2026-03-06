package cloudtrail

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
)

// Event represents a single CloudTrail API call with its principal, action, and resource.
type Event struct {
	Principal string
	Service   string
	Action    string
	Resource  string
	AccountID string
	Region    string
	EventTime time.Time
}

// EventCollection maps "service:action" -> set of resources.
type EventCollection map[string]map[string]struct{}

// ActionCount returns the number of unique service:action pairs.
func (ec EventCollection) ActionCount() int {
	return len(ec)
}

// Add adds a service:action -> resource mapping.
func (ec EventCollection) Add(service, action, resource string) {
	key := fmt.Sprintf("%s:%s", service, action)
	if ec[key] == nil {
		ec[key] = make(map[string]struct{})
	}
	ec[key][resource] = struct{}{}
}

// Merge merges another EventCollection into this one.
func (ec EventCollection) Merge(other EventCollection) {
	for key, resources := range other {
		if ec[key] == nil {
			ec[key] = make(map[string]struct{})
		}
		for r := range resources {
			ec[key][r] = struct{}{}
		}
	}
}

// CollectOptions holds parameters for collecting CloudTrail events.
type CollectOptions struct {
	Principal string
	Service   string
	Days      int
}

// Collector collects CloudTrail events using AWS SDK v2.
type Collector struct {
	cfg aws.Config
}

// NewCollector creates a new Collector with the given AWS config.
func NewCollector(cfg aws.Config) *Collector {
	return &Collector{cfg: cfg}
}

// Collect queries CloudTrail LookupEvents and returns an EventCollection.
func (c *Collector) Collect(ctx context.Context, opts CollectOptions) (EventCollection, error) {
	client := cloudtrail.NewFromConfig(c.cfg)

	endTime := time.Now()
	startTime := endTime.AddDate(0, 0, -opts.Days)

	input := &cloudtrail.LookupEventsInput{
		StartTime: aws.Time(startTime),
		EndTime:   aws.Time(endTime),
		MaxResults: aws.Int32(50),
	}

	// Filter by username/principal if specified
	if opts.Principal != "" {
		// Extract the last part of the ARN as the username for lookup
		username := extractUsername(opts.Principal)
		slog.Info("filtering by principal", "principal", opts.Principal, "lookup_username", username)
		input.LookupAttributes = []types.LookupAttribute{
			{
				AttributeKey:   types.LookupAttributeKeyUsername,
				AttributeValue: aws.String(username),
			},
		}
	}

	collection := make(EventCollection)
	paginator := cloudtrail.NewLookupEventsPaginator(client, input)

	pageCount := 0
	eventCount := 0

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("lookup events page %d: %w", pageCount, err)
		}
		pageCount++

		for _, event := range page.Events {
			parsed, ok := parseEvent(event, opts.Principal, opts.Service)
			if !ok {
				continue
			}
			collection.Add(parsed.Service, parsed.Action, parsed.Resource)
			eventCount++
		}

		slog.Debug("processed page", "page", pageCount, "events_in_page", len(page.Events))
	}

	slog.Info("cloudtrail collection complete", "pages", pageCount, "matched_events", eventCount)
	return collection, nil
}

// parseEvent converts a CloudTrail event into our internal Event struct.
// Returns false if the event should be filtered out.
func parseEvent(event types.Event, principalFilter, serviceFilter string) (Event, bool) {
	if event.EventName == nil || event.EventSource == nil {
		return Event{}, false
	}

	// event.EventSource is like "s3.amazonaws.com" -> service = "s3"
	service := strings.TrimSuffix(aws.ToString(event.EventSource), ".amazonaws.com")

	// Filter by service if requested
	if serviceFilter != "" && service != strings.ToLower(serviceFilter) {
		return Event{}, false
	}

	action := aws.ToString(event.EventName)
	principal := ""
	if event.Username != nil {
		principal = aws.ToString(event.Username)
	}

	// Filter by principal if specified (match on the full ARN or username portion)
	if principalFilter != "" {
		username := extractUsername(principalFilter)
		if principal != username && principal != principalFilter {
			return Event{}, false
		}
	}

	// Collect resource ARNs; fall back to wildcard if none found
	resource := "*"
	if len(event.Resources) > 0 {
		var names []string
		for _, r := range event.Resources {
			if r.ResourceName != nil {
				names = append(names, aws.ToString(r.ResourceName))
			}
		}
		if len(names) == 1 {
			resource = names[0]
		} else if len(names) > 1 {
			// Use wildcard when multiple resources are involved — caller can tighten later
			resource = "*"
		}
	}

	eventTime := time.Time{}
	if event.EventTime != nil {
		eventTime = aws.ToTime(event.EventTime)
	}

	return Event{
		Principal: principal,
		Service:   service,
		Action:    action,
		Resource:  resource,
		EventTime: eventTime,
	}, true
}

// extractUsername returns the last segment of an ARN, or the full string if not an ARN.
func extractUsername(principal string) string {
	if !strings.Contains(principal, ":") {
		return principal
	}
	parts := strings.Split(principal, "/")
	if len(parts) > 1 {
		return parts[len(parts)-1]
	}
	// e.g. arn:aws:iam::123:root — return everything after last ":"
	colonParts := strings.Split(principal, ":")
	return colonParts[len(colonParts)-1]
}
