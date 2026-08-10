package stream

// kafka.go is the Kafka adapter: the first implementation of the ingestion
// port, and the one whose vocabulary the port deliberately refuses to borrow.
//
// Everything Kafka-shaped is in this file and stays here. Offsets, partitions
// and the consumer group appear below and nowhere else in the package; the
// commit after a confirmed batch is this adapter's own bookkeeping, not a step
// the core knows about. That is what the ordering below is for: the batch goes
// into the aggregator's transaction first and the offsets are committed only
// once that transaction returned, so a crash between the two redelivers events
// that were already applied — at-least-once, which is exactly what the port
// asks for and all it asks for. Committing first would be exactly-once
// theatre: the events would be gone and the aggregate would be short.
//
// A record that can never be accepted is dropped rather than retried forever.
// Deduplication makes redelivery safe but it does not make an unparseable
// record parseable, and a consumer that stalls on one poison record stops
// updating every velocity limit in the deployment — which is a cheaper way to
// disable a limit than any of the ones the threat model lists. The drop goes
// to a callback so the deployment can dead-letter and audit it.
//
// Authentication on this path is the broker's. There is no per-request
// credential to scope, so the (source, metric) binding a credential gets on
// the HTTP path is here a property of the topic: an operator maps a topic to a
// source and to the caller identity the broker's ACLs admit on it. Broker ACLs
// restricting produce rights on that topic are therefore mandatory, not
// advisory — without them the topic is an unauthenticated write to somebody's
// velocity aggregate.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
)

// DefaultKafkaPollRecords is how many records one poll asks for. The batch
// becomes one database transaction, so this also bounds how long a single
// transaction runs.
const DefaultKafkaPollRecords = 200

// KafkaTopic binds one topic to one velocity source.
//
// CallerID is configuration rather than anything read off a record. It is the
// caller half of the dedup key, so a record that could name its own caller
// could claim another producer's namespace and suppress its events — the same
// squatting the key's namespacing exists to prevent.
type KafkaTopic struct {
	// Topic is the Kafka topic name.
	Topic string
	// Source is the velocity source the topic feeds.
	Source string
	// CallerID is the identity the broker's ACLs admit as producer on this
	// topic. It namespaces the dedup key for every record on it.
	CallerID string
	// AllowDeduction permits negative deltas from this topic, matching the
	// separate permission an HTTP ingest credential carries.
	AllowDeduction bool
}

// KafkaRecord is the wire form of an event on a Kafka topic.
//
// It carries no metric and no caller: both come from the topic binding, so a
// record cannot choose which aggregate it lands in or whose namespace it
// claims.
type KafkaRecord struct {
	EventID    string    `json:"event_id"`
	Subject    string    `json:"subject"`
	Value      float64   `json:"value"`
	ProducedAt time.Time `json:"produced_at"`
}

// KafkaConfig configures a [Kafka].
type KafkaConfig struct {
	// Name is the adapter name a source declaration joins on. Required.
	Name string
	// Brokers are the seed broker addresses. Required.
	Brokers []string
	// Group is the consumer group. Required.
	Group string
	// Topics binds each consumed topic to a source. Required.
	Topics []KafkaTopic
	// Declarations are the velocity source declarations, which is how a source
	// name resolves to a metric. It is the same slice [NewSources] is given —
	// the adapter is built before the sources so that the sources can be built
	// against the real adapter rather than a placeholder.
	Declarations []Declaration
	// PollRecords caps one poll, and therefore one transaction. Zero selects
	// DefaultKafkaPollRecords.
	PollRecords int
	// OnReject is called for every record that can never be accepted, so a
	// deployment can dead-letter and audit it. Nil discards them.
	OnReject func(topic string, partition int32, offset int64, err error)
	// ClientOptions are extra franz-go options — TLS, SASL, timeouts. They are
	// appended after the options this adapter fixes, which are the ones its
	// correctness argument depends on.
	ClientOptions []kgo.Opt
	// Now overrides the clock. Nil means time.Now.
	Now func() time.Time
}

// Kafka is the Kafka ingestion adapter.
type Kafka struct {
	cfg    KafkaConfig
	topics map[string]kafkaBinding
	poll   int
	lag    LagTracker
}

type kafkaBinding struct {
	KafkaTopic
	metric string
}

var _ Adapter = (*Kafka)(nil)

// NewKafka builds the Kafka adapter.
//
// It does not connect. A broker that is down at startup must not stop a
// deployment from serving check requests off the aggregate it already has, and
// the freshness limit is the control that notices ingestion has stopped —
// refusing to start would replace a graceful, declared deny with an outage.
func NewKafka(cfg KafkaConfig) (*Kafka, error) {
	switch {
	case cfg.Name == "":
		return nil, errors.New("stream: the kafka adapter requires a name")
	case len(cfg.Brokers) == 0:
		return nil, errors.New("stream: the kafka adapter requires seed brokers")
	case cfg.Group == "":
		return nil, errors.New("stream: the kafka adapter requires a consumer group")
	case len(cfg.Topics) == 0:
		return nil, errors.New("stream: the kafka adapter is configured with no topics")
	case len(cfg.Declarations) == 0:
		return nil, errors.New("stream: the kafka adapter requires the velocity source declarations")
	}
	decls := indexDeclarations(cfg.Declarations)
	k := &Kafka{cfg: cfg, topics: make(map[string]kafkaBinding, len(cfg.Topics)), poll: cfg.PollRecords}
	if k.poll <= 0 {
		k.poll = DefaultKafkaPollRecords
	}
	if k.cfg.Now == nil {
		k.cfg.Now = time.Now
	}
	for _, t := range cfg.Topics {
		if t.Topic == "" {
			return nil, errors.New("stream: a kafka topic binding has no topic")
		}
		if t.CallerID == "" {
			return nil, fmt.Errorf("stream: topic %q has no caller identity; the dedup key would not be namespaced", t.Topic)
		}
		if _, dup := k.topics[t.Topic]; dup {
			return nil, fmt.Errorf("stream: topic %q is bound twice", t.Topic)
		}
		decl, ok := decls[t.Source]
		if !ok {
			return nil, fmt.Errorf("stream: topic %q feeds source %q, which is not configured", t.Topic, t.Source)
		}
		if t.AllowDeduction && !decl.AllowDeduction {
			return nil, fmt.Errorf("stream: topic %q permits deductions but source %q does not declare them", t.Topic, t.Source)
		}
		k.topics[t.Topic] = kafkaBinding{KafkaTopic: t, metric: decl.Metric}
	}
	return k, nil
}

// Name implements [Adapter].
func (k *Kafka) Name() string { return k.cfg.Name }

// ReportsLag implements [Adapter]. A record carries its producer timestamp, so
// this adapter always can.
func (k *Kafka) ReportsLag() bool { return true }

// Lag implements [Adapter].
func (k *Kafka) Lag(now time.Time) (time.Duration, bool) { return k.lag.Lag(now) }

// Run implements [Adapter]. It consumes until the context is cancelled.
func (k *Kafka) Run(ctx context.Context, sink Sink) error {
	if sink == nil {
		return ErrNotAccepting
	}
	topics := make([]string, 0, len(k.topics))
	for topic := range k.topics {
		topics = append(topics, topic)
	}
	opts := append([]kgo.Opt{
		kgo.SeedBrokers(k.cfg.Brokers...),
		kgo.ConsumerGroup(k.cfg.Group),
		kgo.ConsumeTopics(topics...),
		// The commit is manual because its ordering against the aggregator's
		// transaction is the adapter's whole correctness argument. Automatic
		// commits would move the position on a timer, with no relationship to
		// whether the batch was applied.
		kgo.DisableAutoCommit(),
	}, k.cfg.ClientOptions...)

	client, err := kgo.NewClient(opts...)
	if err != nil {
		return fmt.Errorf("stream: kafka client: %w", err)
	}
	defer client.Close()

	for {
		// The cancellation check is at the top of the loop rather than only in
		// the error path. A cancelled poll comes back as an empty fetch with a
		// context error, which is not a failure — and treating it as "nothing
		// arrived, poll again" would turn shutdown into a spin.
		if ctx.Err() != nil {
			return nil
		}
		if err := k.pollOnce(ctx, client, sink); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
	}
}

func (k *Kafka) pollOnce(ctx context.Context, client *kgo.Client, sink Sink) error {
	fetches := client.PollRecords(ctx, k.poll)
	if ctx.Err() != nil {
		return nil
	}
	if errs := fetches.Errors(); len(errs) > 0 {
		return fmt.Errorf("stream: kafka fetch from %s: %w", errs[0].Topic, errs[0].Err)
	}

	records := make([]*kgo.Record, 0, fetches.NumRecords())
	events := make([]Event, 0, fetches.NumRecords())
	fetches.EachRecord(func(r *kgo.Record) {
		ev, err := k.decode(r)
		if err != nil {
			// Unparseable now, unparseable on every redelivery. It is dropped
			// so one bad record cannot freeze the aggregate every velocity
			// limit in the deployment reads.
			k.reject(r, err)
			records = append(records, r)
			return
		}
		records = append(records, r)
		events = append(events, ev)
	})
	if len(records) == 0 {
		return nil
	}

	if len(events) > 0 {
		if err := k.apply(ctx, sink, events, records); err != nil {
			return err
		}
	}
	// The commit is last, and that ordering is the at-least-once promise: a
	// crash before it redelivers events the aggregator has already applied,
	// and deduplication makes that harmless. The reverse order would lose them.
	if err := client.CommitRecords(ctx, records...); err != nil {
		return fmt.Errorf("stream: commit: %w", err)
	}
	return nil
}

// apply hands the batch to the sink, falling back to one record at a time when
// the batch is refused.
//
// The fallback is what keeps a permanently unacceptable record — a negative
// delta on a metric that declares none, an event past the retention horizon —
// from stalling the consumer. The batch is all-or-nothing by design, so the
// only way to isolate the offender is to stop batching, and the cost of doing
// that is paid exactly once per bad record.
func (k *Kafka) apply(ctx context.Context, sink Sink, events []Event, records []*kgo.Record) error {
	_, err := sink.Accept(ctx, events)
	if err == nil {
		k.lag.Observe(events)
		return nil
	}
	if !errors.Is(err, ErrRejected) {
		return err
	}

	byID := make(map[string]*kgo.Record, len(records))
	for _, r := range records {
		byID[recordKey(r)] = r
	}
	var accepted []Event
	for _, ev := range events {
		if _, err := sink.Accept(ctx, []Event{ev}); err != nil {
			if !errors.Is(err, ErrRejected) {
				return err
			}
			k.reject(byID[eventKey(ev)], err)
			continue
		}
		accepted = append(accepted, ev)
	}
	k.lag.Observe(accepted)
	return nil
}

func (k *Kafka) decode(r *kgo.Record) (Event, error) {
	binding, ok := k.topics[r.Topic]
	if !ok {
		return Event{}, fmt.Errorf("%w: topic %q is not bound to a source", ErrRejected, r.Topic)
	}
	var rec KafkaRecord
	if err := json.Unmarshal(r.Value, &rec); err != nil {
		return Event{}, fmt.Errorf("%w: record is not a valid event document: %w", ErrRejected, err)
	}
	if rec.Value < 0 && !binding.AllowDeduction {
		return Event{}, fmt.Errorf("%w: topic %q", ErrDeductionNotPermitted, r.Topic)
	}
	ev := Event{
		CallerID:   binding.CallerID,
		EventID:    rec.EventID,
		Metric:     binding.metric,
		SubjectID:  rec.Subject,
		Value:      rec.Value,
		ProducedAt: rec.ProducedAt,
	}
	if err := ev.Validate(); err != nil {
		return Event{}, err
	}
	return ev, nil
}

func (k *Kafka) reject(r *kgo.Record, err error) {
	if k.cfg.OnReject == nil || r == nil {
		return
	}
	k.cfg.OnReject(r.Topic, r.Partition, r.Offset, err)
}

// recordKey and eventKey agree on how a record and the event decoded from it
// are matched up when the batch has to be retried one at a time.
func recordKey(r *kgo.Record) string {
	var rec KafkaRecord
	if err := json.Unmarshal(r.Value, &rec); err != nil {
		return ""
	}
	return r.Topic + "\x1f" + rec.EventID
}

func eventKey(ev Event) string { return ev.Metric + "\x1f" + ev.EventID }

// EncodeKafkaRecord renders an event as the value bytes a producer publishes.
// It is exported because a producer in this repository — a test, a demo
// loader — must encode the same shape the adapter decodes, and two copies of
// that shape would drift.
func EncodeKafkaRecord(rec KafkaRecord) ([]byte, error) {
	data, err := json.Marshal(rec)
	if err != nil {
		return nil, fmt.Errorf("stream: encode kafka record: %w", err)
	}
	return data, nil
}
