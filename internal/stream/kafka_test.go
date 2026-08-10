package stream_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"

	tckafka "github.com/testcontainers/testcontainers-go/modules/kafka"

	"github.com/d0lim/stamp/internal/fact"
	"github.com/d0lim/stamp/internal/stream"
)

// The Kafka adapter's own tests, and the only place in this package a broker
// appears.
//
// They start their broker here rather than in TestMain on purpose. Every
// aggregation test in this package must pass with no broker at all — that is
// the unit's verification gate and the evidence that the ingestion port is a
// seam rather than a Kafka interface with a neutral name — and a container
// started in TestMain would start for those runs too. With it here,
// `go test -skip Kafka ./internal/stream/` runs the whole aggregation suite
// and never contacts a broker.

const kafkaImage = "confluentinc/confluent-local:7.5.0"

var (
	kafkaOnce    sync.Once
	kafkaBrokers []string
	kafkaErr     error
	kafkaSerial  atomic.Int64
)

func brokers(t *testing.T) []string {
	t.Helper()
	kafkaOnce.Do(func() {
		ctx := context.Background()
		container, err := tckafka.Run(ctx, kafkaImage, tckafka.WithClusterID("stamp-test"))
		if err != nil {
			kafkaErr = err
			return
		}
		kafkaBrokers, kafkaErr = container.Brokers(ctx)
	})
	if kafkaErr != nil {
		t.Fatalf("kafka adapter tests need a working Docker daemon: %v", kafkaErr)
	}
	return kafkaBrokers
}

// kafkaHarness is the velocity source fed through a real broker.
type kafkaHarness struct {
	*sourcesHarness
	topic   string
	adapter *stream.Kafka
	brokers []string
	decls   []stream.Declaration
	drops   chan error
}

func newKafkaHarness(t *testing.T) *kafkaHarness {
	t.Helper()
	seeds := brokers(t)
	topic := "withdrawals-" + time.Now().Format("150405") + "-" + string(rune('a'+kafkaSerial.Add(1)%26))

	// The velocity source is declared against the kafka adapter rather than the
	// ingest one, which is the only difference from the brokerless
	// configuration. The wiring order is the same: declarations, aggregator,
	// adapter, sources.
	c := newClock()
	decl := baseDecl()
	decl.Adapter = "kafka"
	decls := []stream.Declaration{decl}

	agg, err := stream.NewAggregator(stream.AggregatorConfig{
		Store: openStore(t, c.Now), Metrics: stream.MetricSpecsFor(decls), Now: c.Now,
	})
	if err != nil {
		t.Fatalf("new aggregator: %v", err)
	}

	drops := make(chan error, 8)
	adapter, err := stream.NewKafka(stream.KafkaConfig{
		Name:    "kafka",
		Brokers: seeds,
		Group:   "stamp-" + topic,
		Topics: []stream.KafkaTopic{{
			Topic: topic, Source: sourceName, CallerID: "workload:kafka#" + topic,
		}},
		Declarations: decls,
		Now:          c.Now,
		OnReject: func(_ string, _ int32, _ int64, err error) {
			select {
			case drops <- err:
			default:
			}
		},
	})
	if err != nil {
		t.Fatalf("new kafka adapter: %v", err)
	}
	sources, err := stream.NewSources(decls, stream.SourcesConfig{
		Aggregator: agg, Adapters: []stream.Adapter{adapter}, Now: c.Now,
	})
	if err != nil {
		t.Fatalf("new sources: %v", err)
	}

	return &kafkaHarness{
		sourcesHarness: &sourcesHarness{sources: sources, agg: agg, clock: c},
		topic:          topic,
		adapter:        adapter,
		brokers:        seeds,
		decls:          decls,
		drops:          drops,
	}
}

// publish writes records to the harness's topic.
func (h *kafkaHarness) publish(t *testing.T, recs ...stream.KafkaRecord) {
	t.Helper()
	client, err := kgo.NewClient(
		kgo.SeedBrokers(h.brokers...),
		kgo.AllowAutoTopicCreation(),
	)
	if err != nil {
		t.Fatalf("kafka producer: %v", err)
	}
	defer client.Close()
	for _, rec := range recs {
		value, err := stream.EncodeKafkaRecord(rec)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		if err := client.ProduceSync(t.Context(), &kgo.Record{Topic: h.topic, Value: value}).FirstErr(); err != nil {
			t.Fatalf("produce: %v", err)
		}
	}
}

// publishRaw writes bytes that are not a valid event document.
func (h *kafkaHarness) publishRaw(t *testing.T, value []byte) {
	t.Helper()
	client, err := kgo.NewClient(kgo.SeedBrokers(h.brokers...), kgo.AllowAutoTopicCreation())
	if err != nil {
		t.Fatalf("kafka producer: %v", err)
	}
	defer client.Close()
	if err := client.ProduceSync(t.Context(), &kgo.Record{Topic: h.topic, Value: value}).FirstErr(); err != nil {
		t.Fatalf("produce: %v", err)
	}
}

// consume runs the adapter until the aggregate for subject reaches want, or
// the deadline passes. It uses the adapter under test rather than a second
// consumer so that what is being waited on is the thing being asserted.
func (h *kafkaHarness) consume(t *testing.T, adapter *stream.Kafka, subject string, want float64) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- adapter.Run(ctx, h.agg) }()

	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		v, err := h.sources.Lookup(t.Context(), sourceName, fact.String(subject))
		if err == nil && v.Data == want {
			cancel()
			if err := <-done; err != nil {
				t.Fatalf("adapter Run: %v", err)
			}
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	cancel()
	<-done
	v, _ := h.sources.Lookup(t.Context(), sourceName, fact.String(subject))
	t.Fatalf("aggregate for %s settled at %#v, want %v", subject, v.Data, want)
}

// A Kafka-fed source reaches the same aggregate the brokerless path reaches
// from the same events. Nothing in the aggregator distinguishes the two, which
// is the property the port exists to make true.
func TestKafkaAdapterFeedsTheSameAggregate(t *testing.T) {
	h := newKafkaHarness(t)
	h.publish(t,
		stream.KafkaRecord{EventID: "e1", Subject: "user-1", Value: 120, ProducedAt: h.clock.Now().Add(-3 * time.Hour)},
		stream.KafkaRecord{EventID: "e2", Subject: "user-1", Value: 380, ProducedAt: h.clock.Now().Add(-time.Hour)},
		stream.KafkaRecord{EventID: "e3", Subject: "user-1", Value: 55, ProducedAt: h.clock.Now()},
	)
	h.consume(t, h.adapter, "user-1", 555)

	// The same total the ingest adapter produced from the same three events in
	// TestBothAdaptersProduceTheSameAggregate.
	if lag, ok := h.adapter.Lag(h.clock.Now()); !ok || lag != 0 {
		t.Errorf("lag = %s (reported %v), want 0 — the newest record was produced at now", lag, ok)
	}
}

// A record redelivered by a consumer that restarted without having committed
// is applied once. The whole uncommitted range is replayed here by pointing a
// second consumer group at the topic from the beginning, which is the same
// thing from the aggregator's side and is deterministic.
func TestKafkaReplayDoesNotDoubleCount(t *testing.T) {
	h := newKafkaHarness(t)
	h.publish(t,
		stream.KafkaRecord{EventID: "e1", Subject: "user-1", Value: 200, ProducedAt: h.clock.Now().Add(-time.Hour)},
		stream.KafkaRecord{EventID: "e2", Subject: "user-1", Value: 300, ProducedAt: h.clock.Now()},
	)
	h.consume(t, h.adapter, "user-1", 500)

	replay, err := stream.NewKafka(stream.KafkaConfig{
		Name:    "kafka",
		Brokers: h.brokers,
		Group:   "stamp-replay-" + h.topic,
		Topics: []stream.KafkaTopic{{
			Topic: h.topic, Source: sourceName, CallerID: "workload:kafka#" + h.topic,
		}},
		Declarations: h.decls,
		Now:          h.clock.Now,
	})
	if err != nil {
		t.Fatalf("replay adapter: %v", err)
	}
	// The aggregate is already 500; a replay that double counted would take it
	// to 1000, so waiting for 500 and then asserting it is what catches the
	// failure. Give the replay time to actually consume first.
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- replay.Run(ctx, h.agg) }()
	<-ctx.Done()
	if err := <-done; err != nil {
		t.Fatalf("replay Run: %v", err)
	}

	v, err := h.sources.Lookup(t.Context(), sourceName, fact.String("user-1"))
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if v.Data != 500.0 {
		t.Errorf("aggregate after a full replay = %#v, want 500.0", v.Data)
	}
}

// A record that can never be accepted is dropped rather than retried forever,
// and the records around it are still applied. A consumer stalled on one
// poison record stops updating every velocity limit in the deployment, which
// is a cheaper way to disable a limit than forging events.
func TestKafkaPoisonRecordDoesNotStallTheConsumer(t *testing.T) {
	h := newKafkaHarness(t)
	h.publish(t, stream.KafkaRecord{
		EventID: "e1", Subject: "user-1", Value: 100, ProducedAt: h.clock.Now(),
	})
	h.publishRaw(t, []byte("{not json"))
	h.publish(t, stream.KafkaRecord{
		EventID: "e2", Subject: "user-1", Value: 250, ProducedAt: h.clock.Now(),
	})
	// A record with no producer identifier is refused by the port itself.
	h.publish(t, stream.KafkaRecord{Subject: "user-1", Value: 900, ProducedAt: h.clock.Now()})
	h.publish(t, stream.KafkaRecord{
		EventID: "e3", Subject: "user-1", Value: 50, ProducedAt: h.clock.Now(),
	})

	h.consume(t, h.adapter, "user-1", 400)

	select {
	case <-h.drops:
	default:
		t.Error("no record was reported as dropped")
	}
}
