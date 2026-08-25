package policy

// This file holds the compliant shapes the harness shows alongside a rule's
// rationale, for the three rules where every operator otherwise designs the
// target idiom from scratch and each of them designs it differently.
//
// They are prose in the registry rather than code in a package because they are
// what a reader should write in their own repository, in their own types. The
// harness never generates them and never checks that a fix matches one.

// errcheckPattern answers the question the field data forced: one rule produced
// four unrelated remedies, and grouping by the discarded callee turns hundreds
// of rows into a handful of decisions.
//
// The encode case is the harness's position on a pack that would otherwise
// contradict itself. A linter that proves a json.Marshal cannot fail then
// objects to checking its error, while errcheck objects to discarding it; the
// two positions cannot both be satisfied at the call site, and no configuration
// language expresses "this linter's proof settles that linter's finding". A
// typed helper that owns the decision once is the Go answer, and the operator
// should not have to invent it.
const errcheckPattern = `The remedy differs by what was discarded. Take the remedyClass on the finding.

resource-close: keep the failure, do not invent a place to put it.
    func read(name string) (err error) {
        f, openErr := os.Open(name)
        if openErr != nil {
            return openErr
        }
        defer func() { err = errors.Join(err, f.Close()) }()
        ...
    }
For a read-only handle whose close cannot fail meaningfully, say so once, in
one helper, rather than at every call site:
    // closeReading closes a handle opened for reading, where a close error
    // reports nothing the read did not already report.
    func closeReading(c io.Closer) { _ = c.Close() }

cleanup: a rollback after a commit is expected to fail; anything else is not.
    defer func() {
        if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
            log.Error("rollback failed", "err", rbErr)
        }
    }()

encode: prove it once in a typed helper, and let the type carry the proof.
    // mustEncodeJSON marshals a value whose type contains no channel, function,
    // or cyclic pointer, so json.Marshal has no failure mode left to report.
    // The type parameter is what keeps that argument checkable by a reader.
    func encodeJSON[T Serializable](v T) []byte {
        out, err := json.Marshal(v)
        if err != nil {
            panic(fmt.Sprintf("unserializable %T reached encodeJSON: %v", v, err))
        }
        return out
    }
The check lives in one place, the proof is stated where it can be reviewed, and
no call site carries a discard.

diagnostic: an unwritable stderr is not a defect in the caller's logic, but it
is still a fact. Write through a helper that owns the decision.

domain-write: this is the class the rule exists for. Handle it.
    if err := s.store.Audit(ctx, event); err != nil {
        return fmt.Errorf("recording audit event %s: %w", event.ID, err)
    }
If the write is genuinely best-effort, that is a design decision and belongs in
the code as one, with the failure observable:
    if err := s.store.Audit(ctx, event); err != nil {
        s.metrics.AuditWriteFailed.Inc()
        s.log.Error("audit trail write dropped", "event", event.ID, "err", err)
    }
A discard with no observer means nobody will ever learn the trail has holes.`

// goroutineInLoopPattern shows the bound the rule is asking for, in the form
// the language now offers directly. The rule fires on a spawn count that comes
// from input; it must never push anyone towards decorating a pool that is
// already bounded with a semaphore that changes nothing.
const goroutineInLoopPattern = `Bound the number of goroutines by something the reader can see.

A fixed-size pool, where the bound is a constant or a validated config field:
    const transcriptionWorkers = 4

    for range transcriptionWorkers {
        go w.run(ctx)
    }
The iteration count is the bound, so no semaphore is needed and adding one would
only be decoration.

Work that scales with input belongs behind a limit rather than behind a
goroutine each:
    sem := semaphore.NewWeighted(int64(runtime.GOMAXPROCS(0)))
    group, ctx := errgroup.WithContext(ctx)
    for _, item := range items {
        if err := sem.Acquire(ctx, 1); err != nil {
            return err
        }
        group.Go(func() error {
            defer sem.Release(1)
            return handle(ctx, item)
        })
    }
    return group.Wait()

Or feed a fixed pool through a channel, so the work is unbounded and the
concurrency is not:
    jobs := make(chan Item)
    for range workerCount {
        go func() {
            for item := range jobs {
                handle(ctx, item)
            }
        }()
    }`

// testNoAssertionPattern separates executing code from observing it, which is
// the distinction the rule is built on and the one an agent-written test most
// often loses.
const testNoAssertionPattern = `A test has to be able to fail. Observe a result, not the absence of a panic.

Not a test:
    func TestNilReceiverIsSafe(t *testing.T) {
        var s *Store
        s.Close()
    }
It passes whether Close is correct, empty, or silently corrupting.

A test:
    func TestCloseOnNilReceiverIsANoOp(t *testing.T) {
        var s *Store
        if err := s.Close(); err != nil {
            t.Fatalf("Close on a nil receiver: %v", err)
        }
        if s.openConnections() != 0 {
            t.Fatalf("a nil receiver reported %d open connections", s.openConnections())
        }
    }

The question to ask of any test: what would I have to break for this to fail?
If the answer is "nothing that matters", the test observes execution rather than
behaviour, and the suite it belongs to overstates what it proves.`
