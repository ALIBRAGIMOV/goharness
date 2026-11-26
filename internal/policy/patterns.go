package policy

// This file holds the compliant shapes the harness shows alongside a rule's
// rationale, for the three rules where every operator otherwise designs the
// target idiom from scratch and each of them designs it differently.
//
// They are prose in the registry rather than code in a package because they are
// what a reader should write in their own repository, in their own types. The
// harness never generates them and never checks that a fix matches one.

// errcheckPattern exists because one rule covers four unrelated remedies, and
// grouping by the discarded callee turns hundreds of rows into a handful of
// decisions.
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
            slog.Error("rollback failed", "err", rbErr)
        }
    }()

encode: prove it once in a helper named for what it does on failure.
    // mustEncodeJSON marshals a value whose type holds no channel, function,
    // or cyclic pointer, so json.Marshal has no failure left to report. A
    // failure here is a programming error, which is what the Must prefix says,
    // as it does for regexp.MustCompile and template.Must.
    func mustEncodeJSON(v Record) []byte {
        out, err := json.Marshal(v)
        if err != nil {
            panic(fmt.Sprintf("encoding %T: %v", v, err))
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
    const workers = 4

    var wg sync.WaitGroup
    for range workers {
        wg.Go(func() { w.run(ctx) })
    }
    wg.Wait()
The iteration count is the bound, so no semaphore is needed and adding one would
only be decoration. wg.Wait is the termination path, visible where the
goroutines start.

Work that scales with input belongs behind a limit rather than behind a
goroutine each:
    group, ctx := errgroup.WithContext(ctx)
    group.SetLimit(runtime.GOMAXPROCS(0))
    for _, item := range items {
        group.Go(func() error { return handle(ctx, item) })
    }
    return group.Wait()

Or feed a fixed pool through a channel, so the work is unbounded and the
concurrency is not:
    jobs := make(chan Item)
    var wg sync.WaitGroup
    for range workerCount {
        wg.Go(func() {
            for item := range jobs {
                handle(ctx, item)
            }
        })
    }
    for _, item := range items {
        jobs <- item
    }
    close(jobs)
    wg.Wait()`

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
