package Elliptic

import (
    "sync"
    "testing"
)

// TestPrecomputeMatrixWithGenerator_CachesAcrossConcurrentCalls asserts the
// cache-hit property by referential pointer-equality of the returned
// precompute-matrix's [0][1].EX *big.Int across N concurrent invocations.
//
// Element [0][1] is P02 = noErrDoubling(P) — an actual product of modular
// arithmetic, allocated fresh every time PrecomputeMatrix runs. (Element
// [0][0] is the input point P itself, whose EX field aliases the fixed
// e.G.AX pointer on the Ellipse struct — that pointer is identical across
// rebuild calls and would NOT distinguish cached from rebuilt. Probing a
// computed entry is the correct discriminator.)
//
// Without a cache, every call to PrecomputeMatrixWithGenerator rebuilds the
// matrix, allocating fresh *big.Int for every computed entry — the pointer
// addresses across calls are necessarily distinct.
//
// With a one-shot-guarded cache, the populator runs exactly once and every
// caller receives the same cached matrix: all returned matrices share the
// same underlying *big.Int allocations. Pointer-equality on a computed
// entry is therefore decisive proof that the cache populated once and was
// reused.
//
// This is observable-only: the test mutates no production state and does
// not depend on any test-only counter or instrumentation in the production
// code (acceptance bullet T2.1).
func TestPrecomputeMatrixWithGenerator_CachesAcrossConcurrentCalls(t *testing.T) {
    curves := []struct {
        name    string
        factory func() Ellipse
    }{
        {"DALOS", DalosEllipse},
        {"LETO", LetoEllipse},
        {"ARTEMIS", ArtemisEllipse},
        {"APOLLO", ApolloEllipse},
    }

    for _, tc := range curves {
        tc := tc
        t.Run(tc.name, func(t *testing.T) {
            e := tc.factory()

            const N = 10
            results := make([][7][7]CoordExtended, N)

            var wg sync.WaitGroup
            wg.Add(N)
            for i := 0; i < N; i++ {
                go func(idx int) {
                    defer wg.Done()
                    results[idx] = e.PrecomputeMatrixWithGenerator()
                }(i)
            }
            wg.Wait()

            // Pointer-equality probe on a COMPUTED entry [0][1] = P02
            // (= noErrDoubling(P)). Distinct pointers across the 10
            // results mean the populator ran more than once (no cache
            // or broken cache).
            base := results[0][0][1].EX
            if base == nil {
                t.Fatalf("results[0][0][1].EX is nil — populator returned a zero-value matrix")
            }
            for i := 1; i < N; i++ {
                if results[i][0][1].EX != base {
                    t.Fatalf(
                        "PM rebuild detected at call %d: results[%d][0][1].EX = %p, expected %p (cache miss — populator ran more than once)",
                        i, i, results[i][0][1].EX, base,
                    )
                }
            }

            // Probe a deeper computed element to catch a populator that
            // returns a partially-cached matrix.
            baseDeep := results[0][6][6].EX
            for i := 1; i < N; i++ {
                if results[i][6][6].EX != baseDeep {
                    t.Fatalf(
                        "PM[6][6] rebuild detected at call %d: results[%d][6][6].EX = %p, expected %p",
                        i, i, results[i][6][6].EX, baseDeep,
                    )
                }
            }
        })
    }
}

// TestPrecomputeMatrixWithGenerator_CacheSurvivesValueCopy asserts the
// cache survives the pattern `e := DalosEllipse()` — i.e., the populator
// runs once and subsequent reads on the same value-copied Ellipse return
// the same allocation. This guards the option-(a) embedded-pointer-field
// implementation choice: pointer fields are copied (shared underlying
// memory) on return-by-value, so once-semantics survive struct copies.
//
// Holds all returned matrices live in a slice for the duration of the
// pointer-equality check so the GC cannot re-use freed addresses between
// sequential calls (which would produce a false-positive on the no-cache
// path).
func TestPrecomputeMatrixWithGenerator_CacheSurvivesValueCopy(t *testing.T) {
    e := DalosEllipse()

    const N = 5
    pms := make([][7][7]CoordExtended, N)
    for i := 0; i < N; i++ {
        pms[i] = e.PrecomputeMatrixWithGenerator()
    }

    base := pms[0][0][1].EX
    if base == nil {
        t.Fatalf("pms[0][0][1].EX is nil")
    }
    for i := 1; i < N; i++ {
        if pms[i][0][1].EX != base {
            t.Fatalf("pms[%d][0][1].EX = %p, expected %p — cache did not populate or was lost between calls", i, pms[i][0][1].EX, base)
        }
    }
}

// TestPrecomputeMatrixWithGenerator_ValueCopyAfterPopulationDoesNotPanic
// is the F-GO-001 regression guard. The pre-fix layout had
// `generatorPM *[7][7]CoordExtended` as a direct field on Ellipse — a
// value-copy made BEFORE the populator ran would have an independent nil
// generatorPM field, but a SHARED *sync.Once. After the original copy
// triggered the once, the value-copy's own once would refuse to fire
// (already done) and the read of *generatorPM would dereference nil.
//
// The fix moved both the once and the matrix slot into a single
// heap-resident *generatorPMCache holder. All value-copies now share
// the same holder pointer; the populator writes into the holder, and
// every reader sees the populated state regardless of when the copy
// was taken.
func TestPrecomputeMatrixWithGenerator_ValueCopyAfterPopulationDoesNotPanic(t *testing.T) {
    e1 := DalosEllipse()
    // Take the value-copy BEFORE any call populates the cache. With the
    // pre-fix layout, e1 and e2 would share the *sync.Once but have
    // independent nil generatorPM fields.
    e2 := e1

    // Populate via e1 first — fires the shared once. e2's holder is the
    // same pointer, so the populated matrix slot is visible to e2.
    pm1 := e1.PrecomputeMatrixWithGenerator()
    if pm1[0][1].EX == nil {
        t.Fatalf("e1 populator returned a zero-value matrix")
    }

    // Now read via e2 — would panic with the pre-fix layout because the
    // once is spent and e2.generatorPM was never assigned. Post-fix,
    // both reach into the shared *generatorPMCache and observe the same
    // matrix.
    pm2 := e2.PrecomputeMatrixWithGenerator()
    if pm2[0][1].EX == nil {
        t.Fatalf("e2 read returned a zero-value matrix — value-copy lost the cache")
    }
    if pm1[0][1].EX != pm2[0][1].EX {
        t.Fatalf("pm1[0][1].EX = %p, pm2[0][1].EX = %p — value-copy did not see the populated cache", pm1[0][1].EX, pm2[0][1].EX)
    }
}
