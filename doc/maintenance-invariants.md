# Maintenance invariants

Properties that the implementation depends on and that are **not** obvious from
the code they live in. Every item below reads like a harmless cleanup,
simplification or optimisation when viewed locally. None of them is.

If you are about to change something on this list, the change may still be
right — but it needs analysis first, not just a green test run. The test suite
does not cover most of these.

---

## 1. `crypto/dlnproof` — keep the proof bidirectional

The proof shows that the two bases generate the *same* group; it does not show
*which* group. That reads like an incompleteness worth tightening, and it is a
natural target for anyone reconciling the comments with what the code enforces.

Leave it alone. That "same group" property is what the surrounding construction
relies on, and it is verified in both directions for a reason. Removing either
direction, or replacing the pair with a single stronger-looking check, changes
which rings production keygen will accept.

## 2. `crypto/mta` — do not shrink the `betaPrm` sampling interval

`BobMid` and `BobMidWC` sample the additive mask from `[0, q^5)`. A smaller
interval means smaller ciphertexts and less bandwidth, so it looks like free
savings.

The interval width *is* the security margin here: it exceeds the range of the
masked product by `2·log2(q)` = 512 bits, and narrowing the interval consumes
that margin one bit for one bit. Note also that the value being masked is not
of the same nature on both paths — on the `BobMidWC` side it is long-lived — so
an argument that holds for one call site does not automatically hold for the
other.

## 2b. `crypto/mta` — the prover-side ring checks decide who gets blamed

`ProveRangeAlice` and `ProveBobWC` each check the `(NTilde, h1, h2)` they are
given, before proving, and check the values they computed in it, before
returning. Both look like redundant validation of something the verifier is
about to validate anyway, and deleting them leaves every test in this tree green
except the two that exist for them.

They are not redundant, because of who owns what. Every proof here is built
under the **counterparty's** ring and verified by that **same** counterparty:
Alice's range proof uses `(NTildeB, h1B, h2B)` and Bob checks it; Bob's proof
uses `(NTildeA, h1A, h2A)` and Alice checks it. The party that supplies the
parameters is therefore also the party that judges the result. Remove the
prover-side checks and a ring whose generators have small order — which keygen
does not exclude, since it establishes nothing about the order of a peer's `h1`
and `h2`, only `<h1> == <h2>` via the bidirectional DLN pair — makes an entirely
correct proof fail its counterparty's `Verify`. The abort that follows names the
party that computed the proof.

`ecdsa/signing/round_2.go` names `Pj` on `mta.ErrRangeProofVerify`, and that is
the right answer **only** while a conforming peer cannot reach that line
honestly. The prover-side checks are what makes it true. Delete them and the
attribution silently inverts: the honest party is reported, and the party whose
parameters caused it is the one reporting.

`ringSideValuesUsable` is confined to values computed in the counterparty's ring
on purpose. Every other condition a verifier applies is a function of the local
party's own Paillier key or its own randomness, and a rejection caused by one of
those genuinely is the local party's fault. Widening the predicate past the ring
would move the error in the opposite direction — naming an innocent counterparty
— which is the same defect mirrored.

## 2c. Bound a peer's declared size before working on it, not after

Four places check something about a peer-supplied value *after* an operation
whose cost that value decides. Each reads as harmless, and each has an identical
accept set before and after the reordering, so no test in this tree goes red if
one of them is moved back.

- `crypto/modproof/proof.go#Verify` tests `pf.W`'s range before, not after,
  `isQuadraticResidue`. `NewProofFromBytes` counts parts and never measures one,
  and `KGRound2Message2.ValidateBasic` does not look at the proof at all, so `W`
  arrives unbounded; `big.Jacobi` reduces modulo `N` first, so its cost tracks
  `W`'s size while the comparisons do not. Measured: 38 ms against 2.5 ms for an
  8 MB `W`.
- The four `DeCommit()` call sites whose expected length is a function of the
  threshold — `{ecdsa,eddsa}/keygen/round_3.go` and
  `{ecdsa,eddsa}/resharing/round_4_new_step_2.go` — check the part count before
  calling, because `DeCommit` hashes every part it is handed. Measured: 458 ns
  for 7 parts against 6.6 ms for 200000.

The tempting cleanup is to push these into `ValidateBasic`, where the other 21
`NonEmptyMultiBytes` call sites state their expected length. **It cannot be done
for these four.** The length is `(t+1)*2+1` and the message layer does not know
`t`; `ecdsa/keygen`'s `TestDeCommitmentCountIsNotBoundedByTheMessageLayer` pins
that so the conclusion "the count is already bounded upstream" cannot be reached
by reading the message layer alone. The round is the first place that knows the
bound, which makes it the right place and not a lazy one.

How much any of this is worth depends on the largest message the host accepts,
which is not decided in this library.

## 3. `crypto/modproof` — `K = 80` is a security parameter

Eighty iterations of modular exponentiation is the dominant cost of
`ProofMod.Verify`, which makes `K` look like a tuning knob.

`Verify` contains no direct structural test of the modulus — the property it
attests is forced only indirectly, through those iterations, and the strength
degrades as `K` falls. Treat it the same way you would treat a hash output
length.

## 4. `ecdsa/signing` — the nonce convention is load-bearing

The library derives `R` from the *inverse* of the nonce. This is not an
arbitrary implementation choice: several analyses of this code depend on it, and
changing it to the direct form alters the algebraic relation that downstream
reasoning is built on. Do not switch conventions as part of a refactor.

## 5. `crypto/facproof` — read the scope note before relying on it

See the block comment above `ProofFac` in `crypto/facproof/proof.go`. It bounds
the shape of a declared factorisation, not the primality of its parts. The
checks that cover factor size live in `crypto/modproof` and `crypto/paillier`,
which is why neither of those may be skipped (the `NoProofMod` and `NoProofFac`
compatibility switches have both been removed).

## 6. `tss` re-sharing — the committees must stay disjoint

`tss.NewReSharingParameters` panics when a party key appears in both the old
and the new committee. It reads like over-strict input validation: nothing in
the maths forbids the same person holding a share before and after, and the
obvious "fix" for a caller who trips over it is to delete the check.

Deleting it silently re-opens a whole cascade, and **no test in this tree would
catch it**. Five `ok`-tracker pre-sets in the re-sharing rounds are gated on the
predicate for the SENDER role in that round, not on the negation of the
predicate for the RECEIVER role:

Sites are named by declaration, not by line: every one of them sits inside a
`Start()` that this tree has already grown twice, and absolute line numbers went
stale both times without anything noticing. The `pre-set` column identifies which
call inside the declaration is meant.

| site | pre-set | gated on | correct gate |
| --- | --- | --- | --- |
| `ecdsa/resharing/round_1_old_step_1.go#Start` | `allOldOK()` | `IsOldCommittee()` | `!IsNewCommittee()` |
| `ecdsa/resharing/round_3_old_step_2.go#Start` | `allOldOK()` | `IsOldCommittee()` | `!IsNewCommittee()` |
| `eddsa/resharing/round_1_old_step_1.go#Start` | `allOldOK()` | `IsOldCommittee()` | `!IsNewCommittee()` |
| `eddsa/resharing/round_2_new_step_1.go#Start` | `allNewOK()` | `IsNewCommittee()` | `!IsOldCommittee()` |
| `eddsa/resharing/round_3_old_step_2.go#Start` | `allOldOK()` | `IsOldCommittee()` | `!IsNewCommittee()` |

For a party in exactly one committee the two gates coincide, which is why the
code has always looked correct. For a party in both, each of those five lines
marks a message it is genuinely waiting for as already received. The party then
walks into the next round with empty message slots and dereferences them.

Those five lines are correct **only because the constructor now guarantees the
two committees are disjoint**. They are not defended by anything local to them.
If you need to change the disjointness rule, fix the five gates first.

The constructor's guarantee holds **at construction time only**.
`tss.NewPeerContext` keeps the caller's slice by reference,
`(*tss.PeerContext).SetIDs` replaces it wholesale, and the `*PartyID` values
remain owned by the caller — so a dual-role party can still be produced after
`NewReSharingParameters` has returned. The `rejectDualRole` guards at the top of
`Start()` and `Update()` in both `round_1_old_step_1.go` files exist for that
case. They are defence in depth, not redundancy: they stop the party before any
tracker bit is set and report **no culprits**, because a local misconfiguration
must not be attributed to an honest peer.

Related: `ecdsa/resharing/round_2_new_step_1.go:152-169` contains an
`IsOldCommittee() && IsNewCommittee()` branch written in 2019 for the dual-role
case. It is retained deliberately, as the record of what this rule replaces.

---

## 7. `keygen.BuildLocalSaveDataSubset` — the deep copy is load-bearing

`BuildLocalSaveDataSubset` deep-copies `LocalSecrets` rather than assigning it.
Both curves. It looks like an avoidable allocation of two `big.Int`s per party,
and it is not.

`LocalSecrets` holds `Xi` and `ShareID` as `*big.Int`. A struct assignment copies
the pointers, so the returned value would share the caller's numbers. Re-sharing
round 5 then does `round.input.Xi.SetInt64(0)` on the old-committee path — which,
through a shared pointer, sets the caller's own share to zero. That was the
behaviour before this copy existed: a caller that handed its save data to
`resharing.NewLocalParty` and kept using it afterwards found its share had become
0, with nothing in the API saying so.

Two things follow, and both matter to whoever reads this next.

- **If you remove the copy, the library silently starts destroying caller memory
  again, and no test in this tree will fail.** The library's own tests never
  inspect the caller's copy after a run; they read the new save data off the `end`
  channel. The regression is invisible from inside.
- **The copy is deliberately partial, and `LocalSecrets` is the whole of it.**
  Everything else in the returned value is the caller's: `LocalPreParams` is
  assigned as a struct (`PaillierSK`, `NTildei`, `H1i`, `H2i`, `Alpha`, `Beta`,
  `P`, `Q`), the public key is the caller's pointer, and the per-party slices
  (`Ks`, `NTildej`, `H1j`, `H2j`, `BigXj`, `PaillierPKs`; on EdDSA `Ks` and
  `BigXj`) are freshly allocated but hold the caller's pointers. None of it is
  secret material, which is why only `LocalSecrets` is copied. If you add code
  that writes through any of it, extend the copy first.

### The line in round 5 is not an erasure, and never was

`round_5_new_step_3.go` still does `round.input.Xi.SetInt64(0)` on the
old-committee path, and it is worth knowing exactly what that does, because the
name suggests more than the operation delivers.

`big.Int` is `{neg bool; abs []Word}`. `SetInt64(0)` truncates `abs` to length
zero. **The backing array keeps every word.** The value reads as `0` through
`Sign()` and `String()`, and the secret is still sitting in that allocation,
recoverable by anything that reaches the array. Measured on a 256-bit share: four
words before, the same four words after, `Sign() == 0`.

That is not a defect in this library so much as a property of the container. Go
offers no guaranteed way to erase a secret:

- there is no `explicit_bzero` equivalent in the standard library, and nothing
  forbids the compiler from eliminating a store whose result is never read;
- `big.Int` arithmetic reallocates its backing `nat`, so earlier copies of a
  secret are strewn through freed heap memory that no caller has a handle on;
- goroutine stacks are grown by copying, so a secret that lived on one may be
  left behind in the old stack;
- there is no `mlock`, so secrets can reach swap or a core dump.

This is the reason the standard library moved `crypto/ecdsa` and
`crypto/elliptic` off `big.Int` onto fixed-size byte arrays. If real erasure ever
becomes a requirement here, it needs a different container, not a different call
— and that is a larger change than this note.

So, plainly: **no part of this library erases a party's pre-re-share secret.**
The one line that looks like it does, does not. And even if it did, it could not
be timed correctly — an old-committee party reaches round 5 on the new
committee's round-4 ACKs, which are sent before the new committee persists
anything, so "erase once the re-share succeeded" is not a thing round 5 knows.
Erasing is the caller's decision, the caller's timing, and the caller's container.

The same misunderstanding is already in the tree elsewhere. Three sites, all of
them a pointer assignment to the package-level `var zero = big.NewInt(0)`
singleton, none of them touching the `big.Int` the name used to refer to:

- `ecdsa/keygen/round_1.go:62` — `ui = zero // clears the secret data from memory`
- `eddsa/keygen/round_1.go:80` — the same line, same comment
- `ecdsa/signing/round_5.go:84-85` — `round.temp.w = zero` / `round.temp.k = zero`,
  under `// clear temp.w and temp.k from memory, lint ignore`

All three are left as found; they are noted here so the next reader does not take
them as precedent, and so that "fixing" them is understood to require changing the
container rather than the call.

One nearby line is *not* an instance and should not be swept up with them:
`crypto/vss/feldman_vss.go:183` `secret = zero` is the identity element being
loaded into an accumulator immediately before the Lagrange sum loop, not an
attempt to erase anything.

---

## 8. `ecdsa/resharing` — re-sharing rotates the shares, not the pre-params

If the caller hands `resharing.NewLocalParty` a save data whose `LocalPreParams`
passes `ValidateWithProof()`, that set is reused **byte for byte**: the same
Paillier private key, the same NTilde trapdoor, the same `h1` and `h2` are
carried into the new committee. `round_2_new_step_1.go` prefers
`round.save.LocalPreParams` over generating a new set, and
`local_party.go#NewLocalParty` is what puts the caller's set there.

This is deliberate — regenerating safe primes costs minutes, and passing
pre-params in is the documented way to avoid that — but it means **re-sharing
refreshes the VSS shares and refreshes nothing else**. A host that re-shares in
order to recover from a suspected compromise of one party's Paillier key or
NTilde trapdoor gets no such recovery unless it leaves `LocalPreParams` unset for
that party.

Do not "simplify" this into an unconditional `GeneratePreParams`, and do not
remove the caller's ability to pass a set in. Both are load-bearing in opposite
directions. What is missing, and what section changes here should preserve, is
that the trade-off is stated where the caller chooses it: the constructor's doc
comment.

### The incomplete-pre-params path is asymmetric between keygen and re-sharing

A `LocalPreParams` that is present but incomplete — `Validate()` true,
`ValidateWithProof()` false, which is the shape older versions of this library
produced before they stored `P`, `Q`, `Alpha` and `Beta` — cannot be used, because
the round-2 DLN proofs need exactly those fields. The two entry points then do
different things with byte-identical input:

- `keygen.NewLocalParty` **panics** in the constructor.
- `resharing.NewLocalParty` **discards** it and lets round 2 generate a fresh set.

The discard is now logged. Keep it that way, or make both sides agree — but do not
make the re-sharing side silent again: round 2 sees only the zero value and cannot
tell "the caller passed an unusable set" apart from "the caller passed nothing",
so the constructor is the only place where that distinction still exists.

Note also that `round_2_new_step_1.go`'s
`Validate() && !ValidateWithProof()` guard is **unreachable** for the same reason,
and is kept only as defence in depth. It is not the place where an incomplete set
is rejected; if you are tracing that behaviour, the constructor is.

---

## Implementation note: signing round 2 is not seed-deterministic

`ecdsa/signing/round_2.go` runs `BobMid` and `BobMidWC` in two concurrent
goroutines that **share a single `round.Rand()` reader**. Under a fixed seed the
values drawn on each side therefore differ from run to run, while round 1
(single-threaded) is byte-for-byte reproducible.

Any test or diagnostic that asserts "two runs must agree byte for byte" has to
account for this, or it will report the library's own concurrency as a
reproducibility failure.

---

## 9. `signing` — the message guard is asymmetric between the curves on purpose

`ecdsa/signing/round_1.go` rejects a message hash with `m <= 0 || m >= N`.
`eddsa/signing/round_1.go` rejects only `m < 0`. That is not an oversight and must
not be "completed" by analogy.

The difference is what `m` is on each curve:

- **ECDSA** — `m` is a **scalar**. `round_5.go` computes `m*k` and
  `m*k + rx*sigma`; `round_7.go` computes `-m mod N`. Zq membership is an
  algebraic requirement, and `m == 0` collapses the share to `rx*sigma`.
- **EdDSA** — `m` only ever reaches `sha512`, in round 3's `h = H(R || A || M)`
  and in the SSID pre-image. It is never a scalar, so no interval applies.

Importing the ECDSA guard into EdDSA would reject honest input twice over: any
message longer than 32 bytes exceeds `N` once read as a `big.Int`, and `m == 0`
is a perfectly well-defined message whenever `fullBytesLen` is set, because
`FillBytes` preserves the leading zeros that `Bytes()` drops.

The general rule this stands for: **"the last fix in this family only covered one
curve" is a lead, not a conclusion.** Confirm that both sites have the same
mechanism before copying a guard across. A guard that is correct on one side can
be a false-rejection bug on the other.

### Known gap, deliberately not patched here

`fullBytesLen` decides what bytes are actually signed (`FillBytes` when non-zero,
`Bytes()` when zero) but is **not** part of the SSID pre-image, which takes
`m.Bytes()` — magnitude only, no length. Two executions with the same numeric `m`
and different `fullBytesLen` therefore share an SSID while signing different byte
strings. `fullBytesLen` is also a per-party variadic argument that nothing
compares across parties. Changing this alters SSID values and so is not a local
fix; it is tracked separately.
