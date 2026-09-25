# Architecture decision records

A decision lands here when it changes what Shapoclyack ships or promises across
components and releases — what a customer receives, verifies or depends on —
rather than how one feature works. Feature design stays in its own guide.

| # | Decision | Status | Issue |
|---|---|---|---|
| [0001](0001-pulse-distribution-model.md) | Distribution model for the default Pulse backend | **Proposed** — decision by the owner | [#340](https://github.com/onixus/Shapoclyack/issues/340) |

Decisions taken before this directory existed are recorded where they were
made: the endpoint-inventory decisions in
[Agent_plan.md §17](../../Agent_plan.md#17-architecture-decision-records-adrs).

## Conventions

- One file per decision, `NNNN-short-title.md`, numbered in order of creation.
  Numbers are never reused.
- **Status** is one of *Proposed*, *Accepted*, *Rejected* or *Superseded by
  NNNN*. A *Proposed* record is a question to the owner: its recommendation is
  not policy, and nothing in the product may depend on it, until the record is
  *Accepted*. The person who accepts it is named with the date.
- An accepted record is not rewritten when the decision changes. A new record
  supersedes it and both link to each other, so the reasoning that was true at
  the time stays readable.
- Sections: *Context* (facts, with file references), *Decision drivers*,
  *Options*, *Recommendation* or *Decision*, *Consequences*, and *Not decided
  here* — the neighbouring decisions the record deliberately leaves to other
  issues.
- Facts are cited to code or to a measurement with its environment. A record
  that needs a number nobody has measured says so instead of estimating it.
