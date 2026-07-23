# Annex IV technical documentation generator

Annex IV of the EU AI Act lists nine sections of technical documentation.
Most teams start it as a blank Word document, which is why most teams do not
start it.

`flugschreiber report` produces a Markdown skeleton with the sections that can
be derived from observed traffic already filled in, and everything else marked
`TODO` with one sentence on what belongs there. It is a starting point, not a
submission.

## Running it

```bash
flugschreiber report \
  --dir /var/lib/flugschreiber \
  --out ./reports \
  --organisation "Muster GmbH" \
  --system-name "Support Assistant" \
  --purpose "drafting first-line support replies for human review" \
  --contact "ai-governance@muster.example"
```

```
generated 3 artifact(s) from 1284 record(s):

  reports/technical-documentation.md       Annex IV technical documentation skeleton
  reports/transparency-article-50-en.md    Article 50 transparency pack (English)
  reports/transparency-article-50-de.md    Article 50 transparency pack (German)

  evidence chain    intact (1284 records, 2026-05-01 to 2026-07-22)
  models observed   llama-3.1-8b-instruct, bge-m3
  content mode      hash

27 section(s) need a human. They are marked TODO with a note on what belongs there.
```

Output is deterministic. The same evidence and the same flags produce
byte-identical documents, so you can commit them and read the diff between
quarters as a record of what changed.

## What gets filled in

| Annex IV section | Filled from evidence |
| --- | --- |
| 1. General description | Models requested and served, endpoints, streaming share, upstreams, traffic volume |
| 2. Elements and development process | Generation parameters with observed ranges, tools offered and actually called |
| 3. Monitoring, functioning and control | Record counts, distinct callers and sessions, error rate, token totals, latency percentiles, content mode, retention setting, chain verification result and head hash |
| 4. Performance metrics | Nothing. Traffic volume is not a quality metric |
| 5. Risk management | Nothing, deliberately |
| 6. Lifecycle changes | Model identifiers seen in traffic |
| 7. Harmonised standards | Nothing |
| 8. Declaration of conformity | Nothing |
| 9. Post-market monitoring | Nothing |

Roughly a third of the document arrives written. The rest is the part that
required a human all along.

## Why section 5 is empty on purpose

The generator will not draft your risk management system, and this is the design
decision most likely to disappoint someone evaluating the tool.

A generated risk assessment would be fluent, structurally correct, and about a
system the generator has never understood. It would sit in a folder looking
finished. Someone would ship it. A blank section marked `TODO` with a sentence
explaining what belongs there is less impressive in a demo and considerably
harder to mistake for work that has been done.

The same reasoning applies to sections 4, 7, 8 and 9.

## What the TODO markers look like

```markdown
### 3.5 Human oversight

> **TODO:** Describe how a human can understand, question, override or shut down
> this system's output, and who that human is. Article 14 asks for oversight that
> is effective in practice, not just available in principle. Flugschreiber can
> record human interventions as evidence once you send them to its intervention
> endpoint, but it cannot design the oversight itself.
```

Each one says what the section is for, why it matters, and where the tool's
knowledge stops. Search for `TODO:` to find every remaining gap.

## Filling in the deployment metadata once

Rather than repeating flags, put them in a config file and pass it to both
`serve` and `report`:

```json
{
  "upstream": "http://vllm:8000",
  "data_dir": "/var/lib/flugschreiber",
  "content_mode": "hash",
  "retention_days": 365,
  "deployment": {
    "organisation": "Muster GmbH",
    "system_name": "Support Assistant",
    "purpose": "drafting first-line support replies, reviewed by an agent before sending",
    "contact": "ai-governance@muster.example",
    "role": "deployer",
    "environment": "production"
  }
}
```

```bash
flugschreiber report --config /etc/flugschreiber/config.json \
  --dir /var/lib/flugschreiber --out ./reports
```

`role` matters more than it looks. Provider and deployer carry different
obligations, and the generated document repeats whatever you put there, so
getting it wrong propagates.

## The integrity section

Section 3.4 reports the verification result, the segment list and the chain head
hash at generation time. If the chain does not verify, the document says so at
the top and lists every problem with its segment and line number, rather than
quietly generating a clean-looking report over a damaged log.

That behaviour is tested. `TestGenerateOnEmptyEvidenceDirectory` asserts that a
report over an empty directory says plainly that nothing was observed, because
the failure mode worth designing against is a document that implies coverage it
does not have.

## Regenerating

Run it whenever the picture changes: after a model upgrade, at the end of a
quarter, before an audit. Keep the outputs in git. The diff between two
generations is a change log of what your system actually did, which is close to
what Annex IV section 6 is asking for.

The generated files are yours to edit. Nothing in the tool round-trips them, so
your edits will be overwritten by the next run. Either keep your prose in a
separate document that references the generated one, or treat regeneration as a
merge.

## What it cannot do

It cannot tell you whether your system is high-risk. That is a determination
about your use case.

It cannot see anything above the model API: which human made a request, what
your application did with the answer, whether anyone reviewed it.

It cannot see training data, fine-tuning, or your retrieval corpus.

It does not make anyone compliant. It produces documentation inputs.

See [MAPPING.md](../MAPPING.md) for the field-by-field mapping and the full list
of caveats.
