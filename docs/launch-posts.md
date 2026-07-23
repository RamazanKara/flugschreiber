# Launch post drafts

Drafts, not scheduled copy. Read them out loud before posting, and cut anything
that sounds like it came from a template.

<!-- unslop-ignore: the rules here separate whole draft posts, not sections of one document. -->
Do not post any of these until the repository is public, the GIF is recorded,
and `docker run ghcr.io/ramazankara/flugschreiber:latest` actually works for a
stranger. The fastest way to waste a Show HN is to publish it against a README
whose first command fails.

---

## Show HN

### Title (80 char limit, this is 74)

```
Show HN: Flugschreiber, tamper-evident audit logs for self-hosted LLMs
```

### Body

```
Somebody asked us what evidence we had of what our internal LLM did last
quarter. We had Grafana dashboards and 30 days of application logs that were
never designed to answer that, and no realistic way to get six product teams to
add an SDK because compliance asked.

So I built a proxy. You put it in front of vLLM, Ollama, LiteLLM, or anything
else speaking the OpenAI API, change one base URL, and every model interaction
lands in an append-only JSONL log where each record carries the SHA-256 of the
one before it. Change a byte and verification fails at that record and every
record after it.

  docker run -p 8080:8080 -v fs-evidence:/var/lib/flugschreiber \
    ghcr.io/ramazankara/flugschreiber:latest serve --mock-upstream

  export OPENAI_BASE_URL=http://localhost:8080/v1
  # ... make some calls ...

  flugschreiber verify --dir /var/lib/flugschreiber
  flugschreiber report --dir /var/lib/flugschreiber --out ./reports

`verify` reads files and nothing else, so you can hand someone the directory and
the binary and they can check it on their own machine. `report` generates an
Annex IV-shaped technical documentation skeleton pre-filled from traffic it
actually observed (models seen, endpoints, parameters, token usage, integrity
status), plus Article 50 chatbot disclosure snippets in German and English.
Everything it cannot know is marked TODO with a sentence on what belongs there,
because a generated risk assessment is worse than none.

Some things I decided that might be worth arguing about:

- The default content mode stores no prompt text, just a SHA-256 of the request
  and response bytes. Storing prompts by default means every deployment becomes
  a fresh copy of whatever users type. The digest is over the wire bytes in
  every mode, so a transcript you hold elsewhere can still be proven to be the
  transcript of that interaction.
- Zero dependencies. `go.mod` has no require block, CI fails if one appears. It
  is a tool whose value is that you can trust what it wrote, and every
  dependency is a party that can change what ends up in an evidence file.
- The hash chain proves the log is internally consistent, not who wrote it.
  Someone with write access to the whole directory could recompute it from
  scratch. Signed checkpoints are next. I would rather say that plainly than let
  someone discover it during an audit.

It does not make anyone compliant, it is not legal advice, and an LLM is not
high-risk in itself. It produces evidence and documentation inputs. That is the
whole pitch.

p50 overhead is about 0.5ms. Streaming is relayed frame by frame with a test
that fails if that regresses. Apache-2.0, no telemetry, no phone-home.

https://github.com/RamazanKara/flugschreiber

What I would most like from HN: if you have been through an actual AI Act or
ISO 42001 audit, tell me what the auditor asked for that this does not record.
```

### Notes for the day

Post Tuesday to Thursday, roughly 09:00 to 11:00 Eastern. Be around for the first
four hours; a Show HN dies without the author answering.

Have honest answers ready for the three questions that will definitely come:

- *"Why not Langfuse?"* Because they are built for debugging and this is built
  for evidence. Say it without knocking them, and say you can run both.
- *"The chain doesn't prove anything, you can just rewrite it."* Agree that a
  chain alone does not, then say what closes it: signed checkpoints are on by
  default, verification checks the signature and the chain together, and the
  remaining gap is custody of the key, which is why an external signer and
  timestamp anchoring exist. It is in the README, SECURITY.md and the generated
  docs, stated as a limitation rather than buried.
- *"This is compliance theatre."* Also fair as a prior. The answer is that it
  produces evidence and documentation inputs, that it never claims otherwise
  anywhere in the product, and that the generated documents mark their gaps
  rather than filling them with plausible text.

---

## LinkedIn, English

```
"What evidence do we have of what our AI did?"

If you run self-hosted LLMs in the EU, someone is going to ask you that, and
"we have logs" is not going to be the end of the conversation. The follow-up is
whether anyone could have changed them.

I have open-sourced Flugschreiber, a proxy that sits in front of vLLM, Ollama,
LiteLLM or any OpenAI-compatible endpoint and records every model interaction to
a hash-chained, append-only log. Change one base URL, no application code.

Two commands matter:

flugschreiber verify confirms the chain is intact. It reads files, needs no
server, and can be run by anyone you hand a copy of the directory to.

flugschreiber report generates an Annex IV-shaped technical documentation
skeleton, pre-filled from traffic it actually observed, plus Article 50 chatbot
disclosure snippets in German and English.

Two things I want to be clear about, because this space is full of people who
are not.

It does not make you compliant. It produces evidence and documentation inputs.
The judgement calls stay with your DPO and your lawyers, and everything the tool
cannot know is marked TODO rather than filled in with something plausible.

An LLM is not high-risk in itself. Obligations attach to the use case, not to
the technology. Anyone selling you a "high-risk AI" product without asking what
your system does is selling you something else.

By default it stores no prompt text at all, only a cryptographic hash of the
request and response. Storing every prompt by default would turn each
deployment into a new copy of whatever users type into a chat box, which is not
a thing a logging tool should do to you quietly.

Apache-2.0. No telemetry, no phone-home, no SaaS.

Article 50 transparency obligations apply from 2 August 2026 under the timeline
following the Digital Omnibus agreement. That is closer than it reads.

github.com/RamazanKara/flugschreiber

If you have been through an audit and can tell me what was actually asked for,
I would rather hear that than a star.

#EUAIAct #AICompliance #MLOps #OpenSource #SelfHosted
```

---

## LinkedIn, German

```
„Welche Nachweise haben wir darüber, was unsere KI getan hat?"

Wer in der EU LLMs selbst betreibt, bekommt diese Frage irgendwann gestellt. Und
„wir haben Logs" beendet das Gespräch nicht. Die Anschlussfrage lautet, ob die
jemand hätte verändern können.

Ich habe Flugschreiber als Open Source veröffentlicht: ein Proxy, der sich vor
vLLM, Ollama, LiteLLM oder jeden OpenAI-kompatiblen Endpunkt setzt und jede
Modellinteraktion in ein hash-verkettetes, nur anfügbares Protokoll schreibt.
Eine Basis-URL ändern, kein Eingriff in den Anwendungscode.

Zwei Befehle sind entscheidend:

flugschreiber verify prüft, ob die Kette unversehrt ist. Der Befehl liest
ausschließlich Dateien, braucht keinen laufenden Server, und lässt sich von
jeder Person ausführen, der Sie eine Kopie des Verzeichnisses aushändigen.

flugschreiber report erzeugt ein an Anhang IV orientiertes Gerüst für die
technische Dokumentation, vorbefüllt aus tatsächlich beobachtetem Verkehr, sowie
Textbausteine für die Chatbot-Kennzeichnung nach Artikel 50 auf Deutsch und
Englisch.

Zwei Punkte, die mir wichtig sind, weil in diesem Umfeld viel behauptet wird.

Das Werkzeug stellt keine Konformität her. Es liefert Nachweise und Grundlagen
für die Dokumentation. Die Bewertung bleibt bei Ihrem Datenschutzbeauftragten und
Ihrer Rechtsabteilung. Alles, was das Werkzeug nicht wissen kann, wird als TODO
markiert statt mit plausibel klingendem Text gefüllt.

Ein LLM ist nicht per se ein Hochrisikosystem. Die Pflichten knüpfen an den
Anwendungsfall an, nicht an die Technologie. Wer Ihnen ein „Hochrisiko-KI"-Produkt
verkauft, ohne zu fragen, was Ihr System eigentlich tut, verkauft Ihnen etwas
anderes.

Standardmäßig wird kein Prompt-Text gespeichert, sondern nur ein kryptografischer
Hash von Anfrage und Antwort. Alle Prompts per Voreinstellung zu speichern würde
aus jeder Installation eine neue Kopie dessen machen, was Nutzerinnen und Nutzer
in ein Chatfenster tippen. Das sollte ein Protokollierungswerkzeug niemand
stillschweigend antun.

Apache-2.0. Keine Telemetrie, kein Phone-Home, kein SaaS.

Die Transparenzpflichten nach Artikel 50 gelten nach dem Zeitplan im Anschluss an
die Einigung zum Digital Omnibus ab dem 2. August 2026. Das ist näher, als es
klingt.

github.com/RamazanKara/flugschreiber

Wenn Sie ein Audit hinter sich haben und mir sagen können, wonach tatsächlich
gefragt wurde: Das interessiert mich mehr als ein Stern.

#EUAIAct #KIVerordnung #MLOps #OpenSource #Compliance
```

---

## Where else

The German-speaking DPO and works-council audience is on LinkedIn and in
Fachgruppen, not on Hacker News. Consider a shorter German version for
r/de_EDV, and a plain-text post to a GDPR or DSB mailing list without the
hashtags.

For r/selfhosted and r/LocalLLaMA, drop the compliance framing almost entirely
and lead with the tamper-evident log and the zero-dependency binary. That
audience cares about the proxy, and the AI Act angle will read as marketing.
