# Technische Dokumentation: Support-Assistent

Erstellt von Flugschreiber v0.1.0-test am 2026-05-04T09:00:00Z aus beobachtetem Verkehr in `/var/lib/flugschreiber`.

> **Dies ist ein Gerüst, kein Konformitätsdokument.** Mit *beobachtet* gekennzeichnete
> Abschnitte sind aus Nachweisen befüllt, die Flugschreiber tatsächlich aufgezeichnet hat.
> Alles mit **TODO** verlangt einen Menschen, der das System und seinen Anwendungsfall
> versteht. Flugschreiber kann diese Dinge nicht wissen und rät nicht.
>
> Dieses Dokument ist keine Rechtsberatung. Ein LLM ist nicht per se ein Hochrisikosystem.
> Die Pflichten der KI-Verordnung knüpfen an den *Anwendungsfall* an, nicht an die
> Technologie. Ob Anhang III auf dieses System zutrifft, müssen Sie selbst feststellen;
> dieses Dokument ist wie Anhang IV aufgebaut, damit es nützlich ist, wenn er zutrifft,
> und harmlos, wenn nicht.

## Dokumentenkontrolle

| Feld | Wert |
| --- | --- |
| Systemname | Support-Assistent |
| Organisation | Muster GmbH |
| Rolle nach der KI-Verordnung | deployer |
| Umgebung | production |
| Ansprechstelle | ai-governance@muster.example |
| Nachweiszeitraum | 2026-05-04T08:31:00Z to 2026-05-04T08:36:00Z |
| Erfasste Aufzeichnungen | 6 (5 Inferenz-Ereignisse) |
| Integrität | Hash-Kette als unversehrt geprüft |

---

## 1. Allgemeine Beschreibung des KI-Systems

### 1.1 Zweckbestimmung

drafting first-line support replies, reviewed by an agent before sending

> **TODO:** Legen Sie ausdrücklich fest, wofür das System *nicht* bestimmt ist und welche Nutzung Sie ausgeschlossen haben. Auch vernünftigerweise vorhersehbarer Fehlgebrauch gehört hierher.

### 1.2 Beobachtete Modelle und Versionen

*Beobachtet.* Im Nachweiszeitraum wurden von Aufrufern die folgenden Modellkennungen
angefragt und vom Upstream als bereitgestellt gemeldet:

| Modell angefragt | Modell bereitgestellt | Anfragen | Gestreamt | Fehler | Prompt-Token | Completion-Token |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| `llama-3.1-8b-instruct` | `llama-3.1-8b-instruct` | 2 | 1 | 0 | 390 | 404 |
| `bge-m3` | `bge-m3` | 1 | 0 | 0 | 96 | 0 |
| `llama-3.1-8b-instruct` | `llama-3.1-8b-instruct-awq` | 1 | 0 | 0 | 340 | 28 |
| `mistral-7b` | `n/a` | 1 | 0 | 1 | 0 | 0 |

In mindestens einem Fall weicht die bereitgestellte Kennung von der angefragten ab: Der
Upstream hat ein Modell ausgetauscht. Dieser Austausch gehört mit seiner Begründung in
dieses Dokument.

> **TODO:** Halten Sie für jedes Modell oben fest: seine Herkunft (Anbieter, Open-Weights-Repository, internes Fine-Tuning), die in Ihrer Installation festgelegte Version oder Prüfsumme und die Lizenz, unter der es genutzt wird. Flugschreiber sieht die von der API gemeldete Kennung, die nicht immer dem tatsächlich bereitgestellten Artefakt entspricht.

### 1.3 Systemarchitektur und Schnittstellen

*Beobachtet.* Aufrufer erreichten die folgenden API-Endpunkte über Flugschreiber:

| Endpunkt | Anfragen |
| --- | ---: |
| `/v1/chat/completions` | 4 |
| `/v1/embeddings` | 1 |

Der Verkehr wurde weitergeleitet an: http://vllm:8000 (5).

20% der Inferenz-Anfragen nutzten Server-Sent-Event-Streaming.
Gestreamte Antworten werden wieder zusammengesetzt und als die vollständige Nachricht
aufgezeichnet, die der Aufrufer erhalten hat.

> **TODO:** Beschreiben Sie, was vor der Anwendung und was hinter dem Modell liegt: Authentifizierung, Abrufquellen, Werkzeug-Integrationen, nachgelagerte Systeme, die die Ausgabe verarbeiten, und jeden Schritt menschlicher Prüfung. Flugschreiber sieht nur die Grenze der Modell-API.

### 1.4 Bereitstellungsform und Hardware

> **TODO:** Geben Sie an, wie das System bereitgestellt wird (Container, Kubernetes, VM), auf welcher Hardware es läuft und in welcher Jurisdiktion diese Hardware steht. Läuft die Inferenz auf Infrastruktur, die Sie nicht kontrollieren, benennen Sie den Betreiber.

---

## 2. Bestandteile des Systems und Entwicklungsprozess

### 2.1 Verwendete Generierungsparameter

*Beobachtet.* Aufrufer setzten die folgenden Generierungsparameter:

| Parameter | Beobachteter Bereich | Anfragen |
| --- | --- | ---: |
| `max_tokens` | 256 to 1024 | 3 |
| `temperature` | 0 to 0.7 | 3 |
| `top_p` | 0.95 | 1 |

### 2.2 Werkzeuge und Funktionsaufrufe

*Beobachtet.*

Dem Modell angebotene Werkzeuge: issue_refund, lookup_order.

Vom Modell tatsächlich aufgerufene Werkzeuge: lookup_order (1).

> **TODO:** Dokumentieren Sie für jedes Werkzeug oben, was es tun kann, worauf es zugreifen kann und ob seine Wirkungen umkehrbar sind. Ein Modell, das ein Werkzeug aufrufen kann, das in ein Produktivsystem schreibt, ist ein wesentlich anderes Risikobild als eines, das nur lesen kann.

### 2.3 Vom System verwendete Daten

> **TODO:** Beschreiben Sie die Daten, die das System zur Inferenzzeit verarbeitet: was Nutzer übermitteln, was abgerufen und als Kontext eingefügt wird und was die Grenze verlässt. Wurde das System feinabgestimmt oder mit einem Abrufkorpus genutzt, beschreiben Sie diese Datensätze, ihre Herkunft und ihre Lizenzierung. Flugschreiber zeichnet Verkehr auf, keine Trainingsdaten, daher lässt sich dieser Abschnitt nicht generieren.

> **TODO:** Halten Sie fest, ob personenbezogene Daten verarbeitet werden, die Rechtsgrundlage nach der DSGVO und den Verweis auf die Datenschutz-Folgenabschätzung, falls eine vorliegt. Was Flugschreiber selbst speichert, steht in Abschnitt 3.2.

### 2.4 Entwicklungsprozess und Validierung

> **TODO:** Beschreiben Sie, wie das System gebaut wurde und wie Änderungen daran geprüft und ausgeliefert werden. Verweisen Sie auf Ihr Repository, Ihre CI-Pipeline und Ihren Release-Prozess, statt sie zu wiederholen.

> **TODO:** Beschreiben Sie die vor dem Einsatz durchgeführten Tests und ihre Ergebnisse.

---

## 3. Überwachung, Funktionsweise und Kontrolle

### 3.1 Protokollierung (Artikel 12 und Artikel 19)

*Beobachtet.* Flugschreiber zeichnet pro Modellinteraktion ein strukturiertes,
hash-verkettetes Ereignis auf. Im Nachweiszeitraum erfasste es:

| Größe | Wert |
| --- | --- |
| Aufzeichnungen gesamt | 6 |
| Inferenz-Ereignisse | 5 |
| Verschiedene aufrufende Identitäten | 3 (als gesalzene Hashes gespeichert, nicht als Zugangsdaten) |
| Verschiedene Sitzungen | 3 |
| Anfragen mit Fehlern | 1 (20%) |
| Prompt-Token | 826 |
| Completion-Token | 432 |
| Mediane Ende-zu-Ende-Latenz | 812.4 ms |
| 95. Perzentil der Latenz | 2240.9 ms |
| Aufgezeichnete Ereignistypen | inference (5), human_intervention (1) |
| HTTP-Statuscodes | 200 (4), 503 (1) |
| Abschlussgründe | stop (2), tool_calls (1) |

Jede Aufzeichnung trägt: einen RFC3339-Zeitstempel, eine monotone Folgenummer, Anfrage-
und Sitzungskennungen, das angefragte und bereitgestellte Modell, den Endpunkt und den
Upstream, Generierungsparameter, Token-Verbrauch, Latenz, HTTP-Status, einen gesalzenen
Hash der aufrufenden Identität und die in 3.2 beschriebene Inhaltsaufzeichnung.

> **TODO:** Artikel 12 verlangt eine dem Zweck angemessene Protokollierung. Bestätigen Sie, dass die obigen Felder für Ihren Anwendungsfall ausreichen, und halten Sie hier fest, was Sie andernorts protokollieren und Flugschreiber nicht sieht, etwa die anwendungsseitige Nutzeridentität oder die in einen Prompt eingefügten Abrufdokumente.

### 3.2 Was vom Inhalt selbst aufgezeichnet wird

*Beobachtet.* Der aktive Inhaltsmodus ist **`hash`**.
Im aufgezeichneten Zeitraum gesehene Modi: hash (5).

- `hash`: Es wird ein SHA-256 der exakten Anfrage- und Antwortbytes aufgezeichnet; kein
  Prompt- oder Completion-Text wird aufbewahrt. Dies ist die Voreinstellung, gewählt zur
  Datenminimierung nach Artikel 5 Absatz 1 Buchstabe c DSGVO: Ein Proxy, der jeden Prompt
  voreingestellt speichert, würde eine neue Kopie dessen anlegen, was Nutzer eingeben, in
  einem System, das dafür nicht ausgelegt war.
- `redact`: Text wird aufbewahrt, wobei konfigurierte Muster ersetzt werden.

  Musterbasierte Schwärzung ist ihrer Natur nach nur bestmöglich; freier Text kann
  personenbezogene Daten in Formen tragen, die kein regulärer Ausdruck erfasst.
- `store`: Der vollständige Anfrage- und Antworttext wird aufbewahrt.

In jedem Modus wird der SHA-256 über die vollständigen Bytes berechnet, die über die
Leitung gingen. Genau das erlaubt es, ein andernorts gehaltenes Transkript als das
Transkript der Interaktion nachzuweisen, die dieses Protokoll bezeugt, selbst wenn das
Protokoll selbst keinen Text enthält.

> **TODO:** Halten Sie fest, warum der gewählte Inhaltsmodus hier angemessen ist und wo die zugehörigen Aufbewahrungs- und Zugriffskontrollen dokumentiert sind.

### 3.3 Aufbewahrung

*Beobachtet.* Konfigurierte Aufbewahrung: **180 Tage** (~6.0 Monate).

Artikel 19 erwartet, dass automatisch erzeugte Protokolle mindestens sechs Monate
aufbewahrt werden, soweit sie der Kontrolle des Anbieters unterliegen und vorbehaltlich
sonstigen anwendbaren Rechts. Flugschreiber verweigert den Start mit einer Aufbewahrung
unter 180 Tagen.

Die Durchsetzung erfolgt mit `flugschreiber retention --enforce --confirm`, das nur ganze
Segmente löscht, älteste zuerst, und nur dann, wenn jede Aufzeichnung darin außerhalb des
Aufbewahrungszeitraums liegt. Eine Datei `LEGAL_HOLD` im Nachweisverzeichnis blockiert
jede Löschung, solange sie existiert. Ohne diese beiden ausdrücklichen Schalter löscht
nichts Nachweise, ob von einer Person eingegeben oder als Job geplant.

> **TODO:** Halten Sie fest, wo das Nachweisverzeichnis gespeichert ist, wer es lesen kann, wie es gesichert wird und wer oder was die Aufbewahrung in welchem Turnus durchsetzt. Läuft nichts, sammeln sich Aufzeichnungen über den Aufbewahrungszeitraum hinaus an, bis etwas läuft, was eine Frage der Datenminimierung ist, keine des Werkzeugs.

### 3.4 Integritätsmechanismus

*Beobachtet.* Jede Aufzeichnung trägt den SHA-256 ihres Vorgängers und einen SHA-256 ihres
eigenen Inhalts und bildet so eine Kette. Das Ändern, Einfügen oder Entfernen einer
Aufzeichnung bricht die Kette an dieser Stelle und an jeder Stelle danach.

| Größe | Wert |
| --- | --- |
| Prüfergebnis | **unversehrt**, jeder Aufzeichnungs-Hash und jede Verkettung geprüft |
| Segmente | 1 (seg-00000001.jsonl) |
| Hash des Kettenkopfs | `ab3616607f5bf3c8f3b747fa7c41212922992ac81444a70bf4401977cef87943` |
| Signierte Kontrollpunkte | 1, davon 1 gegen Signatur und Kette geprüft |
| Beglaubigung | **beglaubigt**: mindestens eine Ed25519-Kontrollpunktsignatur wurde geprüft und stimmt mit der Kette überein |
| Kennung des Signaturschlüssels | `9a82517f9af19416` |
| Geprüft am | 2026-05-04T09:00:00Z |

Jede Person kann diese Prüfung gegen das Nachweisverzeichnis erneut ausführen mit:

```
flugschreiber verify --dir <Nachweisverzeichnis>
```

Der Prüfer liest ausschließlich die Dateien auf der Festplatte. Er braucht keinen
laufenden Server und keinen Zugang zu Ihrer Infrastruktur, sodass die Prüfung von einer
prüfenden Stelle wiederholt werden kann, die nichts als eine Kopie des Protokolls besitzt.

Die Kette samt der geprüften Kontrollpunkte bedeutet, dass dieses Protokoll von niemandem
umgeschrieben worden sein kann, der nicht auch den Signaturschlüssel hielt. Offen bleibt
die Verwahrung des Schlüssels, und das ist die Sicherheitsgrenze.

> **TODO:** Halten Sie fest, was das Nachweisverzeichnis und den Signaturschlüssel schützt: nur-anfügbarer oder mit Object Lock versehener Speicher, Off-Host-Replikation versiegelter Segmente, eingeschränkte Dateisystemrechte und wo der Schlüssel relativ zum Nachweis liegt. Ein neben dem Protokoll aufbewahrter Schlüssel schützt weit weniger als ein anderswo aufbewahrter.

### 3.5 Menschliche Aufsicht

*Beobachtet.* 1 Aufzeichnung(en) menschlicher Eingriffe wurden im
Zeitraum in die Nachweiskette geschrieben: override (1).
Jede trägt die handelnde Person, die Entscheidung und die betroffene Interaktion, in
derselben manipulationssicheren Kette wie die Interaktionen selbst.

> **TODO:** Beschreiben Sie den Aufsichtsprozess, aus dem diese Aufzeichnungen stammen: wer die handelnden Personen sind, welche Befugnis sie haben und was eine Prüfung auslöst. Aufgezeichnete Eingriffe belegen, dass Aufsicht stattfand; sie beschreiben nicht, wie sie organisiert ist.

### 3.6 Genauigkeit, Robustheit und Cybersicherheit

> **TODO:** Halten Sie fest, welche Genauigkeit vom System erwartet wird und wie sie gemessen wird. Halten Sie fest, was geschieht, wenn der Upstream nicht verfügbar ist oder einen Fehler liefert. Die oben beobachtete Fehlerquote ist ein Ausgangspunkt für diese Erörterung.

> **TODO:** Halten Sie die Sicherheitsmaßnahmen rund um den Modell-Endpunkt fest: Authentifizierung, Netzwerkisolierung, Ratenbegrenzung und wie das Risiko von Prompt-Injection behandelt wird, falls das System nicht vertrauenswürdige Eingaben verarbeitet.

---

## 4. Angemessenheit der Leistungskennzahlen

> **TODO:** Geben Sie an, mit welchen Kennzahlen Sie beurteilen, ob dieses System funktioniert, und warum diese Kennzahlen für die Zweckbestimmung die richtigen sind. Flugschreiber misst Verkehr, Latenz und Token-Verbrauch; keines davon sagt Ihnen, ob die Ausgabe gut war.

---

## 5. Risikomanagementsystem (Artikel 9)

> **TODO:** Verweisen Sie auf Ihren Risikomanagementprozess: die für diesen Anwendungsfall ermittelten Risiken, die getroffenen Maßnahmen und das akzeptierte Restrisiko. Flugschreiber erzeugt dies bewusst nicht, denn eine generierte Risikobeurteilung wäre schlechter als keine, weil sie wie eine aussähe.

---

## 6. Über den Lebenszyklus vorgenommene Änderungen

> **TODO:** Halten Sie wesentliche Änderungen am System und ihren Zeitpunkt fest. Änderungen der Modellversion sind in Abschnitt 1.2 sichtbar, wenn sie im Verkehr auftreten; Änderungen an Prompts, Abrufquellen, Werkzeugen und Schwellenwerten sind für Flugschreiber nicht sichtbar und müssen hier festgehalten werden.

---

## 7. Angewandte harmonisierte Normen

> **TODO:** Führen Sie alle ganz oder teilweise angewandten harmonisierten Normen oder gemeinsamen Spezifikationen auf. Falls keine, sagen Sie das ausdrücklich.

---

## 8. EU-Konformitätserklärung

> **TODO:** Fügen Sie die Erklärung bei, falls eine für dieses System erforderlich ist. Ist das System nicht hochriskant und keine Erklärung erforderlich, halten Sie das fest und dokumentieren Sie die Begründung, die zu diesem Schluss führte. Die Begründung ist der wertvolle Teil.

---

## 9. Beobachtung nach dem Inverkehrbringen

> **TODO:** Beschreiben Sie, wie das System nach dem Einsatz beobachtet wird und wie Vorfälle erkannt, eskaliert und gemeldet werden. Das Nachweisprotokoll ist ein Eingang dafür, nicht der Plan selbst.

---

## Anhang A: Regulatorischer Zeitplan

Die Daten spiegeln den Zeitplan nach der Einigung zum Digital Omnibus wider. Prüfen Sie
sie gegen den aktuellen Wortlaut, bevor Sie sich darauf verlassen.

| Datum | Was gilt |
| --- | --- |
| 2. August 2026 | Transparenzpflichten nach Artikel 50 |
| 2. Dezember 2026 | Neue Verbote |
| 2. Dezember 2027 | Hochrisiko-Pflichten nach Anhang III |
| 2. August 2028 | Pflichten nach Anhang I |

In der ersten Zeile beginnt eine Pflicht später: Die maschinenlesbare Kennzeichnung nach
Artikel 50 Absatz 2 gilt ab dem 2. Dezember 2026 für Systeme, die am 2. August 2026 bereits
auf dem Markt sind. Die Interaktions-Kennzeichnung nach Artikel 50 Absatz 1 ist nicht
aufgeschoben.

## Anhang B: Wie dieses Dokument entstanden ist

Flugschreiber las 6 Aufzeichnungen aus `/var/lib/flugschreiber`, umfassend
2026-05-04T08:31:00Z to 2026-05-04T08:36:00Z, prüfte die Hash-Kette und befüllte jeden Abschnitt, den es mit
beobachteten Nachweisen stützen konnte. Abschnitte, die es nicht stützen konnte, sind mit
**TODO** gekennzeichnet, statt geraten zu werden.

Die feldweise Zuordnung des Protokollschemas zu den Bestimmungen, die es stützt, steht in
`MAPPING.md` im Flugschreiber-Repository, samt ihren Vorbehalten.
