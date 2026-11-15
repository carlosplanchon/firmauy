# Security invariants of timestamp verification

How firmauy's handling of RFC 3161 signature timestamps is tested against hostile and damaged
input, stated as invariants: the risk each one controls, the clause of Agesic's Marco de
Ciberseguridad (MCU 5.0) it speaks to, the tests that enforce it, and the counterexamples that
were actually found on the way here.

**Scope, in the title on purpose.** All eight invariants below are about timestamps. That is where
the defects were, so that is where the work went, and calling the page "the verifiers" claimed a
coverage the matrix does not have. Signature and certificate verification outside the timestamp
path is tested like the rest of the library and has no matrix, no clause mapping and no searching
check. Neither does the signing side: see gap 8.

| Baseline | |
|---|---|
| Release | firmauy 1.14.0 |
| Commit | [`d2c9267`](https://github.com/carlosplanchon/firmauy/commit/d2c9267d6b61bb0cf8a4f91d2897beb57db31ea2) |
| Dated | 2026-08-05 |

Every number and every test name below describes that commit. The links to test files are
relative, so reading this page at the `v1.14.0` tag shows the tests as they were, and reading it
at `main` shows them as they are now, which may have moved. The commit links in the
counterexamples are absolute and always point at the fix they name.

Agesic's audit guidance for requirement AD.1 lists this category of evidence by name:
"Documentación de pruebas de seguridad, criterios de aceptación y entregables vinculados a
requisitos de seguridad". This page packages that evidence for the timestamp path. The format, a
traceability matrix, is this project's choice, not something the guidance prescribes.

## What this is, and what it is not

**It is** a traceability matrix, and together with the procedure below, a documented and
reproducible baseline: the measured state of the timestamp path's security testing at 1.14.0. Each row
connects one invariant to the risk it controls, the clause it speaks to, the tests that enforce
it, and the real defects found while getting there. Later audits, reviews and releases have this
to compare against.

**Quotes are verbatim, mappings are interpretation.** Text inside quotation marks is quoted
verbatim, in Spanish, from Agesic's published guidance or from the law. The mapping between an
invariant and a clause is this project's reading of where the evidence belongs, not a
determination by Agesic.

**It is not a compliance claim.** AD.1 and CA.4 describe an organisation's lifecycle and
controls, with maturity levels that presume an organisation around them. What this page shows is
narrower and checkable: the artifacts those clauses list as evidence exist here and can be
audited.

**It is not an audit.** Auditable is not audited. No external party has audited, certified or
otherwise assessed what this page describes. What the page does is lay the artifacts out so that
somebody could: every test is named, the procedure and its acceptance criteria are written down,
and every finding traces to a commit.

**It is not an accreditation, and cannot become one.** Under Ley 18.600, accreditation belongs
to certification service providers (the law's own words in art. 6 are "prestador de servicios de
certificación acreditado") and is granted by the UCE. A library is not a prestador. firmauy is
independent and unofficial, and a VALID from it is a technical assessment rather than a legal
one. The State-operated verification service is [firma.gub.uy](https://firma.gub.uy/).

## The clauses cited, verbatim

Every quotation below was checked on 2026-08-05, and each is quoted from the artifact that
carries it, because Agesic publishes two and they are not interchangeable:

- The **requirement catalogue**, [Planilla MCU 5.0
  Avanzado](https://www.gub.uy/agencia-gobierno-electronico-sociedad-informacion-conocimiento/sites/agencia-gobierno-electronico-sociedad-informacion-conocimiento/files/documentos/publicaciones/Planilla%20MCU%205.0%20Avanzado.xlsx)
  and its Básico and Estándar tiers, which give each requirement a **title** and the numbered
  text of every control. All twelve CA.4 controls appear identically in all three tiers.
- The **implementation guide**, one page per requirement, which states an objective the
  catalogue does not carry and sorts the controls into four levels the catalogue does not show.

Each line below says which of the two it came from, because checking against one of them alone
will report the other's fields as missing. Control texts are the catalogue's, levels are the
guide's, and the law at the end is IMPO's.

The check is repeatable: [`scripts/check_mcu_quotes.py`](https://github.com/carlosplanchon/firmauy/blob/main/scripts/check_mcu_quotes.py) fetches
the artifacts fresh, prints the SHA-256 of each so "checked" means "against these bytes", and
re-checks every quotation and level annotation below against the artifact its line declares. A
checker and not a generator, on purpose: when it fails, the next step is a person reading what
the source now says, never a script rewriting this page. The chain's other direction is hermetic
and runs with the suite on every pull request:
[`tests/test_invariants_doc.py`](https://github.com/carlosplanchon/firmauy/blob/main/tests/test_invariants_doc.py) fails when a test named on this
page stops existing where the page says it lives, when an internal anchor or relative link
breaks, or when the matrix cites a clause label, gap or counterexample the page does not define.

- **[CA.4 title]**, from the catalogue: "Establecer los controles para el uso de firma
  electrónica"
- **[CA.4 objective]**, from the guide: "Lograr el cumplimiento con los lineamientos
  establecidos por la UCE y Agesic para el uso de firma electrónica avanzada."
- **[CA.4-5]** (level 1) "se debe hacer la validación de certificados a través de OCSP (Online
  Certificate Status Protocol), CRL (Certificate Revocation List) o equivalente."
- **[CA.4-6]** (level 2) "la solución incorpora medidas de detección de firmas alteradas o
  invalidadas, incluyendo trazabilidad del error."
- **[CA.4-10]** (level 4) "los sistemas deben permitir el uso de sellos de tiempo compatibles
  con RFC 3161."
- **[CA.4-11]** (level 4) "se realizan auditorías de los módulos de firma electrónica,
  incluyendo pruebas de cumplimiento de formatos, protocolos, protección de claves y servicios
  de sellado de tiempo."
- **[CA.4-12]** (level 4) "los resultados de las auditorías o revisiones son analizados e
  incorporados a la mejora de la solución y comunicados al RSI."
- **[AD.1-4]** (level 2) "se sistematizan las actividades de prueba, incluyendo casos de prueba orientados
  a las validaciones de seguridad."
- **[AD.1-5]** (level 3) "se define un procedimiento documentado de pruebas de seguridad."
- **[AD.1-6]** (level 3) "se definen los criterios de aceptación de los productos desde la perspectiva de
  seguridad de la información."
- **[AD.1 evidencia]** (guide, its evidence list) "Documentación de pruebas de seguridad, criterios de aceptación y
  entregables vinculados a requisitos de seguridad"
- **[Ley 18.600 art. 6]** "El documento electrónico no hará fe respecto de su fecha, a menos que
  ésta conste a través de un fechado electrónico otorgado por un prestador de servicios de
  certificación acreditado."

## One definition the matrix leans on

A timestamp contributes a **usable validation time** only when every one of these holds:

```text
usable validation time =
    timestamp.present
    and timestamp.intact
    and timestamp.valid
    and timestamp.trusted is True
```

Only then does its `genTime` move the moment the signer's certificate is judged at (rows 4 and
7). In every other state, a `genTime` that can still be parsed is preserved and reported as
asserted evidence, and a token too damaged to state one reports `gen_time` as null. Neither is
allowed to affect the signer's validation. The implementation is `evaluate_timestamp` in
`src/firmauy/verify_common.py`, which returns a trusted time on that exact conjunction and on
nothing less.

## Who the invariants are against

Stated once here rather than left to be inferred from eight rows, because an invariant is only
as meaningful as the adversary it is about.

**What the attacker controls: the whole file.** Verification is handed a document from somewhere
else, by definition. Every byte of it is hostile input, including the parts that look structural.
That is the premise of both searching checks below.

**Where that costs least effort: the unsigned attributes.** A signature timestamp lives in the
SignerInfo's *unsigned* attributes, which by construction the document's signature does not
cover. So a token can be rewritten while the signature over the document stays perfectly intact.
This is not a weakness in the design of CMS, it is what the attribute is for, and it is why
invariants 2, 3 and 4 exist: whoever can edit a file gets the timestamp for free, and must not
thereby be able to accuse the signature, reach VALID, or choose the day the signer's certificate
is judged on.

**What the attacker does not control: the anchors.** Trust roots come from the caller, and the
caller is the person verifying. `ca_file` and `tsa_ca` are theirs to pass. Invariant 5 is about
keeping those two decisions apart, so that trusting a timestamping authority never widens who may
sign.

**What is trusted, and therefore out of scope.** The cryptographic primitives, asn1crypto's and
pyHanko's correctness beyond the failures listed as counterexamples, the operating system, and
the anchors the caller chose. A defect in any of those is not something these invariants defend
against, and the sweep finding two escapes that had sailed through that trusted parsing layer
(C6, C7) is a reminder that the line is a decision rather than a guarantee.

**What is deliberately not defended.** Resource exhaustion (gap 7). An adversary who controls the
trust anchors, which is the same as controlling the answer. Anything about the key: this page is
about reading signatures, not making them, and key protection is the card's job.

## The matrix

All named tests run in CI with the normal suite (`uv run pytest`), which includes the properties
at their shallow profile, on every pull request and every push to main. The sweep and the deep
property profile run on the same trigger in their own job, and locally with `FIRMAUY_SWEEP=1`
and `FIRMAUY_DEEP=1`. Counterexample numbers (C1 to C7) refer to the section below. Unless a file
is named, tests live in [`tests/test_timestamp_status.py`](https://github.com/carlosplanchon/firmauy/blob/main/tests/test_timestamp_status.py);
the others are [`test_xades_t.py`](https://github.com/carlosplanchon/firmauy/blob/main/tests/test_xades_t.py),
[`test_properties_timestamp.py`](https://github.com/carlosplanchon/firmauy/blob/main/tests/test_properties_timestamp.py) and
[`test_sweep_tstinfo.py`](https://github.com/carlosplanchon/firmauy/blob/main/tests/test_sweep_tstinfo.py), and the job that runs them is in
[`ci.yml`](https://github.com/carlosplanchon/firmauy/blob/main/.github/workflows/ci.yml). Files rather than line numbers on purpose: a link to a
line is wrong the first time somebody edits above it, and a stale link in a page like this is
worse than none. The test names are exact, so `pytest -k` finds any of them.

Clause labels refer to the verbatim list above. **Limits** points at the numbered gap that bounds
a row, when one does; a dash means the row is stated no wider than what its tests hold.

| # | Invariant | Risk controlled | Formats | Clause | Enforced by | Counterexamples | Limits |
|---|---|---|---|---|---|---|---|
| 1 | A damaged timestamp token always yields a verdict with the cause in `timestamp.detail`, never an escaped exception | A crafted file crashes the verifier, or the damage is detected with no traceable cause | PDF, XAdES, CMS | [CA.4-6], [CA.4-11] | `test_an_unreadable_token_does_not_take_the_whole_result_down`, `test_an_unreadable_token_does_not_take_a_pdf_down_either`, `test_damage_beyond_the_first_field_read_is_still_caught`, `test_a_hash_nobody_implements_is_an_answer_and_not_a_crash`, `test_xades_t.py::test_tampered_timestamp_fails_only_the_timestamp_check`, plus the sweep and `test_properties_timestamp.py::test_combined_damage_stays_inside_the_failure_envelope` | C5, C6, C7 | - |
| 2 | Damage to the timestamp attribute never indicts the document's own signature | A broken stamp reads as a forged document, accusing the wrong thing. The attribute is unsigned, so it says nothing about the document | PDF, XAdES, CMS | [CA.4-6] (traceability means the error is attributed where it is) | `test_neither_kind_of_damage_touches_the_signature_itself`, `test_an_unreadable_token_still_lets_the_signature_be_judged`, `test_tampering_with_the_unsigned_timestamp_attribute_leaves_the_signature_intact`, `test_xades_t.py::test_a_forged_token_does_not_make_the_signature_invalid`, plus the sweep and the combined-damage property | none: held by design, verified by the sweep and the properties | - |
| 3 | A broken timestamp never leaves the overall verdict at VALID | A tampered token hides behind a green verdict | PDF, XAdES, CMS | [CA.4-6] | `test_a_tampered_pdf_timestamp_holds_the_verdict_at_indeterminate`, `test_a_tampered_timestamp_holds_the_verdict_at_indeterminate`, `test_xades_t.py::test_tampered_timestamp_fails_only_the_timestamp_check` | C1 | - |
| 4 | Only a token with a usable validation time (definition above) moves the moment the signer's certificate is judged at | Whoever can rewrite an unsigned attribute picks the day an expired or revoked certificate is checked on | PDF, XAdES, CMS (one shared `evaluate_timestamp`) | [CA.4-10], [CA.4-6] | `test_an_untrusted_stamp_does_not_move_the_moment`, `test_a_stamp_from_an_expired_responder_is_still_not_trusted_under_the_wrong_root`, `test_xades_t.py::test_tsa_ca_wrong_anchor_does_not_trust_timestamp`, `test_properties_timestamp.py::test_an_untrusted_stamp_never_rescues_an_expired_certificate` | none. The guarding test itself was strengthened after mutation testing showed it passed for the wrong reason | - |
| 5 | Signer anchors and TSA anchors never contaminate each other, in either direction | Trusting a timestamping authority quietly widens who may sign, or trusting a signer vouches for a TSA | PDF, XAdES, CMS (separate validation contexts everywhere) | [CA.4 objective] | `test_the_signer_anchors_do_not_decide_the_timestamp`, `test_the_tsa_anchors_do_not_vouch_for_the_signer` | none | - |
| 6 | Timestamp trust is three-valued end to end: "never evaluated" is never reported as "evaluated and failed", and `gen_time` survives an untrusted chain | Inventing a failure nobody went looking for, or erasing the date, which is the one thing the stamp exists to state | PDF, XAdES, CMS, and the `--json` output | [CA.4-6] | `test_xades_t.py::test_a_sound_token_under_the_wrong_anchor_is_not_called_broken`, `test_xades_t.py::test_the_gen_time_survives_a_chain_that_did_not_validate`, `test_the_json_says_null_for_a_chain_that_was_not_looked_at` | C2 | - |
| 7 | A timestamp does not decay: the TSA's certificate is judged at `genTime`, and a wrong anchor still refuses it | Every stamped document silently loses its time evidence the day the responder certificate behind it expires | PDF, XAdES, CMS | [CA.4-10] | `test_a_pdf_timestamp_is_judged_at_gentime_and_not_at_verification_time`, `test_a_p7s_timestamp_is_judged_at_gentime_and_not_at_verification_time`, `test_xades_t.py::test_tsa_ca_enables_ltv_evaluation_at_gentime`, `test_properties_timestamp.py::test_a_trusted_stamp_makes_the_verdict_independent_of_when_you_look` | C3 | [gap 3](#known-gaps-in-the-order-they-should-close): judged at its own asserted `genTime`, which -LTA would settle |
| 8 | The three formats agree on the expired-signer, trusted-stamp scenario: same verdict | The verdict depends on the file container instead of on the cryptography | PDF, XAdES, CMS | [CA.4 objective], [AD.1-4] | `test_the_three_formats_agree_about_an_expired_signer_with_a_trusted_stamp`. **One scenario, not a table of them**: the row is stated no wider than its evidence, and widening it means parameterising over trust and time states first | C4 | [gap 6](#known-gaps-in-the-order-they-should-close): one scenario, not a table of them |

## Counterexamples found

Each one was a real defect in released or reviewed code, reduced to a deterministic regression
before it was fixed, and traceable to the commit that fixed it. How each one surfaced is
recorded because it says something about which checks earn their keep, and for no other reason.
None of it is a credential: nobody external has assessed this code.

- **C1, VALID over a broken token** (before 1.12.0). PDF and CMS discarded pyHanko's
  `timestamp_validity` entirely, so a file whose token was broken in every way pyHanko reports
  still came back VALID with no row about it. Found by code review. Fixed in 1.12.0
  ([`1cf4689`](https://github.com/carlosplanchon/firmauy/commit/1cf4689), [`74efb50`](https://github.com/carlosplanchon/firmauy/commit/74efb50)). Regressions:
  `test_a_tampered_pdf_timestamp_holds_the_verdict_at_indeterminate` and its CMS twin, which
  edit the real unsigned attribute in the file.
- **C2, a sound token reported as destroyed** (before 1.12.1). XAdES answered integrity,
  validity and trust with one boolean, so a correct token under the wrong anchor came back
  `intact=False, valid=False` with its `genTime` erased, sending the reader to inspect the file
  when the problem was the anchors they passed. Found by code review. Fixed in 1.12.1
  ([`441b589`](https://github.com/carlosplanchon/firmauy/commit/441b589)). Regressions:
  `test_xades_t.py::test_a_sound_token_under_the_wrong_anchor_is_not_called_broken`,
  `test_xades_t.py::test_the_gen_time_survives_a_chain_that_did_not_validate`.
- **C3, decaying trust** (before 1.12.1). PDF and CMS judged the TSA's certificate at
  verification time instead of at `genTime`. Measured against a real DigiCert token: the same
  stamp read as trusted through 2036-09-03 and as untrusted from 2036-09-05, tracking the
  responder certificate's expiry to the day (found by bisection). Found by code review, confirmed by
  measurement. Fixed in 1.12.1 ([`441b589`](https://github.com/carlosplanchon/firmauy/commit/441b589)). Regressions:
  `test_a_pdf_timestamp_is_judged_at_gentime_and_not_at_verification_time` and its CMS twin.
- **C4, format asymmetry** (before 1.13.0). The same expired-signer, trusted-stamp scenario
  returned VALID as XAdES and INDETERMINATE as PDF or CMS. Found by cross-format measurement
  during development. Fixed in 1.13.0 ([`4c9084b`](https://github.com/carlosplanchon/firmauy/commit/4c9084b)). Regression:
  `test_the_three_formats_agree_about_an_expired_signer_with_a_trusted_stamp`.
- **C5, escaped exception on a malformed TSTInfo** (before 1.13.1). The extractor reported an
  unreadable token as absent, pyHanko then parsed the same bytes again, and the `ValueError`
  left a public function. Found by code review. Fixed in 1.13.1 ([`3ee3418`](https://github.com/carlosplanchon/firmauy/commit/3ee3418)). Regressions:
  `test_an_unreadable_token_does_not_take_the_whole_result_down` and its PDF twin.
- **C6, lazy parsing escape** (before 1.14.0). asn1crypto parses lazily, so damage anywhere past
  the first field read handed back a perfectly good `genTime`, was accepted, and raised later
  inside pyHanko. Found by the sweep below. Fixed in 1.14.0 ([`62c2fc2`](https://github.com/carlosplanchon/firmauy/commit/62c2fc2)). Regression:
  `test_damage_beyond_the_first_field_read_is_still_caught`.
- **C7, a digest nobody implements** (before 1.14.0). A structurally perfect OID naming a
  nonexistent hash algorithm parsed cleanly, was approved, and raised at first use.
  Structurally sound is not the same as usable. Found by the sweep below. Fixed in 1.14.0
  ([`62c2fc2`](https://github.com/carlosplanchon/firmauy/commit/62c2fc2)). Regression: `test_a_hash_nobody_implements_is_an_answer_and_not_a_crash`.

## The two searching checks

Most of the tests above answer a question somebody already thought to ask. Two do not: they
search. [AD.1-5] asks for "un procedimiento documentado de pruebas de seguridad" and [AD.1-6] for
"criterios de aceptación de los productos desde la perspectiva de seguridad de la información",
and for the timestamp parser these two sections are that procedure and those criteria.

They divide the work by whether the space can be walked. All three are finite. The sweep
enumerates, because 1096 cases is a number you can count to. The properties sample, because
theirs run to about 6x10^27 and 3.15x10^15, which are numbers you can only write down.

### The sweep: every single-bit mutation

1. Sign a detached `.p7s` with software keys and a local RFC 3161 timestamper. No card and no
   network are involved.
2. Locate the embedded TSTInfo, the timestamped structure inside the signature's unsigned
   attribute.
3. For every byte of it, and for every bit of that byte, flip exactly that one bit and verify
   the mutated file.
4. Acceptance criteria, all four for every mutation:
   - no exception escapes `verify_cms`,
   - the timestamp is reported present and not sound,
   - the overall indication is INDETERMINATE,
   - every check about the document's own signature stays green.
5. Any violation becomes a deterministic regression in `test_timestamp_status.py` before it is
   fixed, so the finding outlives the sweep that made it.

It runs in CI as the `sweep` job, on every pull request and every push to main, and locally
with:

```bash
FIRMAUY_SWEEP=1 uv run pytest tests/test_sweep_tstinfo.py -q
```

Last full run: firmauy 1.14.0, a 137 byte TSTInfo, 1096 single-bit mutations, zero violations,
25 seconds on a desktop machine. The two escapes it found (C6, C7) were in code that had been
reviewed three times and shipped with a deterministic suite of 390 tests, which is why it runs
continuously rather than sitting archived.

Two of CA.4's level 4 controls describe this loop. [CA.4-11] asks for audits of the signature
modules "incluyendo pruebas de cumplimiento de formatos, protocolos, protección de claves y
servicios de sellado de tiempo". The sweep provides technical evidence relevant to the
timestamping side of such an audit and nothing more. What it demonstrates is robustness under
corruption, not conformance: broader format and protocol conformance, and key protection, are
outside its scope, and it is not itself an audit, independent or otherwise. [CA.4-12] asks for
audit results to be "analizados e incorporados a la mejora de la solución", and C1 to C7 show
that loop in practice, each finding folded back into the solution and traceable from defect to
commit to regression. Consistent with the clause, not a claim of compliance with it.

### The properties: what cannot be walked through

`tests/test_properties_timestamp.py`, using Hypothesis. The sweep counts to 1096 and stops. Two
spaces are finite too and nowhere near walkable, and there sampling is the only option:

- **Combined damage.** The unrestricted mutation space of a 137 byte structure is 2^1096. This
  property samples its two-to-twelve-flip subspace, about 6x10^27 sets. Each example draws
  between two and twelve flips and applies them together, and the acceptance criteria are the
  sweep's four, unchanged. When a property fails, Hypothesis
  shrinks the failure toward a smaller and simpler failing set, which is the part a loop cannot
  do. It searches for that rather than proving minimality, so a reported counterexample is small
  and not necessarily the smallest.
- **Time.** A hundred years at the microsecond resolution `timedelta` carries is about
  3.15x10^15 instants. Two properties sample it, over a signer certificate that expires the day
  after signing and a domain running from the genTime the token states out to a century. With a
  trusted timestamp the verdict must not depend on when you look, and with an unvalidated or
  wrongly anchored one the expired certificate must never be rescued. The second asserts on the
  chain row rather than on the indication, because an unvalidated token already holds the verdict
  at INDETERMINATE by itself and asserting on the word would pass either way. That trap was found
  in this suite by mutation testing, which is why it is called out here.

Two profiles: 50 examples with the normal suite across the whole Python matrix, and forty times
that once in the `sweep` job, both on every pull request and every push to main, and reachable
locally with `FIRMAUY_DEEP=1`. Keys and signed artifacts are built once per module and reused
for every example, because a 2048 bit RSA chain costs 1.76 seconds to generate and doing it per
example would buy nothing but wall clock.

The same rule as the sweep: any counterexample becomes a deterministic regression in
`test_timestamp_status.py` before it is fixed. Last deep run at 1.14.0: 6000 examples across the
three properties, no counterexamples, 3 minutes 15 seconds. Said plainly, because a reader is
otherwise left to guess, and because finding nothing is the honest expected result here: the
sweep had already enumerated the neighbourhood these properties extend outward from.

## Downstream

The three-valued semantics survive past this repository. firmauy-desktop asserts that a never
evaluated chain is not rendered as a failed one, and firmauy-mcp-inspect asserts that its batch
summary never collapses `trusted: null` into `false` and refuses to run on a CLI older than
these semantics. Both carry their own suites.

## Known gaps, in the order they should close

1. **Conformance against the official validator.** Everything above proves the verifier does not
   crash and does not misreport its own model. None of it proves the verdicts agree with
   [firma.gub.uy](https://firma.gub.uy/) on real cédula signatures, and that agreement is the
   first thing an institutional reviewer should ask about. Manual today, and in two parts that
   need different people. What one signer with one card can close is the format side: their own
   signatures, through both validators. What needs breadth is the certificate side, because cards
   are issued across years and two chip generations, and the Ministerio publishes three CRL
   streams while the one card measured points at one of them, so nothing says every card does.
   The [conformance protocol](#the-conformance-protocol) below turns that breadth into redacted
   one-line reports anybody can contribute.
2. **Revocation end to end.** [CA.4-5] asks for certificate validation "a través de OCSP (Online
   Certificate Status Protocol), CRL (Certificate Revocation List) o equivalente", and firmauy
   does it on request with `--check-revocation`. What is missing is confirmation against a live
   cédula signature, as recorded in [trust-anchors.md](trust-anchors.md). No invariant above
   covers it, which is why the clause appears here and not in the matrix. Measured on 2026-08-05:
   the cédula's chain publishes no OCSP at any level, and its CRL is 12.6 MB with 269,202
   entries, so "o equivalente" is doing real work in that sentence.

   Two halves, and only one closes with a valid card. The negative half, a current certificate
   passing with the CRL fetched and applied, is one signature and one afternoon. The positive
   half, a revoked certificate actually being caught, needs what no valid card can provide: a
   signature made with a certificate that was later revoked, which every renewal creates. It also
   carries an interpretation trap: under a trusted timestamp predating the revocation, VALID can
   be the correct answer, so the clean positive case is an unstamped signature verified today.
   The [conformance protocol](#the-conformance-protocol) accepts rows for either half.
3. **AdES -LT and -LTA are not implemented**, so a timestamp is judged optimistically at its own
   asserted `genTime`. Documented in [trust-anchors.md](trust-anchors.md) and [api.md](api.md).
4. **Coherent structural mutation is still out of reach.** Both searching checks preserve the
   size of the message: they flip bits, never insert, delete or re-nest. They do corrupt ASN.1
   length headers, since a length byte is as flippable as any other, but corrupting one is not
   the same as building a message whose lengths and nesting are internally consistent and
   different. A parser can reject the first at the door and still be wrong about the second. Out
   of scope too: any mutation outside the TSTInfo, and any fixture other than the one detached
   CMS both of them run against.
5. **The `--json` contract is prose plus tests**, not a machine-checked schema.
6. **Cross-format agreement is asserted on one scenario.** Invariant 8 covers an expired signer
   with a trusted stamp, which is the case that was actually wrong (C4). Agreement across the
   other combinations of trust and time state is expected and untested. Closing this means a
   parameterised table over those states, not another single case.
7. **Resource exhaustion is uncharacterised.** Nothing in this library bounds oversized or
   deeply nested input, whether ASN.1, PDF or XML. The sweep demonstrates robustness under
   bounded, length-preserving corruption, which says nothing about a gigabyte file or a
   thousand-deep nesting. The MCP server mitigates downstream with a subprocess timeout. The
   library itself does not.
8. **Neither the signing side nor the rest of the verifier has a page like this one.** This page
   covers timestamp handling, as its title says. How a signature is written, which is where the
   PIN, the staging file and the access control of the replaced output live, is documented in the
   code and covered by regressions of the same kind, including several that came from the same
   reviews. So is signature and certificate verification outside the timestamp path. Neither has
   a matrix, a clause mapping or a searching check, so nothing here should be read as evidence
   about either.

## The conformance protocol

Gaps 1 and 2 do not close with more code, and they do not close with one person either. They
close with variety: certificates issued in different years, cards of both chip generations,
signatures that aged into revocation. No single signer holds all of that. And a corpus of real
signed documents cannot be collected at all, because a signature file carries the signer's name,
their document number and their certificate. What can be collected is verdicts.

**A row, not a document.** [`scripts/conformance_row.py`](https://github.com/carlosplanchon/firmauy/blob/main/scripts/conformance_row.py) verifies
a signed file locally, extracts only what identifies the infrastructure, and prints one markdown
row. A row may never contain the signer's name, their document number, the certificate serial,
or the file's name. The script enforces that mechanically, refusing to print a row that carries
any signer field the verifier saw, and
[`tests/test_conformance_row.py`](https://github.com/carlosplanchon/firmauy/blob/main/tests/test_conformance_row.py) holds the refusal in place
with a fixture that contains a fake document number, so its absence from the output means the
redaction ran rather than that there was nothing to redact. What a row does carry is public:
the issuing CA's name, which CRL the certificate points at, the algorithm, the TSA's name, the
two verdicts, and whether they agree. Redacted is not anonymous: a rare combination of year,
chip, CA and CRL narrows who a row could describe, so contribute knowing it is coarse, not
invisible.

**Contributing one:**

```bash
uv run scripts/conformance_row.py firmado.pdf
# upload the same file at https://firma.gub.uy/ and read its answer, then:
uv run scripts/conformance_row.py firmado.pdf --firma-gub-uy "correcta"
# a second row with revocation consulted says more:
uv run scripts/conformance_row.py firmado.pdf --check-revocation --firma-gub-uy "correcta"
```

Paste the output into a GitHub issue titled "Conformance row" at
[github.com/carlosplanchon/firmauy/issues](https://github.com/carlosplanchon/firmauy/issues).

**What the portal answers, measured 2026-08-05.** firma.gub.uy describes its validation for PDF
("Podés comprobar la validez de un documento PDF") and answers with one of three phrases, taken
from the portal's own interface text: "La firma del documento es correcta.", "La firma del
documento no es correcta", "Se encontró un problema al analizar el documento." Quote the one you
saw. Whether the portal accepts XAdES XML is unconfirmed, and a detached `.p7s` has no place
there, so CAdES rows will usually carry a pending portal verdict, which is itself information.
There is no API and none is wanted here: a person uploads, a person reads, the row records.

**What each axis of variety buys.** The certificate year covers profile changes across
emissions. The CRL column covers the three streams the Ministerio publishes, of which the one
card measured points at `crl.crl` and nothing says every card does. The chip column, v4 or v5
and self-reported, covers the two applet generations. And a row whose certificate was since
revoked, verified without a timestamp and with revocation on, is the one observation that can
show detection detecting.

As of 2026-08-05 there are no rows. The protocol exists so that the first ones come from more
wallets than one.

## References

- Agesic, [Planilla MCU 5.0 Avanzado](https://www.gub.uy/agencia-gobierno-electronico-sociedad-informacion-conocimiento/sites/agencia-gobierno-electronico-sociedad-informacion-conocimiento/files/documentos/publicaciones/Planilla%20MCU%205.0%20Avanzado.xlsx),
  the requirement catalogue itself, linked from the [Marco de ciberseguridad
  5.0](https://www.gub.uy/agencia-gobierno-electronico-sociedad-informacion-conocimiento/comunicacion/publicaciones/marco-ciberseguridad-50)
  page. Every CA.4 control text above is a cell in its Cumplimiento sheet, which is the form an
  auditor can open and search rather than a page to read.
- Agesic, MCU 5.0, requisito AD.1 (Adquisición, desarrollo y mantenimiento):
  [guía de implementación](https://www.gub.uy/agencia-gobierno-electronico-sociedad-informacion-conocimiento/comunicacion/publicaciones/guia-implementacion-del-mcu-50/adquisicion-desarrollo-mantenimiento).
  Quoted above: AD.1-4, AD.1-5, AD.1-6 and the audit evidence list.
- Agesic, MCU 5.0, control CA.4 (Establecer los controles para el uso de firma electrónica):
  [guía de implementación](https://www.gub.uy/agencia-gobierno-electronico-sociedad-informacion-conocimiento/comunicacion/publicaciones/guia-implementacion-del-mcu-50/control-acceso/ca4-establecer-controles).
  Quoted above: the objective, and the level of each control. The control texts themselves are quoted from the catalogue.
- Ley 18.600, art. 6, official text at
  [IMPO](https://www.impo.com.uy/bases/leyes/18600-2009/6). Quoted verbatim above and discussed
  in [usage.md](usage.md) and [trust-anchors.md](trust-anchors.md).
