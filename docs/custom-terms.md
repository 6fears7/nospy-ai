# Custom terms

[Back to the README](../README.md)

`nospy` already redacts secrets, emails, IPs, hostnames and so on. It doesn't know about your spooky, upcoming project called `Project Falcon` or that `ACME-20431` is a customer ticket. A **terms file** is where you manage that sensitive data. It's a plain text list of words and patterns that are specific to you. Every match is replaced with a placeholder, the same as any built-in rule.

## Example

Create `terms.txt`:

```
# Entries before any [SECTION] are redacted as TERM
Project Falcon

[CODENAME]
bluebird
Orion Next

[CUSTOMER]
Acme Corp
re:ACME-\d{4,}
```

Create `notes.md`:

```
Kickoff for Project Falcon (internal codename: bluebird).
Acme Corp opened ticket ACME-20431 about orion   next.
Contact Dana at dana@example.com
```

Redact it:

```bash
nospy scan --terms terms.txt notes.md
```

```
Kickoff for [REDACTED_TERM_1] (internal codename: [REDACTED_CODENAME_1]).
[REDACTED_CUSTOMER_1] opened ticket [REDACTED_CUSTOMER_2] about [REDACTED_CODENAME_2].
Contact Dana at [REDACTED_EMAIL_1]
nospy: redacted CODENAME=2 CUSTOMER=2 EMAIL=1 TERM=1
```

The redacted text goes to stdout and the counts to stderr. Note that:

- `orion   next` (awkward spacing with lower case) still matched `Orion Next`.
- The `[SECTION]` name became the kind in the placeholder: `[CODENAME]` gives `[REDACTED_CODENAME_n]`.
- The email was caught by a built-in rule.

To see *why* each thing matched,  you can add `--explain` to the command:

```
1:13  TERM  terms  "Project Falcon"
1:48  CODENAME  terms  "bluebird"
2:1  CUSTOMER  terms  "Acme Corp"
2:25  CUSTOMER  terms-re  "ACME-20431"
2:42  CODENAME  terms  "orion   next"
3:17  EMAIL  email  "dana@example.com"
```

Format is: `line:col KIND rule "text"`.

## Use it with the proxy

```bash
nospy --terms terms.txt -- claude          # wrap a command
nospy serve --terms /etc/nospy/terms ...   # shared proxy (read once at startup)
nospy check --terms terms.txt ...          # validate without starting
```

`check` takes the same flags as `serve` and is the quickest way to test a file you just edited. It exits non-zero on any problem:

```
$ nospy check --auth none --route /openai=https://api.openai.com/v1 --terms terms.txt
ok: routes openai(passthrough); auth none; terms 5 in 3 sections; plaintext
```

In Kubernetes, see [the Helm values](kubernetes.md) (`terms: {existingSecret: ...}`).

Encrypt the file at rest. If you're deploying it in Kubernetes, mount it from a Secret.

## File format

One entry per line. `#` starts a comment (at the start of a line or after whitespace). Blank lines are ignored.

| Line | Meaning |
|---|---|
| `some words` | Redact this exact text. Case is ignored and any run of whitespace matches. It matches whole words only, so `Acme` does not match `Acmeville`. Minimum 3 characters |
| `re:PATTERN` | Redact whatever a [Go RE2 regex](https://github.com/google/re2/wiki/Syntax) matches. It is used as written, so add `(?i)` if you want it case-insensitive. It must not match the empty string |
| `[NAME]` | Start a section. Following entries are redacted as `[REDACTED_NAME_n]`. Names are upper case letters, digits and `_`, starting with a letter. Use whatever helps you read the output (`CUSTOMER`, `PROJECT`, ...) |
| `[ADDRESS]` | A section like any other, for known postal addresses |
| `[ALLOW]` | A section of exceptions, see below |

Entries above the first section are kind `TERM`. When several entries overlap, the longest match is used.

### Exemptions: `[ALLOW]`

`[ALLOW]` entries are never redacted by **any** rule, built-in or yours. Use it for harmless values that a rule catches by accident, such as a placeholder ticket number in your templates:

```
[CUSTOMER]
re:ACME-\d{4,}

[ALLOW]
ACME-0000
```

```
Template uses ACME-0000, real one is [REDACTED_CUSTOMER_1].
```

An allow entry only exempts a match that is identical to it, ignoring case. It is not a pattern, and it does not protect text that contains it or sits inside it.

For example, with the term `Acme` and the allow entry `docs.acme.example`, the hostname `docs.acme.example` is fully matched by the built-in hostname rule and left alone. But the `Acme` term separately matches just `acme` inside it. That is not identical to the allow entry, so it is still redacted: `docs.[REDACTED_TERM_1].example`. To keep it, you would have to allow `acme` itself, which stops `Acme` being redacted everywhere.

Use allow entries for identifiers such as hosts, IPs, emails and usernames. Passwords, tokens and keys can never be allowed, and nospy rejects the file if they are used.

## When a built-in rule also matches

Your terms have the **lowest** priority. If a built-in rule already claims the text (a token, an email, an IP), that rule wins and the placeholder uses its kind. Use `[ALLOW]` if you want the text left alone.

## Errors

A bad file stops startup (or `scan`, or `check`) and lists problems with the line number.

```bash
nospy: --terms bad.txt:
  terms line 1: term shorter than 3 characters
  terms line 2: invalid regex
  terms line 3: invalid section name
```

## Addresses

Postal address detection only uses high-precision patterns: US street lines, PO boxes, US city lines, UK postcodes and Canadian postal codes. Add the addresses you care about under `[ADDRESS]` if they are not in those formats.
