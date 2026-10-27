# Web Assessment Validation Checklist

- [ ] Target origin verified against `ProjectScope`.
- [ ] Raw HTTP status line and headers stored as immutable `http_exchange` evidence.
- [ ] Sensitive `Cookie` / `Set-Cookie` / `Authorization` values redacted prior to external sharing.
- [ ] Finding distinguishes `severity` from `confidence` and cites `evidenceIds`.
