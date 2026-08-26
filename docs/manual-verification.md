# Manual verification (touches real trust stores — run on a scratch macOS account or VM)

1. Build Release and launch `Cheburcert.app`.
2. Add `gosuslugi.ru`, click **Применить**, enter the admin password once.
3. Status banner shows Safari · Chrome · Firefox with the profile count.
4. In **Firefox**, open a real Минцифры-served `.ru` site (e.g. a gov/bank site that serves a Минцифры cert) — it loads without a certificate warning.
5. In **Firefox**, confirm a Минцифры-issued cert for a domain NOT in your list is rejected with a name-constraint error (`SEC_ERROR_...`/"issuer not permitted for this name"). This demonstrates the constraint. Safari/Chrome may NOT enforce this — that is the documented caveat.
6. Click **Удалить всё** — banner returns to "Защита выключена"; in Firefox, Preferences → Privacy & Security → Certificates → View Certificates → Authorities, the "Cheburcert Local Constrained Root" is gone.
