# Receiver-observed secure Zenoh ACL campaign

This candidate was generated from clean Haldir commit `a10f41f7edd2309520652b87e4d4c5c1e4cbf3c8` using the exact `haldir-secure-reference-v1` profile. Separate remote Zenoh sessions observed the fixed final-command/controller-intent ACL subset and a late quarantine window. Only callbacks count as delivery evidence; local `put()` returns and router logs are non-authoritative corroboration.

The result is narrow: it exercises certificate-principal ACL behavior in the pinned synthetic deployment. It does not prove exclusive custom-CA trust, runtime Gate selection, credential custody, Crebain application, or complete mediation.
