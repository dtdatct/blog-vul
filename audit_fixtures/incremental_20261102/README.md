# Incremental Code Audit fixture

All values in `.env` are explicitly synthetic and nonfunctional. No application loads this directory. The database domain is reserved `.invalid`. `.env.example` provides empty and placeholder controls.

This tests changed-file coverage, synthetic-secret classification, and preservation of existing finding identities. A false-positive decision is acceptable; these files do not prove live credential exposure. Provider-shaped synthetic keys were rejected by repository secret protection and are not included.
