# vldap

Pure V LDAP v3 primitives for simple bind and subtree search.

This module currently focuses on the Teedy/VeloDocs authentication flow:

- LDAP v3 simple bind
- subtree search with equality, AND, OR, and NOT filters
- SearchResultEntry attribute extraction
- pure V fake-server protocol tests

LDAPS is intentionally surfaced in the configuration but not enabled until a pure V TLS transport is added.
