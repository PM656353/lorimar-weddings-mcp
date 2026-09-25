# Controlled lead and contact updates

This change adds `update_lead` and `update_contact`, gated by a new
`tripleseat:write` authorization. Existing read grants remain read-only.

Read the record first and supply its returned `revision` with the update.
Allowed fields are names, lead guest count/contact preference/additional
information, and contact description. Ownership, opt-in, site/location,
financial fields, nested records, deletion, and tour scheduling are excluded.
Preserve existing descriptive information when adding new information.

The server validates the ID, configured site, field allowlist, fresh record
revision, and authorization. It records an attempted operation before PUT and
reads back the requested values before reporting success. A timeout or failed
verification requires reconciliation; it must not cause an automatic retry.
The upstream API does not provide an atomic compare-and-swap guarantee, so a
human edit between the preflight GET and PUT remains a concurrency limitation.

## Activation requirements

- Review and pass repository CI. Local 25 mocked tests, TypeScript, targeted
  lint, and Vite build pass. `pnpm run check` is blocked by tsx IPC EPERM locally.
- Deploy only after review; this draft is not production activation.
- Refresh the MCP definition, then authorize `tripleseat:write` explicitly.
- Verify the real API returns `site_id` on records. Missing or mismatched
  `site_id` fails closed, even if a site query parameter was supplied.
- Test on an explicitly designated test record, including read-back and
  preservation of unrelated fields. No customer record was changed by tests.
- This does not implement email delivery, tour calendar notes, or unattended
  automation. Those require separate verified workflows.

References: Tripleseat official OpenAPI `/api-docs/v1/openapi.yaml` and
https://support.tripleseat.com/hc/en-us/articles/211858578-API-Contacts-Endpoint
