# Immediate Next Steps (Execution)

1. Replace API in-memory stores with Postgres persistence using `docs/db/schema-v1.sql`
2. Add Slack webhook/Slack app alert sender for new `high|critical` findings
3. Build web dashboard (Overview + Findings + Remediation Queue)
4. Wire scheduled worker jobs per tenant (hourly posture + daily external scan)
5. Add migration pipeline and integration tests
