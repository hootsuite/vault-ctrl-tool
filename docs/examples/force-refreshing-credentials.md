Aside from allow credentials to be refreshed just prior to their expirty (i.e. within the renew-interval), you can configure a
force refresh TTL which will make vault-ctrl-tool attempt to renew dynamically generated credentials (AWS STS) prior to their actual expiry.
This is to allow sensitive workloads to have a buffer in case of Vault issues. For example a STS token generated with a TTL of 1hr (+ using a 10m renew interval)
will be renewed at approx 50 minutes (as it would expire before the next interval). This means that if begins to Vault experiences issues at 49 minutes, there is only a
ten minute window between that and when systems using vault-ctrl-tool may experience outages due to expired credentials.

By generating credentials with a longer ttl and forcing them to be renewed prior to their expiry time, you can ensure that systems using vault-ctrl-tool have some buffer while issues are addressed.

For example, by setting a force refresh time of 1hr, and an STS TTL of 3 hr you can ensure in the event of a Vault outage that systems can still run up to two hours - giving you time to deal issues
without any disruption of service 

```bash
vault-ctrl-tool --sidecar --output-prefix=/tmp/v-c-t --force-refresh-ttl=60m --renew-interval=10m --sts-ttl=3h
```