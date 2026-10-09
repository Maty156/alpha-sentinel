# tests/ - event fixtures for the rule engine

The synthetic self-test proves that Sentinel's **thresholds** work, but it
invents the field names it feeds the engine - so it can never catch a rule that
reads the wrong field or the wrong log channel. Both of the bugs that mattered
most in v2.1 were exactly that kind:

- `dcsync_replication` compared the replication GUIDs against `ObjectType`, but a
  real 4662 carries them in `Properties`, so it could never fire;
- `eventlog_service_stopped` polled `1100` from the **System** log, but the
  Eventlog service writes it to the **Security** log.

These fixtures are small, hand-written event XML in the exact shape the real
events have (field names taken from Microsoft's per-event reference pages). Each
one has its expected outcome in `expected.json`.

## Run them

```powershell
# the whole directory
.\AlphaSentinel.ps1 -ReplayPath .\tests\fixtures

# or one file
.\AlphaSentinel.ps1 -ReplayPath .\tests\fixtures\dcsync-4662-properties.xml
```

Replay runs the events through the **real** `Get-NormalizedEvent` +
`Evaluate-Event` path - the same code live polling uses - oldest first, prints
every alert that would fire, and writes a `*.alerts.csv` report next to the
input. It does not touch `sentinel-history.csv`, so it is safe to run against a
live monitor.

A replay that finds nothing is a result, not necessarily a bug: it means the
events are benign, or the rule that should catch them is reading a field that is
not in that XML. Compare the field names against the file you fed it.

To replay **real** events from your lab DC:

```powershell
wevtutil epl Security C:\evt\security.evtx
wevtutil qe C:\evt\security.evtx /f:xml /c:1000 > C:\evt\security.xml
.\AlphaSentinel.ps1 -ReplayPath C:\evt\security.xml
```

## expected.json

```json
"dcsync-4662-properties.xml": {
  "expect":  ["dcsync_replication"],   // rule keys that MUST fire
  "expectCount": 2,                    // optional: exact count of expect[0]
  "forbid":  ["ldap_recon"],           // rule keys that must NOT fire
  "note":    "why this fixture exists"
}
```

`expect` and `forbid` let a fixture assert both directions - a false positive
(a rule firing on a legitimately quiet event) is recorded the same way as a
miss.

## The fixtures

| Fixture | Expected | What it pins down |
|---|---|---|
| `dcsync-4662-properties.xml` | `dcsync_replication` | The replication GUID is in `Properties`; `ObjectType` holds the object class |
| `dcsync-4662-dc-machine-account.xml` | nothing | A DC replicating as `DC02$` is normal, and must not be counted as enumeration either |
| `ntlm-4776-successful-validations.xml` | nothing | 4776 logs successes too (`Status 0x0`) - not a failure burst |
| `ntlm-4776-failed-validations.xml` | `ntlm_failed_auth` | A real failure burst still fires |
| `uac-4738-no-net-change.xml` | nothing | Editing an account that already had `DONT_REQ_PREAUTH` is not a new weakening |
| `uac-4738-preauth-removed.xml` | `account_control_changed` | The flag actually changing does fire |
| `uac-4738-already-disabled.xml` | nothing | An edit on an already-disabled account moves no flag |
| `kerberoasting-4769-mixed.xml` | `kerberoasting` | `krbtgt` and the machine SPN are excluded; the RC4 user SPN is the roast |
| `kerberoasting-4769-failure.xml` | nothing | A failed ticket request issued nothing to crack |
| `asrep-4768-single-request.xml` | `asrep_roasting` | One no-preauth TGT request is enough |
| `eventlog-1100-service-stopped.xml` | `eventlog_service_stopped` | 1100 is written to the **Security** channel |
| `account-created-4720-computer.xml` | nothing | A domain join is not an attacker creating an account |
| `account-created-4720-user.xml` | `account_created` | A real user account creation does fire |
| `privesc-4728-two-accounts.xml` | `privilege_escalation` x2 | Dedupe is per added account, not per rule |
| `logon-4624-service-account-type3.xml` | nothing | Routine service-account network logon is not lateral movement |
| `logon-4624-domain-admin-rdp.xml` | `suspicious_remote_logon` | Admin RDP does fire |

## Adding a fixture

1. Export or hand-write the event XML (one or many `<Event>` elements, bare or
   wrapped in `<Events>` - both parse).
2. Drop it in this directory.
3. Add an entry to `expected.json` saying what should and should not fire, and
   one sentence of why it exists.
4. Run `.\AlphaSentinel.ps1 -ReplayPath .\tests\fixtures`.
