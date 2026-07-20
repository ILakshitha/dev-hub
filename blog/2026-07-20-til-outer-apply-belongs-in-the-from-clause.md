---
title: "TIL: OUTER APPLY belongs in the FROM clause, not after WHERE"
description: Reusing a SQL string fragment that already ends in WHERE makes it impossible to add joins to one of the queries.
date: 2026-07-20
authors: [ishan]
tags: [til, sql, databases, typescript]
---

I was factoring shared filters out of a paginated query and ended up with SQL that wouldn't parse. The error pointed at `OUTER APPLY`, but the real problem was how I'd split the reusable fragment.

{/* truncate */}

## Context

I was building a paginated endpoint that returns reefer fuel readings, and I wanted each row to also carry the asset's last known location. The count query and the data query share the same filters, so I factored the table joins *and* the filters into one reusable `fromClause` string.

## The discovery

The shared fragment ended with the `WHERE`, so the only place left to append the location lookup was *after* it:

```sql
-- before — fromClause bakes in the WHERE, so the APPLY lands after it
SELECT f.UMDFridgeFuelId AS id, loc.Latitude AS latitude
FROM UMDFridgeFuel f
INNER JOIN AssetMapping am ON am.UMDId = f.UMDId
WHERE am.Deleted = 0
  AND f.SampleTime <= @to
OUTER APPLY (                      -- Incorrect syntax near the keyword 'OUTER'
  SELECT TOP 1 l.Latitude, l.Longitude
  FROM UMDLocation l
  WHERE l.UMDId = f.UMDId AND l.SampleTime <= f.SampleTime
  ORDER BY l.SampleTime DESC
) loc
ORDER BY f.SampleTime DESC
```

`OUTER APPLY` — like every `JOIN` — is part of the `FROM` clause. It has to appear *before* `WHERE`, because `WHERE` filters the row set that `FROM` has finished assembling. Splitting the fragment in two fixes it:

```sql
-- after — joins and where are separate fragments, so the APPLY goes in the right place
-- joins:
FROM UMDFridgeFuel f
INNER JOIN AssetMapping am ON am.UMDId = f.UMDId
OUTER APPLY (
  SELECT TOP 1 l.Latitude, l.Longitude
  FROM UMDLocation l
  WHERE l.UMDId = f.UMDId AND l.SampleTime <= f.SampleTime
  ORDER BY l.SampleTime DESC
) loc

-- where:
WHERE am.Deleted = 0
  AND f.SampleTime <= @to
```

Now the count query composes `joins + where`, and the data query composes `joins + apply + where + ORDER BY + paging`.

## Why it matters

The real lesson isn't the clause order — it's that **a shared SQL fragment should never bake in the `WHERE`**. Once it does, any query that needs an extra join is stuck, and the "obvious" workaround produces SQL that doesn't parse. Keep joins and where as separate strings from the start and each query can assemble the parts it actually needs.

Bonus failure mode: this breaks at execution, not at build time. TypeScript happily concatenates broken SQL, so if your tests mock the DB response you won't catch it until it hits a real server.

## Source / further reading

- [FROM clause plus JOIN, APPLY, PIVOT (T-SQL)](https://learn.microsoft.com/en-us/sql/t-sql/queries/from-transact-sql) — `APPLY` is documented as part of `FROM`
- [Logical query processing order](https://learn.microsoft.com/en-us/sql/t-sql/queries/select-transact-sql) — `FROM` runs before `WHERE`
