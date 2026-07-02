# Advisory 보강 댓글 (GHSA-m5rj-39jf-xqp에 추가)

---

Hi Simon,

I wanted to add a follow-up to address a potential rebuttal: "if the table is accessible anyway, facets just aggregate visible data."

That's a fair point for Test 4. So here's a more precise framing of the issue.

## The core problem: SQL operations, not data visibility

`allow_sql: false` is described as preventing "arbitrary SQL execution." The question is whether facet aggregation counts as SQL execution. I'd argue it does — here's why.

## Test 5 — SQL filter vs. SQL aggregation under `allow_sql: false`

Same table, same setting, two built-in parameters that both trigger SQL:

```
[Test 5a] ?_where=amount>3000  (SQL filter)
          Settings: default_allow_sql=False
          HTTP 403  <- blocked

[Test 5b] ?_facet=customer_email  (SQL GROUP BY)
          Settings: default_allow_sql=False
          HTTP 200  <- allowed
          alice@corp.com : 2
          bob@corp.com   : 2
          carol@corp.com : 1

[Test 5c] ?_facet=amount  (SQL GROUP BY)
          Settings: default_allow_sql=False
          HTTP 200  <- allowed
          amount=2000 : 1
          amount=3000 : 1
          amount=4000 : 1
          amount=5000 : 1
          amount=7000 : 1
```

`?_facet=customer_email` generates and executes this SQL:
```sql
SELECT customer_email as value, count(*) as count
FROM (SELECT * FROM sales)
WHERE customer_email is not null
GROUP BY customer_email
ORDER BY count DESC
LIMIT 31
```

`?_where=amount>3000` generates:
```sql
SELECT * FROM sales WHERE amount > 3000
```

Both are SQL. Both are triggered by URL parameters. Only one is gated by `execute-sql` permission.

## Why this matters beyond "data is accessible anyway"

An admin who sets `allow_sql: false` may be trying to prevent:
- Bulk data extraction via aggregation (e.g., enumerate all unique emails)
- Statistical inference from column distributions
- SQL-based data mining in general

They are not necessarily trying to hide tables — they may want row browsing to work while preventing SQL-level operations. `allow_sql: false` appears to be the right tool for that, but facets bypass it.

The inconsistency with `?_where=` remains the clearest evidence that this is unintentional: datasette already treats some built-in SQL-triggering parameters as subject to `execute-sql` permission, and others not.

---

If the intended design is "allow_sql only gates the SQL editor, not facets," I think that's worth documenting explicitly — users who set `allow_sql: false` should know that facets remain an active SQL execution path.

Thanks again for your time.
