# IAM/RBAC Demo

A small Identity and Access Management system demonstrating role-based access
control (RBAC) and compliance-grade audit logging, modeled on how a bank
branch controls who can view/edit accounts, approve transactions, and review
the audit trail.

Built to demonstrate three deliberately decoupled layers, the way a real
enterprise access-control system should be structured:

1. **Authentication** — "Who are you?" (bcrypt-hashed password login)
2. **Authorization** — "What are you allowed to do?" (roles → permissions,
   enforced by a reusable decorator)
3. **Audit** — "What did you actually do?" (every login, permission check,
   and role change is written to an immutable log)

## Architecture

```mermaid
graph LR
    User[Browser] -->|HTTP :5000| App[Flask app container]
    App -->|SQL :5432| DB[(Postgres container)]
    subgraph compose[docker-compose network]
        App
        DB
    end
