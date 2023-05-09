# ADR IAM M2M authentication and authorization
Date: 2023-04-06

## Summary

### Issue

We want machine to machine authentication and authorization with ARLAS IAM in ARLAS stack.

### Decision

Clearly state the architecture’s direction—that is, the position you’ve
selected.

### Status

The decision’s status, such as pending, decided, or approved.

## Details

### Assumptions

We are using ARLAS IAM in order to create M2M credentials and permissions.
We need:
- some credentials used by an application
- some permissions must be linked to these credentials
- we can revoke easily these credentials
- the credentials must be created by a IAM user
- the permissions cannot be larger that the credentials creator
- the credentials should have an optional expiration date
- we should be able to renew the credentials
- we can create multiple credentials
- 

### Constraints

The M2M auth is done from a software client (programmatically).

### Positions

List the positions (viable options or alternatives) you considered.
These often require long explanations, sometimes even models and
diagrams. This isn’t an exhaustive list. However, you don’t want to hear
the question ``Did you think about…?'' during a final review; this leads
to loss of credibility and questioning of other architectural decisions.
This section also helps ensure that you heard others’ opinions;
explicitly stating other opinions helps enroll their advocates in your
decision.

* P1: Use existing IAM mechanism: use login/password credentials to get a token and call the APIs with it.
* P2: Allow the creation of API Keys by users: used with a secret, it can be used to call directly the APIs.
* P3: Use a Service Account: create specific accounts usable only by applications to get a token and call the APIs with it (created by IAM admin, not org owner)

### Argument

Outline why you selected a position, including items such as
implementation cost, total ownership cost, time to market, and required
development resources’ availability. This is probably as important as
the decision itself.

### Implications

A decision comes with many implications, as the REMAP metamodel denotes.
For example, a decision might introduce a need to make other decisions,
create new requirements, or modify existing requirements; pose
additional constraints to the environment; require renegotiating scope
or schedule with customers; or require additional staff training.
Clearly understanding and stating your decision’s implications can be
very effective in gaining buy-in and creating a roadmap for architecture
execution.

## Related

### Related decisions

It’s obvious that many decisions are related; you can list them here.
However, we’ve found that in practice, a traceability matrix, decision
trees, or metamodels are more useful. Metamodels are useful for showing
complex relationships diagrammatically (such as Rose models).

### Related requirements

Decisions should be business driven. To show accountability, explicitly
map your decisions to the objectives or requirements. You can enumerate
these related requirements here, but we’ve found it more convenient to
reference a traceability matrix. You can assess each architecture
decision’s contribution to meeting each requirement, and then assess how
well the requirement is met across all decisions. If a decision doesn’t
contribute to meeting a requirement, don’t make that decision.

### Related artifacts

List the related architecture, design, or scope documents that this
decision impacts.

### Related principles

If the enterprise has an agreed-upon set of principles, make sure the
decision is consistent with one or more of them. This helps ensure
alignment along domains or systems.

## Notes

Because the decision-making process can take weeks, we’ve found it
useful to capture notes and issues that the team discusses during the
socialization process.
