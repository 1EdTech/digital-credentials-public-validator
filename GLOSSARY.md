# VC Public Validator

Validates 1EdTech verifiable credentials (Open Badges 3.0, CLR 2.0, endorsements, status lists) against their specifications and reports the outcome of each check.

## Language

### Validation

**Probe**:
A single named check run against a credential, producing report items under its own probe ID.
_Avoid_: Check, rule, validator (for a single check)

**Inspector**:
The orchestrator for one credential kind that runs a sequence of probes and assembles the report.
_Avoid_: Validator (for the orchestrator)

### Open Badges 3.0

**Achievement**:
The accomplishment being asserted, embedded in the credential subject of an AchievementCredential.

**Result Description**:
An entry in an Achievement's `resultDescription` list that describes a possible result, identified by its `id`.
_Avoid_: Result definition, result template

**Result**:
An entry in the credential subject's `result` list recording what the recipient actually achieved.

**Result Description Reference**:
The `resultDescription` value on a Result: a URI that must equal, exactly, the `id` of a Result Description in the asserted Achievement.
_Avoid_: Result description (when meaning the reference rather than the object)

**Unresolved Result Description Reference**:
A Result Description Reference that matches no Result Description `id` in the asserted Achievement, including when the Achievement has no Result Descriptions at all.
_Avoid_: Dangling reference, broken link

**Rubric Criterion Level**:
An entry in a Result Description's `rubricCriterionLevel` list describing one level of achievement, identified by its `id`.

**Achieved Level**:
The `achievedLevel` value on a Result: a URI that must equal the `id` of a Rubric Criterion Level in the Result's referenced Result Description.

### TrustEd Credentials 1.0

**TrustEd Credential**:
An Open Badges 3.0 AchievementCredential that conforms to the TrustEd Credentials 1.0 profile: it must first be a valid OB 3.0 credential, then satisfy the profile's additional rules.
_Avoid_: OBTC, trusted badge

**TrustEd Schema**:
The JSON Schema a TrustEd Credential declares in its `credentialSchema` to claim conformance to the profile.
