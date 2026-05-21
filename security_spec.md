# Security Specification: NetAudit Security Rules

This document outlines the security invariants, threat modeling "Dirty Dozen" payloads, and validation rules for the NetAudit perimetral security scanner application.

## 1. Data Invariants

1. **Identity Integrity**: A project's `userId` must always equal the `uid` of the authenticated user who created it (`request.auth.uid`). No user can read, list, update, or delete a project belonging to someone else.
2. **Temporal Integrity**: Create and update operations must rely strictly on server-generated dates and timestamps (`request.time` for `createdAt` and `updatedAt`). Client-submitted timestamps must not be trusted.
3. **Immutable Fields**: Once created, `id`, `userId`, and `createdAt` are strictly immutable and cannot be changed during any update.
4. **Boundary Checks**: Strings like `name`, `scope`, `auditor`, and `desc` must have strict size limits (e.g., `.size() <= 256`) to prevent Denial of Wallet and buffer flooding style exploits.
5. **Enums Validation**: The project's `status` field must strictly match one of: `'pending'`, `'active'`, `'done'`, `'archived'`.
6. **Self-Contained Sub-Structures**: The `entries` and `phaseStatus` fields are saved as maps belonging directly to the project document for rapid atomic writes.

---

## 2. The "Dirty Dozen" Threat Payloads

The following malicious writes are blocked by the security architecture:

1. **Self-Assigned Identity**: An auditor attempts to create a project with a hijacked `userId` (i.e., spoofing another auditor's UID).
2. **Ghost Property Injection**: Creating or updating a project with a malicious `isVerifiedBySystem` or other unrecognized fields.
3. **Denial of Wallet Buffer Flood**: Creating a project with a `name` of 1MB string to inflate read/storage costs.
4. **Malformed Status Enum**: Trying to set the status to `"admin-level"`.
5. **Missing Mandatory Fields**: Attempting to create a project without a `name`.
6. **Immutability Bypass (Owner Hijacking)**: A malicious update trying to change `userId` to a target victim's UID.
7. **Temporal Fraud**: Creating a document with a hardcoded `createdAt` in the past/future rather than `request.time`.
8. **Malicious Path Injection (ID Poisoning)**: Creating a project document with a custom ID consisting of 1.5KB of garbage characters (`isValidId` check).
9. **Private Document Get Leak**: Authenticated user B attempting to fetch project document owned by authenticated user A.
10. **Listing Query Scraping**: Running a broad list query for `projects` without enforcing resource filter checks.
11. **Immutability Bypass (Time Travel)**: Attempting to modify `createdAt` during a normal update.
12. **State Shortcutting**: Updating `phaseStatus` with invalid fields or non-conforming status strings.

---

## 3. Test Cases (TDD Blueprint for Security Rules)

The rule sets are designed to enforce authorization and schema validation on every request. Our secure fortress rules strictly reject any operation attempting these Dirty Dozen anomalies.
