---- MODULE RequestApproval ----
EXTENDS Naturals

VARIABLES state, authorityIssued, policyAllows, actorAuthorized, claimAllowed, approvalMode

vars == <<state, authorityIssued, policyAllows, actorAuthorized, claimAllowed, approvalMode>>

Init ==
  /\ state = "none"
  /\ authorityIssued = FALSE
  /\ policyAllows = TRUE
  /\ actorAuthorized = TRUE
  /\ claimAllowed = FALSE
  /\ approvalMode = "none"

SubmitManual ==
  /\ state = "none"
  /\ policyAllows
  /\ state' = "pending"
  /\ approvalMode' = "manual"
  /\ UNCHANGED <<authorityIssued, policyAllows, actorAuthorized, claimAllowed>>

SubmitAutomatic ==
  /\ state = "none"
  /\ policyAllows
  /\ state' = "pending"
  /\ approvalMode' = "automatic"
  /\ UNCHANGED <<authorityIssued, policyAllows, actorAuthorized, claimAllowed>>

BeginAutomatic ==
  /\ state = "pending"
  /\ approvalMode = "automatic"
  /\ policyAllows
  /\ state' = "issuing"
  /\ claimAllowed' = TRUE
  /\ UNCHANGED <<authorityIssued, policyAllows, actorAuthorized, approvalMode>>

BeginApproval ==
  /\ state = "pending"
  /\ approvalMode = "manual"
  /\ policyAllows
  /\ actorAuthorized
  /\ state' = "issuing"
  /\ claimAllowed' = TRUE
  /\ UNCHANGED <<authorityIssued, policyAllows, actorAuthorized, approvalMode>>

IssueAuthority ==
  /\ state = "issuing"
  /\ claimAllowed
  /\ authorityIssued' = TRUE
  /\ UNCHANGED <<state, policyAllows, actorAuthorized, claimAllowed, approvalMode>>

FinishApproval ==
  /\ state = "issuing"
  /\ authorityIssued
  /\ state' = "approved"
  /\ UNCHANGED <<authorityIssued, policyAllows, actorAuthorized, claimAllowed, approvalMode>>

Deny ==
  /\ state = "pending"
  /\ actorAuthorized
  /\ state' = "denied"
  /\ UNCHANGED <<authorityIssued, policyAllows, actorAuthorized, claimAllowed, approvalMode>>

Cancel ==
  /\ state = "pending"
  /\ actorAuthorized
  /\ state' = "cancelled"
  /\ UNCHANGED <<authorityIssued, policyAllows, actorAuthorized, claimAllowed, approvalMode>>

Expire ==
  /\ state = "pending"
  /\ state' = "expired"
  /\ UNCHANGED <<authorityIssued, policyAllows, actorAuthorized, claimAllowed, approvalMode>>

ChangePolicy ==
  /\ state \in {"none", "pending"}
  /\ policyAllows' = ~policyAllows
  /\ UNCHANGED <<state, authorityIssued, actorAuthorized, claimAllowed, approvalMode>>

ChangeActorAuthorization ==
  /\ state \in {"none", "pending"}
  /\ actorAuthorized' = ~actorAuthorized
  /\ UNCHANGED <<state, authorityIssued, policyAllows, claimAllowed, approvalMode>>

Next ==
  SubmitManual \/ SubmitAutomatic \/ BeginAutomatic \/ BeginApproval \/ IssueAuthority \/ FinishApproval \/
  Deny \/ Cancel \/ Expire \/ ChangePolicy \/ ChangeActorAuthorization

ApprovedImpliesIssued == state # "approved" \/ authorityIssued

IssuanceRequiresDurableClaim == ~authorityIssued \/ state \in {"issuing", "approved"}

CommittedClaimWasAllowed == state \notin {"issuing", "approved"} \/ claimAllowed

RejectedRequestsNeverIssue == state \notin {"denied", "cancelled", "expired"} \/ ~authorityIssued

TypeOK ==
  /\ state \in {"none", "pending", "issuing", "approved", "denied", "cancelled", "expired"}
  /\ authorityIssued \in BOOLEAN
  /\ policyAllows \in BOOLEAN
  /\ actorAuthorized \in BOOLEAN
  /\ claimAllowed \in BOOLEAN
  /\ approvalMode \in {"none", "manual", "automatic"}

Spec == Init /\ [][Next]_vars

====
