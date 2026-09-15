---- MODULE Publication ----
EXTENDS Naturals, FiniteSets

CONSTANT Permissions, OldSource, NewSource

VARIABLES source, snapshot, phase

vars == <<source, snapshot, phase>>

Init ==
  /\ source = OldSource
  /\ snapshot = OldSource
  /\ phase = "idle"

BeginChange ==
  /\ phase = "idle"
  /\ snapshot' = {}
  /\ phase' = "denied"
  /\ UNCHANGED source

WriteSource ==
  /\ phase = "denied"
  /\ source' \in SUBSET Permissions
  /\ phase' = "sourceWritten"
  /\ UNCHANGED snapshot

PublishCompiled ==
  /\ phase = "sourceWritten"
  /\ snapshot' = source
  /\ phase' = "idle"
  /\ UNCHANGED source

Crash ==
  /\ phase # "idle"
  /\ phase' = "idle"
  /\ UNCHANGED <<source, snapshot>>

Recover ==
  /\ phase = "idle"
  /\ snapshot # source
  /\ snapshot' = source
  /\ UNCHANGED <<source, phase>>

Next == BeginChange \/ WriteSource \/ PublishCompiled \/ Crash \/ Recover

SnapshotNeverBroaderThanSource == snapshot \subseteq source

TypeOK ==
  /\ source \subseteq Permissions
  /\ snapshot \subseteq Permissions
  /\ phase \in {"idle", "denied", "sourceWritten"}

Spec == Init /\ [][Next]_vars

====
