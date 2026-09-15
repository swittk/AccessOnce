---- MODULE PublicationUnsafe ----
EXTENDS Publication

UnsafeWriteSource ==
  /\ phase = "idle"
  /\ source' = NewSource
  /\ UNCHANGED <<snapshot, phase>>

UnsafeSpec == Init /\ [][UnsafeWriteSource]_vars

====
