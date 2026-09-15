---- MODULE TemporalEvaluation ----
EXTENDS Integers, Sequences, TLC

\* Three half-open boundaries for one representative temporal grant:
\* add at 10, remove at 20, add again at 30.
TransitionTimes == <<10, 20, 30>>
Times == {0, 10, 15, 20, 25, 30, 35}
TransitionCount == Len(TransitionTimes)

VARIABLES cursor, active, time, seeking
vars == <<cursor, active, time, seeking>>

Init ==
  /\ cursor = 0
  /\ active = FALSE
  /\ time = 0
  /\ seeking = FALSE

\* Pick an arbitrary requested instant; the implementation may need several delta steps to reach it.
ChooseTime ==
  /\ ~seeking
  /\ \E chosen \in Times:
       /\ time' = chosen
       /\ seeking' = TRUE
  /\ UNCHANGED <<cursor, active>>

\* Apply the next forward delta when its half-open boundary is at or before the requested instant.
Advance ==
  /\ seeking
  /\ cursor < TransitionCount
  /\ TransitionTimes[cursor + 1] <= time
  /\ cursor' = cursor + 1
  /\ active' = IF cursor' \in {1, 3} THEN TRUE ELSE FALSE
  /\ UNCHANGED <<time, seeking>>

\* Reverse the most recently applied delta when historical evaluation moves before that boundary.
Rewind ==
  /\ seeking
  /\ cursor > 0
  /\ TransitionTimes[cursor] > time
  /\ active' = IF cursor \in {1, 3} THEN FALSE ELSE TRUE
  /\ cursor' = cursor - 1
  /\ UNCHANGED <<time, seeking>>

\* Once neither direction is due, the cached materialization covers the requested instant.
Finish ==
  /\ seeking
  /\ ~(cursor < TransitionCount /\ TransitionTimes[cursor + 1] <= time)
  /\ ~(cursor > 0 /\ TransitionTimes[cursor] > time)
  /\ seeking' = FALSE
  /\ UNCHANGED <<cursor, active, time>>

Next == ChooseTime \/ Advance \/ Rewind \/ Finish
Spec == Init /\ [][Next]_vars

CursorWithinBounds == cursor \in 0..TransitionCount
ActiveMatchesCursor == active = (cursor \in {1, 3})
IdleIntervalContainsTime ==
  seeking \/
  ((cursor = 0 \/ TransitionTimes[cursor] <= time) /\
   (cursor = TransitionCount \/ time < TransitionTimes[cursor + 1]))

====
