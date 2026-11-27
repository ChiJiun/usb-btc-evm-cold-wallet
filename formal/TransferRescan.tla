---- MODULE TransferRescan ----
EXTENDS TLC

CONSTANTS ProbeDeadline, KeepPending
VARIABLES phase, media, selected, mounted, worker, locked, marker, reported

vars == <<phase, media, selected, mounted, worker, locked, marker, reported>>
Media == {"first", "replacement", "absent"}

Init ==
    /\ phase = "Idle"
    /\ media = "first"
    /\ selected = "absent"
    /\ mounted = "absent"
    /\ worker = "none"
    /\ locked = FALSE /\ marker = FALSE /\ reported = FALSE

Start ==
    /\ phase = "Idle" /\ ~locked /\ ~marker
    /\ phase' = "Unmount" /\ selected' = "absent" /\ reported' = FALSE
    /\ marker' = TRUE /\ worker' = "unmount"
    /\ UNCHANGED <<media, mounted, locked>>

UnmountDone ==
    /\ phase = "Unmount"
    /\ phase' = "Probe" /\ mounted' = "absent"
    /\ marker' = FALSE /\ worker' = "none"
    /\ UNCHANGED <<media, selected, locked, reported>>

Swap ==
    /\ phase # "Off"
    /\ media' \in Media \ {media}
    /\ reported' = FALSE
    /\ UNCHANGED <<phase, selected, mounted, worker, locked, marker>>

ProbeDone ==
    /\ phase = "Probe"
    /\ IF media = "absent"
          THEN /\ phase' = "Idle" /\ marker' = FALSE /\ worker' = "none"
          ELSE /\ phase' = "Mount" /\ marker' = TRUE /\ worker' = "mount"
    /\ selected' = media
    /\ UNCHANGED <<media, mounted, locked, reported>>

ProbeTimeout ==
    /\ phase = "Probe" /\ ProbeDeadline
    /\ phase' = "Locked" /\ locked' = TRUE
    /\ UNCHANGED <<media, selected, mounted, worker, marker, reported>>

MountDone ==
    /\ phase = "Mount"
    /\ phase' = "Audit" /\ marker' = FALSE /\ worker' = "none"
    /\ mounted' \in {"absent", media}
    /\ UNCHANGED <<media, selected, locked, reported>>

CommandTimeout ==
    /\ phase \in {"Unmount", "Mount"}
    /\ phase' = "Locked" /\ locked' = TRUE /\ marker' = KeepPending
    /\ UNCHANGED <<media, selected, mounted, worker, reported>>

Audit ==
    /\ phase = "Audit"
    /\ reported' = (mounted = selected /\ selected = media)
    /\ phase' = IF reported' THEN "Idle" ELSE "Locked"
    /\ locked' = ~reported'
    /\ UNCHANGED <<media, selected, mounted, marker, worker>>

LateExit ==
    /\ phase = "Locked" /\ worker \in {"unmount", "mount", "cleanup"}
    /\ mounted' \in (IF worker = "mount" THEN {"absent", media} ELSE {"absent", mounted})
    /\ worker' = "exited"
    /\ UNCHANGED <<phase, media, selected, locked, marker, reported>>

Respawn ==
    /\ phase = "Locked" /\ marker /\ worker # "unknown"
    /\ worker' = "unknown"
    /\ UNCHANGED <<phase, media, selected, mounted, locked, marker, reported>>

ObserveExit ==
    /\ phase = "Locked" /\ worker = "exited"
    /\ marker' = FALSE /\ worker' = "none"
    /\ UNCHANGED <<phase, media, selected, mounted, locked, reported>>

Shutdown ==
    /\ phase \in {"Idle", "Locked"} /\ ~marker
    /\ phase' = "Cleanup" /\ locked' = TRUE /\ marker' = TRUE
    /\ worker' = "cleanup" /\ reported' = FALSE
    /\ UNCHANGED <<media, selected, mounted>>

CleanupDone ==
    /\ phase = "Cleanup"
    /\ phase' = "Off" /\ mounted' = "absent" /\ marker' = FALSE /\ worker' = "none"
    /\ UNCHANGED <<media, selected, locked, reported>>

CleanupFailed ==
    /\ phase = "Cleanup"
    /\ phase' = "Locked"
    /\ \/ marker' = FALSE /\ worker' = "none"
       \/ marker' = TRUE /\ worker' = "cleanup"
    /\ UNCHANGED <<media, selected, mounted, locked, reported>>

OffStaysOff == phase = "Off" /\ UNCHANGED vars

Next == Start \/ UnmountDone \/ Swap \/ ProbeDone \/ ProbeTimeout \/ MountDone \/ CommandTimeout \/
        Audit \/ LateExit \/ Respawn \/ ObserveExit \/ Shutdown \/ CleanupDone \/ CleanupFailed \/ OffStaysOff

Spec == Init /\ [][Next]_vars /\ WF_vars(ProbeTimeout) /\ WF_vars(CommandTimeout) /\ WF_vars(Audit)

NoReadyWithoutAudit ==
    reported => (phase = "Idle" /\ ~locked /\ ~marker /\ mounted = selected /\ mounted = media /\ media # "absent")

PendingIsGuarded ==
    worker \in {"unmount", "mount", "cleanup", "exited", "unknown"} => marker

SafePoweroff ==
    phase = "Off" => (locked /\ ~marker /\ worker = "none" /\ mounted = "absent")

ReturnToMenu ==
    (phase \in {"Unmount", "Probe", "Mount", "Audit"}) ~> (phase \in {"Idle", "Locked", "Cleanup", "Off"})

NoNormalReady == ~reported
NoSafePoweroff == phase # "Off"
====
