---- MODULE MediaAudit ----
EXTENDS TLC

CONSTANTS RequireGeometry, RequireBothWritable, AllowLegacyBootable
VARIABLES layout, esp, geometry, flags, decision, live

vars == <<layout, esp, geometry, flags, decision, live>>
MountLayers == [vaultMount : {"rw", "ro"}, vaultSuper : {"rw", "ro"},
                transferMount : {"rw", "ro"}, transferSuper : {"rw", "ro"}]

Init ==
    /\ layout \in {"single", "legacy"}
    /\ esp \in {"readonly", "readonlyAndBootable", "other"}
    /\ geometry \in {"valid", "labelOnly"}
    /\ flags \in MountLayers
    /\ decision = "unchecked" /\ live = "unchecked"

CheckBoot ==
    /\ decision = "unchecked"
    /\ decision' =
          IF (esp = "readonly" \/
              (AllowLegacyBootable /\ layout = "legacy" /\ esp = "readonlyAndBootable"))
             /\ (layout = "legacy" \/ ~RequireGeometry \/ geometry = "valid")
          THEN "accepted" ELSE "rejected"
    /\ UNCHANGED <<layout, esp, geometry, flags, live>>

Remount ==
    /\ flags' \in MountLayers
    /\ live' = "unchecked"
    /\ UNCHANGED <<layout, esp, geometry, decision>>

WritableLayers(mount, superblock) ==
    IF RequireBothWritable THEN mount = "rw" /\ superblock = "rw"
    ELSE mount = "rw" \/ superblock = "rw"

Audit ==
    /\ decision = "accepted"
    /\ live' =
          IF WritableLayers(flags.vaultMount, flags.vaultSuper)
             /\ WritableLayers(flags.transferMount, flags.transferSuper)
          THEN "accepted" ELSE "rejected"
    /\ UNCHANGED <<layout, esp, geometry, flags, decision>>

Next == CheckBoot \/ Remount \/ Audit
Spec == Init /\ [][Next]_vars

SingleBootRequiresGeometry ==
    decision = "accepted" /\ layout = "single" => geometry = "valid" /\ esp = "readonly"

LegacyEspCompatibility ==
    layout = "legacy" /\ esp = "readonlyAndBootable" => decision # "rejected"

UnknownEspRejected ==
    esp = "other" => decision # "accepted"

LiveRequiresAllWritable ==
    live = "accepted" => \A layer \in DOMAIN flags : flags[layer] = "rw"

NoLiveAcceptance == live # "accepted"
====
