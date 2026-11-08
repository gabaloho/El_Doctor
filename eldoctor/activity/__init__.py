"""User-activity recording for forensics and triage: sessions, applications, file activity (created, edited,
deleted, renamed, opened, downloaded), boots / shutdowns / monitoring gaps and data-wipe incidents reported
to the registered administrators.  See ``eldoctor.activity.monitor``."""
from eldoctor.activity.monitor import ActivityMonitor
from eldoctor.activity.rules import ACTIVITY_RULES

__all__ = ["ActivityMonitor", "ACTIVITY_RULES"]
