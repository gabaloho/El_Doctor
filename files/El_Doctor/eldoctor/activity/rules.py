"""Detection rules raised by the user-activity recorder (listed by `eldoctor rules`, silenced with
detection.disabled_rules like every other rule)."""

ACTIVITY_RULES = {
    "ED-ACT-001": ("Mass file deletion (possible data wipe)", "critical", ["T1485", "T1070.004"],
                   "Many files and folders were deleted in a short time. Wipers, ransomware and insiders destroying "
                   "data look like this. The report lists who did it and every affected file."),
    "ED-ACT-002": ("Files deleted while El Doctor was not running", "critical", ["T1485", "T1070.004"],
                   "At start-up, files known to exist when El Doctor last ran were gone. The deletion happened "
                   "while the agent was stopped or the system was off (or booted from other media)."),
    "ED-ACT-003": ("El Doctor evidence store deleted or moved", "critical", ["T1070", "T1485"],
                   "The El Doctor database, keys or logs disappeared from the data folder: someone is destroying "
                   "the forensic record."),
    "ED-ACT-004": ("Downloaded file matches threat intelligence", "critical", ["T1105", "T1204.002"],
                   "A file that was just downloaded has a hash or name listed in a threat-intel feed."),
    "ED-ACT-005": ("El Doctor stopped unexpectedly (monitoring gap)", "medium", ["T1562.001"],
                   "The agent stopped without a clean shutdown while the system kept running - it may have been "
                   "killed. Nothing was recorded during the gap."),
}
