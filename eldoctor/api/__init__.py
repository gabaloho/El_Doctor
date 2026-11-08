"""Local authenticated API between the El Doctor agent and its front ends (CLI, TUI, GUI).

    front end (any OS user)                         agent (service account, owns the data folder)
    -----------------------                         ---------------------------------------------
    eldoctor approvals approve 3f2a  --- JSON --->  peer credentials (kernel) -> JWT check -> RBAC
    TUI / GUI                        <-- JSON ----  -> action -> hash-chained audit -> SIEM

* ``transport`` / ``winpipe`` - Unix domain socket / Windows named pipe, peer credentials, framing.
* ``server``   - ``AgentService``: the only code that opens the database, and the only place where
                 roles and permissions are checked.
* ``client``   - ``connect()``, ``ApiClient``, ``RemoteAgent`` used by the CLI, TUI and GUI.
"""
