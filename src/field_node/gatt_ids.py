"""Vendor identifiers the board runtime and the player probe share.

The second-stage firmware registers its own service through S130, so the host
learns those identifiers from the image rather than from this module.
"""

MAINTENANCE_SERVICE_UUID = "5a1c0001-7c5d-4c8d-942c-a786c1d58b6d"
MAINTENANCE_CONTROL_UUID = "5a1c0002-7c5d-4c8d-942c-a786c1d58b6d"
MAINTENANCE_INFO_UUID = "5a1c0003-7c5d-4c8d-942c-a786c1d58b6d"

INMU_KING_SERVICE_UUID = "5a1c1001-7c5d-4c8d-942c-a786c1d58b6d"
INMU_KING_FRAME_UUID = "5a1c1002-7c5d-4c8d-942c-a786c1d58b6d"
