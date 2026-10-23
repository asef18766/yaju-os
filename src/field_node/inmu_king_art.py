"""Host-side preview mirror of the firmware's ASCII chorus.

Visual reference: https://www.youtube.com/watch?v=MFwtpM21wWc&t=58s
The sampled chorus poses (roughly 0:58-1:14) alternate hands behind the
head and BOTH thumbs toward the viewer, accompanied by bent-knee steps.
Intermediate poses and timing are drawn by hand, not extracted video frames.

The deployed UUIDs, poses, timeline, and playback cursor live in
``firmware/maintenance_application.c``. This mirror supplies labels and an
offline preview without requiring Qiling; integration tests require its bytes
to match the compiled firmware exactly.

Each frame has the same canvas and floor. The artwork exceeds the default ATT
Read Response payload, so the transport preserves one firmware frame across
all Read Blob requests belonging to a logical read.
"""

from __future__ import annotations


FRAME_WIDTH = 17
FRAME_HEIGHT = 7
PREVIEW_FPS = 6.0


def _frame(*lines: str) -> bytes:
    """Pad the canvas on the right without moving any body part."""

    if len(lines) != FRAME_HEIGHT or any(len(line) > FRAME_WIDTH for line in lines):
        raise ValueError("dance pose does not fit the fixed canvas")
    return "\n".join(line.ljust(FRAME_WIDTH) for line in lines).encode("ascii")


# The head is always o.  Its neutral column is 8, with one-column leans.
# <o> keeps both elbows beside the head; b/d appear together at the shoulders
# for a foreshortened, front-facing thumbs-up.  Feet stay on the last row.
_POSES = {
    "head": _frame(
        "",
        "       <o>",
        "        |",
        "        |",
        "       / \\",
        "      /   \\",
        "     _|   |_",
    ),
    "head_left": _frame(
        "",
        "      <o>",
        "       \\",
        "        |",
        "       / \\",
        "      |  |",
        "     _|  |_",
    ),
    "head_down": _frame(
        "",
        "",
        "       <o>",
        "        |",
        "      _/ \\_",
        "      |   |",
        "     _|   |_",
    ),
    "head_right": _frame(
        "",
        "        <o>",
        "         /",
        "        |",
        "       / \\",
        "       |  |",
        "      _|  |_",
    ),
    "release": _frame(
        "",
        "       \\o/",
        "        |",
        "        |",
        "       / \\",
        "      /   \\",
        "     _|   |_",
    ),
    "ready": _frame(
        "",
        "        o",
        "       /|\\",
        "       b|d",
        "       / \\",
        "      /   \\",
        "     _|   |_",
    ),
    "thumbs": _frame(
        "",
        "        o",
        "      b/|\\d",
        "        |",
        "       / \\",
        "      /   \\",
        "     _|   |_",
    ),
    "thumbs_down": _frame(
        "",
        "",
        "        o",
        "      b/|\\d",
        "      _/ \\_",
        "      |   |",
        "     _|   |_",
    ),
    "thumbs_in": _frame(
        "",
        "        o",
        "      b/|\\d",
        "        |",
        "       / \\",
        "       | |",
        "      _| |_",
    ),
    "ready_in": _frame(
        "",
        "        o",
        "       /|\\",
        "       b|d",
        "       / \\",
        "       | |",
        "      _| |_",
    ),
}

_LABELS = {
    "head": "雙手抱頭",
    "head_left": "抱頭／向左換重心",
    "head_down": "抱頭／屈膝",
    "head_right": "抱頭／向右換重心",
    "release": "鬆開抱頭",
    "ready": "雙手收至胸前",
    "thumbs": "雙手朝前比讚",
    "thumbs_down": "朝前比讚／屈膝",
    "thumbs_in": "朝前比讚／收步",
    "ready_in": "收手／收步",
}

# Holds are intentional: key gestures need time to read.  Passing through the
# center pose avoids teleporting the head directly from left to right.
# Repeat the head / forward-thumbs motif before returning to the opening pose.
_TIMELINE = (
    ("head", 3),
    ("head_left", 2),
    ("head", 1),
    ("head_down", 2),
    ("head", 1),
    ("head_right", 2),
    ("head", 2),
    ("release", 1),
    ("ready", 1),
    ("thumbs", 3),
    ("thumbs_down", 2),
    ("thumbs", 1),
    ("thumbs_in", 2),
    ("ready_in", 1),
    ("ready", 1),
    ("release", 1),
    ("head", 3),
    ("head_right", 2),
    ("head", 1),
    ("head_down", 2),
    ("head", 1),
    ("head_left", 2),
    ("head", 2),
    ("release", 1),
    ("ready", 1),
    ("thumbs", 3),
    ("thumbs_in", 2),
    ("thumbs", 1),
    ("thumbs_down", 2),
    ("thumbs", 1),
    ("ready", 1),
    ("release", 1),
    ("head", 2),
)

INMU_KING_DANCE_FRAMES: tuple[bytes, ...] = tuple(
    _POSES[pose] for pose, hold in _TIMELINE for _ in range(hold)
)
INMU_KING_DANCE_LABELS: tuple[str, ...] = tuple(
    _LABELS[pose] for pose, hold in _TIMELINE for _ in range(hold)
)
