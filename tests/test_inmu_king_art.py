from __future__ import annotations

import unittest

from yaju_os.inmu_king_art import (
    FRAME_HEIGHT,
    FRAME_WIDTH,
    INMU_KING_DANCE_FRAMES,
    INMU_KING_DANCE_LABELS,
)


class InmuKingArtTests(unittest.TestCase):
    def test_frames_share_a_fixed_ascii_canvas(self) -> None:
        self.assertTrue(INMU_KING_DANCE_FRAMES)
        self.assertEqual(len(INMU_KING_DANCE_FRAMES), len(INMU_KING_DANCE_LABELS))
        for frame in INMU_KING_DANCE_FRAMES:
            self.assertTrue(frame.isascii())
            self.assertLessEqual(len(frame), 512)
            rows = frame.split(b"\n")
            self.assertEqual(len(rows), FRAME_HEIGHT)
            self.assertTrue(all(len(row) == FRAME_WIDTH for row in rows))
            self.assertEqual(frame.count(b"o"), 1)
            self.assertEqual(rows[-1].count(b"_"), 2)


if __name__ == "__main__":
    unittest.main()
