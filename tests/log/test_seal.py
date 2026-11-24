"""Executable contract for segmented append-only audit-log sealing.

The fixtures below are built independently with the canonical SHA-256 recipe
documented in ``engine/log/seal.py``.  Damaged fixtures therefore look exactly
like tampering that leaves the stored digest or seal stale; the tests never
use a stub to manufacture their own expected answers.

These tests are immutable acceptance criteria.
"""

import copy
import hashlib
import json

import pytest

from engine.log.seal import (
    detect_gap,
    detect_truncation,
    read_range,
    seal_batch,
    seal_block,
    validate_chain,
    verify_block,
    verify_chain,
)

BASE_TS = 1_700_000_000
STEP = 10
EMPTY_RESULT = {"ok": True, "index": None, "reason": ""}


def ref_digest(entries):
    payload = json.dumps(
        entries,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def ref_seal(index, prev_seal, entries):
    payload = json.dumps(
        {
            "index": index,
            "prev_seal": prev_seal,
            "digest": ref_digest(entries),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def make_entry(number, **overrides):
    entry = {
        "ts": BASE_TS + number * STEP,
        "actor": "user%d" % number,
        "action": "append",
        "detail": "record-%d" % number,
    }
    entry.update(overrides)
    return entry


def make_block(index, entries, prev_seal):
    stored_entries = copy.deepcopy(entries)
    return {
        "index": index,
        "prev_seal": prev_seal,
        "entries": stored_entries,
        "digest": ref_digest(stored_entries),
        "seal": ref_seal(index, prev_seal, stored_entries),
    }


def make_chain(sizes):
    """Build a valid chain whose segment sizes are given by ``sizes``."""
    blocks = []
    previous = None
    number = 0
    for index, size in enumerate(sizes):
        entries = [make_entry(number + offset) for offset in range(size)]
        block = make_block(index, entries, previous)
        blocks.append(block)
        previous = block["seal"]
        number += size
    return blocks


def test_seal_block_binds_previous_seal():
    entries = [make_entry(0), make_entry(1)]
    first = seal_block(entries, 0, None)
    second = seal_block(entries, 0, "a" * 64)
    assert first["digest"] == second["digest"]
    assert first["seal"] != second["seal"]

    forged = copy.deepcopy(first)
    forged["prev_seal"] = "b" * 64
    assert verify_block(forged, "b" * 64) is False


def test_seal_block_binds_segment_number():
    entries = [make_entry(0)]
    first = seal_block(entries, 0, None)
    second = seal_block(entries, 1, None)
    assert first["seal"] != second["seal"]

    forged = copy.deepcopy(first)
    forged["index"] = 1
    assert verify_block(forged, None) is False


def test_verify_chain_checks_first_block():
    blocks = make_chain((2, 2, 2))
    blocks[0]["entries"][0]["detail"] = "rewritten-first-block"
    result = verify_chain(blocks)
    assert result["ok"] is False
    assert result["index"] == 0
    assert result["reason"] == "digest"


def test_verify_chain_reports_first_break():
    blocks = make_chain((2, 2, 2, 2))
    blocks[1]["entries"][0]["detail"] = "first-damage"
    blocks[3]["entries"][0]["detail"] = "later-damage"
    result = verify_chain(blocks)
    assert result["ok"] is False
    assert result["index"] == 1
    assert result["reason"] == "digest"

    spliced = make_chain((2, 2, 2, 2))
    spliced[2] = make_block(2, spliced[2]["entries"], "f" * 64)
    report = verify_chain(spliced)
    assert report["ok"] is False
    assert report["index"] == 2
    assert report["reason"] == "prev-seal"


def test_detect_truncation_uses_block_count():
    missing_tail = make_chain((2, 1))
    assert [block["index"] for block in missing_tail] == [0, 1]
    assert sum(len(block["entries"]) for block in missing_tail) == 3
    assert detect_truncation(missing_tail, 3) is True

    packed = make_chain((2, 1, 1))
    assert len(packed) == 3
    assert sum(len(block["entries"]) for block in packed) == 4
    assert detect_truncation(packed, 3) is False
    assert detect_truncation([], 0) is False


def test_detect_gap_reports_duplicates_and_holes():
    duplicate = make_chain((1, 1, 1))
    duplicate[2]["index"] = 1
    assert detect_gap(duplicate) == ["duplicate:1"]

    hole = make_chain((1, 1, 1))
    del hole[1]
    assert detect_gap(hole) == ["missing:1"]

    swapped = make_chain((1, 1, 1))
    swapped[0], swapped[1] = swapped[1], swapped[0]
    assert detect_gap(swapped) == ["out-of-order"]


def test_read_range_includes_both_endpoints():
    blocks = make_chain((1, 1, 1, 1))
    selected = read_range(blocks, 1, 3)
    assert [block["index"] for block in selected] == [1, 2, 3]
    assert selected == blocks[1:4]
    assert [block["index"] for block in read_range(blocks, 0, 0)] == [0]


def test_read_range_raises_on_out_of_bounds():
    blocks = make_chain((1, 1, 1))
    for start, end in ((-1, 1), (0, 3), (2, 1)):
        with pytest.raises(IndexError):
            read_range(blocks, start, end)
    with pytest.raises(IndexError):
        read_range([], 0, 0)


def test_validate_chain_rejects_duplicate_prev_and_non_append():
    blocks = make_chain((2, 2, 2))
    assert validate_chain(blocks) == []

    reversed_entries = make_chain((2, 2, 2))
    reversed_entries[0]["entries"][1]["ts"] = (
        reversed_entries[0]["entries"][0]["ts"] - 1
    )
    reversed_entries[2]["entries"][0]["ts"] = (
        reversed_entries[1]["entries"][-1]["ts"] - 1
    )
    assert validate_chain(reversed_entries) == [
        "index=0:entry=1:not-append",
        "index=2:entry=0:not-append",
    ]

    duplicate = make_chain((1, 1, 1))
    duplicate[2]["index"] = 1
    assert validate_chain(duplicate) == ["index=2:duplicate-index"]

    broken = make_chain((1, 1, 1))
    broken[1]["prev_seal"] = "0" * 64
    assert validate_chain(broken) == ["index=1:prev-seal"]


def test_seal_batch_does_not_reuse_previous_seal():
    streams = {
        "alpha": [make_entry(0), make_entry(1), make_entry(2)],
        "beta": [make_entry(10), make_entry(11)],
    }
    result = seal_batch(streams, {"block_size": 2})
    assert set(result) == {"alpha", "beta"}
    assert [block["index"] for block in result["alpha"]] == [0, 1]
    assert [block["index"] for block in result["beta"]] == [0]
    assert result["beta"][0]["prev_seal"] is None
    assert result["alpha"][1]["prev_seal"] == result["alpha"][0]["seal"]
    assert result["beta"][0]["seal"] != result["alpha"][0]["seal"]
    assert verify_chain(result["beta"]) == EMPTY_RESULT


def test_complete_chain_verifies():
    blocks = make_chain((2, 2, 2))
    assert verify_chain(blocks) == EMPTY_RESULT
    assert verify_block(blocks[2], blocks[1]["seal"]) is True
    assert detect_gap(blocks) == []
    assert detect_truncation(blocks, 3) is False
    assert validate_chain(blocks) == []


def test_any_single_block_replacement_is_located():
    original = make_chain((2, 2, 2, 2, 2))
    for index in range(len(original)):
        damaged = copy.deepcopy(original)
        damaged[index]["entries"][0]["detail"] = "replacement-%d" % index
        result = verify_chain(damaged)
        assert result["ok"] is False
        assert result["index"] == index
        assert result["reason"] == "digest"


def test_deleted_tail_is_detected():
    blocks = make_chain((2, 2, 2))
    short = copy.deepcopy(blocks[:-1])
    assert detect_truncation(short, 3) is True
    assert detect_truncation(blocks, 3) is False
    assert verify_chain(short) == EMPTY_RESULT


def test_read_range_keeps_stable_segment_order():
    blocks = make_chain((1, 1, 1, 1))
    shuffled = [blocks[index] for index in (2, 0, 3, 1)]
    selected = read_range(shuffled, 0, 3)
    assert [block["index"] for block in selected] == [0, 1, 2, 3]
    assert read_range(shuffled, 1, 2) == [blocks[1], blocks[2]]


def test_batch_matches_individual_sealing():
    streams = {
        "alpha": [make_entry(0), make_entry(1), make_entry(2)],
        "beta": [make_entry(10), make_entry(11), make_entry(12)],
        "empty": [],
    }
    policy = {"block_size": 2}
    batched = seal_batch(streams, policy)

    manual = {}
    for name, entries in streams.items():
        blocks = []
        previous = None
        for start in range(0, len(entries), policy["block_size"]):
            block = seal_block(
                entries[start : start + policy["block_size"]],
                len(blocks),
                previous,
            )
            blocks.append(block)
            previous = block["seal"]
        manual[name] = blocks

    assert batched == manual
    assert batched["empty"] == []