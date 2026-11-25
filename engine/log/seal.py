"""Segmented append-only audit-log seals: executable specification (stubs only).

The log is split into zero-based segments.  Every segment is represented by a
dict with exactly these fields::

    {
        "index": int,          # zero-based segment number
        "prev_seal": str|None, # previous segment's seal, None for segment 0
        "entries": list[dict], # all entries in this segment, in append order
        "digest": str,         # SHA-256 over this segment's entries
        "seal": str,           # SHA-256 over index, prev_seal and digest
    }

An entry is a JSON-serialisable dict.  The standard audit fields are ``ts``
(int Unix seconds), ``actor`` (str), ``action`` (str) and ``detail`` (str),
but the digest covers every key and value that is actually present.

Canonical form
--------------

Both digests use UTF-8 and compact, key-sorted JSON with no ASCII escaping::

    canonical(value) = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    digest = sha256(canonical(entries)).hexdigest()
    seal = sha256(canonical({
        "index": index,
        "prev_seal": prev_seal,
        "digest": digest,
    })).hexdigest()

Every digest is 64 lowercase hexadecimal characters.  The seal binds the
segment number, the previous segment's seal and all entries of the segment.
A stored digest or seal is never trusted: verification recomputes both from
the data and compares exactly.

The segment numbers of a healthy chain are exactly ``0, 1, ..., n - 1`` in
stored order.  Timestamps inside one stream are non-decreasing in append
order.  No function mutates its arguments.  The functions return reported
problems rather than hiding them, except ``read_range`` which raises for an
out-of-bounds request and ``seal_block``/``seal_batch`` which raise
``ValueError`` for malformed input.
"""


import copy
import hashlib
import json


def _canonical(value) -> bytes:
    """Compact, key-sorted JSON without ASCII escaping, encoded as UTF-8."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _digest(entries) -> str:
    return hashlib.sha256(_canonical(entries)).hexdigest()


def _seal(index, prev_seal, digest) -> str:
    # Defect 1 fix: prev_seal is part of the seal, so a broken chain cannot
    # be reconnected without recomputing it.
    # Defect 2 fix: index is part of the seal, so segments cannot be swapped
    # to another position while keeping their stored seal.
    return hashlib.sha256(
        _canonical(
            {
                "index": index,
                "prev_seal": prev_seal,
                "digest": digest,
            }
        )
    ).hexdigest()


def _is_real_int(value) -> bool:
    """``bool`` is an ``int`` subclass but must never count as one here."""
    return isinstance(value, int) and not isinstance(value, bool)


def _well_formed_block(block) -> bool:
    if not isinstance(block, dict):
        return False
    for field in ("index", "prev_seal", "entries", "digest", "seal"):
        if field not in block:
            return False
    if not isinstance(block["entries"], list):
        return False
    return all(isinstance(entry, dict) for entry in block["entries"])


def seal_block(entries, index, prev_seal) -> dict:
    """Seal one segment and return a new block dict.

    ``entries`` is a list of JSON-serialisable entry dicts and is not
    modified.  ``index`` is a non-negative int (``bool`` is rejected).
    ``prev_seal`` is the previous segment's seal string, or ``None`` for a
    segment that starts a stream.  This low-level function does not judge
    whether ``prev_seal`` is appropriate for ``index``; it only seals the
    three inputs together.

    The returned dict has ``index``, ``prev_seal``, a deep copy of
    ``entries``, ``digest`` and ``seal``.  ``digest`` is the canonical
    SHA-256 of ``entries``.  ``seal`` is the canonical SHA-256 of
    ``{"index": index, "prev_seal": prev_seal, "digest": digest}``.
    Consequently, changing the index, changing the previous seal, or
    changing any entry must change the seal.  A seal that covers only the
    entries lets an attacker move a segment to another position or splice a
    different predecessor without touching the segment contents.

    Raises ``ValueError`` when ``entries`` is not a list of dicts, when
    ``index`` is not a non-negative int, or when ``prev_seal`` is neither
    ``None`` nor a string.
    """
    if not isinstance(entries, list) or not all(
        isinstance(entry, dict) for entry in entries
    ):
        raise ValueError("entries must be a list of dicts")
    if not _is_real_int(index) or index < 0:
        raise ValueError("index must be a non-negative int")
    if prev_seal is not None and not isinstance(prev_seal, str):
        raise ValueError("prev_seal must be None or a string")

    stored_entries = copy.deepcopy(entries)
    digest = _digest(stored_entries)
    seal = _seal(index, prev_seal, digest)
    return {
        "index": index,
        "prev_seal": prev_seal,
        "entries": stored_entries,
        "digest": digest,
        "seal": seal,
    }


def verify_block(block, prev_seal) -> bool:
    """Verify one block against the expected previous seal.

    Return ``True`` only when all of the following hold:

    * ``block`` is a dict with the five required fields;
    * its stored ``prev_seal`` equals the ``prev_seal`` argument exactly;
    * its stored ``digest`` equals the canonical digest of ``entries``;
    * its stored ``seal`` equals the canonical seal over its own ``index``,
      ``prev_seal`` and computed ``digest``.

    Any shape error, missing field, wrong type or mismatch returns ``False``;
    malformed data must not produce an exception from this predicate.  The
    function cannot decide by itself whether ``index`` is the right position
    in a chain, so ``verify_chain`` performs that additional check.  It must
    compare the previous seal and recompute the seal from the supplied
    ``prev_seal``: comparing only the stored digest, or accepting a seal
    that was computed without the predecessor, allows a broken chain to be
    reconnected silently.
    """
    try:
        if not _well_formed_block(block):
            return False
        if block["prev_seal"] != prev_seal:
            return False
        if not _is_real_int(block["index"]) or block["index"] < 0:
            return False
        if not isinstance(block["digest"], str) or not isinstance(
            block["seal"], str
        ):
            return False

        computed_digest = _digest(block["entries"])
        if block["digest"] != computed_digest:
            return False
        # Recompute the seal from the *supplied* prev_seal, never trusting
        # the stored one, so a spliced predecessor cannot pass.
        if block["seal"] != _seal(
            block["index"], prev_seal, computed_digest
        ):
            return False
        return True
    except (TypeError, ValueError):
        return False


def verify_chain(blocks) -> dict:
    """Verify a complete chain and stop at the first failed segment.

    Segments must appear in ascending position order.  At position ``i`` the
    expected segment number is ``i``; the expected previous seal is ``None``
    for ``i == 0`` and the previous block's ``seal`` for ``i > 0``.  The
    first segment is verified exactly like every other segment.

    Return::

        {"ok": True, "index": None, "reason": ""}

    for an intact chain, including an empty chain, or::

        {"ok": False, "index": i, "reason": code}

    for the first failed position, where ``i`` is the zero-based position
    (and therefore the expected segment number).  Codes, in checking order:

    * ``"shape"``: not a dict, missing fields, or unusable entries;
    * ``"index"``: stored index is not the expected position;
    * ``"prev-seal"``: stored prev_seal is not the expected seal;
    * ``"digest"``: stored digest is not the digest of entries;
    * ``"seal"``: stored seal is not the seal over index, prev_seal, digest.

    Return the first failure, never the last one: a later failure sits behind
    the first break and reporting it hides where the damage starts.
    ``read-only``: the argument is not modified.
    """
    if not isinstance(blocks, list):
        return {"ok": False, "index": 0, "reason": "shape"}

    previous_seal = None
    for position, block in enumerate(blocks):
        # Defect 3 fix: position 0 goes through exactly the same checks as
        # every later segment; the loop starts at the first block, not the
        # second.
        if not _well_formed_block(block):
            return {"ok": False, "index": position, "reason": "shape"}

        if not _is_real_int(block["index"]) or block["index"] != position:
            return {"ok": False, "index": position, "reason": "index"}

        if block["prev_seal"] != previous_seal:
            return {"ok": False, "index": position, "reason": "prev-seal"}

        computed_digest = _digest(block["entries"])
        if block["digest"] != computed_digest:
            # Defect 4 fix: return immediately on the first failure instead
            # of walking the whole chain and reporting the last break.
            return {"ok": False, "index": position, "reason": "digest"}

        if block["seal"] != _seal(
            block["index"], previous_seal, computed_digest
        ):
            return {"ok": False, "index": position, "reason": "seal"}

        previous_seal = block["seal"]

    return {"ok": True, "index": None, "reason": ""}


def detect_truncation(blocks, expected_blocks) -> bool:
    """Return ``True`` when the tail of the segment sequence is missing.

    ``expected_blocks`` is the independently known total number of segments,
    not the number of entries.  A chain is truncated when
    ``len(blocks) != expected_blocks``, or when it is non-empty and its last
    segment index is not ``expected_blocks - 1``.  The second rule catches a
    tail replaced by lower-numbered segments while the count stays the same.

    Counting entries instead of segments is wrong: one segment can contain
    many entries, so a missing tail may leave the entry count equal to the
    expected segment count, and extra entries in a complete chain may make a
    healthy chain look truncated.  An empty chain with ``expected_blocks == 0``
    is intact.  Raises ``ValueError`` for an invalid expected count.
    """
    if not _is_real_int(expected_blocks) or expected_blocks < 0:
        raise ValueError("expected_blocks must be a non-negative int")

    # Defect 5 fix: truncation is measured in segments, never in entries.
    if len(blocks) != expected_blocks:
        return True
    if blocks:
        if blocks[-1]["index"] != expected_blocks - 1:
            return True
    return False


def detect_gap(blocks) -> list:
    """Return problem codes for missing, duplicate or out-of-order segments.

    The result is a list of strings, empty exactly when the stored sequence
    is ``0, 1, ..., n - 1`` with no duplicates and no ordering violation.
    Walking the blocks in stored order:

    * ``"duplicate:<n>"`` for a segment number that was already seen;
    * ``"out-of-order"`` at the first non-duplicate segment whose number is
      smaller than the previous one.

    After the walk, ``"missing:<n>"`` is appended in ascending order for
    every number in ``0 .. max_index`` that never appeared.  A sequence such
    as ``0, 1, 1, 2`` therefore reports ``duplicate:1`` rather than silently
    accepting the duplicate, and ``0, 2`` reports ``missing:1``.  Checking
    only the size of adjacent differences is insufficient: equal neighbours
    have difference zero and a repeated segment number escapes.
    """
    problems = []
    seen = set()
    previous = None
    max_index = -1

    for block in blocks:
        number = block["index"] if isinstance(block, dict) else None
        if not _is_real_int(number) or number < 0:
            continue
        if number in seen:
            # Defect 6 fix: equal neighbours (difference zero) must not slip
            # past an adjacent-comparison check.
            problems.append("duplicate:%d" % number)
        else:
            if previous is not None and number < previous:
                problems.append("out-of-order")
            seen.add(number)
            previous = number
            if number > max_index:
                max_index = number

    for number in range(max_index):
        if number not in seen:
            problems.append("missing:%d" % number)

    return problems


def read_range(blocks, start, end) -> list:
    """Return the blocks whose segment numbers are in ``start .. end``.

    Both boundaries are inclusive.  The result is ordered by ascending
    segment number regardless of the storage order of ``blocks``, so a
    shuffled input still produces a stable read.  Segment numbers, not list
    positions, define the range.

    Raise ``IndexError`` when ``start`` or ``end`` is not an int, when
    ``start < 0``, when ``end < start``, when a requested segment number is
    absent, or when the same segment number appears more than once.  An
    out-of-bounds read must not be disguised as an empty successful read:
    silently returning ``[]`` makes a missing tail look like a valid empty
    range.
    """
    if not _is_real_int(start) or not _is_real_int(end):
        raise IndexError("range bounds must be ints")
    if start < 0 or end < start:
        raise IndexError("invalid range %r..%r" % (start, end))

    by_index = {}
    for block in blocks:
        if not isinstance(block, dict) or not _is_real_int(block.get("index")):
            raise IndexError("block without a usable segment index")
        number = block["index"]
        if number in by_index:
            raise IndexError("duplicate segment number %d" % number)
        by_index[number] = block

    result = []
    for number in range(start, end + 1):
        # Defect 7 fix: the end boundary is inclusive, so the last segment
        # of the requested range is actually read.
        # Defect 8 fix: a missing segment is an error, not an empty result.
        if number not in by_index:
            raise IndexError("segment %d is absent" % number)
        result.append(by_index[number])
    return result


def validate_chain(blocks) -> list[str]:
    """Return structural and append-order problems; ``[]`` when clean.

    This function checks the shape and links of the stored blocks; it does
    not recompute seals or decide whether the tail is complete.  Problems
    are emitted in position order and, within one block, in this order:

    * ``"index=<i>:not-dict"`` when the element is not a dict;
    * ``"index=<i>:bad-index"`` when ``index`` is missing or not an int;
    * ``"index=<i>:duplicate-index"`` for a segment number already seen;
    * ``"index=<i>:prev-seal"`` when the first block's ``prev_seal`` is not
      ``None``, or a later block's ``prev_seal`` is missing or does not equal
      the previous block's ``seal``;
    * ``"index=<i>:entry=<j>:bad-ts"`` when an entry has no integer ``ts``;
    * ``"index=<i>:entry=<j>:not-append"`` when an entry's timestamp is
      smaller than the previous timestamp in the stream.

    The append check spans segment boundaries: the last timestamp of one
    segment is compared with the first timestamp of the next.  Equal
    timestamps are allowed; going backwards is not.  Accepting a descending
    timestamp admits an entry that was inserted or moved instead of being
    appended.  The argument is not modified.
    """
    problems = []
    seen = set()
    previous_seal = None
    last_ts = None

    for position, block in enumerate(blocks):
        prefix = "index=%d" % position

        if not isinstance(block, dict):
            problems.append("%s:not-dict" % prefix)
            continue

        number = block.get("index")
        if not _is_real_int(number):
            problems.append("%s:bad-index" % prefix)
        else:
            if number in seen:
                problems.append("%s:duplicate-index" % prefix)
            seen.add(number)

        stored_prev = block.get("prev_seal")
        if position == 0:
            if stored_prev is not None:
                problems.append("%s:prev-seal" % prefix)
        else:
            if stored_prev is None or stored_prev != previous_seal:
                problems.append("%s:prev-seal" % prefix)

        entries = block.get("entries")
        if isinstance(entries, list):
            for entry_position, entry in enumerate(entries):
                if not isinstance(entry, dict) or not _is_real_int(
                    entry.get("ts")
                ):
                    problems.append(
                        "%s:entry=%d:bad-ts" % (prefix, entry_position)
                    )
                    continue
                ts = entry["ts"]
                # Defect 9 fix: the append check spans segment boundaries;
                # a timestamp smaller than the previous one means the entry
                # was not appended.
                if last_ts is not None and ts < last_ts:
                    problems.append(
                        "%s:entry=%d:not-append" % (prefix, entry_position)
                    )
                last_ts = ts

        if isinstance(block, dict) and "seal" in block:
            previous_seal = block["seal"]

    return problems


def seal_batch(streams, policy) -> dict:
    """Seal several independent streams in one call.

    ``streams`` is a mapping from stream name to a list of entry dicts.
    ``policy`` is ``{"block_size": int}`` with a positive int (``bool`` is
    rejected), giving the maximum number of entries per segment for every
    stream.

    Each stream starts a fresh chain: its first block has index ``0`` and
    ``prev_seal`` equal to ``None``, and later blocks use that same stream's
    previous seal only.  Entries are split into chunks of at most
    ``block_size``; a stream with no entries maps to ``[]``.  Return a dict
    with the same stream names and the list of blocks for each stream.

    The result for a stream must be exactly what sealing that stream alone
    would produce.  Carrying the previous stream's tail seal into the next
    stream connects two independent logs and makes every stream after the
    first look spliced.  Raises ``ValueError`` for malformed streams or
    policy.
    """
    if not isinstance(streams, dict):
        raise ValueError("streams must be a mapping of name to entries")
    if not isinstance(policy, dict):
        raise ValueError("policy must be a mapping")
    block_size = policy.get("block_size")
    if not _is_real_int(block_size) or block_size <= 0:
        raise ValueError("policy block_size must be a positive int")

    result = {}
    for name, entries in streams.items():
        if not isinstance(entries, list) or not all(
            isinstance(entry, dict) for entry in entries
        ):
            raise ValueError("stream %r must be a list of entry dicts" % name)

        blocks = []
        # Defect 10 fix: every stream starts its own genesis chain.  The
        # previous seal is reset here instead of being carried over from the
        # preceding stream's tail block.
        previous_seal = None
        for start in range(0, len(entries), block_size):
            block = seal_block(
                entries[start : start + block_size],
                len(blocks),
                previous_seal,
            )
            blocks.append(block)
            previous_seal = block["seal"]
        result[name] = blocks

    return result