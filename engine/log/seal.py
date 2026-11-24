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
    raise NotImplementedError


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
    raise NotImplementedError


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
    raise NotImplementedError


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
    raise NotImplementedError


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
    raise NotImplementedError


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
    raise NotImplementedError


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
    raise NotImplementedError


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
    raise NotImplementedError