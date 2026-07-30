# Generate a differential corpus with the reference C++ coder.
#
# Microsoft's two recorded vectors (bit_estimator_z0, gaussian_encoder0) are the
# stronger evidence, because nobody here produced them — but between them they
# miss two things this crate has to get right: positions the model masks out with
# a negative index, and values far enough outside their distribution to need
# several bypass digits. Neither appears in either vector.
#
# So this asks the reference itself for streams covering those, over randomised
# table shapes. It is run rarely and by hand; the corpus it writes is checked in,
# so the Rust tests need neither Python nor the C++ extension.
#
# Requires the reference package, which is not a dependency of anything here:
#
#   git clone https://github.com/microsoft/mlvc
#   cd mlvc && uv sync --no-dev && uv pip install packages/msrtc_rans
#   uv run python <path-to>/generate.py
#
# Determinism is on purpose: a fixed seed and a fixed case list mean a rerun
# produces a byte-identical corpus, so an accidental regeneration shows up as no
# diff at all rather than as an unreviewable one.

from __future__ import annotations

import struct
from pathlib import Path

import numpy as np

from msrtc.rans import EntropyEncoder

MAGIC = b"MOQOM-RANS-CORP1"
SEED = 0x4D4F_514F_4D00_0001

OUT = Path(__file__).parent / "corpus.bin"


def tables(rng, distributions: int, symbol_bits: int, max_length: int):
    """Random but valid probability tables.

    Valid means every frequency is at least one and each distribution's total
    does not exceed the scale — the reference refuses anything else, and so does
    the port. Totals are deliberately allowed to land *below* the scale
    sometimes, since that is permitted and leaves part of the code space mapping
    to no symbol.
    """
    scale = 1 << symbol_bits
    lengths, offsets, table = [], [], []

    for _ in range(distributions):
        length = int(rng.integers(2, max_length + 1))
        lengths.append(length)
        # Zero can sit anywhere, including outside the range, which is what makes
        # a whole distribution bypass-only.
        offsets.append(int(rng.integers(-1, length + 1)))

        # A Dirichlet-ish split, then floored to at least one each. Skew matters:
        # a uniform table never drives the state near its bounds.
        weights = rng.random(length) ** int(rng.integers(1, 5))
        budget = scale - length  # one already reserved per symbol
        counts = np.floor(weights / weights.sum() * budget).astype(np.int64) + 1
        # Sometimes leave headroom, sometimes fill the scale exactly.
        if rng.random() < 0.5:
            counts[int(rng.integers(0, length))] += scale - counts.sum()
        assert counts.min() >= 1 and counts.sum() <= scale
        table.extend(int(c) for c in counts)

    return (
        np.asarray(lengths, dtype=np.int32),
        np.asarray(offsets, dtype=np.int32),
        np.asarray(table, dtype=np.int32),
    )


def data(rng, lengths, offsets, count: int, masked: float, wild: float):
    """Random indices and values.

    `masked` is the share of positions given a negative index, which the coder
    must skip without spending a bit. `wild` is the share pushed far outside
    their distribution, which forces multi-digit bypass.
    """
    distributions = len(lengths)
    indices = rng.integers(0, distributions, size=count).astype(np.int32)
    values = np.zeros(count, dtype=np.int32)

    for i in range(count):
        if rng.random() < masked:
            indices[i] = -1
            continue
        d = int(indices[i])
        sentinel = int(lengths[d]) - 1
        offset = int(offsets[d])
        if rng.random() < wild:
            # Far outside, both directions, sometimes very far — a value needing
            # the maximum number of bypass digits is the case that makes the
            # reference's own shift undefined on the way back.
            magnitude = int(rng.integers(1, 1 << int(rng.integers(4, 27))))
            values[i] = magnitude if rng.random() < 0.5 else -magnitude
        else:
            # In range, or just over the edge — the boundary is where an
            # off-by-one at the sentinel would hide.
            values[i] = int(rng.integers(-offset - 1, sentinel - offset + 1))

    return indices, values


def cases():
    """The corpus, described rather than generated at random.

    Each entry says what it is for. A pile of undifferentiated random cases
    would give the same coverage and tell a later reader nothing about which
    property broke when one fails.
    """
    return [
        # (name, distributions, symbol_bits, bypass_bits, max_length, count, masked, wild)
        ("mlvc-shaped", 128, 16, 2, 12, 8192, 0.00, 0.01),
        ("mostly-masked", 64, 16, 2, 9, 8192, 0.90, 0.02),
        ("half-masked", 64, 16, 2, 9, 4096, 0.50, 0.05),
        ("bypass-heavy", 32, 16, 2, 6, 4096, 0.05, 0.60),
        ("bypass-only", 16, 16, 2, 2, 2048, 0.00, 1.00),
        ("wide-bypass-digits", 32, 16, 4, 8, 4096, 0.10, 0.40),
        ("widest-bypass-digits", 16, 16, 8, 8, 2048, 0.10, 0.40),
        ("narrow-symbols", 32, 8, 2, 5, 4096, 0.10, 0.20),
        # 23 is the largest scale this variant can actually code: the scale has to
        # divide the normalisation interval's lower bound of 1 << 23. The
        # reference advertises 30 and fails its own round trip at 24, which is how
        # that limit was found.
        ("widest-symbols", 16, 23, 2, 6, 2048, 0.10, 0.20),
        ("two-symbol-distributions", 8, 16, 2, 2, 1024, 0.20, 0.30),
        ("long-distributions", 8, 16, 2, 64, 4096, 0.10, 0.10),
        ("single-distribution", 1, 16, 2, 16, 2048, 0.10, 0.20),
        ("tiny", 4, 16, 2, 4, 1, 0.00, 0.00),
        ("all-masked", 4, 16, 2, 4, 64, 1.00, 0.00),
    ]


def main():
    rng = np.random.default_rng(SEED)
    blobs = []

    for name, distributions, symbol_bits, bypass_bits, max_length, count, masked, wild in cases():
        lengths, offsets, table = tables(rng, distributions, symbol_bits, max_length)
        indices, values = data(rng, lengths, offsets, count, masked, wild)

        encoder = EntropyEncoder(
            pmfLengths=lengths,
            pmfOffsets=offsets,
            pmfTable=table,
            symbolBits=symbol_bits,
            bypassBits=bypass_bits,
        )
        stream = bytes(encoder.encode(indices, values))

        # Prove the reference agrees with itself before asking anyone to match it.
        from msrtc.rans import EntropyDecoder

        decoder = EntropyDecoder(
            pmfLengths=lengths,
            pmfOffsets=offsets,
            pmfTable=table,
            symbolBits=symbol_bits,
            bypassBits=bypass_bits,
        )
        check = np.empty_like(values)
        decoder.decode(check, indices, stream)
        assert np.array_equal(check, values), f"{name}: the reference did not round-trip"

        name_bytes = name.encode()
        blob = struct.pack(
            "<IiiIIII",
            len(name_bytes),
            symbol_bits,
            bypass_bits,
            len(lengths),
            len(table),
            len(indices),
            len(stream),
        )
        blob += name_bytes
        blob += lengths.astype("<i4").tobytes()
        blob += offsets.astype("<i4").tobytes()
        blob += table.astype("<i4").tobytes()
        blob += indices.astype("<i4").tobytes()
        blob += values.astype("<i4").tobytes()
        blob += stream
        blobs.append(blob)

        bypassed = sum(
            1
            for index, value in zip(indices, values)
            if index >= 0
            and not (0 <= value + offsets[index] < lengths[index] - 1)
        )
        print(
            f"{name:24} {len(indices):6} values  "
            f"{int((indices < 0).sum()):6} masked  {bypassed:6} bypassed  "
            f"{len(stream):7} bytes"
        )

    with open(OUT, "wb") as f:
        f.write(MAGIC)
        f.write(struct.pack("<I", len(blobs)))
        for blob in blobs:
            f.write(blob)

    print(f"\nwrote {OUT} ({OUT.stat().st_size} bytes, {len(blobs)} cases)")


if __name__ == "__main__":
    main()
