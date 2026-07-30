# The C++ side of the throughput comparison.
#
# Mirrors examples/throughput.rs as closely as the two languages allow: same
# fixtures, same coder settings, median of the same number of runs. Run both and
# the difference is the language choice, which was argued on safety and
# portability with performance claimed to be a wash.
#
# One caveat that cannot be removed: this times a Python call into a C++
# extension, so it includes the pybind11 boundary and numpy's buffer handling.
# That overhead is on the order of a microsecond and the measurements are tens to
# hundreds, so it does not change the conclusion — but it does mean the C++ number
# is an upper bound on the C++ itself, and a small difference in its favour would
# be larger than it looks.
#
# Requires the reference package:
#
#   cd <mlvc-checkout> && uv run python <path-to>/throughput.py
#
# The checked-in fixtures turn out to be a poor guide to cost: `gaussian_encoder0`
# is 99.7% zeros and codes 58,880 symbols into 108 bytes, so it almost never
# renormalises and runs roughly twice as fast per symbol as a real frame does.
# `--tables <dir>`, pointed at what `deployment-tables.py` writes, measures the
# shipped tables at a realistic bitrate instead, and matches what the same flag
# does on the Rust side.

from __future__ import annotations

import argparse
import statistics
import time
from pathlib import Path

import numpy as np

from msrtc.rans import EntropyDecoder, EntropyEncoder

FIXTURES = Path(__file__).parent.parent / "tests/fixtures"

CASES = [
    ("bit_estimator_z0", 16, 2),
    ("gaussian_encoder0", 16, 4),
]


def load(d: Path, bits):
    def arr(file):
        return np.frombuffer((d / file).read_bytes(), dtype=np.int32)

    if bits is None:
        bits = tuple(int(n) for n in (d / "bits.txt").read_text().split())

    return {
        "name": d.name,
        "bits": bits,
        "lengths": arr("pmf_lengths.np"),
        "offsets": arr("pmf_offsets.np"),
        "table": arr("pmf_table.np"),
        "indices": arr("indices.np"),
        "values": arr("values.np"),
    }


def median_micros(runs, body):
    samples = []
    for _ in range(runs):
        start = time.perf_counter()
        body()
        samples.append((time.perf_counter() - start) * 1e6)
    return statistics.median(samples)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tables", type=Path)
    args = parser.parse_args()

    if args.tables:
        cases = [load(d, None) for d in sorted(args.tables.iterdir()) if d.is_dir()]
        assert cases, f"no table directories under {args.tables}"
    else:
        cases = [load(FIXTURES / n, (sb, bb)) for n, sb, bb in CASES]

    print(
        f"{'case':<18} {'symbols':>8} {'bytes':>8} {'build ms':>11} "
        f"{'enc us':>11} {'dec us':>11} {'Msym/s dec':>11}"
    )

    encode_total = decode_total = 0.0

    for case in cases:
        symbol_bits, bypass_bits = case["bits"]
        settings = dict(
            pmfLengths=case["lengths"],
            pmfOffsets=case["offsets"],
            pmfTable=case["table"],
            symbolBits=symbol_bits,
            bypassBits=bypass_bits,
        )

        build = median_micros(
            5, lambda: (EntropyEncoder(**settings), EntropyDecoder(**settings))
        )

        encoder = EntropyEncoder(**settings)
        decoder = EntropyDecoder(**settings)
        indices, values = case["indices"], case["values"]
        # Encode here rather than reading bitstream.bin, so both sides time a decode
        # of the same bytes even when the directory did not ship one.
        stream = bytes(encoder.encode(indices, values))

        for _ in range(20):
            encoder.encode(indices, values)

        encode = median_micros(200, lambda: encoder.encode(indices, values))

        scratch = np.empty_like(values)
        decode = median_micros(200, lambda: decoder.decode(scratch, indices, stream))

        encode_total += encode
        decode_total += decode

        print(
            f"{case['name']:<18} {len(values):>8} {len(stream):>8} {build / 1000:>11.2f} "
            f"{encode:>11.1f} {decode:>11.1f} {len(values) / decode:>11.1f}"
        )

    if args.tables:
        print(
            f"\nOne frame over all cases: {encode_total / 1000:.2f}ms encode, "
            f"{decode_total / 1000:.2f}ms decode."
        )


if __name__ == "__main__":
    main()
