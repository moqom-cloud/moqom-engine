# Check an exported model's real tables against the Rust coder.
#
# The checked-in fixtures date from 2024 and were dumped from whatever model the
# reference's tests used. What ships is different: `convert.py export` writes
# `gaussian_pmf.json` and `bit_estimator_pmf.json` next to the CoreML packages,
# and those are the tables a client would actually be handed. They are larger, and
# their offsets and lengths come from a different checkpoint — so "the port accepts
# the fixtures" does not by itself mean "the port accepts what we would ship".
#
# This converts them to the raw int32 layout `throughput.rs --tables` reads, and
# generates latents of the right shape to go with them. It writes to a temporary
# directory by default because these tables are a few hundred kilobytes and belong
# to the model, not to this repository.
#
#   uv run python deployment-tables.py \
#       <export-dir>/640x368 [--out /tmp/mlvc-tables]
#
# Then:
#
#   cargo run --release --example throughput -p moqom-rans -- --tables /tmp/mlvc-tables

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np


def convert(
    source: Path,
    out: Path,
    name: str,
    symbol_bits: int,
    bypass_bits: int,
    count: int,
    seed: int,
    escape_rate: float,
):
    """Write one table set plus latents shaped to match it."""
    tables = json.loads(source.read_text())
    lengths = np.asarray(tables["pmf_lengths"], dtype=np.int32)
    offsets = np.asarray(tables["pmf_offsets"], dtype=np.int32)
    table = np.asarray(tables["pmf_table"], dtype=np.int32)

    assert lengths.sum() == len(table), (
        f"{name}: lengths sum to {lengths.sum()} but the table has {len(table)}"
    )

    # Latents shaped like a real frame's, but *not* distributed like one. A trained
    # model puts almost everything within a couple of steps of zero, and how often a
    # value escapes to the bypass path drives the cost — each escape at bypassBits=2
    # costs several digits. Drawing uniformly across each distribution's window and
    # escaping at a fixed rate therefore gives an upper bound, not a prediction:
    # good enough to show the coder fits the budget, not good enough to quote as
    # the per-frame cost. For that, the values have to come from a real encode.
    rng = np.random.default_rng(seed)
    indices = rng.integers(0, len(lengths), size=count).astype(np.int32)
    values = np.zeros(count, dtype=np.int32)
    for i, d in enumerate(indices):
        sentinel = int(lengths[d]) - 1
        offset = int(offsets[d])
        if rng.random() < escape_rate:
            values[i] = int(rng.integers(-4000, 4000))
        else:
            lo, hi = -offset, sentinel - offset
            values[i] = int(rng.integers(lo, hi)) if hi > lo else lo

    directory = out / name
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "pmf_lengths.np").write_bytes(lengths.tobytes())
    (directory / "pmf_offsets.np").write_bytes(offsets.tobytes())
    (directory / "pmf_table.np").write_bytes(table.tobytes())
    (directory / "indices.np").write_bytes(indices.tobytes())
    (directory / "values.np").write_bytes(values.tobytes())
    (directory / "bits.txt").write_text(f"{symbol_bits} {bypass_bits}\n")

    # Encode with the reference so the Rust side has bytes to match, making this a
    # differential check on real tables rather than only a round trip.
    try:
        from msrtc.rans import EntropyDecoder, EntropyEncoder

        settings = dict(
            pmfLengths=lengths,
            pmfOffsets=offsets,
            pmfTable=table,
            symbolBits=symbol_bits,
            bypassBits=bypass_bits,
        )
        stream = bytes(EntropyEncoder(**settings).encode(indices, values))
        check = np.empty_like(values)
        EntropyDecoder(**settings).decode(check, indices, stream)
        assert np.array_equal(check, values), f"{name}: reference did not round-trip"
        (directory / "bitstream.bin").write_bytes(stream)
        note = f"{len(stream)} bytes from the reference"
    except ImportError:
        note = "no reference available, tables and latents only"

    print(
        f"{name:16} {len(lengths):6} distributions  {len(table):7} entries  "
        f"lengths {lengths.min()}..{lengths.max()}  "
        f"offsets {offsets.min()}..{offsets.max()}  "
        f"{count:7} symbols  {note}"
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("export", type=Path, help="a resolution directory from convert.py export")
    parser.add_argument("--out", type=Path, default=Path("/tmp/mlvc-tables"))
    parser.add_argument(
        "--escape-rate",
        type=float,
        default=0.02,
        help="how often a value lands outside its distribution and takes the bypass path",
    )
    # The tables do not depend on frame size — 128 Gaussian distributions indexed by
    # scale, 9216 bit-estimator distributions indexed by channel and qp, whatever the
    # resolution. Only the symbol count grows. So the cost at a resolution nothing has
    # been exported for yet can be measured today, by keeping the exported tables and
    # sizing the latents for the frame in question.
    parser.add_argument(
        "--resolution",
        help="WxH to size latents for, instead of the export's own (e.g. 1280x720)",
    )
    args = parser.parse_args()

    if not (args.export / "gaussian_pmf.json").exists():
        sys.exit(f"no gaussian_pmf.json under {args.export}")

    metadata = json.loads((args.export / "metadata.json").read_text())
    params = metadata["params"]["full_model_params"]
    channels = params["latent_channels"]
    stride = params["downsample_latent"]
    source = args.resolution or args.export.name
    width, height = (int(n) for n in source.split("x"))
    # The latent grid is the frame divided by the stride, so a frame that is not a
    # multiple of it gets padded up — which is why the 640x360 export is 640x368.
    if width % stride or height % stride:
        width += -width % stride
        height += -height % stride
        print(f"padded to {width}x{height} for a stride of {stride}")

    # One frame's worth. The latent grid is the frame divided by the stride, and the
    # y latent is coded in two halves by the checkerboard split — which is why the
    # export declares `y_raw_0` and `y_raw_1`.
    grid_w, grid_h = width // stride, height // stride
    positions = grid_w * grid_h
    y_half = positions * channels // 2
    # The hyperprior is a further four down in each direction, rounding up rather than
    # truncating: at 640x368 the latent grid is 40x23, and 23 becomes 6 rather than 5.
    # Getting this wrong is visible — it is what makes the recorded z fixture 7,680
    # symbols rather than 6,400.
    ceil_div = lambda a, b: -(-a // b)
    z_count = ceil_div(grid_w, 4) * ceil_div(grid_h, 4) * params["hyperprior_channels"]

    print(f"{width}x{height}: {grid_w}x{grid_h} latent positions, {channels} channels")
    print(f"  y: 2 x {y_half} symbols, z: {z_count} symbols\n")

    # Both halves are emitted, with different draws, so that summing the cases gives
    # one frame rather than half of one. bypassBits is 2 for all of them, as
    # entropy_models.py constructs them.
    for half in range(2):
        convert(
            args.export / "gaussian_pmf.json",
            args.out,
            f"y-half-{half}",
            16,
            2,
            y_half,
            seed=0xB1A5 + half,
            escape_rate=args.escape_rate,
        )
    convert(
        args.export / "bit_estimator_pmf.json",
        args.out,
        "z",
        16,
        2,
        z_count,
        seed=0x2EE0,
        escape_rate=args.escape_rate,
    )

    print(f"\nwrote {args.out}")
    print(
        "cargo run --release --example throughput -p moqom-rans -- "
        f"--tables {args.out}"
    )


if __name__ == "__main__":
    main()
