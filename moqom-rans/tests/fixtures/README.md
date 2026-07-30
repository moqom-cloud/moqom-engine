# Test fixtures

Two kinds, for two different jobs.

## Recorded reference vectors

`bit_estimator_z0/` and `gaussian_encoder0/` are the contents of
`packages/msrtc_rans/python/test/*.zip` from
[microsoft/mlvc](https://github.com/microsoft/mlvc), extracted and otherwise
untouched. Each holds real probability tables from a trained model, the latents
that were coded against them, and the bitstream that came out — recorded in March
2024, going by the timestamps in the archives.

These are the fixtures worth the most, because nobody here produced them. They
prove interoperability with the reference *as shipped*, rather than with a copy of
it built on this machine last week. `reference_vectors.rs` requires the port to
reproduce those bytes exactly.

Source digests, so provenance can be checked against a fresh clone:

```
5a067f2571cb1487b6a4b188afd837a30030fb9b37ad7a3a93cfb7fb5417ca35  bit_estimator_z0.zip
4da1cd1cea6c572883f8c9a6b8193106f9a7c7eb20e30dcb59968e5f84b8a333  gaussian_encoder0.zip
```

Coder settings are not in the archives; they come from the reference's own test,
`test_msrtc_rans.py`. `bit_estimator_z0` is `symbolBits=16, bypassBits=2` — the
configuration MLVC's models actually construct — and `gaussian_encoder0` uses the
library default of `bypassBits=4`. Both are the `RansByte` variant.

What they do *not* cover, which is why the corpus below exists: neither masks a
position out with a negative index, and `gaussian_encoder0` never reaches the
bypass path at all. Its 58,880 latents fit in 108 bytes, which is what a
distribution skewed almost entirely onto one symbol looks like.

**Do not benchmark on these.** That 108 bytes is 0.015 bits per symbol, so the
encoder almost never renormalises, and `bit_estimator_z0` is 75% zeros. Timing
either one measures a case no real frame resembles — and it measures it about twice
as fast per symbol, which was enough to invert the Rust-versus-C++ comparison and
send the author off optimising a gap that did not exist. For cost, use
`examples/deployment-tables.py` to convert the tables `convert.py export` writes
beside the CoreML packages, and measure those. They are correctness fixtures; that
is all they claim to be.

## Generated differential corpus

`corpus.bin` is fourteen cases produced by `generate.py`, which drives the
reference C++ through the same Python API the models use. It covers what the
recorded vectors miss: masked positions from none to all, bypass from none to
every value, bypass values up to twenty-six bits wide, bypass widths of 2, 4 and
8, symbol scales of 8, 16 and 23, and distributions from two to sixty-four
symbols. Each case is round-tripped by the reference before it is written, so a
failure in `differential_corpus.rs` is this crate's fault and not the fixture's.

Regenerating needs the reference package, which nothing else here depends on:

```sh
git clone https://github.com/microsoft/mlvc
cd mlvc && uv sync --no-dev && uv pip install packages/msrtc_rans
uv run python <path-to>/generate.py
```

The generator is seeded, so a rerun that changes nothing produces a byte-identical
file. If regenerating produces a diff, either the case list changed or the
reference did — and the second of those is worth stopping to understand.

### One finding from building it

The generator originally included a case at `symbolBits=30`, since that is what
the reference reports as its maximum for this variant. The reference cannot
round-trip it: rANS needs the symbol scale to divide the lower bound of the
normalisation interval, which for the byte variant is `1 << 23`, so 23 bits is
the real ceiling and 24 already fails. Above it, low-frequency symbols push the
state out of the interval and the flushed result decodes to nothing.

It is a latent bug rather than a live one — MLVC uses 16 — but this crate refuses
scales above 23 rather than accepting a configuration whose output nothing can
read. See the `MAX_SCALE_BITS` note in `src/rans.rs`.
