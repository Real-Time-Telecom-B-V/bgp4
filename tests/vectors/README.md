# Decoder test vectors

One BGP message per file, as hex, exactly as FRR or BIRD sent it. Produced by
`scripts/vectors/capture.sh`, which runs the two against each other in
containers and splits the captured streams with `scripts/vectors/extract.py`.
This crate takes no part in producing them.

File names are `<scenario>-<sequence>-<sender>-<message type>.hex`. The values
the tests assert (AS numbers, addresses, communities, texts) are the ones in
the router configurations next to the capture script. All of them come from
the documentation ranges. `VERSIONS` records what produced the current set.

Do not edit these files by hand. Rerun the capture instead.
