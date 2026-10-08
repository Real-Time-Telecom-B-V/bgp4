//! UPDATE encode and decode throughput.
//!
//! The message is the shape a customer-edge speaker handles most: a handful of
//! prefixes sharing one set of attributes, with a few attributes the crate
//! passes through untouched.

use std::hint::black_box;
use std::net::Ipv4Addr;

use bgp4::wire::{
    AsPath, Ipv4Prefix, Origin, PathAttributes, UnknownAttribute, Update, UpdateContext,
    HEADER_LENGTH,
};
use bytes::{Bytes, BytesMut};
use criterion::{criterion_group, criterion_main, Criterion, Throughput};

const CONTEXT: UpdateContext = UpdateContext::new(true);

fn announcement(prefixes: u8) -> Update {
    let mut attributes = PathAttributes::default();
    attributes.origin = Some(Origin::Igp);
    attributes.as_path = Some(AsPath::sequence([64496, 64497, 65550]));
    attributes.next_hop = Some(Ipv4Addr::new(192, 0, 2, 1));
    attributes.multi_exit_discriminator = Some(50);
    attributes.unknown.push(UnknownAttribute::new(
        8,
        Bytes::from_static(&[0xfb, 0xf0, 0x00, 0x64]),
    ));
    attributes.unknown.push(UnknownAttribute::new(
        32,
        Bytes::from_static(&[0, 0, 0xfb, 0xf0, 0, 0, 0, 1, 0, 0, 0, 2]),
    ));
    let announced = (0..prefixes)
        .filter_map(|index| Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, index), 32))
        .collect();
    Update {
        withdrawn: Vec::new(),
        attributes,
        announced,
    }
}

fn update(criterion: &mut Criterion) {
    for prefixes in [1u8, 100] {
        let update = announcement(prefixes);
        let mut wire = BytesMut::new();
        update
            .encode(CONTEXT, &mut wire)
            .expect("bench message encodes");
        let body = wire.freeze().slice(HEADER_LENGTH..);

        let mut group = criterion.benchmark_group(format!("update/{prefixes}_prefixes"));
        group.throughput(Throughput::Elements(1));
        group.bench_function("encode", |bencher| {
            let mut buffer = BytesMut::with_capacity(4096);
            bencher.iter(|| {
                buffer.clear();
                black_box(&update)
                    .encode(CONTEXT, &mut buffer)
                    .expect("bench message encodes");
                black_box(buffer.len())
            });
        });
        group.bench_function("decode", |bencher| {
            bencher.iter(|| Update::decode(black_box(body.clone()), CONTEXT));
        });
        group.finish();
    }
}

criterion_group!(benches, update);
criterion_main!(benches);
