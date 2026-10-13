// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! The multiples of the generator `G` that [`super::mul_generator`] adds up.

use dusk_jubjub::{Fq, JubJubAffine};

/// The point of affine coordinates `u` and `v`, in big-endian hex.
const fn point(u: &str, v: &str) -> JubJubAffine {
    JubJubAffine::from_raw_unchecked(
        Fq::from_raw(limbs(u)),
        Fq::from_raw(limbs(v)),
    )
}

/// The little-endian 64-bit limbs of a 256-bit integer in big-endian hex.
const fn limbs(hex: &str) -> [u64; 4] {
    let hex = hex.as_bytes();
    assert!(hex.len() == 64);

    let mut limbs = [0; 4];
    let mut i = 0;
    while i < 64 {
        let digit = match hex[i] {
            c @ b'0'..=b'9' => c - b'0',
            c @ b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("not a lowercase hex digit"),
        };
        limbs[3 - i / 16] = limbs[3 - i / 16] << 4 | digit as u64;
        i += 1;
    }
    limbs
}

/// `TABLE[j][k] = (k + 1) · 2^(32j) · G`, built at compile time from the
/// coordinates below, which `table_holds_the_multiples_of_the_generator`
/// recomputes.
pub(super) static TABLE: [[JubJubAffine; 8]; 8] = [
    // 2^0 · G
    [
        point(
            "3fd2814c43ac65a6f1fbf02d0fd6cce62e3ebb21fd6c54ed4df7b7ffec7beaca",
            "0000000000000000000000000000000000000000000000000000000000000012",
        ),
        point(
            "3406866c17fc106f8654a8c770137476caf3ad858ea04c0c80eee554cba976b4",
            "477abd3191d9c67eacd365a062345c7bf59f8a8c277fdbe75ff2d4023d8c2e5f",
        ),
        point(
            "4e7d425467582402f3ab723f0a0c86d18c6bd932e32884256ff29ccfc8721673",
            "120a54568c3669646e870dd6f278bae1ffa2cfcbb64ca56d4cdcfa0fb390ea65",
        ),
        point(
            "5c04fb190826f2c43a623f7b4927ea8b9e8eacc6eaec84e70cb2050058618cf3",
            "6193d76c552fa2b73ee41cc1d9710d899aeba1cf6db2c547f4b633c64622faa5",
        ),
        point(
            "247e39c4befa9263866da36a2483210ea1e65965cacb65ddbd5fd1e9219ec531",
            "6332c7decb0a3db52abe79f6d597ed151f192911bbea4cebf3b953b148bd62d1",
        ),
        point(
            "002160769e6465d321fca588d6d4182fdbc599df4a23bed974e15f48954bee49",
            "1aac94899aa2b76e8ff99f12927785eedddfe9a168c04a9b394a6b3ccfc0980a",
        ),
        point(
            "5be1df023c2e9ebcd7a2c9554d1e9a182a32b8ed8d642f737ff490adb40ba97d",
            "69626e011cd0ef5d22950cabc4638536162678c9a2a59420cf055597585b43c9",
        ),
        point(
            "4ed30131f493d0c0c90545deb13d03ae3536e4483edc880bf7d457cd47928d7d",
            "28dbd377c5faa8a89fa61985dce763a4f891212b51e9da5ff824758eb7f3e7c0",
        ),
    ],
    // 2^32 · G
    [
        point(
            "0cbcaf497b3fa2687d819d35097e7d8b8695cc959f327d517a936bde3fe9b4e7",
            "0260909b61900879d8cec79cf66507d3b3abcda724b82f20fd29cd87747a3e73",
        ),
        point(
            "08eca409fc123f133360d4f66fbd1198fc0a44ad5151cf4536da31ca85b7d3bd",
            "6fd71bfb92d27ba4ed1a480396e7da827c2b8108f61ca2579217a8c5d2e0e1a4",
        ),
        point(
            "663bfedb0f6fd0e0f952c29a8e46c88e7f6bfc15889c3d38992294fe70e7fe2d",
            "6ef77c5b6d19b0a197413ff18e7979c4ab06fe9c04fe8e9adf48bf1ac2e3581c",
        ),
        point(
            "08b3fcabf10223950a0d66206ed5aa746d4bc02e804192c08fffbcc3665f3877",
            "254aaf226b429a7b11ae6f65bd2dfd1a72848ac4ec671fc44c4db6cb083ed208",
        ),
        point(
            "5f4dfdfb46ee2bfea0c70fe6382cc8dac1c77e426dc09cb3af4a166e7ea42514",
            "64f4c5a8c54ca7b58f330132f27cad77a09c17e9c8bbf14ad0484db3922496ed",
        ),
        point(
            "317e4d640a2a5d4bbcf11fbbe225c549edbbad504bd2fd13357b337078b3db68",
            "2fc611542060ae1536e04c5e0c1df6bd22799f13fe5550b8cedbcd3d0c9d82b5",
        ),
        point(
            "6f93ea3cb115df3d4e76c3615be7f11efd7f37f9535cd76506d3e4c0aa3953ab",
            "6a4aebe6d3834cb51b67c11e5e905d015631f9228aefdf453deeb9dbb3379398",
        ),
        point(
            "11c6d9c6f6b4f51cf46229ae988436d004629f4ee8734ff27e91c1c4be68522d",
            "3cb5b4e42223be955093768f82a725237d3fa71f6386788ae14473909f3b40f2",
        ),
    ],
    // 2^64 · G
    [
        point(
            "1a1a60ac726f3313856c7ac7f4a0f56b08694ed0c0ac7a368a85362dd9464d6b",
            "55ff86e93182b08ba7a6c741867969c0bf1b50570cc49e0b15574d2be2f3889e",
        ),
        point(
            "4985ba83c18012c2d250cf9d496d40feb470ce39dad9ada430311adf72adb7fe",
            "42ec3180e55359abcb8c6a013a92d812a8bb74360dd7bc078c0379a33d7715af",
        ),
        point(
            "159e876f3ae9251004be71433d4febe0f8bb3a8d684a495f7ff32f1c7751513d",
            "08e6f9580cc846608c273e77549a5556eac98359c7a355de2b233e5b0eda71dd",
        ),
        point(
            "559b2e1e482c9bbeee20d3fa20cb8f17666f6e4f4e6a30e2399c6282d04b6b56",
            "34a9de3c86bae296535a292ded3eb2de565963c3a7e3bb4999f893e56936cfd2",
        ),
        point(
            "2ec45f330bf68f637d2d615dd623f8a12f33a7c7fbfbe140647a81b7c354862b",
            "5958dd177bf4956ee817c221e377ada8b619601e884fb3ab1f1c28f606430449",
        ),
        point(
            "49884822146e3877c09492991edb19d08b26c505e3d0bf41997ecbdbbb881bfc",
            "392997b13d326f047646ca79fa022814dc591af883bd8dd4352e2d2cc042f8d5",
        ),
        point(
            "4ae4b7e55c1957efb52b5b2c8f9c9ee01149a37a536c8586169e82355321b430",
            "05b1c6e5d567fa17b2ef3a3e819ead5bcbafd7d75e2684a9bb9796081cc6dcc5",
        ),
        point(
            "19fa58a1452d77c84285277c87fef5bcd500063fe92f6e524e50c34f053f28fe",
            "22ee8e59b1440e06872c52e32bb9ba1c22fd9e158d015e6c7a5cf0f5b28a30dd",
        ),
    ],
    // 2^96 · G
    [
        point(
            "673adc9471d2ddfdd736005fff6f3e32abfbbc0fc30e5b54b4f5618c2343811d",
            "24551d3e5f5551e4ad98b5583580cc9ee9abbd0844c00c4671997270aaa7e8be",
        ),
        point(
            "57c5396a6ce4120bb117f1c04ac649e3cb76aa60d862977d871e3d7d27395187",
            "68b2d124bb0dae537acac0becce949308c34294771f81c3b6782716de76a3de2",
        ),
        point(
            "5e8a1f27cd3cd429695f98b63a574d33ae5da93f08510d444a8f37322782127b",
            "0460c0292def64301d4756a9b9e056fc953639efe00200c550dfc65a5a00cef2",
        ),
        point(
            "68dea610de2946327e2fc32a2ba0c65857683e07f67da44cae862ceedd7e97ca",
            "349972abffa894018b6f73c364a305ede0ec110d1fb4ca06f2b5b763551b7a7f",
        ),
        point(
            "6e0631706fbb9b57392dca2e6de29018b8bf325ed940b0274f5721bbce28184c",
            "2fc385f14e17df43fa9e5137562d331088a0dcdb5b470fec123a3eeae422cfb7",
        ),
        point(
            "64b71d0973016421b29ca8e930ba76b699eefd13dcce3f899deff9ad95e7f45e",
            "51276de0d4df08122a893f221ab8013fe561c6ac5f8c998d3f24a88fce06234e",
        ),
        point(
            "33ef2581f9e207d63f02973b7db15c3d743e16df7a8b6fdac5fba41f514f62cc",
            "5ca535f43ce50e1df8bd43c0fd0c48f1acbd441d9bfbb201552b487cde6a33b0",
        ),
        point(
            "1a1f0beb8e3ce1d36a7d51fe3ab0b4008af34cbb591f4fe4c5dd4c409b0f4e3f",
            "66eedf806de8ac2706bef09b5dc98ba70bdda682c780652c86bdad5a7a371f55",
        ),
    ],
    // 2^128 · G
    [
        point(
            "081ed7b396ed12b2f516aec026e254846d1b570a8bb02bcba9e9ba9b21164311",
            "09e52ed91288ff22e24b7a69a0348c7f5afe8e0deb87d60ad36dbea62df934a6",
        ),
        point(
            "371e581ec89dbb9dc13ccb08a02d103967e14473c0f539a11eb3549ab1e7d47b",
            "1de03e61bcbc5d2290dbc0f6a0418cc2e89244acf62d7dded4d4dbb3c8c0d544",
        ),
        point(
            "6ad6971574393e9dc06e2282b5360ed6cbecb8a564b0f7696049d949a71064b8",
            "647bff40a72215a2922ed1664028157e9daff187568fef5c57feb38c79376eac",
        ),
        point(
            "29dff744a331cc0ffd49e7eb063c9b5198ec44e3127309f53943019e28f4c243",
            "68909a9202e5a5a1bddbba329a03e0271d20383fb963baace7f3aa9e0dbcf329",
        ),
        point(
            "38e1113d6118e20928486af6ec755d3f8ee3c9848ae6aca872c6271e817dcbb1",
            "5cdc4ba5d6b9cd4d8a92c1e445ea16baa374b76be59b9514d66e8cb44e58c5de",
        ),
        point(
            "1e5f530ff94a920616455016d2259a04c127f2590fb201aabde671591dc5e22b",
            "6b101d85a22114603047e222fa2cc910656feb83a79aa9098525e4444d602bd8",
        ),
        point(
            "56fd4732cad429583abe4cb365a78d422fee113ded1c2a07ae3af15abb393bfc",
            "1fda3aff8b840a7945d7d51a52606cf9f87f01188e0e4f97413f1ec493dc3130",
        ),
        point(
            "09eceb7e6af3272813d030723860fc81bbee21572cce1fce853489030af71afc",
            "33e83045cee588d91568009deda2b0faf3f8d301fbd26d07b555732230f72de8",
        ),
    ],
    // 2^160 · G
    [
        point(
            "03954c74c3fd8dae118f971270197a6505bccb2c1d941dbc08249d65e2660c9e",
            "4373bd06e51e4e430dfeb69acd775fde09ea70d209d300cdfcab3e355d651de8",
        ),
        point(
            "1604cd9ebdb4efc51e41d77e1bf6d294a62d9bed004add09f5585ee9664efa4e",
            "4ee1fe34d0827b4adfaa6fc942b73d27544dea3e925bca70439dacbd10d89a86",
        ),
        point(
            "6a8ddb9e892f9e722c19e0d0576381358be8daa4cf2919e953ec7e0b775e2fe5",
            "340ccfa32cd4fb9ded17e79947ceade64d644c1fb4ce1a1ed956dad1c4986125",
        ),
        point(
            "1a456fab907a759420b1ce0ba2e5b8abcbcbcb3355ec30751ef7153e990d292e",
            "2b89593947001c11c1d0438a13ced336d2c44667c439e0fbd64d427acba2f558",
        ),
        point(
            "015b4c8981a8f1260f758b8eb21f6185284337e3109fa9c63481e5118f2f439b",
            "4c771f1b0c308261ac358f480ebfcdf1f6b4769251b44d7c1e1b13a79b305ba7",
        ),
        point(
            "2d9a31c0c794fdf7f4c11021d10c6b5efa87fa33a76a985b63420eb888e18089",
            "37585598b6df852604dbaceabeaf885290ecb1078bcf388de99f4b727f9b3ea0",
        ),
        point(
            "0190dbdfd09cdad9db7e1d8ac76362da612936aa5780b165d8711ab9744ba01c",
            "2cc999a9ec1e35460d578a0de7614a5c58fb78d6ae7a83da6e9838d988e839e0",
        ),
        point(
            "16f3440a5305e418952f567c8f0f3cb8a2bae0a4de2bd4213f8412d44ba444e7",
            "43eb0f4a8647d0f085b3343741d778a9ad45705532e518de07d888ce1f55f0da",
        ),
    ],
    // 2^192 · G
    [
        point(
            "045f4bef3b9576706c9d8c5f6cf429f3e1056b0d7576cc58aedfdcb0fda5c790",
            "5b9f5c6021542115281444334eba20b272c79c2050732699eee3db524fc484ee",
        ),
        point(
            "10a6957a6711cef3e0546dffdd65a81167d537ba3e147ea0bf85094be9da04e9",
            "5bd43361db609d56bb9e8c2ca69daefccbf543bd5de3a4e45d9f2f8003712ae3",
        ),
        point(
            "5da017f40068bc3bd15a0d7c3a0ab8820be65227fcd54451f24baa3c4aa10de2",
            "39fcb66317a620fd30d9b103940e26a22cbf7fcb51227b6220992fe1656166d0",
        ),
        point(
            "738e6b1ded1443ad15086a5fe9242a16c7ab67a6116e5e60594393efcc3ddb3a",
            "6493f6c60042a1e5995e40e910dddd236b17da41609c13060854ecea49953924",
        ),
        point(
            "088f29b045d879ea4070dd013f2c22ad4b7364e237364cd2112eb06f26ebb176",
            "391f8af873543bf7f8aaf87deee53c744a33f58fd421d2c2b9a2418477b9569c",
        ),
        point(
            "2771b9d962068fb7c9865e51c735ac23a4fb4e62d06e2e8bef496ca0ae4ac9c4",
            "3bd5e096740d0395ec1a404938dbf08ef713156371d5c4c5868bc8787e82195a",
        ),
        point(
            "48f3dcf3569d536fd94da4743475d10b4c69dd31446c9df8cd58bbebff289698",
            "6849465c7d0968d35c0047b9a059df8895e442111c1f3efb4631aa5fdb7bde34",
        ),
        point(
            "2a29d58f78bfa9a335e239544a447c0fd144bd0ed37caded823ff8850fe1ec61",
            "094d5075a6350f5a281a063fc63f615b24964cd0b958e034c81895ab4dbb7d30",
        ),
    ],
    // 2^224 · G
    [
        point(
            "5b2f2eee34ad8602e8724133e3fbdf2f3b126ed148ed2ee5d6de47ab227c0e2e",
            "54b86e5a58f40ae2aa12b90f963485a4c1b72041bbfcff5438b8b977893c5dfd",
        ),
        point(
            "268bc72fe360987beb56a875172211cb4ba8b1c2c63f66f21e8aecbbb361a8f3",
            "2a04fce50e3676dc97bb3667fe300123b50272e3631984bf5352c89dca8fb87e",
        ),
        point(
            "1b2eeb389c1cf76940381a37490f547929bc4839ac95dcbef3a82e07d1c38776",
            "296e818f24fc8387522607e44025391e218909d12e97d25b122c0adf8e41a326",
        ),
        point(
            "444bc089c9f94af8dc468b3253e4911cb79451131179f220c6cc82e96fbb5ed0",
            "2824150479365c509c87c6cf943496dc74349437a3cf6806d04e684ae79c5da4",
        ),
        point(
            "13656c15cdd894a62ecbbc2899fb54f190ab99f60df8794b5c073794a7f586cc",
            "468064b1b6767eb58f64650d19968a8faab997f3acdfa9348aab4a499622663e",
        ),
        point(
            "102995d96c180223ca90736a1c28b3388d2b71f83dee8774b4f883a3b61f7c79",
            "4f82db6c26f371aa26eba8e312ac1b60613b78f94aa1e4e957bcbf927a3a7fa7",
        ),
        point(
            "5c2e58e6a09c7e2524844256c00a537326f20f9dc266ade1adde1901bcbac656",
            "39963ea09b73efd0b847b68e996c1ea7abc854b08ca7df629d0ee0bb1ddc6a73",
        ),
        point(
            "376f9f1f8a6dd040d5a7e6679e3ab1aedc9620c44633a3e24aaf9a523725285b",
            "12b02c2070ea45587b76ef95bfeb9d9623f6c33913f645b05a5ffce4238cb598",
        ),
    ],
];
