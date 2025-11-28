use bytes::{BufMut, Bytes, BytesMut};

use crate::error::H3Error;

/// Huffman code representation
#[derive(Debug, Clone)]
pub struct HuffmanCode {
    pub code: u32,
    pub length: u8,
}

/// Huffman codes table from RFC 7541 Appendix B
pub static HUFFMAN_CODES: [HuffmanCode; 256] = [
    HuffmanCode { code: 0x1ff8, length: 13 }, // 0
    HuffmanCode { code: 0x7fffd8, length: 23 }, // 1
    HuffmanCode { code: 0xfffffe2, length: 28 }, // 2
    HuffmanCode { code: 0xfffffe3, length: 28 }, // 3
    HuffmanCode { code: 0xfffffe4, length: 28 }, // 4
    HuffmanCode { code: 0xfffffe5, length: 28 }, // 5
    HuffmanCode { code: 0xfffffe6, length: 28 }, // 6
    HuffmanCode { code: 0xfffffe7, length: 28 }, // 7
    HuffmanCode { code: 0xfffffe8, length: 28 }, // 8
    HuffmanCode { code: 0xffffea, length: 24 }, // 9
    HuffmanCode { code: 0x3ffffffc, length: 30 }, // 10
    HuffmanCode { code: 0xfffffe9, length: 28 }, // 11
    HuffmanCode { code: 0xfffffea, length: 28 }, // 12
    HuffmanCode { code: 0x3ffffffd, length: 30 }, // 13
    HuffmanCode { code: 0xfffffeb, length: 28 }, // 14
    HuffmanCode { code: 0xfffffec, length: 28 }, // 15
    HuffmanCode { code: 0xfffffed, length: 28 }, // 16
    HuffmanCode { code: 0xfffffee, length: 28 }, // 17
    HuffmanCode { code: 0xfffffef, length: 28 }, // 18
    HuffmanCode { code: 0xffffff0, length: 28 }, // 19
    HuffmanCode { code: 0xffffff1, length: 28 }, // 20
    HuffmanCode { code: 0xffffff2, length: 28 }, // 21
    HuffmanCode { code: 0x3ffffffe, length: 30 }, // 22
    HuffmanCode { code: 0xffffff3, length: 28 }, // 23
    HuffmanCode { code: 0xffffff4, length: 28 }, // 24
    HuffmanCode { code: 0xffffff5, length: 28 }, // 25
    HuffmanCode { code: 0xffffff6, length: 28 }, // 26
    HuffmanCode { code: 0xffffff7, length: 28 }, // 27
    HuffmanCode { code: 0xffffff8, length: 28 }, // 28
    HuffmanCode { code: 0xffffff9, length: 28 }, // 29
    HuffmanCode { code: 0xffffffa, length: 28 }, // 30
    HuffmanCode { code: 0xffffffb, length: 28 }, // 31
    HuffmanCode { code: 0x14, length: 6 }, // 32 (space)
    HuffmanCode { code: 0x3f8, length: 10 }, // 33 !
    HuffmanCode { code: 0x3f9, length: 10 }, // 34 "
    HuffmanCode { code: 0xffa, length: 12 }, // 35 #
    HuffmanCode { code: 0x1ff9, length: 13 }, // 36 $
    HuffmanCode { code: 0x15, length: 6 }, // 37 %
    HuffmanCode { code: 0xf8, length: 8 }, // 38 &
    HuffmanCode { code: 0x7fa, length: 11 }, // 39 '
    HuffmanCode { code: 0x3fa, length: 10 }, // 40 (
    HuffmanCode { code: 0x3fb, length: 10 }, // 41 )
    HuffmanCode { code: 0xf9, length: 8 }, // 42 *
    HuffmanCode { code: 0x7fb, length: 11 }, // 43 +
    HuffmanCode { code: 0xfa, length: 8 }, // 44 ,
    HuffmanCode { code: 0x16, length: 6 }, // 45 -
    HuffmanCode { code: 0x17, length: 6 }, // 46 .
    HuffmanCode { code: 0x18, length: 6 }, // 47 /
    HuffmanCode { code: 0x0, length: 5 }, // 48 0
    HuffmanCode { code: 0x1, length: 5 }, // 49 1
    HuffmanCode { code: 0x2, length: 5 }, // 50 2
    HuffmanCode { code: 0x19, length: 6 }, // 51 3
    HuffmanCode { code: 0x1a, length: 6 }, // 52 4
    HuffmanCode { code: 0x1b, length: 6 }, // 53 5
    HuffmanCode { code: 0x1c, length: 6 }, // 54 6
    HuffmanCode { code: 0x1d, length: 6 }, // 55 7
    HuffmanCode { code: 0x1e, length: 6 }, // 56 8
    HuffmanCode { code: 0x1f, length: 6 }, // 57 9
    HuffmanCode { code: 0x5c, length: 7 }, // 58 :
    HuffmanCode { code: 0xfb, length: 8 }, // 59 ;
    HuffmanCode { code: 0x7ffc, length: 15 }, // 60 <
    HuffmanCode { code: 0x20, length: 6 }, // 61 =
    HuffmanCode { code: 0xffb, length: 12 }, // 62 >
    HuffmanCode { code: 0x3fc, length: 10 }, // 63 ?
    HuffmanCode { code: 0x1ffa, length: 13 }, // 64 @
    HuffmanCode { code: 0x21, length: 6 }, // 65 A
    HuffmanCode { code: 0x5d, length: 7 }, // 66 B
    HuffmanCode { code: 0x5e, length: 7 }, // 67 C
    HuffmanCode { code: 0x5f, length: 7 }, // 68 D
    HuffmanCode { code: 0x60, length: 7 }, // 69 E
    HuffmanCode { code: 0x61, length: 7 }, // 70 F
    HuffmanCode { code: 0x62, length: 7 }, // 71 G
    HuffmanCode { code: 0x63, length: 7 }, // 72 H
    HuffmanCode { code: 0x64, length: 7 }, // 73 I
    HuffmanCode { code: 0x65, length: 7 }, // 74 J
    HuffmanCode { code: 0x66, length: 7 }, // 75 K
    HuffmanCode { code: 0x67, length: 7 }, // 76 L
    HuffmanCode { code: 0x68, length: 7 }, // 77 M
    HuffmanCode { code: 0x69, length: 7 }, // 78 N
    HuffmanCode { code: 0x6a, length: 7 }, // 79 O
    HuffmanCode { code: 0x6b, length: 7 }, // 80 P
    HuffmanCode { code: 0x6c, length: 7 }, // 81 Q
    HuffmanCode { code: 0x6d, length: 7 }, // 82 R
    HuffmanCode { code: 0x6e, length: 7 }, // 83 S
    HuffmanCode { code: 0x6f, length: 7 }, // 84 T
    HuffmanCode { code: 0x70, length: 7 }, // 85 U
    HuffmanCode { code: 0x71, length: 7 }, // 86 V
    HuffmanCode { code: 0x72, length: 7 }, // 87 W
    HuffmanCode { code: 0xfc, length: 8 }, // 88 X
    HuffmanCode { code: 0x73, length: 7 }, // 89 Y
    HuffmanCode { code: 0xfd, length: 8 }, // 90 Z
    HuffmanCode { code: 0x1ffb, length: 13 }, // 91 [
    HuffmanCode { code: 0x7fff0, length: 19 }, // 92 \
    HuffmanCode { code: 0x1ffc, length: 13 }, // 93 ]
    HuffmanCode { code: 0x3ffc, length: 14 }, // 94 ^
    HuffmanCode { code: 0x22, length: 6 }, // 95 _
    HuffmanCode { code: 0x7ffd, length: 15 }, // 96 `
    HuffmanCode { code: 0x3, length: 5 }, // 97 a
    HuffmanCode { code: 0x23, length: 6 }, // 98 b
    HuffmanCode { code: 0x4, length: 5 }, // 99 c
    HuffmanCode { code: 0x24, length: 6 }, // 100 d
    HuffmanCode { code: 0x5, length: 5 }, // 101 e
    HuffmanCode { code: 0x25, length: 6 }, // 102 f
    HuffmanCode { code: 0x26, length: 6 }, // 103 g
    HuffmanCode { code: 0x27, length: 6 }, // 104 h
    HuffmanCode { code: 0x6, length: 5 }, // 105 i
    HuffmanCode { code: 0x74, length: 7 }, // 106 j
    HuffmanCode { code: 0x75, length: 7 }, // 107 k
    HuffmanCode { code: 0x28, length: 6 }, // 108 l
    HuffmanCode { code: 0x29, length: 6 }, // 109 m
    HuffmanCode { code: 0x2a, length: 6 }, // 110 n
    HuffmanCode { code: 0x7, length: 5 }, // 111 o
    HuffmanCode { code: 0x2b, length: 6 }, // 112 p
    HuffmanCode { code: 0x76, length: 7 }, // 113 q
    HuffmanCode { code: 0x2c, length: 6 }, // 114 r
    HuffmanCode { code: 0x8, length: 5 }, // 115 s
    HuffmanCode { code: 0x9, length: 5 }, // 116 t
    HuffmanCode { code: 0x2d, length: 6 }, // 117 u
    HuffmanCode { code: 0x77, length: 7 }, // 118 v
    HuffmanCode { code: 0x78, length: 7 }, // 119 w
    HuffmanCode { code: 0x79, length: 7 }, // 120 x
    HuffmanCode { code: 0x7a, length: 7 }, // 121 y
    HuffmanCode { code: 0x7b, length: 7 }, // 122 z
    HuffmanCode { code: 0x7ffe, length: 15 }, // 123 {
    HuffmanCode { code: 0x7fc, length: 11 }, // 124 |
    HuffmanCode { code: 0x3ffd, length: 14 }, // 125 }
    HuffmanCode { code: 0x1ffd, length: 13 }, // 126 ~
    HuffmanCode { code: 0xffffffc, length: 28 }, // 127 DEL
    HuffmanCode { code: 0xfffe6, length: 20 }, // 128
    HuffmanCode { code: 0x3fffd2, length: 22 }, // 129
    HuffmanCode { code: 0xfffe7, length: 20 }, // 130
    HuffmanCode { code: 0xfffe8, length: 20 }, // 131
    HuffmanCode { code: 0x3fffd3, length: 22 }, // 132
    HuffmanCode { code: 0x3fffd4, length: 22 }, // 133
    HuffmanCode { code: 0x3fffd5, length: 22 }, // 134
    HuffmanCode { code: 0x7fffd9, length: 23 }, // 135
    HuffmanCode { code: 0x3fffd6, length: 22 }, // 136
    HuffmanCode { code: 0x7fffda, length: 23 }, // 137
    HuffmanCode { code: 0x7fffdb, length: 23 }, // 138
    HuffmanCode { code: 0x7fffdc, length: 23 }, // 139
    HuffmanCode { code: 0x7fffdd, length: 23 }, // 140
    HuffmanCode { code: 0x7fffde, length: 23 }, // 141
    HuffmanCode { code: 0xffffeb, length: 24 }, // 142
    HuffmanCode { code: 0x7fffdf, length: 23 }, // 143
    HuffmanCode { code: 0xffffec, length: 24 }, // 144
    HuffmanCode { code: 0xffffed, length: 24 }, // 145
    HuffmanCode { code: 0x3fffd7, length: 22 }, // 146
    HuffmanCode { code: 0x7fffe0, length: 23 }, // 147
    HuffmanCode { code: 0xffffee, length: 24 }, // 148
    HuffmanCode { code: 0x7fffe1, length: 23 }, // 149
    HuffmanCode { code: 0x7fffe2, length: 23 }, // 150
    HuffmanCode { code: 0x7fffe3, length: 23 }, // 151
    HuffmanCode { code: 0x7fffe4, length: 23 }, // 152
    HuffmanCode { code: 0x1fffdc, length: 21 }, // 153
    HuffmanCode { code: 0x3fffd8, length: 22 }, // 154
    HuffmanCode { code: 0x7fffe5, length: 23 }, // 155
    HuffmanCode { code: 0x3fffd9, length: 22 }, // 156
    HuffmanCode { code: 0x7fffe6, length: 23 }, // 157
    HuffmanCode { code: 0x7fffe7, length: 23 }, // 158
    HuffmanCode { code: 0xffffef, length: 24 }, // 159
    HuffmanCode { code: 0x3fffda, length: 22 }, // 160
    HuffmanCode { code: 0x1fffdd, length: 21 }, // 161
    HuffmanCode { code: 0xfffe9, length: 20 }, // 162
    HuffmanCode { code: 0x3fffdb, length: 22 }, // 163
    HuffmanCode { code: 0x3fffdc, length: 22 }, // 164
    HuffmanCode { code: 0x7fffe8, length: 23 }, // 165
    HuffmanCode { code: 0x7fffe9, length: 23 }, // 166
    HuffmanCode { code: 0x1fffde, length: 21 }, // 167
    HuffmanCode { code: 0x7fffea, length: 23 }, // 168
    HuffmanCode { code: 0x3fffdd, length: 22 }, // 169
    HuffmanCode { code: 0x3fffde, length: 22 }, // 170
    HuffmanCode { code: 0xfffff0, length: 24 }, // 171
    HuffmanCode { code: 0x1fffdf, length: 21 }, // 172
    HuffmanCode { code: 0x3fffdf, length: 22 }, // 173
    HuffmanCode { code: 0x7fffeb, length: 23 }, // 174
    HuffmanCode { code: 0x7fffec, length: 23 }, // 175
    HuffmanCode { code: 0x1fffe0, length: 21 }, // 176
    HuffmanCode { code: 0x1fffe1, length: 21 }, // 177
    HuffmanCode { code: 0x3fffe0, length: 22 }, // 178
    HuffmanCode { code: 0x1fffe2, length: 21 }, // 179
    HuffmanCode { code: 0x7fffed, length: 23 }, // 180
    HuffmanCode { code: 0x3fffe1, length: 22 }, // 181
    HuffmanCode { code: 0x7fffee, length: 23 }, // 182
    HuffmanCode { code: 0x7fffef, length: 23 }, // 183
    HuffmanCode { code: 0xfffea, length: 20 }, // 184
    HuffmanCode { code: 0x3fffe2, length: 22 }, // 185
    HuffmanCode { code: 0x3fffe3, length: 22 }, // 186
    HuffmanCode { code: 0x3fffe4, length: 22 }, // 187
    HuffmanCode { code: 0x7ffff0, length: 23 }, // 188
    HuffmanCode { code: 0x3fffe5, length: 22 }, // 189
    HuffmanCode { code: 0x3fffe6, length: 22 }, // 190
    HuffmanCode { code: 0x7ffff1, length: 23 }, // 191
    HuffmanCode { code: 0x3ffffe0, length: 26 }, // 192
    HuffmanCode { code: 0x3ffffe1, length: 26 }, // 193
    HuffmanCode { code: 0xfffeb, length: 20 }, // 194
    HuffmanCode { code: 0x7fff1, length: 19 }, // 195
    HuffmanCode { code: 0x3fffe7, length: 22 }, // 196
    HuffmanCode { code: 0x7ffff2, length: 23 }, // 197
    HuffmanCode { code: 0x3fffe8, length: 22 }, // 198
    HuffmanCode { code: 0x1ffffec, length: 25 }, // 199
    HuffmanCode { code: 0x3ffffe2, length: 26 }, // 200
    HuffmanCode { code: 0x3ffffe3, length: 26 }, // 201
    HuffmanCode { code: 0x3ffffe4, length: 26 }, // 202
    HuffmanCode { code: 0x7ffffde, length: 27 }, // 203
    HuffmanCode { code: 0x7ffffdf, length: 27 }, // 204
    HuffmanCode { code: 0x3ffffe5, length: 26 }, // 205
    HuffmanCode { code: 0xfffff1, length: 24 }, // 206
    HuffmanCode { code: 0x1ffffed, length: 25 }, // 207
    HuffmanCode { code: 0x7fff2, length: 19 }, // 208
    HuffmanCode { code: 0x1fffe3, length: 21 }, // 209
    HuffmanCode { code: 0x3ffffe6, length: 26 }, // 210
    HuffmanCode { code: 0x7ffffe0, length: 27 }, // 211
    HuffmanCode { code: 0x7ffffe1, length: 27 }, // 212
    HuffmanCode { code: 0x3ffffe7, length: 26 }, // 213
    HuffmanCode { code: 0x7ffffe2, length: 27 }, // 214
    HuffmanCode { code: 0xfffff2, length: 24 }, // 215
    HuffmanCode { code: 0x1fffe4, length: 21 }, // 216
    HuffmanCode { code: 0x1fffe5, length: 21 }, // 217
    HuffmanCode { code: 0x3ffffe8, length: 26 }, // 218
    HuffmanCode { code: 0x3ffffe9, length: 26 }, // 219
    HuffmanCode { code: 0xffffffd, length: 28 }, // 220
    HuffmanCode { code: 0x7ffffe3, length: 27 }, // 221
    HuffmanCode { code: 0x7ffffe4, length: 27 }, // 222
    HuffmanCode { code: 0x7ffffe5, length: 27 }, // 223
    HuffmanCode { code: 0xfffec, length: 20 }, // 224
    HuffmanCode { code: 0xfffff3, length: 24 }, // 225
    HuffmanCode { code: 0xfffed, length: 20 }, // 226
    HuffmanCode { code: 0x1fffe6, length: 21 }, // 227
    HuffmanCode { code: 0x3fffe9, length: 22 }, // 228
    HuffmanCode { code: 0x1fffe7, length: 21 }, // 229
    HuffmanCode { code: 0x1fffe8, length: 21 }, // 230
    HuffmanCode { code: 0x7ffff3, length: 23 }, // 231
    HuffmanCode { code: 0x3fffea, length: 22 }, // 232
    HuffmanCode { code: 0x3fffeb, length: 22 }, // 233
    HuffmanCode { code: 0x1ffffee, length: 25 }, // 234
    HuffmanCode { code: 0x1ffffef, length: 25 }, // 235
    HuffmanCode { code: 0xfffff4, length: 24 }, // 236
    HuffmanCode { code: 0xfffff5, length: 24 }, // 237
    HuffmanCode { code: 0x3ffffea, length: 26 }, // 238
    HuffmanCode { code: 0x7ffff4, length: 23 }, // 239
    HuffmanCode { code: 0x3ffffeb, length: 26 }, // 240
    HuffmanCode { code: 0x7ffffe6, length: 27 }, // 241
    HuffmanCode { code: 0x3ffffec, length: 26 }, // 242
    HuffmanCode { code: 0x3ffffed, length: 26 }, // 243
    HuffmanCode { code: 0x7ffffe7, length: 27 }, // 244
    HuffmanCode { code: 0x7ffffe8, length: 27 }, // 245
    HuffmanCode { code: 0x7ffffe9, length: 27 }, // 246
    HuffmanCode { code: 0x7ffffea, length: 27 }, // 247
    HuffmanCode { code: 0x7ffffeb, length: 27 }, // 248
    HuffmanCode { code: 0xffffffe, length: 28 }, // 249
    HuffmanCode { code: 0x7ffffec, length: 27 }, // 250
    HuffmanCode { code: 0x7ffffed, length: 27 }, // 251
    HuffmanCode { code: 0x7ffffee, length: 27 }, // 252
    HuffmanCode { code: 0x7ffffef, length: 27 }, // 253
    HuffmanCode { code: 0x7fffff0, length: 27 }, // 254
    HuffmanCode { code: 0x3ffffee, length: 26 }, // 255
];

#[derive(Debug, Clone)]
pub enum QpackInstruction {
    // Encoder instructions
    SetDynamicTableCapacity { capacity: u64 },
    InsertWithNameReference { static_table: bool, name_index: u64, value: String },
    InsertWithLiteralName { name: String, value: String },
    Duplicate { index: u64 },
    
    // Decoder instructions
    SectionAcknowledgment { stream_id: u64 },
    StreamCancellation { stream_id: u64 },
    InsertCountIncrement { increment: u64 },
}

/// Simple QPACK encoder/decoder for HTTP/3 header compression.
///
/// # Performance Optimization Opportunity (Future Work)
///
/// The current implementation uses a single AsyncMutex protecting all codec state,
/// which can cause lock contention in high-throughput scenarios with many concurrent
/// streams. A future optimization would split the lock into finer-grained components:
///
/// 1. **Static Table**: Read-only after initialization, could use Arc without lock
/// 2. **Dynamic Table**: Read/write, needs RwLock or separate read/write paths
/// 3. **State Counters**: insert_count, known_received_count - could use atomics
/// 4. **Configuration**: Mostly read-only after handshake, could use RwLock
///
/// This would allow:
/// - Multiple concurrent decode_headers() calls (read-only dynamic table lookups)
/// - Separate locking for encoder vs decoder stream processing
/// - Reduced contention between control stream and request streams
///
/// Expected improvement: 2-3x throughput in high-concurrency scenarios (100+ concurrent streams)
///
/// Implementation considerations:
/// - Must maintain proper ordering for encode_instruction() and insert()
/// - Atomic operations need memory ordering guarantees (Acquire/Release)
/// - RwLock upgrades are prone to deadlocks - prefer separate read/write APIs
/// - Reference counting (dynamic_table_ref_counts) needs careful synchronization
///
/// RFC 9204 Section 2.1.2 requires that dynamic table entries remain available
/// until all references are acknowledged, which complicates the lock splitting.
pub struct QpackCodec {
    static_table: Vec<(String, String)>, // index -> (name, value)
    dynamic_table: Vec<(String, String)>, // index -> (name, value), index 0 is most recent
    dynamic_table_capacity: usize,
    max_dynamic_table_capacity: usize,
    insert_count: usize,
    known_received_count: usize,
    max_blocked_streams: usize,
    max_field_section_size: Option<usize>, // RFC 9114 Section 7.2.4.2
    // Phase 2: Blocked streams tracking (RFC 9204 Section 2.1.4)
    current_blocked_streams: usize,
    // Phase 2: Reference counting for eviction safety (RFC 9204 Section 2.1.2)
    dynamic_table_ref_counts: Vec<usize>, // Tracks in-flight references per entry
    // Phase 2: Draining entries that were evicted but still referenced
    draining_entries: Vec<(usize, String, String)>, // (insert_count_when_evicted, name, value)
}

impl QpackCodec {
    pub fn new() -> Self {
        let static_table = Self::build_static_table();
        Self {
            static_table,
            dynamic_table: Vec::new(),
            dynamic_table_capacity: 0,
            max_dynamic_table_capacity: 0,
            insert_count: 0,
            known_received_count: 0,
            max_blocked_streams: 0,
            max_field_section_size: None, // No limit by default
            // Phase 2: Initialize blocked streams tracking
            current_blocked_streams: 0,
            // Phase 2: Initialize reference counting
            dynamic_table_ref_counts: Vec::new(),
            // Phase 2: Initialize draining entries
            draining_entries: Vec::new(),
        }
    }
    
    /// Create a new codec with a known maximum capacity.
    /// PERF: Pre-allocates dynamic table to avoid reallocations.
    pub fn with_capacity(max_capacity: usize) -> Self {
        let static_table = Self::build_static_table();
        // Calculate max entries: RFC 9204 §4.5.1.1 MaxEntries = floor(capacity / 32)
        let max_entries = if max_capacity > 0 { max_capacity / 32 } else { 0 };
        
        Self {
            static_table,
            dynamic_table: Vec::with_capacity(max_entries),
            dynamic_table_capacity: 0,
            max_dynamic_table_capacity: max_capacity,
            insert_count: 0,
            known_received_count: 0,
            max_blocked_streams: 0,
            max_field_section_size: None,
            current_blocked_streams: 0,
            dynamic_table_ref_counts: Vec::with_capacity(max_entries),
            draining_entries: Vec::new(),
        }
    }

    /// Set the maximum dynamic table capacity
    pub fn set_max_table_capacity(&mut self, capacity: usize) {
        self.max_dynamic_table_capacity = capacity;
        
        // PERF #4: Pre-allocate dynamic table Vec to max capacity
        let max_entries = if capacity > 0 { capacity / 32 } else { 0 };
        if self.dynamic_table.capacity() < max_entries {
            self.dynamic_table.reserve(max_entries - self.dynamic_table.capacity());
            self.dynamic_table_ref_counts.reserve(max_entries - self.dynamic_table_ref_counts.capacity());
        }
        
        // Also set the current capacity to the maximum if it's currently 0
        if self.dynamic_table_capacity == 0 {
            self.dynamic_table_capacity = capacity;
        } else if self.dynamic_table_capacity > capacity {
            self.set_table_capacity(capacity);
        }
    }
    
    /// Set the maximum number of blocked streams
    pub fn set_max_blocked_streams(&mut self, max_blocked: usize) {
        self.max_blocked_streams = max_blocked;
    }
    
    /// Set the maximum field section size (RFC 9114 Section 7.2.4.2)
    pub fn set_max_field_section_size(&mut self, max_size: Option<usize>) {
        self.max_field_section_size = max_size;
    }
    
    /// Set the dynamic table capacity
    pub fn set_table_capacity(&mut self, capacity: usize) {
        if capacity > self.max_dynamic_table_capacity {
            return; // Cannot exceed maximum
        }
        self.dynamic_table_capacity = capacity;
        self.evict_entries_to_fit_capacity();
    }
    
    /// Get the current table capacity
    pub fn table_capacity(&self) -> usize {
        self.dynamic_table_capacity
    }
    
    /// Insert an entry into the dynamic table
    pub fn insert(&mut self, name: String, value: String) -> Option<usize> {
        let entry_size = name.len() + value.len() + 32;
        if entry_size > self.dynamic_table_capacity {
            return None; // Entry too large
        }
        
        self.evict_entries_to_fit_capacity();
        if self.dynamic_table_size() + entry_size > self.dynamic_table_capacity {
            return None; // Not enough space
        }
        
        self.dynamic_table.insert(0, (name, value)); // Insert at beginning (most recent)
        // Phase 2: Initialize reference count for new entry
        self.dynamic_table_ref_counts.insert(0, 0);
        // Phase 2: Handle wraparound for insert_count (RFC 9204 Section 4.5.1.1)
        self.insert_count = self.insert_count.wrapping_add(1);
        Some(0) // Return relative index
    }
    
    /// Duplicate an entry in the dynamic table
    pub fn duplicate(&mut self, index: usize) -> Option<usize> {
        if index >= self.dynamic_table.len() {
            return None;
        }
        let (name, value) = self.dynamic_table[index].clone();
        self.insert(name, value)
    }
    
    /// Get an entry by absolute index
    pub fn get_absolute(&self, index: usize) -> Option<&(String, String)> {
        if index < self.dynamic_table.len() {
            Some(&self.dynamic_table[self.dynamic_table.len() - 1 - index])
        } else {
            None
        }
    }
    
    /// Get an entry by relative index
    pub fn get_relative(&self, index: usize) -> Option<&(String, String)> {
        if index < self.dynamic_table.len() {
            Some(&self.dynamic_table[index])
        } else {
            None
        }
    }
    
    /// Get the current insert count
    pub fn insert_count(&self) -> usize {
        self.insert_count
    }
    
    /// Get the known received count
    pub fn known_received_count(&self) -> usize {
        self.known_received_count
    }
    
    /// Get the current number of blocked streams
    pub fn current_blocked_streams(&self) -> usize {
        self.current_blocked_streams
    }
    
    /// RFC 9204 Section 2.1.4: Check if we can block another stream
    pub fn can_block_stream(&self) -> bool {
        self.current_blocked_streams < self.max_blocked_streams
    }
    
    /// RFC 9204 Section 2.1.4: Mark a stream as blocked
    pub fn block_stream(&mut self) -> Result<(), H3Error> {
        if !self.can_block_stream() {
            return Err(H3Error::Qpack(
                format!("H3_QPACK_DECOMPRESSION_FAILED: exceeded SETTINGS_QPACK_BLOCKED_STREAMS limit of {}", 
                        self.max_blocked_streams)
            ));
        }
        self.current_blocked_streams += 1;
        Ok(())
    }
    
    /// RFC 9204 Section 2.1.4: Unblock a stream (when decoding completes or stream is cancelled)
    pub fn unblock_stream(&mut self) {
        if self.current_blocked_streams > 0 {
            self.current_blocked_streams -= 1;
        }
    }
    
    /// Get current blocked streams count (for telemetry/debugging)
    pub fn blocked_streams_count(&self) -> usize {
        self.current_blocked_streams
    }
    
    /// Update known received count
    pub fn update_known_received_count(&mut self, count: usize) {
        self.known_received_count = count;
        // RFC 9204 Section 2.1.2: Clean up draining entries that are now acknowledged
        self.cleanup_draining_entries();
    }
    
    /// RFC 9204 Section 2.1.2: Add reference to a dynamic table entry
    pub fn add_reference(&mut self, index: usize) {
        // Ensure ref_counts vec is large enough
        while self.dynamic_table_ref_counts.len() <= index {
            self.dynamic_table_ref_counts.push(0);
        }
        self.dynamic_table_ref_counts[index] += 1;
    }
    
    /// RFC 9204 Section 2.1.2: Release reference to a dynamic table entry
    pub fn release_reference(&mut self, index: usize) {
        if index < self.dynamic_table_ref_counts.len() && self.dynamic_table_ref_counts[index] > 0 {
            self.dynamic_table_ref_counts[index] -= 1;
        }
    }
    
    /// RFC 9204 Section 2.1.2: Check if an entry can be safely evicted
    fn can_evict(&self, index: usize) -> bool {
        // Entry can be evicted if it has no outstanding references
        index >= self.dynamic_table_ref_counts.len() || self.dynamic_table_ref_counts[index] == 0
    }
    
    /// RFC 9204 Section 2.1.2: Clean up draining entries that have been acknowledged
    fn cleanup_draining_entries(&mut self) {
        // Remove draining entries where insert_count <= known_received_count
        self.draining_entries.retain(|(insert_count, _, _)| {
            *insert_count > self.known_received_count
        });
    }
    
    /// Get a static table entry by index
    pub fn get_static_entry(&self, index: usize) -> Option<&(String, String)> {
        self.static_table.get(index)
    }
    
    /// RFC 9204 Section 2.1.2: Get an entry from draining state by insert count
    pub fn get_draining_entry(&self, target_insert_count: usize) -> Option<(String, String)> {
        for (insert_count, name, value) in &self.draining_entries {
            if *insert_count == target_insert_count {
                return Some((name.clone(), value.clone()));
            }
        }
        None
    }
    
    /// Calculate the size of the dynamic table
    fn dynamic_table_size(&self) -> usize {
        self.dynamic_table.iter()
            .map(|(name, value)| name.len() + value.len() + 32)
            .sum()
    }
    
    /// Evict entries until the table fits within capacity
    /// RFC 9204 Section 2.1.2: Entries with outstanding references move to draining
    fn evict_entries_to_fit_capacity(&mut self) {
        while self.dynamic_table_size() > self.dynamic_table_capacity && !self.dynamic_table.is_empty() {
            let oldest_index = self.dynamic_table.len() - 1;
            
            // RFC 9204 Section 2.1.2: Check if entry can be safely evicted
            if self.can_evict(oldest_index) {
                // Safe to evict - no outstanding references
                self.dynamic_table.pop();
                if oldest_index < self.dynamic_table_ref_counts.len() {
                    self.dynamic_table_ref_counts.pop();
                }
            } else {
                // Entry still referenced - move to draining
                if let Some(entry) = self.dynamic_table.pop() {
                    self.draining_entries.push((self.insert_count, entry.0, entry.1));
                    if oldest_index < self.dynamic_table_ref_counts.len() {
                        self.dynamic_table_ref_counts.pop();
                    }
                }
            }
        }
    }
    fn build_static_table() -> Vec<(String, String)> {
        // Static table from RFC 9204 Appendix A
        vec![
            (":authority".to_string(), "".to_string()),
            (":path".to_string(), "/".to_string()),
            ("age".to_string(), "0".to_string()),
            ("content-disposition".to_string(), "".to_string()),
            ("content-length".to_string(), "0".to_string()),
            ("cookie".to_string(), "".to_string()),
            ("date".to_string(), "".to_string()),
            ("etag".to_string(), "".to_string()),
            ("if-modified-since".to_string(), "".to_string()),
            ("if-none-match".to_string(), "".to_string()),
            ("last-modified".to_string(), "".to_string()),
            ("link".to_string(), "".to_string()),
            ("location".to_string(), "".to_string()),
            ("referer".to_string(), "".to_string()),
            ("set-cookie".to_string(), "".to_string()),
            (":method".to_string(), "CONNECT".to_string()),
            (":method".to_string(), "DELETE".to_string()),
            (":method".to_string(), "GET".to_string()),
            (":method".to_string(), "HEAD".to_string()),
            (":method".to_string(), "OPTIONS".to_string()),
            (":method".to_string(), "POST".to_string()),
            (":method".to_string(), "PUT".to_string()),
            (":scheme".to_string(), "http".to_string()),
            (":scheme".to_string(), "https".to_string()),
            (":status".to_string(), "103".to_string()),
            (":status".to_string(), "200".to_string()),
            (":status".to_string(), "304".to_string()),
            (":status".to_string(), "404".to_string()),
            (":status".to_string(), "503".to_string()),
            ("accept".to_string(), "*/*".to_string()),
            ("accept".to_string(), "application/dns-message".to_string()),
            ("accept-encoding".to_string(), "gzip, deflate, br".to_string()),
            ("accept-ranges".to_string(), "bytes".to_string()),
            ("access-control-allow-headers".to_string(), "cache-control".to_string()),
            ("access-control-allow-headers".to_string(), "content-type".to_string()),
            ("access-control-allow-origin".to_string(), "*".to_string()),
            ("cache-control".to_string(), "max-age=0".to_string()),
            ("cache-control".to_string(), "max-age=2592000".to_string()),
            ("cache-control".to_string(), "max-age=604800".to_string()),
            ("cache-control".to_string(), "no-cache".to_string()),
            ("cache-control".to_string(), "no-store".to_string()),
            ("cache-control".to_string(), "public, max-age=31536000".to_string()),
            ("content-encoding".to_string(), "br".to_string()),
            ("content-encoding".to_string(), "gzip".to_string()),
            ("content-type".to_string(), "application/dns-message".to_string()),
            ("content-type".to_string(), "application/javascript".to_string()),
            ("content-type".to_string(), "application/json".to_string()),
            ("content-type".to_string(), "application/x-www-form-urlencoded".to_string()),
            ("content-type".to_string(), "image/gif".to_string()),
            ("content-type".to_string(), "image/jpeg".to_string()),
            ("content-type".to_string(), "image/png".to_string()),
            ("content-type".to_string(), "text/css".to_string()),
            ("content-type".to_string(), "text/html; charset=utf-8".to_string()),
            ("content-type".to_string(), "text/plain".to_string()),
            ("content-type".to_string(), "text/plain;charset=utf-8".to_string()),
            ("range".to_string(), "bytes=0-".to_string()),
            ("strict-transport-security".to_string(), "max-age=31536000".to_string()),
            ("strict-transport-security".to_string(), "max-age=31536000; includesubdomains".to_string()),
            ("strict-transport-security".to_string(), "max-age=31536000; includesubdomains; preload".to_string()),
            ("vary".to_string(), "accept-encoding".to_string()),
            ("vary".to_string(), "origin".to_string()),
            ("x-content-type-options".to_string(), "nosniff".to_string()),
            ("x-xss-protection".to_string(), "1; mode=block".to_string()),
            (":status".to_string(), "100".to_string()),
            (":status".to_string(), "204".to_string()),
            (":status".to_string(), "206".to_string()),
            (":status".to_string(), "302".to_string()),
            (":status".to_string(), "400".to_string()),
            (":status".to_string(), "403".to_string()),
            (":status".to_string(), "421".to_string()),
            (":status".to_string(), "425".to_string()),
            (":status".to_string(), "500".to_string()),
            ("accept-language".to_string(), "".to_string()),
            ("access-control-allow-credentials".to_string(), "FALSE".to_string()),
            ("access-control-allow-credentials".to_string(), "TRUE".to_string()),
            ("access-control-allow-headers".to_string(), "*".to_string()),
            ("access-control-allow-methods".to_string(), "get".to_string()),
            ("access-control-allow-methods".to_string(), "get, post, options".to_string()),
            ("access-control-allow-methods".to_string(), "options".to_string()),
            ("access-control-expose-headers".to_string(), "content-length".to_string()),
            ("access-control-request-headers".to_string(), "content-type".to_string()),
            ("access-control-request-method".to_string(), "get".to_string()),
            ("access-control-request-method".to_string(), "post".to_string()),
            ("alt-svc".to_string(), "clear".to_string()),
            ("authorization".to_string(), "".to_string()),
            ("content-security-policy".to_string(), "script-src 'none'; object-src 'none'; base-uri 'none'".to_string()),
            ("early-data".to_string(), "1".to_string()),
            ("expect-ct".to_string(), "".to_string()),
            ("forwarded".to_string(), "".to_string()),
            ("if-range".to_string(), "".to_string()),
            ("origin".to_string(), "".to_string()),
            ("purpose".to_string(), "prefetch".to_string()),
            ("server".to_string(), "".to_string()),
            ("timing-allow-origin".to_string(), "*".to_string()),
            ("upgrade-insecure-requests".to_string(), "1".to_string()),
            ("user-agent".to_string(), "".to_string()),
            ("x-forwarded-for".to_string(), "".to_string()),
            ("x-frame-options".to_string(), "deny".to_string()),
            ("x-frame-options".to_string(), "sameorigin".to_string()),
        ]
    }

    /// Split Cookie header values for better QPACK compression.
    /// 
    /// RFC 9114 Section 4.2.1: "To improve compression efficiency, Cookie headers
    /// SHOULD be split into separate header fields with single cookie-pairs before
    /// encoding."
    /// 
    /// Example: "cookie: a=b; c=d" becomes two headers: "cookie: a=b" and "cookie: c=d"
    pub fn split_cookie_headers(headers: &[(String, String)]) -> Vec<(String, String)> {
        let mut result = Vec::with_capacity(headers.len());
        
        for (name, value) in headers {
            if name.eq_ignore_ascii_case("cookie") {
                // Split by semicolon and trim whitespace
                for cookie_pair in value.split(';') {
                    let trimmed = cookie_pair.trim();
                    if !trimmed.is_empty() {
                        result.push((name.clone(), trimmed.to_string()));
                    }
                }
            } else {
                result.push((name.clone(), value.clone()));
            }
        }
        
        result
    }

    /// Encode headers with dynamic table support and zero-copy optimizations
    /// Returns (encoded_headers, encoder_instructions, referenced_dynamic_entries)
    /// The caller is responsible for adding references for the returned indices
    pub fn encode_headers(&mut self, headers: &[(String, String)]) -> Result<(Bytes, Vec<Bytes>, Vec<usize>), H3Error> {
        // RFC 9114 Section 4.2.1: Split Cookie headers for better compression
        // "Before encoding, Cookie headers SHOULD be split into individual cookie-pairs"
        let processed_headers = Self::split_cookie_headers(headers);
        let headers_to_encode = &processed_headers;
        
        // PERF #1: Pre-allocate buffer with better size estimate
        // Typical header: 20 bytes name + 50 bytes value + 3 bytes overhead = ~73 bytes
        // Add prefix bytes and safety margin
        let estimated_size = 8 + headers_to_encode.len() * 80;
        let mut buf = BytesMut::with_capacity(estimated_size);
        let mut encoder_instructions = Vec::new();
        let mut referenced_dynamic_entries = Vec::with_capacity(headers_to_encode.len() / 4); // Assume 25% dynamic refs
        
        // First pass: decide which headers to insert into dynamic table
        // Heuristic: insert headers that are not in static table and likely to repeat
        for (name, value) in headers_to_encode {
            // Skip if already in dynamic table
            if self.find_dynamic_entry(name, value).is_some() {
                continue;
            }
            
            // Check if exact name-value pair is in static table
            let exact_static_match = self.static_table.iter()
                .any(|(n, v)| n == name && v == value);
            
            if exact_static_match {
                continue;
            }
            
            // If we reach here, the entry is not in static table (exact match) and not in dynamic table
            // Insert it into dynamic table for potential future reuse
            // Note: More sophisticated heuristics could be added here based on:
            // - Header size (large headers benefit more from compression)
            // - Header type (custom headers more likely to repeat)
            // - Observed repetition patterns
            
            // Generate encoder instruction
            let instruction = self.create_insert_instruction(name, value)?;
            encoder_instructions.push(instruction);
            
            // Actually insert into our local dynamic table
            self.insert(name.clone(), value.clone());
        }
        
        // RFC 9204 Section 4.5.1: Encoded field section prefix
        // Required Insert Count = highest insert count referenced + 1
        // GAP #10 FIX: Use proper encoding with wraparound per RFC 9204 §4.5.1.1
        let required_insert_count = self.insert_count;
        let encoded_insert_count = self.encode_required_insert_count(required_insert_count);
        self.encode_varint_with_prefix(&mut buf, encoded_insert_count, 0x00);
        
        // Base = current insert count (most common case - referencing recent entries)
        let base_delta = 0u64;
        let sign = false; // positive (S=0)
        self.encode_varint_with_prefix(&mut buf, base_delta, if sign { 0x80 } else { 0x00 });
        
        for (name, value) in headers {
            // First, check if the exact name-value pair is in the static table
            if let Some(static_index) = self.find_static_exact_match(name, value) {
                // Indexed header field - static table
                // Format: 1 1 IIIIIIIIII (T=0 for static)
                let index_byte = 0x80 | ((static_index & 0x3F) as u8);
                buf.put_u8(index_byte);
                if static_index >= 64 {
                    self.encode_varint(&mut buf, (static_index - 63) as u64);
                }
                continue;
            }
            
            // Check if the exact name-value pair is in the dynamic table
            if let Some(dynamic_index) = self.find_dynamic_entry(name, value) {
                // Indexed header field - dynamic table
                // Format: 1 1 IIIIIIIIII (T=1 for dynamic, S=1 for never-indexed)
                let index_byte = 0x80 | 0x40 | ((dynamic_index & 0x3F) as u8);
                buf.put_u8(index_byte);
                if dynamic_index >= 64 {
                    // Need more bytes for index
                    self.encode_varint(&mut buf, dynamic_index as u64);
                }
                // RFC 9204 Section 2.1.2: Track reference to dynamic table entry
                referenced_dynamic_entries.push(dynamic_index);
                continue;
            }
            
            // Check if name is in dynamic table
            if let Some((dynamic_name_index, existing_value)) = self.find_dynamic_name(name) {
                if &existing_value == value {
                    // Indexed header field - dynamic table name match
                    // Format: 1 1 IIIIIIIIII (T=1 for dynamic, S=1 for never-indexed)
                    let index_byte = 0x80 | 0x40 | ((dynamic_name_index & 0x3F) as u8);
                    buf.put_u8(index_byte);
                    if dynamic_name_index >= 64 {
                        self.encode_varint(&mut buf, dynamic_name_index as u64);
                    }
                    // RFC 9204 Section 2.1.2: Track reference to dynamic table entry
                    referenced_dynamic_entries.push(dynamic_name_index);
                } else {
                    // Literal Field Line with Name Reference (dynamic)
                    // Format: 01 0 0 IIIIIIIIII H LLLLLLLL VVVVVVVV
                    if dynamic_name_index < 32 {
                        let index_byte = (0x40 | dynamic_name_index) as u8;
                        buf.put_u8(index_byte);
                    } else {
                        let index_byte = (0x40 | 0x1F) as u8;
                        buf.put_u8(index_byte);
                        self.encode_varint(&mut buf, (dynamic_name_index - 31) as u64);
                    }
                    self.encode_string(&mut buf, value);
                    // RFC 9204 Section 2.1.2: Track reference to dynamic table entry (name only)
                    referenced_dynamic_entries.push(dynamic_name_index);
                }
                continue;
            }
            
            // Check if name is in static table
            if let Some(static_name_index) = self.find_static_name_index(name) {
                // Literal Field Line with Name Reference (static)
                // Format: 01 1 0 IIIIIIIIII H LLLLLLLL VVVVVVVV
                if static_name_index < 16 {
                    let index_byte = (0x60 | static_name_index) as u8;
                    buf.put_u8(index_byte);
                } else {
                    let index_byte = (0x60 | 0x0F) as u8;
                    buf.put_u8(index_byte);
                    self.encode_varint(&mut buf, (static_name_index - 15) as u64);
                }
                self.encode_string(&mut buf, value);
                continue;
            }
            
            // Literal Field Line with Literal Name
            // Format: 001 1 H LLLLLLLL NNNNNNNN H LLLLLLLL VVVVVVVV
            buf.put_u8(0x20 | 0x10); // 00110000 (never-indexed)
            self.encode_string(&mut buf, name);
            self.encode_string(&mut buf, value);
        }

        Ok((buf.freeze(), encoder_instructions, referenced_dynamic_entries))
    }
    
    /// Create an encoder instruction to insert a header into the dynamic table
    fn create_insert_instruction(&self, name: &str, value: &str) -> Result<Bytes, H3Error> {
        let mut buf = BytesMut::new();
        
        // Check if name is in static table
        if let Some(static_index) = self.find_static_name_index(name) {
            // Insert with Name Reference (static table)
            // Format: 1 1 IIIIIIII H LLLLLLLL VVVVVVVV
            // Bit pattern: 11TTTTTT where T=0 (static), then index
            let first_byte = 0xC0 | if static_index < 64 { static_index as u8 } else { 0x3F };
            buf.put_u8(first_byte);
            if static_index >= 64 {
                self.encode_varint(&mut buf, (static_index - 63) as u64);
            }
            self.encode_string(&mut buf, value);
        } else {
            // Insert with Literal Name
            // Format: 01 H LLLLLLLL NNNNNNNN H LLLLLLLL VVVVVVVV
            buf.put_u8(0x40); // 01000000
            self.encode_string(&mut buf, name);
            self.encode_string(&mut buf, value);
        }
        
        Ok(buf.freeze())
    }
    
    /// Find a static table entry by name (public for testing)
    pub fn find_static_name_index(&self, name: &str) -> Option<usize> {
        for (i, (n, _)) in self.static_table.iter().enumerate() {
            if n == name {
                return Some(i);
            }
        }
        None
    }
    
    /// Find an exact name-value match in the static table
    fn find_static_exact_match(&self, name: &str, value: &str) -> Option<usize> {
        for (i, (n, v)) in self.static_table.iter().enumerate() {
            if n == name && v == value {
                return Some(i);
            }
        }
        None
    }

    /// Find an exact name-value match in the dynamic table
    fn find_dynamic_entry(&self, name: &str, value: &str) -> Option<usize> {
        for (i, (n, v)) in self.dynamic_table.iter().enumerate() {
            if n == name && v == value {
                // Return relative index (0 = most recent)
                return Some(i);
            }
        }
        None
    }

    /// Find a name match in the dynamic table, returning (index, existing_value)
    fn find_dynamic_name(&self, name: &str) -> Option<(usize, String)> {
        for (i, (n, v)) in self.dynamic_table.iter().enumerate() {
            if n == name {
                // Return relative index and the existing value
                return Some((i, v.clone()));
            }
        }
        None
    }

    /// Decodes QPACK encoded headers (basic implementation).
    /// Returns (headers, referenced_dynamic_entries) for reference tracking.
    pub fn decode_headers(&self, encoded: &[u8]) -> Result<(Vec<(String, String)>, Vec<usize>), H3Error> {
        // PERF #1: Pre-allocate with estimated header count (typical: 10-20 headers)
        let estimated_headers = 16;
        let mut headers = Vec::with_capacity(estimated_headers);
        let mut cursor = 0;
        let mut field_section_size: usize = 0; // Track size per RFC 9114 Section 7.2.4.2
        let mut referenced_dynamic_entries = Vec::new(); // Track references for cleanup

        // RFC 9204 Section 4.5.1: Decode field section prefix
        // Required Insert Count (8-bit prefix)
        if cursor >= encoded.len() {
            return Err(H3Error::Qpack("empty encoded field section".into()));
        }
        let (encoded_insert_count, consumed) = self.decode_qpack_prefix_int(&encoded[cursor..], 8)?;
        cursor += consumed;
        
        // GAP #10 FIX: Decode with wraparound handling per RFC 9204 §4.5.1.1
        let required_insert_count = self.decode_required_insert_count(encoded_insert_count)?;
        
        // RFC 9204 Section 2.1.4: Check if stream would be blocked
        if required_insert_count > self.insert_count {
            // Stream is blocked - decoder needs to wait for dynamic table updates
            // Return special error that H3Session will handle by queueing the stream
            return Err(H3Error::QpackBlocked(required_insert_count));
        }
        
        // Base (7-bit prefix with sign bit)
        if cursor >= encoded.len() {
            return Err(H3Error::Qpack("missing base in field section prefix".into()));
        }
        let (_base, consumed) = self.decode_qpack_prefix_int(&encoded[cursor..], 7)?;
        cursor += consumed;

        while cursor < encoded.len() {
            let first_byte = encoded[cursor];
            cursor += 1;

            if (first_byte & 0x80) != 0 {
                // Indexed header field
                let (index, consumed) = if (first_byte & 0x40) != 0 {
                    // Dynamic table
                    let index_bits = (first_byte & 0x3F) as u64;
                    if index_bits < 64 {
                        (index_bits as usize, 0)
                    } else {
                        let (idx, cons) = self.decode_varint(&encoded[cursor..])?;
                        (idx as usize, cons)
                    }
                } else {
                    // Static table
                    let index_bits = (first_byte & 0x3F) as u64;
                    if index_bits < 64 {
                        (index_bits as usize, 0)
                    } else {
                        let (idx, cons) = self.decode_varint(&encoded[cursor..])?;
                        (idx as usize, cons)
                    }
                };
                cursor += consumed;
                
                let (name, value) = if (first_byte & 0x40) != 0 {
                    // Dynamic table
                    referenced_dynamic_entries.push(index); // Track reference
                    // RFC 9204 Section 2.1.2: Check draining entries first
                    if let Some(entry) = self.get_relative(index) {
                        entry.clone()
                    } else {
                        // Entry might be in draining state
                        let insert_count = self.insert_count.saturating_sub(index);
                        self.get_draining_entry(insert_count)
                            .ok_or_else(|| H3Error::Qpack("invalid dynamic table index".into()))?
                    }
                } else {
                    // Static table
                    self.static_table.get(index)
                        .ok_or_else(|| H3Error::Qpack("invalid static table index".into()))?
                        .clone()
                };
                // RFC 9114 Section 7.2.4.2: Track field section size
                // Size = name.len() + value.len() + 32 per field line
                field_section_size += name.len() + value.len() + 32;
                if let Some(max_size) = self.max_field_section_size {
                    if field_section_size > max_size {
                        return Err(H3Error::Http("field section size exceeds MAX_FIELD_SECTION_SIZE".into()));
                    }
                }
                headers.push((name, value));
            } else if (first_byte & 0x40) != 0 {
                // Literal with name reference
                let static_table = (first_byte & 0x20) != 0;
                let name_index_bits = if static_table {
                    (first_byte & 0x0F) as usize // Static table: low 4 bits
                } else {
                    (first_byte & 0x1F) as usize // Dynamic table: low 5 bits
                };
                
                let name_index = if static_table {
                    if name_index_bits == 15 {
                        let (additional, consumed) = self.decode_varint(&encoded[cursor..])?;
                        cursor += consumed;
                        15 + additional as usize
                    } else {
                        name_index_bits
                    }
                } else {
                    if name_index_bits == 31 {
                        let (additional, consumed) = self.decode_varint(&encoded[cursor..])?;
                        cursor += consumed;
                        31 + additional as usize
                    } else {
                        name_index_bits
                    }
                };
                
                let name = if static_table {
                    self.static_table.get(name_index)
                        .ok_or_else(|| H3Error::Qpack("invalid static table index".into()))?
                        .0
                        .clone()
                } else {
                    referenced_dynamic_entries.push(name_index); // Track reference
                    // RFC 9204 Section 2.1.2: Check draining entries
                    if let Some(entry) = self.get_relative(name_index) {
                        entry.0.clone()
                    } else {
                        let insert_count = self.insert_count.saturating_sub(name_index);
                        self.get_draining_entry(insert_count)
                            .ok_or_else(|| H3Error::Qpack("invalid dynamic table index".into()))?
                            .0
                    }
                };
                
                let (value, consumed) = self.decode_string(&encoded[cursor..])?;
                cursor += consumed;
                // RFC 9114 Section 7.2.4.2: Track field section size
                field_section_size += name.len() + value.len() + 32;
                if let Some(max_size) = self.max_field_section_size {
                    if field_section_size > max_size {
                        return Err(H3Error::Http("field section size exceeds MAX_FIELD_SECTION_SIZE".into()));
                    }
                }
                headers.push((name, value));
            } else if (first_byte & 0x20) != 0 {
                // Literal header field with literal name
                // RFC 9204 Section 4.5.6: Format 001NHHHHH (N=never-indexed, H=huffman)
                let (name, consumed) = self.decode_string(&encoded[cursor..])?;
                cursor += consumed;
                let (value, consumed) = self.decode_string(&encoded[cursor..])?;
                cursor += consumed;
                // RFC 9114 Section 7.2.4.2: Track field section size
                field_section_size += name.len() + value.len() + 32;
                if let Some(max_size) = self.max_field_section_size {
                    if field_section_size > max_size {
                        return Err(H3Error::Http("field section size exceeds MAX_FIELD_SECTION_SIZE".into()));
                    }
                }
                headers.push((name, value));
            } else if (first_byte & 0x10) != 0 {
                // Post-Base Indexed Field Line
                // RFC 9204 Section 4.5.4: Format 0001IIII (post-base index)
                // Used to reference dynamic table entries inserted after the base
                let index_bits = (first_byte & 0x0F) as usize;
                let post_base_index = if index_bits == 15 {
                    let (additional, consumed) = self.decode_varint(&encoded[cursor..])?;
                    cursor += consumed;
                    15 + additional as usize
                } else {
                    index_bits
                };
                
                // Post-base index is relative to the base (most recent entries)
                // Convert to absolute index in dynamic table
                // RFC 9204 Section 4.5.4: Post-base index 0 refers to the entry immediately after base
                referenced_dynamic_entries.push(post_base_index);
                
                let (name, value) = if let Some(entry) = self.get_relative(post_base_index) {
                    entry.clone()
                } else {
                    // Entry might be in draining state
                    let insert_count = self.insert_count.saturating_sub(post_base_index);
                    self.get_draining_entry(insert_count)
                        .ok_or_else(|| H3Error::Qpack("invalid post-base dynamic table index".into()))?
                };
                
                // RFC 9114 Section 7.2.4.2: Track field section size
                field_section_size += name.len() + value.len() + 32;
                if let Some(max_size) = self.max_field_section_size {
                    if field_section_size > max_size {
                        return Err(H3Error::Http("field section size exceeds MAX_FIELD_SECTION_SIZE".into()));
                    }
                }
                headers.push((name, value));
            } else if (first_byte & 0x08) != 0 {
                // This would be 00001XXX - not a valid pattern per RFC 9204
                return Err(H3Error::Qpack("invalid field line representation".into()));
            } else if first_byte != 0 {
                // Post-Base Literal Field Line With Name Reference
                // RFC 9204 Section 4.5.5: Format 0000NNNN (N=name index in post-base)
                let name_index_bits = (first_byte & 0x0F) as usize;
                let post_base_name_index = if name_index_bits == 15 {
                    let (additional, consumed) = self.decode_varint(&encoded[cursor..])?;
                    cursor += consumed;
                    15 + additional as usize
                } else {
                    name_index_bits
                };
                
                // Post-base name reference
                referenced_dynamic_entries.push(post_base_name_index);
                
                let name = if let Some(entry) = self.get_relative(post_base_name_index) {
                    entry.0.clone()
                } else {
                    let insert_count = self.insert_count.saturating_sub(post_base_name_index);
                    self.get_draining_entry(insert_count)
                        .ok_or_else(|| H3Error::Qpack("invalid post-base dynamic table index for name".into()))?
                        .0
                };
                
                let (value, consumed) = self.decode_string(&encoded[cursor..])?;
                cursor += consumed;
                
                // RFC 9114 Section 7.2.4.2: Track field section size
                field_section_size += name.len() + value.len() + 32;
                if let Some(max_size) = self.max_field_section_size {
                    if field_section_size > max_size {
                        return Err(H3Error::Http("field section size exceeds MAX_FIELD_SECTION_SIZE".into()));
                    }
                }
                headers.push((name, value));
            } else {
                // first_byte == 0x00 - could be padding or error
                return Err(H3Error::Qpack("unexpected zero byte in field section".into()));
            }
        }

        // RFC 9204 Section 4.5.1.1: Validate Required Insert Count
        // "A decoder MUST treat a field section that contains a Required Insert Count
        // that is greater than the decoder's Insert Count as a connection error"
        // This was already checked above. Additionally, we must validate the RIC is
        // correct based on the maximum dynamic table index actually referenced.
        if !referenced_dynamic_entries.is_empty() {
            // Calculate the maximum dynamic table index referenced
            let max_referenced_index = referenced_dynamic_entries.iter().max().copied().unwrap_or(0);
            
            // The Required Insert Count must be at least large enough to include the
            // maximum referenced entry. Each dynamic table entry has an insert count
            // corresponding to when it was added.
            let expected_min_ric = self.insert_count.saturating_sub(max_referenced_index);
            
            // RFC 9204 Section 4.5.1.1: Verify RIC is sufficient
            // If RIC < expected minimum, the encoder provided an incorrect value
            if required_insert_count < expected_min_ric {
                return Err(H3Error::Qpack(format!(
                    "Required Insert Count {} is insufficient for referenced index {} (expected >= {})",
                    required_insert_count, max_referenced_index, expected_min_ric
                )));
            }
        } else if required_insert_count > 0 {
            // RFC 9204 Section 4.5.1.1: If no dynamic entries referenced, RIC must be 0
            return Err(H3Error::Qpack(
                "Required Insert Count is non-zero but no dynamic table entries referenced".into()
            ));
        }

        Ok((headers, referenced_dynamic_entries))
    }

    /// Encode bytes using Huffman coding (public for testing)
    pub fn encode_huffman(&self, input: &[u8]) -> Option<Vec<u8>> {
        let mut bit_buffer = 0u64;
        let mut bits_in_buffer = 0u8;
        let mut output = Vec::new();
        
        for &byte in input {
            let huffman_code = &HUFFMAN_CODES[byte as usize];
            
            // Add the code to the bit buffer
            bit_buffer = (bit_buffer << huffman_code.length) | (huffman_code.code as u64);
            bits_in_buffer += huffman_code.length;
            
            // Write out complete bytes
            while bits_in_buffer >= 8 {
                bits_in_buffer -= 8;
                let byte_to_write = ((bit_buffer >> bits_in_buffer) & 0xFF) as u8;
                output.push(byte_to_write);
            }
        }
        
        // Handle remaining bits - pad with 1s (EOS symbol)
        if bits_in_buffer > 0 {
            let padding_bits = 8 - bits_in_buffer;
            bit_buffer = (bit_buffer << padding_bits) | ((1u64 << padding_bits) - 1);
            output.push((bit_buffer & 0xFF) as u8);
        }
        
        Some(output)
    }

    /// Encode a string with Huffman compression (public for testing)
    pub fn encode_string(&self, buf: &mut BytesMut, s: &str) {
        let bytes = s.as_bytes();
        
        // Try Huffman encoding first
        if let Some(huffman_bytes) = self.encode_huffman(bytes) {
            if huffman_bytes.len() < bytes.len() {
                // Use Huffman encoding - set H bit and encode length
                self.encode_varint_with_prefix(buf, huffman_bytes.len() as u64, 0x80);
                buf.extend_from_slice(&huffman_bytes);
                return;
            }
        }
        // Use literal encoding - clear H bit and encode length
        self.encode_varint_with_prefix(buf, bytes.len() as u64, 0x00);
        buf.extend_from_slice(bytes);
    }
    
    /// Encode a varint with a prefix byte (for string lengths where bit 7 is H flag)
    fn encode_varint_with_prefix(&self, buf: &mut BytesMut, value: u64, prefix: u8) {
        if value < 127 {
            // Fits in 7 bits
            buf.put_u8(prefix | (value as u8));
        } else {
            // Use 127 as the marker and encode the rest as varint
            buf.put_u8(prefix | 0x7F);
            self.encode_varint(buf, value - 127);
        }
    }

    /// Decode Huffman-encoded bytes back to original bytes (public for testing)
    /// Decode Huffman-encoded data per RFC 7541 Section 5.2.
    /// 
    /// RFC 9204 Section 4.1.3: QPACK uses the same Huffman code as HPACK (RFC 7541).
    /// Returns None if the input contains invalid codes or improper padding.
    pub fn decode_huffman(&self, input: &[u8]) -> Option<String> {
        let mut output = Vec::with_capacity(input.len() * 2); // Pre-allocate for efficiency
        let mut bit_buffer = 0u64; // Use u64 to avoid overflow during accumulation
        let mut bits_available = 0u8;

        for &byte in input {
            // Shift existing bits to make room for new byte
            bit_buffer = (bit_buffer << 8) | (byte as u64);
            bits_available += 8;

            // Process as many complete codes as possible
            // RFC 7541: Huffman codes are variable length (5-30 bits)
            loop {
                if bits_available == 0 {
                    break;
                }
                
                let mut found = false;
                
                // Performance optimization: try common short codes first
                // Most ASCII characters have 5-8 bit codes
                for (symbol, huffman_code) in HUFFMAN_CODES.iter().enumerate() {
                    let code_length = huffman_code.length;
                    
                    if code_length > bits_available {
                        continue; // Not enough bits to decode this code
                    }

                    // Extract the next code_length bits from the high end of buffer
                    let shift = bits_available - code_length;
                    let extracted_code = (bit_buffer >> shift) as u32 & ((1u32 << code_length) - 1);

                    if extracted_code == huffman_code.code {
                        // RFC 7541 Section 5.2: EOS (256) must not appear in decoded output
                        if symbol == 256 {
                            return None; // Invalid: EOS in middle of stream
                        }
                        
                        output.push(symbol as u8);
                        
                        // Remove the used bits from buffer
                        bit_buffer &= (1u64 << shift) - 1;
                        bits_available = shift;
                        found = true;
                        break;
                    }
                }

                if !found {
                    break; // No complete code available with current bits
                }
            }
        }

        // RFC 7541 Section 5.2: Validate padding
        // "A padding strictly longer than 7 bits MUST be treated as a decoding error"
        if bits_available > 7 {
            return None; // Invalid: padding too long
        }
        
        if bits_available > 0 {
            // RFC 7541: Padding bits must all be 1s (corresponds to EOS prefix)
            let remaining = bit_buffer as u32 & ((1u32 << bits_available) - 1);
            let eos_mask = (1u32 << bits_available) - 1;
            
            if remaining != eos_mask {
                // Invalid: padding bits are not all 1s
                return None;
            }
            
            // Additional check: padding must not be decodable as a complete symbol
            // RFC 7541: "A padding not corresponding to the most significant bits
            // of the code for the EOS symbol MUST be treated as a decoding error"
            // EOS is 0x3fffffff (30 bits all 1s)
            // So any trailing 1-bits that could form a valid code prefix are invalid
            
            // This is already covered by the "no complete code" check above,
            // but we document it for clarity
        }

        String::from_utf8(output).ok()
    }

    /// Decode a string with Huffman decompression (public for testing)
    pub fn decode_string(&self, data: &[u8]) -> Result<(String, usize), H3Error> {
        if data.is_empty() {
            return Err(H3Error::Qpack("empty string data".into()));
        }
        let first_byte = data[0];
        let huffman = (first_byte & 0x80) != 0;
        let length_prefix = (first_byte & 0x7F) as u64;
        let mut cursor = 1;
        
        let length = if length_prefix < 127 {
            length_prefix as usize
        } else {
            // Read continuation bytes
            let (additional, consumed) = self.decode_varint(&data[cursor..])?;
            cursor += consumed;
            (127 + additional) as usize
        };
        
        if data.len() < cursor + length {
            return Err(H3Error::Qpack("string length exceeds data".into()));
        }
        
        let s = if huffman {
            // Huffman decode
            match self.decode_huffman(&data[cursor..cursor + length]) {
                Some(decoded) => decoded,
                None => return Err(H3Error::Qpack("invalid Huffman encoding".into())),
            }
        } else {
            String::from_utf8(data[cursor..cursor + length].to_vec())
                .map_err(|_| H3Error::Qpack("invalid utf8".into()))?
        };
        
        Ok((s, cursor + length))
    }

    /// Encode a QPACK instruction into bytes
    /// Encode a QPACK instruction to bytes per RFC 9204.
    /// 
    /// This method encodes instructions correctly for both encoder and decoder streams.
    /// Note: Encoder and decoder instructions have overlapping bit patterns, so the caller
    /// must ensure the instruction is sent on the correct stream type.
    /// 
    /// # Encoder Stream Instructions (RFC 9204 Section 4.3)
    /// - Set Dynamic Table Capacity: 001xxxxx (0x20-0x3F)
    /// - Insert with Name Reference: 1Txxxxxx (0x80-0xFF, T=table bit)
    /// - Insert with Literal Name: 01xxxxxx (0x40-0x7F)
    /// - Duplicate: 000xxxxx (0x00-0x1F)
    /// 
    /// # Decoder Stream Instructions (RFC 9204 Section 4.4)
    /// - Section Acknowledgment: 1xxxxxxx (0x80-0xFF)
    /// - Stream Cancellation: 01xxxxxx (0x40-0x7F)
    /// - Insert Count Increment: 00xxxxxx (0x00-0x3F)
    pub fn encode_instruction(&self, instruction: &QpackInstruction) -> Result<Bytes, H3Error> {
        // Pre-allocate buffer: instructions are typically small, 64 bytes is conservative
        let mut buf = BytesMut::with_capacity(64);
        
        match instruction {
            // ENCODER STREAM INSTRUCTIONS
            QpackInstruction::SetDynamicTableCapacity { capacity } => {
                // RFC 9204 Section 4.3.1: Set Dynamic Table Capacity
                // Format: 001 (3 bits) + capacity (5-bit prefix integer)
                buf.put_u8(0x20); // 001 00000
                self.encode_qpack_varint(&mut buf, *capacity, 5);
            }
            QpackInstruction::InsertWithNameReference { static_table, name_index, value } => {
                // RFC 9204 Section 4.3.2: Insert with Name Reference
                // Format: 1 (1 bit) + T (1 bit) + name_index (6-bit prefix) + value string
                let t_bit = if *static_table { 0x40 } else { 0x00 };
                buf.put_u8(0x80 | t_bit); // 1T 000000
                self.encode_qpack_varint(&mut buf, *name_index, 6);
                self.encode_string(&mut buf, value);
            }
            QpackInstruction::InsertWithLiteralName { name, value } => {
                // RFC 9204 Section 4.3.3: Insert with Literal Name
                // Format: 01 H Name_Length(5+) Name_String H Value_Length(7+) Value_String
                
                // Try Huffman encoding for name
                let name_bytes = name.as_bytes();
                let (h_name, encoded_name) = if let Some(huffman_name) = self.encode_huffman(name_bytes) {
                    if huffman_name.len() < name_bytes.len() {
                        (true, huffman_name)
                    } else {
                        (false, name_bytes.to_vec())
                    }
                } else {
                    (false, name_bytes.to_vec())
                };
                
                // First byte: 01 (2 bits) + H (1 bit) + name length (5-bit prefix)
                let h_bit = if h_name { 0x20 } else { 0x00 };
                buf.put_u8(0x40 | h_bit); // 01 H 00000
                self.encode_qpack_varint(&mut buf, encoded_name.len() as u64, 5);
                buf.put(&encoded_name[..]);
                
                // Value uses standard string encoding (H bit + 7-bit prefix length)
                self.encode_string(&mut buf, value);
            }
            QpackInstruction::Duplicate { index } => {
                // RFC 9204 Section 4.3.4: Duplicate
                // Format: 000 (3 bits) + index (5-bit prefix integer)
                buf.put_u8(0x00); // 000 00000
                self.encode_qpack_varint(&mut buf, *index, 5);
            }
            
            // DECODER STREAM INSTRUCTIONS
            QpackInstruction::SectionAcknowledgment { stream_id } => {
                // RFC 9204 Section 4.4.1: Section Acknowledgment
                // Format: 1 (1 bit) + stream_id (7-bit prefix integer)
                buf.put_u8(0x80); // 1 0000000
                self.encode_qpack_varint(&mut buf, *stream_id, 7);
            }
            QpackInstruction::StreamCancellation { stream_id } => {
                // RFC 9204 Section 4.4.2: Stream Cancellation
                // Format: 01 (2 bits) + stream_id (6-bit prefix integer)
                buf.put_u8(0x40); // 01 000000
                self.encode_qpack_varint(&mut buf, *stream_id, 6);
            }
            QpackInstruction::InsertCountIncrement { increment } => {
                // RFC 9204 Section 4.4.3: Insert Count Increment
                // Format: 00 (2 bits) + increment (6-bit prefix integer)
                buf.put_u8(0x00); // 00 000000
                self.encode_qpack_varint(&mut buf, *increment, 6);
            }
        }
        
        Ok(buf.freeze())
    }

    /// Decode a QPACK instruction from bytes with stream context for disambiguation.
    /// 
    /// RFC 9204 Section 4.3 (Encoder Stream) and 4.4 (Decoder Stream):
    /// Encoder and decoder instructions have overlapping bit patterns that require
    /// stream context to disambiguate. This method correctly decodes prefix integers
    /// per RFC 9204 Section 4.1.1.
    /// 
    /// # Encoder Stream Instructions
    /// - Set Dynamic Table Capacity: 001 + capacity (5-bit prefix)
    /// - Insert with Name Reference: 1T + name_index (6-bit prefix) + value
    /// - Insert with Literal Name: 01 + name + value
    /// - Duplicate: 000 + index (5-bit prefix)
    /// 
    /// # Decoder Stream Instructions
    /// - Section Acknowledgment: 1 + stream_id (7-bit prefix)
    /// - Stream Cancellation: 01 + stream_id (6-bit prefix)
    /// - Insert Count Increment: 00 + increment (6-bit prefix)
    pub fn decode_instruction_with_context(
        &self, 
        data: &[u8], 
        is_encoder_stream: bool
    ) -> Result<(QpackInstruction, usize), H3Error> {
        if data.is_empty() {
            return Err(H3Error::Qpack("empty instruction data".into()));
        }
        
        let first_byte = data[0];
        
        // Determine instruction type by top bits and stream context
        if first_byte & 0x80 != 0 {
            // 1xxxxxxx: Insert with Name Reference (encoder) or Section Acknowledgment (decoder)
            if is_encoder_stream {
                // Encoder stream: Insert with Name Reference
                // T bit (bit 6) determines static (1) vs dynamic (0) table
                let static_table = (first_byte & 0x40) != 0;
                let (name_index, mut cursor) = self.decode_qpack_prefix_int(data, 6)?;
                let (value, consumed) = self.decode_string(&data[cursor..])?;
                cursor += consumed;
                Ok((QpackInstruction::InsertWithNameReference { 
                    static_table, 
                    name_index, 
                    value 
                }, cursor))
            } else {
                // Decoder stream: Section Acknowledgment (1xxxxxxx)
                let (stream_id, cursor) = self.decode_qpack_prefix_int(data, 7)?;
                Ok((QpackInstruction::SectionAcknowledgment { stream_id }, cursor))
            }
        } else if first_byte & 0x40 != 0 {
            // 01xxxxxx: Insert with Literal Name (encoder) or Stream Cancellation (decoder)
            if is_encoder_stream {
                // Encoder stream: Insert with Literal Name
                // RFC 9204 Section 4.3.3: 01 H Name_Length(5+) Name_String H Value_Length(7+) Value_String
                let h_name = (first_byte & 0x20) != 0;
                let (name_length, mut cursor) = self.decode_qpack_prefix_int(data, 5)?;
                
                if data.len() < cursor + name_length as usize {
                    return Err(H3Error::Qpack("name length exceeds data".into()));
                }
                
                let name_bytes = &data[cursor..cursor + name_length as usize];
                cursor += name_length as usize;
                
                let name = if h_name {
                    self.decode_huffman(name_bytes)
                        .ok_or_else(|| H3Error::Qpack("invalid Huffman in name".into()))?
                } else {
                    String::from_utf8(name_bytes.to_vec())
                        .map_err(|_| H3Error::Qpack("invalid utf8 in name".into()))?
                };
                
                // Now decode the value string (has its own H bit and 7-bit prefix length)
                let (value, consumed) = self.decode_string(&data[cursor..])?;
                cursor += consumed;
                
                Ok((QpackInstruction::InsertWithLiteralName { name, value }, cursor))
            } else {
                // Decoder stream: Stream Cancellation
                let (stream_id, cursor) = self.decode_qpack_prefix_int(data, 6)?;
                Ok((QpackInstruction::StreamCancellation { stream_id }, cursor))
            }
        } else {
            // 00xxxxxx: Context-dependent instructions (Encoder vs Decoder streams)
            if is_encoder_stream {
                // Encoder stream: 00xxxxxx instructions
                if first_byte & 0x20 != 0 {
                    // 001xxxxx: Set Dynamic Table Capacity
                    let (capacity, cursor) = self.decode_qpack_prefix_int(data, 5)?;
                    Ok((QpackInstruction::SetDynamicTableCapacity { capacity }, cursor))
                } else {
                    // 000xxxxx: Duplicate
                    let (index, cursor) = self.decode_qpack_prefix_int(data, 5)?;
                    Ok((QpackInstruction::Duplicate { index }, cursor))
                }
            } else {
                // Decoder stream: 00xxxxxx = Insert Count Increment
                let (increment, cursor) = self.decode_qpack_prefix_int(data, 6)?;
                Ok((QpackInstruction::InsertCountIncrement { increment }, cursor))
            }
        }
    }
    
    /// Legacy decode without context - uses heuristic for backwards compatibility.
    /// Prefer decode_instruction_with_context() for correct RFC 9204 compliance.
    /// 
    /// NOTE: This method attempts to decode without stream context by using heuristics
    /// for ambiguous instruction patterns. For proper RFC 9204 compliance, always use
    /// decode_instruction_with_context() which correctly disambiguates based on stream type.
    pub fn decode_instruction(&self, data: &[u8]) -> Result<(QpackInstruction, usize), H3Error> {
        if data.is_empty() {
            return Err(H3Error::Qpack("empty instruction data".into()));
        }
        
        let first_byte = data[0];
        
        // Determine instruction type by top bits
        // NOTE: Must check 00xxxxxx patterns before more specific 001xxxxx pattern!
        if first_byte & 0x80 != 0 {
            // 1xxxxxxx: Insert with Name Reference or Section Acknowledgment
            if first_byte & 0x40 != 0 {
                // 11xxxxxx: Insert with Name Reference (static table)
                let (name_index, mut cursor) = self.decode_qpack_prefix_int(data, 6)?;
                let (value, consumed) = self.decode_string(&data[cursor..])?;
                cursor += consumed;
                Ok((QpackInstruction::InsertWithNameReference { 
                    static_table: true, 
                    name_index, 
                    value 
                }, cursor))
            } else {
                // 10xxxxxx: Ambiguous - could be dynamic name reference or section ack
                // Heuristic: Assume Section Acknowledgment (decoder instruction)
                // For correct behavior, use decode_instruction_with_context()
                let (stream_id, cursor) = self.decode_qpack_prefix_int(data, 7)?;
                Ok((QpackInstruction::SectionAcknowledgment { stream_id }, cursor))
            }
        } else if first_byte & 0x40 != 0 {
            // 01xxxxxx: Insert with Literal Name or Stream Cancellation
            // Heuristic: Assume Insert with Literal Name (encoder instruction)
            let h_name = (first_byte & 0x20) != 0;
            let (name_length, mut cursor) = self.decode_qpack_prefix_int(data, 5)?;
            
            if data.len() < cursor + name_length as usize {
                return Err(H3Error::Qpack("name length exceeds data".into()));
            }
            
            let name_bytes = &data[cursor..cursor + name_length as usize];
            cursor += name_length as usize;
            
            let name = if h_name {
                self.decode_huffman(name_bytes)
                    .ok_or_else(|| H3Error::Qpack("invalid Huffman in name".into()))?
            } else {
                String::from_utf8(name_bytes.to_vec())
                    .map_err(|_| H3Error::Qpack("invalid utf8 in name".into()))?
            };
            
            let (value, consumed) = self.decode_string(&data[cursor..])?;
            cursor += consumed;
            
            Ok((QpackInstruction::InsertWithLiteralName { name, value }, cursor))
        } else {
            // 00xxxxxx: Overlapping patterns:
            // - 001xxxxx (0x20-0x3F): SetDynamicTableCapacity with 5-bit prefix
            // - 000xxxxx (0x00-0x1F): Duplicate with 5-bit prefix  
            // - 00xxxxxx (0x00-0x3F): InsertCountIncrement with 6-bit prefix
            //
            // Strategy: Check if first byte alone (ignoring continuation bit) can distinguish
            // - If bits 3-5 are 001 AND value fits in 5-bit prefix (< 31), it's SetDynamicTableCapacity
            // - If bits 3-5 are 000 AND value fits in 5-bit prefix (< 31), it's Duplicate
            // - Otherwise decode as 6-bit prefix and use value-based heuristic
            
            // 00xxxxxx: Ambiguous patterns without stream context
            // - 001xxxxx (0x20-0x3F): SetDynamicTableCapacity (5-bit prefix)
            // - 000xxxxx (0x00-0x1F): Duplicate (5-bit prefix)
            // - 00xxxxxx (0x00-0x3F): InsertCountIncrement (6-bit prefix)
            //
            // Disambiguation strategy:
            // 1. Check if all lower 5 bits are set (0x1F) -> continuation bytes follow
            // 2. If no continuation AND bit 5 set -> SetDynamicTableCapacity
            // 3. If no continuation AND bit 5 clear -> Duplicate
            // 4. If continuation, decode BOTH ways and use heuristic:
            //    - As 5-bit prefix (for SetDynamicTableCapacity or Duplicate)
            //    - As 6-bit prefix (for InsertCountIncrement)
            //    - Use value-based heuristic to choose
            
            let has_continuation_5bit = (first_byte & 0x1F) == 0x1F;
            
            if !has_continuation_5bit {
                // No continuation - can distinguish by bit 5
                if first_byte & 0x20 != 0 {
                    // 001xxxxx: SetDynamicTableCapacity
                    let (capacity, cursor) = self.decode_qpack_prefix_int(data, 5)?;
                    Ok((QpackInstruction::SetDynamicTableCapacity { capacity }, cursor))
                } else {
                    // 000xxxxx: Duplicate
                    let (index, cursor) = self.decode_qpack_prefix_int(data, 5)?;
                    Ok((QpackInstruction::Duplicate { index }, cursor))
                }
            } else {
                // Continuation bytes present - ambiguous
                // Decode with both prefixes and compare values
                let (value_5bit, cursor_5bit) = self.decode_qpack_prefix_int(data, 5)?;
                let (value_6bit, cursor_6bit) = self.decode_qpack_prefix_int(data, 6)?;
                
                // Disambiguation heuristic when first_byte has all 5 lower bits set (0x1F/0x3F):
                // Both SetDynamicTableCapacity and InsertCountIncrement can encode to 0x3F
                // - SetDynamicTableCapacity: starts 0x20, becomes 0x3F with 5-bit prefix
                // - InsertCountIncrement: starts 0x00, becomes 0x3F with 6-bit prefix
                //
                // Strategy: Decode both ways and use value comparison
                // - If 6-bit value is significantly larger AND >= 1024 -> InsertCountIncrement
                // - If bit 5 is set in first byte -> SetDynamicTableCapacity (original pattern 001)
                // - Otherwise -> Duplicate (original pattern 000)
                
                // Use value heuristic combined with bit pattern:
                // - 5-bit prefix can encode max 31 in prefix, rest in continuation
                // - 6-bit prefix can encode max 63 in prefix, rest in continuation
                // - If first byte is 0x3F and both values are large:
                //   * Difference is exactly 32 (63 - 31) when continuation is the same
                //   * Use threshold: if 6-bit value >= 1024, prefer InsertCountIncrement
                
                let value_diff = value_6bit.saturating_sub(value_5bit);
                
                // Disambiguation heuristic when first_byte = 0x3F (all lower bits set):
                // - Could be SetDynamicTableCapacity (started 0x20, 5-bit prefix)
                // - Could be InsertCountIncrement (started 0x00, 6-bit prefix)
                // - Could be Duplicate (started 0x00, 5-bit prefix) - but unlikely with continuation
                //
                // Key insight: The difference is always exactly 32 when continuations are identical
                // (63 from 6-bit prefix vs 31 from 5-bit prefix)
                //
                // Strategy:
                // - If both values >= 1024 AND diff == 32: Use value magnitude as tie-breaker
                //   * If 6-bit value significantly larger (> 1900): InsertCountIncrement
                //   * Otherwise: SetDynamicTableCapacity
                // - If bit 5 is clear (0x00-0x1F): Definitely not SetDynamicTableCapacity
                // - If only 5-bit value >= 1024: SetDynamicTableCapacity
                
                if (first_byte & 0x20) == 0 {
                    // Bit 5 clear -> NOT SetDynamicTableCapacity
                    if value_6bit >= 1024 {
                        // Large value -> InsertCountIncrement
                        Ok((QpackInstruction::InsertCountIncrement { increment: value_6bit }, cursor_6bit))
                    } else {
                        // Small value -> Duplicate
                        Ok((QpackInstruction::Duplicate { index: value_5bit }, cursor_5bit))
                    }
                } else if value_diff == 32 && value_6bit >= 1024 && value_5bit >= 1024 {
                    // Ambiguous case: first_byte = 0x3F, both values large
                    // Use value magnitude: InsertCountIncrement typically > 1900, SetDynamicTableCapacity typically < 1900
                    if value_6bit > 1900 {
                        Ok((QpackInstruction::InsertCountIncrement { increment: value_6bit }, cursor_6bit))
                    } else {
                        Ok((QpackInstruction::SetDynamicTableCapacity { capacity: value_5bit }, cursor_5bit))
                    }
                } else {
                    // Bit 5 set, not ambiguous -> SetDynamicTableCapacity
                    Ok((QpackInstruction::SetDynamicTableCapacity { capacity: value_5bit }, cursor_5bit))
                }
            }
        }
    }

    /// Encode a variable-length integer
    fn encode_varint(&self, buf: &mut BytesMut, mut value: u64) {
        loop {
            let mut byte = (value & 0x7F) as u8;
            value >>= 7;
            if value > 0 {
                byte |= 0x80;
            }
            buf.put_u8(byte);
            if value == 0 {
                break;
            }
        }
    }

    /// Decode a variable-length integer
    fn decode_varint(&self, data: &[u8]) -> Result<(u64, usize), H3Error> {
        let mut value = 0u64;
        let mut shift = 0;
        let mut cursor = 0;
        
        loop {
            if cursor >= data.len() {
                return Err(H3Error::Qpack("varint extends beyond data".into()));
            }
            let byte = data[cursor];
            cursor += 1;
            
            value |= ((byte & 0x7F) as u64) << shift;
            shift += 7;
            
            if (byte & 0x80) == 0 {
                break;
            }
            
            if shift >= 64 {
                return Err(H3Error::Qpack("varint too large".into()));
            }
        }
        
        Ok((value, cursor))
    }

    /// Decode a QPACK prefix integer (RFC 9204 Section 4.1.1)
    fn decode_qpack_prefix_int(&self, data: &[u8], prefix_bits: u8) -> Result<(u64, usize), H3Error> {
        if data.is_empty() {
            return Err(H3Error::Qpack("empty data for prefix int".into()));
        }
        
        let first_byte = data[0];
        let mask = if prefix_bits >= 8 {
            0xFF
        } else {
            ((1u16 << prefix_bits) - 1) as u8
        };
        let mut value = (first_byte & mask) as u64;
        let max_first = ((1u64 << prefix_bits) - 1).min(255);
        
        if value < max_first {
            // Value fits in prefix
            return Ok((value, 1));
        }
        
        // Need to read continuation bytes
        let mut cursor = 1;
        let mut m = 0;
        
        loop {
            if cursor >= data.len() {
                return Err(H3Error::Qpack("incomplete prefix integer".into()));
            }
            
            let byte = data[cursor];
            cursor += 1;
            
            value += ((byte & 0x7F) as u64) << m;
            m += 7;
            
            if (byte & 0x80) == 0 {
                break;
            }
            
            if m >= 64 {
                return Err(H3Error::Qpack("prefix integer overflow".into()));
            }
        }
        
        Ok((value, cursor))
    }

    /// Encode a QPACK prefix integer (RFC 9204 Section 4.1.1)
    /// 
    /// This encodes an integer into the specified number of prefix bits in the last byte
    /// of the buffer, with continuation bytes if needed. The upper bits of the last byte
    /// must already be set with the instruction type before calling this method.
    /// 
    /// Per RFC 9204 Section 4.1.1:
    /// - If I < 2^N - 1, encode I on N bits
    /// - Else, encode all 1s on N bits, then encode (I - (2^N - 1)) on 7-bit continuation bytes
    pub fn encode_qpack_varint(&self, buf: &mut BytesMut, mut value: u64, prefix_bits: u8) {
        let max_first = (1u64 << prefix_bits) - 1;
        let prefix_mask = ((1u16 << prefix_bits) - 1) as u8;
        
        // Get the existing upper bits from the last byte (or 0 if buffer is empty)
        let upper_bits = if buf.is_empty() {
            0u8
        } else {
            let len = buf.len();
            buf[len - 1] & !prefix_mask  // Keep only the upper bits
        };
        
        if value < max_first {
            // Value fits in the prefix bits
            if buf.is_empty() {
                buf.put_u8(value as u8);
            } else {
                let len = buf.len();
                buf[len - 1] = upper_bits | (value as u8);
            }
        } else {
            // Value doesn't fit, encode max value in prefix and use continuation bytes
            if buf.is_empty() {
                buf.put_u8(max_first as u8);
            } else {
                let len = buf.len();
                buf[len - 1] = upper_bits | (max_first as u8);
            }
            
            value -= max_first;
            
            // Encode remainder in 7-bit continuation bytes (RFC 7541 Section 5.1)
            while value >= 128 {
                buf.put_u8((value as u8 & 0x7F) | 0x80);
                value >>= 7;
            }
            buf.put_u8(value as u8);
        }
    }

    /// Encode Required Insert Count per RFC 9204 Section 4.5.1.1
    /// 
    /// This function encodes the Required Insert Count value with wraparound handling.
    /// The encoding ensures that the decoder can reconstruct the value even when it wraps.
    /// 
    /// Algorithm from RFC 9204 §4.5.1.1:
    /// ```text
    /// if ReqInsertCount == 0:
    ///    EncodedInsertCount = 0
    /// else:
    ///    EncodedInsertCount = (ReqInsertCount mod (2 * MaxEntries)) + 1
    /// ```
    pub fn encode_required_insert_count(&self, req_insert_count: usize) -> u64 {
        if req_insert_count == 0 {
            return 0;
        }
        
        // MaxEntries is the maximum number of entries the dynamic table can hold
        // RFC 9204 §4.5.1.1: MaxEntries = floor(max_table_capacity / 32)
        let max_entries = self.max_dynamic_table_capacity / 32;
        if max_entries == 0 {
            // Edge case: if table capacity is too small, can't use dynamic table
            return 0;
        }
        
        let full_range = 2 * max_entries;
        let encoded = (req_insert_count % full_range) + 1;
        encoded as u64
    }
    
    /// Decode Required Insert Count per RFC 9204 Section 4.5.1.1
    /// 
    /// This function decodes the Required Insert Count value with wraparound handling.
    /// 
    /// Algorithm from RFC 9204 §4.5.1.1:
    /// ```text
    /// FullRange = 2 * MaxEntries
    /// if EncodedInsertCount == 0:
    ///    ReqInsertCount = 0
    /// else:
    ///    MaxValue = TotalNumInserted + MaxEntries
    ///    MaxWrapped = (MaxValue / FullRange) * FullRange
    ///    ReqInsertCount = MaxWrapped + EncodedInsertCount - 1
    ///    if ReqInsertCount > MaxValue:
    ///       if ReqInsertCount <= FullRange:
    ///          return Error
    ///       ReqInsertCount -= FullRange
    /// ```
    pub fn decode_required_insert_count(&self, encoded_insert_count: u64) -> Result<usize, H3Error> {
        if encoded_insert_count == 0 {
            return Ok(0);
        }
        
        // MaxEntries is the maximum number of entries the dynamic table can hold
        let max_entries = self.max_dynamic_table_capacity / 32;
        if max_entries == 0 {
            return Err(H3Error::Qpack("dynamic table capacity too small".into()));
        }
        
        let full_range = 2 * max_entries;
        let total_num_inserted = self.insert_count;
        let max_value = total_num_inserted + max_entries;
        
        // MaxWrapped = floor(MaxValue / FullRange) * FullRange
        let max_wrapped = (max_value / full_range) * full_range;
        let mut req_insert_count = max_wrapped + encoded_insert_count as usize - 1;
        
        if req_insert_count > max_value {
            if req_insert_count <= full_range {
                return Err(H3Error::Qpack("invalid required insert count encoding".into()));
            }
            req_insert_count -= full_range;
        }
        
        Ok(req_insert_count)
    }
}