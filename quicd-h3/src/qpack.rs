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
pub struct QpackCodec {
    static_table: Vec<(String, String)>, // index -> (name, value)
    dynamic_table: Vec<(String, String)>, // index -> (name, value), index 0 is most recent
    dynamic_table_capacity: usize,
    max_dynamic_table_capacity: usize,
    insert_count: usize,
    known_received_count: usize,
    max_blocked_streams: usize,
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
        }
    }

    /// Set the maximum dynamic table capacity
    pub fn set_max_table_capacity(&mut self, capacity: usize) {
        self.max_dynamic_table_capacity = capacity;
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
        self.insert_count += 1;
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
    
    /// Update known received count
    pub fn update_known_received_count(&mut self, count: usize) {
        self.known_received_count = count;
    }
    
    /// Get a static table entry by index
    pub fn get_static_entry(&self, index: usize) -> Option<&(String, String)> {
        self.static_table.get(index)
    }
    
    /// Calculate the size of the dynamic table
    fn dynamic_table_size(&self) -> usize {
        self.dynamic_table.iter()
            .map(|(name, value)| name.len() + value.len() + 32)
            .sum()
    }
    
    /// Evict entries until the table fits within capacity
    fn evict_entries_to_fit_capacity(&mut self) {
        while self.dynamic_table_size() > self.dynamic_table_capacity && !self.dynamic_table.is_empty() {
            self.dynamic_table.pop(); // Remove oldest entry
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

    pub fn encode_headers(&self, headers: &[(String, String)]) -> Result<Bytes, H3Error> {
        // Pre-allocate buffer: rough estimate is 2 bytes prefix + 32 bytes per header
        let estimated_size = 2 + headers.len() * 32;
        let mut buf = BytesMut::with_capacity(estimated_size);
        
        // RFC 9204 Section 4.5.1: Encoded field section prefix
        // Required Insert Count (8-bit prefix)
        let required_insert_count = self.encode_required_insert_count();
        buf.put_u8(required_insert_count as u8); // For now, always fits in 1 byte
        
        // Base (7-bit prefix with sign bit in bit 7)
        // For now, use Base = 0 (no dynamic table references in this encoding)
        let base_delta = 0u64;
        let sign = false; // positive (S=0)
        let base_byte = if sign { 0x80 } else { 0x00 } | (base_delta as u8 & 0x7F);
        buf.put_u8(base_byte);
        
        for (name, value) in headers {
            // First, check if the exact name-value pair is in the dynamic table
            if let Some(dynamic_index) = self.find_dynamic_entry(name, value) {
                // Indexed header field - dynamic table
                // Format: 1 1 IIIIIIIIII (T=1 for dynamic, S=1 for never-indexed)
                let index_byte = 0x80 | 0x40 | ((dynamic_index & 0x3F) as u8);
                buf.put_u8(index_byte);
                if dynamic_index >= 64 {
                    // Need more bytes for index
                    self.encode_varint(&mut buf, dynamic_index as u64);
                }
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
    pub fn decode_headers(&self, encoded: &[u8]) -> Result<Vec<(String, String)>, H3Error> {
        let mut headers = Vec::new();
        let mut cursor = 0;

        // RFC 9204 Section 4.5.1: Decode field section prefix
        // Required Insert Count (8-bit prefix)
        if cursor >= encoded.len() {
            return Err(H3Error::Qpack("empty encoded field section".into()));
        }
        let (_required_insert_count, consumed) = self.decode_qpack_prefix_int(&encoded[cursor..], 8)?;
        cursor += consumed;
        
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
                    self.get_relative(index)
                        .ok_or_else(|| H3Error::Qpack("invalid dynamic table index".into()))?
                        .clone()
                } else {
                    // Static table
                    self.static_table.get(index)
                        .ok_or_else(|| H3Error::Qpack("invalid static table index".into()))?
                        .clone()
                };
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
                    self.get_relative(name_index)
                        .ok_or_else(|| H3Error::Qpack("invalid dynamic table index".into()))?
                        .0
                        .clone()
                };
                
                let (value, consumed) = self.decode_string(&encoded[cursor..])?;
                cursor += consumed;
                headers.push((name, value));
            } else if (first_byte & 0x20) != 0 {
                // Literal header field
                let (name, consumed) = self.decode_string(&encoded[cursor..])?;
                cursor += consumed;
                let (value, consumed) = self.decode_string(&encoded[cursor..])?;
                cursor += consumed;
                headers.push((name, value));
            } else {
                return Err(H3Error::Qpack("unknown field representation".into()));
            }
        }

        Ok(headers)
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
    pub fn decode_huffman(&self, input: &[u8]) -> Option<String> {
        let mut output = Vec::new();
        let mut bit_buffer = 0u32;
        let mut bits_available = 0u8;

        for &byte in input {
            // Shift existing bits to make room for new byte
            bit_buffer <<= 8;
            bit_buffer |= byte as u32;
            bits_available += 8;

            // Process as many complete codes as possible
            loop {
                let mut found = false;
                for (symbol, huffman_code) in HUFFMAN_CODES.iter().enumerate() {
                    let code_length = huffman_code.length as u8;
                    if code_length > bits_available {
                        continue;
                    }

                    // Extract the code from the high bits
                    let shift = bits_available - code_length;
                    let extracted_code = (bit_buffer >> shift) & ((1u32 << code_length) - 1);

                    if extracted_code == huffman_code.code as u32 {
                        output.push(symbol as u8);
                        // Remove the used bits
                        bit_buffer &= (1u32 << shift) - 1;
                        bits_available -= code_length;
                        found = true;
                        break;
                    }
                }

                if !found {
                    break; // No more codes can be decoded
                }
            }
        }

        // Check remaining bits are all 1s (EOS padding)
        if bits_available > 0 {
            let remaining = bit_buffer & ((1u32 << bits_available) - 1);
            let eos_mask = (1u32 << bits_available) - 1;
            if remaining != eos_mask {
                return None;
            }
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
    pub fn encode_instruction(&self, instruction: &QpackInstruction) -> Result<Bytes, H3Error> {
        // Pre-allocate buffer: instructions are typically small, 64 bytes is conservative
        let mut buf = BytesMut::with_capacity(64);
        
        match instruction {
            QpackInstruction::SetDynamicTableCapacity { capacity } => {
                // Format: 00100000 + capacity (variable-length)
                buf.put_u8(0x20);
                self.encode_varint(&mut buf, *capacity);
            }
            QpackInstruction::InsertWithNameReference { static_table, name_index, value } => {
                // Format: 1 T 0 000000 + name_index (variable-length) + value
                let flags = if *static_table { 0x40 } else { 0x00 }; // T bit
                buf.put_u8(0x80 | flags);
                self.encode_varint(&mut buf, *name_index);
                self.encode_string(&mut buf, value);
            }
            QpackInstruction::InsertWithLiteralName { name, value } => {
                // Format: 01000000 + name + value
                buf.put_u8(0x40);
                self.encode_string(&mut buf, name);
                self.encode_string(&mut buf, value);
            }
            QpackInstruction::Duplicate { index } => {
                // Format: 00000000 + index (variable-length)
                buf.put_u8(0x00);
                self.encode_varint(&mut buf, *index);
            }
            QpackInstruction::SectionAcknowledgment { stream_id } => {
                // Format: 10000000 + stream_id (variable-length)
                buf.put_u8(0x80);
                self.encode_varint(&mut buf, *stream_id);
            }
            QpackInstruction::StreamCancellation { stream_id } => {
                // Format: 01000000 + stream_id (variable-length)
                buf.put_u8(0x40);
                self.encode_varint(&mut buf, *stream_id);
            }
            QpackInstruction::InsertCountIncrement { increment } => {
                // Format: 00000000 + increment (variable-length)
                buf.put_u8(0x00);
                self.encode_varint(&mut buf, *increment);
            }
        }
        
        Ok(buf.freeze())
    }

    /// Decode a QPACK instruction from bytes
    pub fn decode_instruction(&self, data: &[u8]) -> Result<(QpackInstruction, usize), H3Error> {
        if data.is_empty() {
            return Err(H3Error::Qpack("empty instruction data".into()));
        }
        
        let first_byte = data[0];
        let mut cursor = 1;
        
        match first_byte {
            0x20..=0x3F => {
                // Set Dynamic Table Capacity
                let (capacity, consumed) = self.decode_varint(&data[cursor..])?;
                cursor += consumed;
                Ok((QpackInstruction::SetDynamicTableCapacity { capacity }, cursor))
            }
            0x80..=0xFF => {
                // Insert with Name Reference or Section Acknowledgment
                if (first_byte & 0x40) != 0 {
                    // Insert with Name Reference static
                    let (name_index, consumed) = self.decode_varint(&data[cursor..])?;
                    cursor += consumed;
                    let (value, consumed) = self.decode_string(&data[cursor..])?;
                    cursor += consumed;
                    Ok((QpackInstruction::InsertWithNameReference { static_table: true, name_index, value }, cursor))
                } else {
                    // Section Acknowledgment
                    let (stream_id, consumed) = self.decode_varint(&data[cursor..])?;
                    cursor += consumed;
                    Ok((QpackInstruction::SectionAcknowledgment { stream_id }, cursor))
                }
            }
            0x40..=0x7F => {
                // Insert with Literal Name or Stream Cancellation
                if (first_byte & 0x20) != 0 {
                    // Stream Cancellation (bit pattern: 01 xxxxxx)
                    let (stream_id, consumed) = self.decode_varint(&data[cursor..])?;
                    cursor += consumed;
                    Ok((QpackInstruction::StreamCancellation { stream_id }, cursor))
                } else {
                    // Insert with Literal Name (bit pattern: 010 xxxxx)
                    let (name, consumed) = self.decode_string(&data[cursor..])?;
                    cursor += consumed;
                    let (value, consumed) = self.decode_string(&data[cursor..])?;
                    cursor += consumed;
                    Ok((QpackInstruction::InsertWithLiteralName { name, value }, cursor))
                }
            }
            0x00..=0x1F => {
                // Duplicate or Insert Count Increment
                let (value, consumed) = self.decode_varint(&data[cursor..])?;
                cursor += consumed;
                
                if first_byte == 0x00 {
                    // Could be Duplicate or Insert Count Increment
                    // For now, assume Duplicate if value is small, Insert Count Increment if large
                    // TODO: proper instruction identification
                    if value < 1024 {
                        Ok((QpackInstruction::Duplicate { index: value }, cursor))
                    } else {
                        Ok((QpackInstruction::InsertCountIncrement { increment: value }, cursor))
                    }
                } else {
                    return Err(H3Error::Qpack("unknown instruction".into()));
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
    /// This is different from the 7-bit continuation encoding used for instructions
    /// (exposed for testing)
    pub fn encode_qpack_varint(&self, buf: &mut BytesMut, mut value: u64, prefix_bits: u8) {
        let max_first = (1u64 << prefix_bits) - 1;
        
        if value < max_first {
            // Value fits in the prefix
            let existing_byte = if buf.is_empty() {
                0
            } else {
                let len = buf.len();
                buf[len - 1]
            };
            
            if buf.is_empty() {
                buf.put_u8(value as u8);
            } else {
                let len = buf.len();
                buf[len - 1] = existing_byte | (value as u8);
            }
        } else {
            // Value doesn't fit, use continuation bytes
            let existing_byte = if buf.is_empty() {
                0
            } else {
                let len = buf.len();
                buf[len - 1]
            };
            
            if buf.is_empty() {
                buf.put_u8(max_first as u8);
            } else {
                let len = buf.len();
                buf[len - 1] = existing_byte | (max_first as u8);
            }
            
            value -= max_first;
            
            // Encode remainder in 7-bit chunks
            while value >= 128 {
                buf.put_u8(((value % 128) as u8) | 0x80);
                value /= 128;
            }
            buf.put_u8(value as u8);
        }
    }

    /// Encode Required Insert Count per RFC 9204 Section 4.5.1.1 (exposed for testing)
    pub fn encode_required_insert_count(&self) -> u64 {
        // For now, if we haven't used dynamic table, return 0
        // TODO: Track actual required insert count based on dynamic table references
        let req_insert_count = 0u64;
        
        if req_insert_count == 0 {
            return 0;
        }
        
        // RFC 9204 Section 4.5.1.1 encoding algorithm
        // MaxEntries = 2 * max_table_capacity / 32 (assuming 32 bytes per entry)
        let max_entries = ((self.max_dynamic_table_capacity * 2) / 32) as u64;
        if max_entries == 0 {
            return 0;
        }
        
        let full_range = 2 * max_entries;
        if req_insert_count > full_range {
            return (req_insert_count % full_range) + full_range;
        }
        
        req_insert_count % full_range
    }
}