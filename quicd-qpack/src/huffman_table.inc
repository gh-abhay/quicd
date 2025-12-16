// Huffman encoding table from RFC 7541 Appendix B
// Format: HuffmanEntry { code, len } for symbols 0-257 (0-255 are bytes, 256 is EOS)
// Generated from RFC 7541 Appendix B static Huffman table
[
    HuffmanEntry { code: 0x1ff8, len: 13 },     // 0
    HuffmanEntry { code: 0x7fffd8, len: 23 },   // 1
    HuffmanEntry { code: 0xfffffe2, len: 28 },  // 2
    HuffmanEntry { code: 0xfffffe3, len: 28 },  // 3
    HuffmanEntry { code: 0xfffffe4, len: 28 },  // 4
    HuffmanEntry { code: 0xfffffe5, len: 28 },  // 5
    HuffmanEntry { code: 0xfffffe6, len: 28 },  // 6
    HuffmanEntry { code: 0xfffffe7, len: 28 },  // 7
    HuffmanEntry { code: 0xfffffe8, len: 28 },  // 8
    HuffmanEntry { code: 0xffffea, len: 24 },   // 9
    HuffmanEntry { code: 0x3ffffffc, len: 30 }, // 10
    HuffmanEntry { code: 0xfffffe9, len: 28 },  // 11
    HuffmanEntry { code: 0xfffffea, len: 28 },  // 12
    HuffmanEntry { code: 0x3ffffffd, len: 30 }, // 13
    HuffmanEntry { code: 0xfffffeb, len: 28 },  // 14
    HuffmanEntry { code: 0xfffffec, len: 28 },  // 15
    HuffmanEntry { code: 0xfffffed, len: 28 },  // 16
    HuffmanEntry { code: 0xfffffee, len: 28 },  // 17
    HuffmanEntry { code: 0xfffffef, len: 28 },  // 18
    HuffmanEntry { code: 0xffffff0, len: 28 },  // 19
    HuffmanEntry { code: 0xffffff1, len: 28 },  // 20
    HuffmanEntry { code: 0xffffff2, len: 28 },  // 21
    HuffmanEntry { code: 0x3ffffffe, len: 30 }, // 22
    HuffmanEntry { code: 0xffffff3, len: 28 },  // 23
    HuffmanEntry { code: 0xffffff4, len: 28 },  // 24
    HuffmanEntry { code: 0xffffff5, len: 28 },  // 25
    HuffmanEntry { code: 0xffffff6, len: 28 },  // 26
    HuffmanEntry { code: 0xffffff7, len: 28 },  // 27
    HuffmanEntry { code: 0xffffff8, len: 28 },  // 28
    HuffmanEntry { code: 0xffffff9, len: 28 },  // 29
    HuffmanEntry { code: 0xffffffa, len: 28 },  // 30
    HuffmanEntry { code: 0xffffffb, len: 28 },  // 31
    HuffmanEntry { code: 0x14, len: 6 },        // 32 ' '
    HuffmanEntry { code: 0x3f8, len: 10 },      // 33 '!'
    HuffmanEntry { code: 0x3f9, len: 10 },      // 34 '"'
    HuffmanEntry { code: 0xffa, len: 12 },      // 35 '#'
    HuffmanEntry { code: 0x1ff9, len: 13 },     // 36 '$'
    HuffmanEntry { code: 0x15, len: 6 },        // 37 '%'
    HuffmanEntry { code: 0xf8, len: 8 },        // 38 '&'
    HuffmanEntry { code: 0x7fa, len: 11 },      // 39 '\''
    HuffmanEntry { code: 0x3fa, len: 10 },      // 40 '('
    HuffmanEntry { code: 0x3fb, len: 10 },      // 41 ')'
    HuffmanEntry { code: 0xf9, len: 8 },        // 42 '*'
    HuffmanEntry { code: 0x7fb, len: 11 },      // 43 '+'
    HuffmanEntry { code: 0xfa, len: 8 },        // 44 ','
    HuffmanEntry { code: 0x16, len: 6 },        // 45 '-'
    HuffmanEntry { code: 0x17, len: 6 },        // 46 '.'
    HuffmanEntry { code: 0x18, len: 6 },        // 47 '/'
    HuffmanEntry { code: 0x0, len: 5 },         // 48 '0'
    HuffmanEntry { code: 0x1, len: 5 },         // 49 '1'
    HuffmanEntry { code: 0x2, len: 5 },         // 50 '2'
    HuffmanEntry { code: 0x19, len: 6 },        // 51 '3'
    HuffmanEntry { code: 0x1a, len: 6 },        // 52 '4'
    HuffmanEntry { code: 0x1b, len: 6 },        // 53 '5'
    HuffmanEntry { code: 0x1c, len: 6 },        // 54 '6'
    HuffmanEntry { code: 0x1d, len: 6 },        // 55 '7'
    HuffmanEntry { code: 0x1e, len: 6 },        // 56 '8'
    HuffmanEntry { code: 0x1f, len: 6 },        // 57 '9'
    HuffmanEntry { code: 0x5c, len: 7 },        // 58 ':'
    HuffmanEntry { code: 0xfb, len: 8 },        // 59 ';'
    HuffmanEntry { code: 0x7ffc, len: 15 },     // 60 '<'
    HuffmanEntry { code: 0x20, len: 6 },        // 61 '='
    HuffmanEntry { code: 0xffb, len: 12 },      // 62 '>'
    HuffmanEntry { code: 0x3fc, len: 10 },      // 63 '?'
    HuffmanEntry { code: 0x1ffa, len: 13 },     // 64 '@'
    HuffmanEntry { code: 0x21, len: 6 },        // 65 'A'
    HuffmanEntry { code: 0x5d, len: 7 },        // 66 'B'
    HuffmanEntry { code: 0x5e, len: 7 },        // 67 'C'
    HuffmanEntry { code: 0x5f, len: 7 },        // 68 'D'
    HuffmanEntry { code: 0x60, len: 7 },        // 69 'E'
    HuffmanEntry { code: 0x61, len: 7 },        // 70 'F'
    HuffmanEntry { code: 0x62, len: 7 },        // 71 'G'
    HuffmanEntry { code: 0x63, len: 7 },        // 72 'H'
    HuffmanEntry { code: 0x64, len: 7 },        // 73 'I'
    HuffmanEntry { code: 0x65, len: 7 },        // 74 'J'
    HuffmanEntry { code: 0x66, len: 7 },        // 75 'K'
    HuffmanEntry { code: 0x67, len: 7 },        // 76 'L'
    HuffmanEntry { code: 0x68, len: 7 },        // 77 'M'
    HuffmanEntry { code: 0x69, len: 7 },        // 78 'N'
    HuffmanEntry { code: 0x6a, len: 7 },        // 79 'O'
    HuffmanEntry { code: 0x6b, len: 7 },        // 80 'P'
    HuffmanEntry { code: 0x6c, len: 7 },        // 81 'Q'
    HuffmanEntry { code: 0x6d, len: 7 },        // 82 'R'
    HuffmanEntry { code: 0x6e, len: 7 },        // 83 'S'
    HuffmanEntry { code: 0x6f, len: 7 },        // 84 'T'
    HuffmanEntry { code: 0x70, len: 7 },        // 85 'U'
    HuffmanEntry { code: 0x71, len: 7 },        // 86 'V'
    HuffmanEntry { code: 0x72, len: 7 },        // 87 'W'
    HuffmanEntry { code: 0xfc, len: 8 },        // 88 'X'
    HuffmanEntry { code: 0x73, len: 7 },        // 89 'Y'
    HuffmanEntry { code: 0xfd, len: 8 },        // 90 'Z'
    HuffmanEntry { code: 0x1ffb, len: 13 },     // 91 '['
    HuffmanEntry { code: 0x7fff0, len: 19 },    // 92 '\\'
    HuffmanEntry { code: 0x1ffc, len: 13 },     // 93 ']'
    HuffmanEntry { code: 0x3ffc, len: 14 },     // 94 '^'
    HuffmanEntry { code: 0x22, len: 6 },        // 95 '_'
    HuffmanEntry { code: 0x7ffd, len: 15 },     // 96 '`'
    HuffmanEntry { code: 0x3, len: 5 },         // 97 'a'
    HuffmanEntry { code: 0x23, len: 6 },        // 98 'b'
    HuffmanEntry { code: 0x4, len: 5 },         // 99 'c'
    HuffmanEntry { code: 0x24, len: 6 },        // 100 'd'
    HuffmanEntry { code: 0x5, len: 5 },         // 101 'e'
    HuffmanEntry { code: 0x25, len: 6 },        // 102 'f'
    HuffmanEntry { code: 0x26, len: 6 },        // 103 'g'
    HuffmanEntry { code: 0x27, len: 6 },        // 104 'h'
    HuffmanEntry { code: 0x6, len: 5 },         // 105 'i'
    HuffmanEntry { code: 0x74, len: 7 },        // 106 'j'
    HuffmanEntry { code: 0x75, len: 7 },        // 107 'k'
    HuffmanEntry { code: 0x28, len: 6 },        // 108 'l'
    HuffmanEntry { code: 0x29, len: 6 },        // 109 'm'
    HuffmanEntry { code: 0x2a, len: 6 },        // 110 'n'
    HuffmanEntry { code: 0x7, len: 5 },         // 111 'o'
    HuffmanEntry { code: 0x2b, len: 6 },        // 112 'p'
    HuffmanEntry { code: 0x76, len: 7 },        // 113 'q'
    HuffmanEntry { code: 0x2c, len: 6 },        // 114 'r'
    HuffmanEntry { code: 0x8, len: 5 },         // 115 's'
    HuffmanEntry { code: 0x9, len: 5 },         // 116 't'
    HuffmanEntry { code: 0x2d, len: 6 },        // 117 'u'
    HuffmanEntry { code: 0x77, len: 7 },        // 118 'v'
    HuffmanEntry { code: 0x78, len: 7 },        // 119 'w'
    HuffmanEntry { code: 0x79, len: 7 },        // 120 'x'
    HuffmanEntry { code: 0x7a, len: 7 },        // 121 'y'
    HuffmanEntry { code: 0x7b, len: 7 },        // 122 'z'
    HuffmanEntry { code: 0x7ffe, len: 15 },     // 123 '{'
    HuffmanEntry { code: 0x7fc, len: 11 },      // 124 '|'
    HuffmanEntry { code: 0x3ffd, len: 14 },     // 125 '}'
    HuffmanEntry { code: 0x1ffd, len: 13 },     // 126 '~'
    HuffmanEntry { code: 0xffffffc, len: 28 },  // 127
    HuffmanEntry { code: 0xfffe6, len: 20 },    // 128
    HuffmanEntry { code: 0x3fffd2, len: 22 },   // 129
    HuffmanEntry { code: 0xfffe7, len: 20 },    // 130
    HuffmanEntry { code: 0xfffe8, len: 20 },    // 131
    HuffmanEntry { code: 0x3fffd3, len: 22 },   // 132
    HuffmanEntry { code: 0x3fffd4, len: 22 },   // 133
    HuffmanEntry { code: 0x3fffd5, len: 22 },   // 134
    HuffmanEntry { code: 0x7fffd9, len: 23 },   // 135
    HuffmanEntry { code: 0x3fffd6, len: 22 },   // 136
    HuffmanEntry { code: 0x7fffda, len: 23 },   // 137
    HuffmanEntry { code: 0x7fffdb, len: 23 },   // 138
    HuffmanEntry { code: 0x7fffdc, len: 23 },   // 139
    HuffmanEntry { code: 0x7fffdd, len: 23 },   // 140
    HuffmanEntry { code: 0x7fffde, len: 23 },   // 141
    HuffmanEntry { code: 0xffffeb, len: 24 },   // 142
    HuffmanEntry { code: 0x7fffdf, len: 23 },   // 143
    HuffmanEntry { code: 0xffffec, len: 24 },   // 144
    HuffmanEntry { code: 0xffffed, len: 24 },   // 145
    HuffmanEntry { code: 0x3fffd7, len: 22 },   // 146
    HuffmanEntry { code: 0x7fffe0, len: 23 },   // 147
    HuffmanEntry { code: 0xffffee, len: 24 },   // 148
    HuffmanEntry { code: 0x7fffe1, len: 23 },   // 149
    HuffmanEntry { code: 0x7fffe2, len: 23 },   // 150
    HuffmanEntry { code: 0x7fffe3, len: 23 },   // 151
    HuffmanEntry { code: 0x7fffe4, len: 23 },   // 152
    HuffmanEntry { code: 0x1fffdc, len: 21 },   // 153
    HuffmanEntry { code: 0x3fffd8, len: 22 },   // 154
    HuffmanEntry { code: 0x7fffe5, len: 23 },   // 155
    HuffmanEntry { code: 0x3fffd9, len: 22 },   // 156
    HuffmanEntry { code: 0x7fffe6, len: 23 },   // 157
    HuffmanEntry { code: 0x7fffe7, len: 23 },   // 158
    HuffmanEntry { code: 0xffffef, len: 24 },   // 159
    HuffmanEntry { code: 0x3fffda, len: 22 },   // 160
    HuffmanEntry { code: 0x1fffdd, len: 21 },   // 161
    HuffmanEntry { code: 0xfffe9, len: 20 },    // 162
    HuffmanEntry { code: 0x3fffdb, len: 22 },   // 163
    HuffmanEntry { code: 0x3fffdc, len: 22 },   // 164
    HuffmanEntry { code: 0x7fffe8, len: 23 },   // 165
    HuffmanEntry { code: 0x7fffe9, len: 23 },   // 166
    HuffmanEntry { code: 0x1fffde, len: 21 },   // 167
    HuffmanEntry { code: 0x7fffea, len: 23 },   // 168
    HuffmanEntry { code: 0x3fffdd, len: 22 },   // 169
    HuffmanEntry { code: 0x3fffde, len: 22 },   // 170
    HuffmanEntry { code: 0xfffff0, len: 24 },   // 171
    HuffmanEntry { code: 0x1fffdf, len: 21 },   // 172
    HuffmanEntry { code: 0x3fffdf, len: 22 },   // 173
    HuffmanEntry { code: 0x7fffeb, len: 23 },   // 174
    HuffmanEntry { code: 0x7fffec, len: 23 },   // 175
    HuffmanEntry { code: 0x1fffe0, len: 21 },   // 176
    HuffmanEntry { code: 0x1fffe1, len: 21 },   // 177
    HuffmanEntry { code: 0x3fffe0, len: 22 },   // 178
    HuffmanEntry { code: 0x1fffe2, len: 21 },   // 179
    HuffmanEntry { code: 0x7fffed, len: 23 },   // 180
    HuffmanEntry { code: 0x3fffe1, len: 22 },   // 181
    HuffmanEntry { code: 0x7fffee, len: 23 },   // 182
    HuffmanEntry { code: 0x7fffef, len: 23 },   // 183
    HuffmanEntry { code: 0xfffea, len: 20 },    // 184
    HuffmanEntry { code: 0x3fffe2, len: 22 },   // 185
    HuffmanEntry { code: 0x3fffe3, len: 22 },   // 186
    HuffmanEntry { code: 0x3fffe4, len: 22 },   // 187
    HuffmanEntry { code: 0x7ffff0, len: 23 },   // 188
    HuffmanEntry { code: 0x3fffe5, len: 22 },   // 189
    HuffmanEntry { code: 0x3fffe6, len: 22 },   // 190
    HuffmanEntry { code: 0x7ffff1, len: 23 },   // 191
    HuffmanEntry { code: 0x3ffffe0, len: 26 },  // 192
    HuffmanEntry { code: 0x3ffffe1, len: 26 },  // 193
    HuffmanEntry { code: 0xfffeb, len: 20 },    // 194
    HuffmanEntry { code: 0x7fff1, len: 19 },    // 195
    HuffmanEntry { code: 0x3fffe7, len: 22 },   // 196
    HuffmanEntry { code: 0x7ffff2, len: 23 },   // 197
    HuffmanEntry { code: 0x3fffe8, len: 22 },   // 198
    HuffmanEntry { code: 0x1ffffec, len: 25 },  // 199
    HuffmanEntry { code: 0x3ffffe2, len: 26 },  // 200
    HuffmanEntry { code: 0x3ffffe3, len: 26 },  // 201
    HuffmanEntry { code: 0x3ffffe4, len: 26 },  // 202
    HuffmanEntry { code: 0x7ffffde, len: 27 },  // 203
    HuffmanEntry { code: 0x7ffffdf, len: 27 },  // 204
    HuffmanEntry { code: 0x3ffffe5, len: 26 },  // 205
    HuffmanEntry { code: 0xfffff1, len: 24 },   // 206
    HuffmanEntry { code: 0x1ffffed, len: 25 },  // 207
    HuffmanEntry { code: 0x7fff2, len: 19 },    // 208
    HuffmanEntry { code: 0x1fffe3, len: 21 },   // 209
    HuffmanEntry { code: 0x3ffffe6, len: 26 },  // 210
    HuffmanEntry { code: 0x7ffffe0, len: 27 },  // 211
    HuffmanEntry { code: 0x7ffffe1, len: 27 },  // 212
    HuffmanEntry { code: 0x3ffffe7, len: 26 },  // 213
    HuffmanEntry { code: 0x7ffffe2, len: 27 },  // 214
    HuffmanEntry { code: 0xfffff2, len: 24 },   // 215
    HuffmanEntry { code: 0x1fffe4, len: 21 },   // 216
    HuffmanEntry { code: 0x1fffe5, len: 21 },   // 217
    HuffmanEntry { code: 0x3ffffe8, len: 26 },  // 218
    HuffmanEntry { code: 0x3ffffe9, len: 26 },  // 219
    HuffmanEntry { code: 0xffffffd, len: 28 },  // 220
    HuffmanEntry { code: 0x7ffffe3, len: 27 },  // 221
    HuffmanEntry { code: 0x7ffffe4, len: 27 },  // 222
    HuffmanEntry { code: 0x7ffffe5, len: 27 },  // 223
    HuffmanEntry { code: 0xfffec, len: 20 },    // 224
    HuffmanEntry { code: 0xfffff3, len: 24 },   // 225
    HuffmanEntry { code: 0xfffed, len: 20 },    // 226
    HuffmanEntry { code: 0x1fffe6, len: 21 },   // 227
    HuffmanEntry { code: 0x3fffe9, len: 22 },   // 228
    HuffmanEntry { code: 0x1fffe7, len: 21 },   // 229
    HuffmanEntry { code: 0x1fffe8, len: 21 },   // 230
    HuffmanEntry { code: 0x7ffff3, len: 23 },   // 231
    HuffmanEntry { code: 0x3fffea, len: 22 },   // 232
    HuffmanEntry { code: 0x3fffeb, len: 22 },   // 233
    HuffmanEntry { code: 0x1ffffee, len: 25 },  // 234
    HuffmanEntry { code: 0x1ffffef, len: 25 },  // 235
    HuffmanEntry { code: 0xfffff4, len: 24 },   // 236
    HuffmanEntry { code: 0xfffff5, len: 24 },   // 237
    HuffmanEntry { code: 0x3ffffea, len: 26 },  // 238
    HuffmanEntry { code: 0x7ffff4, len: 23 },   // 239
    HuffmanEntry { code: 0x3ffffeb, len: 26 },  // 240
    HuffmanEntry { code: 0x7ffffe6, len: 27 },  // 241
    HuffmanEntry { code: 0x3ffffec, len: 26 },  // 242
    HuffmanEntry { code: 0x3ffffed, len: 26 },  // 243
    HuffmanEntry { code: 0x7ffffe7, len: 27 },  // 244
    HuffmanEntry { code: 0x7ffffe8, len: 27 },  // 245
    HuffmanEntry { code: 0x7ffffe9, len: 27 },  // 246
    HuffmanEntry { code: 0x7ffffea, len: 27 },  // 247
    HuffmanEntry { code: 0x7ffffeb, len: 27 },  // 248
    HuffmanEntry { code: 0xffffffe, len: 28 },  // 249
    HuffmanEntry { code: 0x7ffffec, len: 27 },  // 250
    HuffmanEntry { code: 0x7ffffed, len: 27 },  // 251
    HuffmanEntry { code: 0x7ffffee, len: 27 },  // 252
    HuffmanEntry { code: 0x7ffffef, len: 27 },  // 253
    HuffmanEntry { code: 0x7fffff0, len: 27 },  // 254
    HuffmanEntry { code: 0x3ffffee, len: 26 },  // 255
    HuffmanEntry { code: 0x3fffffff, len: 30 }, // 256 EOS
]
