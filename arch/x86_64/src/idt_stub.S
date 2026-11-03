/* File: arch/x86_64/src/idt_stub.S */
/* Purpose: The one entry point every gate's handler goes through, and the
   gates themselves.

   ## Why one stub per vector and one common path

   A gate names an address, and the CPU does not tell a handler which vector it
   arrived on.  It also pushes an error code for some vectors and not others,
   so a common path that assumed either shape would read the frame from the
   wrong words.

   So each gate points at a stub that pushes its own vector number and jumps to
   the common path.  The stubs for vectors without an error code also push a
   zero where one would be, so the frame the common path sees has the same
   shape for every vector — which is what lets the Rust side be one function
   rather than a macro that generates a signature per vector.

   ## The frame

   After a stub, the stack holds:

       [rsp + 0]  error code     (pushed by the CPU, or by the stub as a zero)
       [rsp + 8]  vector number  (pushed by the stub)
       [rsp + 16] rip            (pushed by the CPU)
       [rsp + 24] cs
       [rsp + 32] rflags
       [rsp + 40] rsp            (the interrupted one)
       [rsp + 48] ss

   The stubs push the vector *last* because the Rust side reads the frame from
   the lowest address up, and a structure whose field order disagreed with the
   pushes would read a handler's arguments from the wrong words.

   ## Why the stubs are written out

   The assembler's macro syntax is not portable between GNU as and LLVM's
   integrated assembler — `\param` and a `$` before an immediate are GNU's, and
   this file is assembled by LLVM's.  A generator would be one more thing to
   keep in step; the file is generated once and read as what it is. */

.text
.code64

/* The common path: save what the calling convention lets a handler clobber,
   pass the frame, call Rust, restore, and return through `iretq`. */
common_stub:
    /* The caller-saved registers: an `extern "C"` function may overwrite all of
       them, so a stub that did not save them would hand an interrupted function
       back a machine state it does not expect. */
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11

    /* The frame starts above the nine pushes. */
    lea rdi, [rsp + 72]
    call x86_64_interrupt_dispatch

    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax

    /* Drop the vector number and the error code. */
    add rsp, 16
    iretq

/* Vector 0: no error code, so the stub pushes a zero in its place. */
.global stub_0
stub_0:
    push 0
    push 0
    jmp common_stub

/* Vector 1: no error code, so the stub pushes a zero in its place. */
.global stub_1
stub_1:
    push 0
    push 1
    jmp common_stub

/* Vector 2: no error code, so the stub pushes a zero in its place. */
.global stub_2
stub_2:
    push 0
    push 2
    jmp common_stub

/* Vector 3: no error code, so the stub pushes a zero in its place. */
.global stub_3
stub_3:
    push 0
    push 3
    jmp common_stub

/* Vector 4: no error code, so the stub pushes a zero in its place. */
.global stub_4
stub_4:
    push 0
    push 4
    jmp common_stub

/* Vector 5: no error code, so the stub pushes a zero in its place. */
.global stub_5
stub_5:
    push 0
    push 5
    jmp common_stub

/* Vector 6: no error code, so the stub pushes a zero in its place. */
.global stub_6
stub_6:
    push 0
    push 6
    jmp common_stub

/* Vector 7: no error code, so the stub pushes a zero in its place. */
.global stub_7
stub_7:
    push 0
    push 7
    jmp common_stub

/* Vector 8: the CPU pushes an error code, so only the vector goes above it. */
.global stub_8
stub_8:
    push 8
    jmp common_stub

/* Vector 9: no error code, so the stub pushes a zero in its place. */
.global stub_9
stub_9:
    push 0
    push 9
    jmp common_stub

/* Vector 10: the CPU pushes an error code, so only the vector goes above it. */
.global stub_10
stub_10:
    push 10
    jmp common_stub

/* Vector 11: the CPU pushes an error code, so only the vector goes above it. */
.global stub_11
stub_11:
    push 11
    jmp common_stub

/* Vector 12: the CPU pushes an error code, so only the vector goes above it. */
.global stub_12
stub_12:
    push 12
    jmp common_stub

/* Vector 13: the CPU pushes an error code, so only the vector goes above it. */
.global stub_13
stub_13:
    push 13
    jmp common_stub

/* Vector 14: the CPU pushes an error code, so only the vector goes above it. */
.global stub_14
stub_14:
    push 14
    jmp common_stub

/* Vector 15: no error code, so the stub pushes a zero in its place. */
.global stub_15
stub_15:
    push 0
    push 15
    jmp common_stub

/* Vector 16: no error code, so the stub pushes a zero in its place. */
.global stub_16
stub_16:
    push 0
    push 16
    jmp common_stub

/* Vector 17: the CPU pushes an error code, so only the vector goes above it. */
.global stub_17
stub_17:
    push 17
    jmp common_stub

/* Vector 18: no error code, so the stub pushes a zero in its place. */
.global stub_18
stub_18:
    push 0
    push 18
    jmp common_stub

/* Vector 19: no error code, so the stub pushes a zero in its place. */
.global stub_19
stub_19:
    push 0
    push 19
    jmp common_stub

/* Vector 20: no error code, so the stub pushes a zero in its place. */
.global stub_20
stub_20:
    push 0
    push 20
    jmp common_stub

/* Vector 21: the CPU pushes an error code, so only the vector goes above it. */
.global stub_21
stub_21:
    push 21
    jmp common_stub

/* Vector 22: no error code, so the stub pushes a zero in its place. */
.global stub_22
stub_22:
    push 0
    push 22
    jmp common_stub

/* Vector 23: no error code, so the stub pushes a zero in its place. */
.global stub_23
stub_23:
    push 0
    push 23
    jmp common_stub

/* Vector 24: no error code, so the stub pushes a zero in its place. */
.global stub_24
stub_24:
    push 0
    push 24
    jmp common_stub

/* Vector 25: no error code, so the stub pushes a zero in its place. */
.global stub_25
stub_25:
    push 0
    push 25
    jmp common_stub

/* Vector 26: no error code, so the stub pushes a zero in its place. */
.global stub_26
stub_26:
    push 0
    push 26
    jmp common_stub

/* Vector 27: no error code, so the stub pushes a zero in its place. */
.global stub_27
stub_27:
    push 0
    push 27
    jmp common_stub

/* Vector 28: no error code, so the stub pushes a zero in its place. */
.global stub_28
stub_28:
    push 0
    push 28
    jmp common_stub

/* Vector 29: no error code, so the stub pushes a zero in its place. */
.global stub_29
stub_29:
    push 0
    push 29
    jmp common_stub

/* Vector 30: the CPU pushes an error code, so only the vector goes above it. */
.global stub_30
stub_30:
    push 30
    jmp common_stub

/* Vector 31: no error code, so the stub pushes a zero in its place. */
.global stub_31
stub_31:
    push 0
    push 31
    jmp common_stub

.global stub_32
stub_32:
    push 0
    push 32
    jmp common_stub

.global stub_33
stub_33:
    push 0
    push 33
    jmp common_stub

.global stub_34
stub_34:
    push 0
    push 34
    jmp common_stub

.global stub_35
stub_35:
    push 0
    push 35
    jmp common_stub

.global stub_36
stub_36:
    push 0
    push 36
    jmp common_stub

.global stub_37
stub_37:
    push 0
    push 37
    jmp common_stub

.global stub_38
stub_38:
    push 0
    push 38
    jmp common_stub

.global stub_39
stub_39:
    push 0
    push 39
    jmp common_stub

.global stub_40
stub_40:
    push 0
    push 40
    jmp common_stub

.global stub_41
stub_41:
    push 0
    push 41
    jmp common_stub

.global stub_42
stub_42:
    push 0
    push 42
    jmp common_stub

.global stub_43
stub_43:
    push 0
    push 43
    jmp common_stub

.global stub_44
stub_44:
    push 0
    push 44
    jmp common_stub

.global stub_45
stub_45:
    push 0
    push 45
    jmp common_stub

.global stub_46
stub_46:
    push 0
    push 46
    jmp common_stub

.global stub_47
stub_47:
    push 0
    push 47
    jmp common_stub

.global stub_48
stub_48:
    push 0
    push 48
    jmp common_stub

.global stub_49
stub_49:
    push 0
    push 49
    jmp common_stub

.global stub_50
stub_50:
    push 0
    push 50
    jmp common_stub

.global stub_51
stub_51:
    push 0
    push 51
    jmp common_stub

.global stub_52
stub_52:
    push 0
    push 52
    jmp common_stub

.global stub_53
stub_53:
    push 0
    push 53
    jmp common_stub

.global stub_54
stub_54:
    push 0
    push 54
    jmp common_stub

.global stub_55
stub_55:
    push 0
    push 55
    jmp common_stub

.global stub_56
stub_56:
    push 0
    push 56
    jmp common_stub

.global stub_57
stub_57:
    push 0
    push 57
    jmp common_stub

.global stub_58
stub_58:
    push 0
    push 58
    jmp common_stub

.global stub_59
stub_59:
    push 0
    push 59
    jmp common_stub

.global stub_60
stub_60:
    push 0
    push 60
    jmp common_stub

.global stub_61
stub_61:
    push 0
    push 61
    jmp common_stub

.global stub_62
stub_62:
    push 0
    push 62
    jmp common_stub

.global stub_63
stub_63:
    push 0
    push 63
    jmp common_stub

.global stub_64
stub_64:
    push 0
    push 64
    jmp common_stub

.global stub_65
stub_65:
    push 0
    push 65
    jmp common_stub

.global stub_66
stub_66:
    push 0
    push 66
    jmp common_stub

.global stub_67
stub_67:
    push 0
    push 67
    jmp common_stub

.global stub_68
stub_68:
    push 0
    push 68
    jmp common_stub

.global stub_69
stub_69:
    push 0
    push 69
    jmp common_stub

.global stub_70
stub_70:
    push 0
    push 70
    jmp common_stub

.global stub_71
stub_71:
    push 0
    push 71
    jmp common_stub

.global stub_72
stub_72:
    push 0
    push 72
    jmp common_stub

.global stub_73
stub_73:
    push 0
    push 73
    jmp common_stub

.global stub_74
stub_74:
    push 0
    push 74
    jmp common_stub

.global stub_75
stub_75:
    push 0
    push 75
    jmp common_stub

.global stub_76
stub_76:
    push 0
    push 76
    jmp common_stub

.global stub_77
stub_77:
    push 0
    push 77
    jmp common_stub

.global stub_78
stub_78:
    push 0
    push 78
    jmp common_stub

.global stub_79
stub_79:
    push 0
    push 79
    jmp common_stub

.global stub_80
stub_80:
    push 0
    push 80
    jmp common_stub

.global stub_81
stub_81:
    push 0
    push 81
    jmp common_stub

.global stub_82
stub_82:
    push 0
    push 82
    jmp common_stub

.global stub_83
stub_83:
    push 0
    push 83
    jmp common_stub

.global stub_84
stub_84:
    push 0
    push 84
    jmp common_stub

.global stub_85
stub_85:
    push 0
    push 85
    jmp common_stub

.global stub_86
stub_86:
    push 0
    push 86
    jmp common_stub

.global stub_87
stub_87:
    push 0
    push 87
    jmp common_stub

.global stub_88
stub_88:
    push 0
    push 88
    jmp common_stub

.global stub_89
stub_89:
    push 0
    push 89
    jmp common_stub

.global stub_90
stub_90:
    push 0
    push 90
    jmp common_stub

.global stub_91
stub_91:
    push 0
    push 91
    jmp common_stub

.global stub_92
stub_92:
    push 0
    push 92
    jmp common_stub

.global stub_93
stub_93:
    push 0
    push 93
    jmp common_stub

.global stub_94
stub_94:
    push 0
    push 94
    jmp common_stub

.global stub_95
stub_95:
    push 0
    push 95
    jmp common_stub

.global stub_96
stub_96:
    push 0
    push 96
    jmp common_stub

.global stub_97
stub_97:
    push 0
    push 97
    jmp common_stub

.global stub_98
stub_98:
    push 0
    push 98
    jmp common_stub

.global stub_99
stub_99:
    push 0
    push 99
    jmp common_stub

.global stub_100
stub_100:
    push 0
    push 100
    jmp common_stub

.global stub_101
stub_101:
    push 0
    push 101
    jmp common_stub

.global stub_102
stub_102:
    push 0
    push 102
    jmp common_stub

.global stub_103
stub_103:
    push 0
    push 103
    jmp common_stub

.global stub_104
stub_104:
    push 0
    push 104
    jmp common_stub

.global stub_105
stub_105:
    push 0
    push 105
    jmp common_stub

.global stub_106
stub_106:
    push 0
    push 106
    jmp common_stub

.global stub_107
stub_107:
    push 0
    push 107
    jmp common_stub

.global stub_108
stub_108:
    push 0
    push 108
    jmp common_stub

.global stub_109
stub_109:
    push 0
    push 109
    jmp common_stub

.global stub_110
stub_110:
    push 0
    push 110
    jmp common_stub

.global stub_111
stub_111:
    push 0
    push 111
    jmp common_stub

.global stub_112
stub_112:
    push 0
    push 112
    jmp common_stub

.global stub_113
stub_113:
    push 0
    push 113
    jmp common_stub

.global stub_114
stub_114:
    push 0
    push 114
    jmp common_stub

.global stub_115
stub_115:
    push 0
    push 115
    jmp common_stub

.global stub_116
stub_116:
    push 0
    push 116
    jmp common_stub

.global stub_117
stub_117:
    push 0
    push 117
    jmp common_stub

.global stub_118
stub_118:
    push 0
    push 118
    jmp common_stub

.global stub_119
stub_119:
    push 0
    push 119
    jmp common_stub

.global stub_120
stub_120:
    push 0
    push 120
    jmp common_stub

.global stub_121
stub_121:
    push 0
    push 121
    jmp common_stub

.global stub_122
stub_122:
    push 0
    push 122
    jmp common_stub

.global stub_123
stub_123:
    push 0
    push 123
    jmp common_stub

.global stub_124
stub_124:
    push 0
    push 124
    jmp common_stub

.global stub_125
stub_125:
    push 0
    push 125
    jmp common_stub

.global stub_126
stub_126:
    push 0
    push 126
    jmp common_stub

.global stub_127
stub_127:
    push 0
    push 127
    jmp common_stub

.global stub_128
stub_128:
    push 0
    push 128
    jmp common_stub

.global stub_129
stub_129:
    push 0
    push 129
    jmp common_stub

.global stub_130
stub_130:
    push 0
    push 130
    jmp common_stub

.global stub_131
stub_131:
    push 0
    push 131
    jmp common_stub

.global stub_132
stub_132:
    push 0
    push 132
    jmp common_stub

.global stub_133
stub_133:
    push 0
    push 133
    jmp common_stub

.global stub_134
stub_134:
    push 0
    push 134
    jmp common_stub

.global stub_135
stub_135:
    push 0
    push 135
    jmp common_stub

.global stub_136
stub_136:
    push 0
    push 136
    jmp common_stub

.global stub_137
stub_137:
    push 0
    push 137
    jmp common_stub

.global stub_138
stub_138:
    push 0
    push 138
    jmp common_stub

.global stub_139
stub_139:
    push 0
    push 139
    jmp common_stub

.global stub_140
stub_140:
    push 0
    push 140
    jmp common_stub

.global stub_141
stub_141:
    push 0
    push 141
    jmp common_stub

.global stub_142
stub_142:
    push 0
    push 142
    jmp common_stub

.global stub_143
stub_143:
    push 0
    push 143
    jmp common_stub

.global stub_144
stub_144:
    push 0
    push 144
    jmp common_stub

.global stub_145
stub_145:
    push 0
    push 145
    jmp common_stub

.global stub_146
stub_146:
    push 0
    push 146
    jmp common_stub

.global stub_147
stub_147:
    push 0
    push 147
    jmp common_stub

.global stub_148
stub_148:
    push 0
    push 148
    jmp common_stub

.global stub_149
stub_149:
    push 0
    push 149
    jmp common_stub

.global stub_150
stub_150:
    push 0
    push 150
    jmp common_stub

.global stub_151
stub_151:
    push 0
    push 151
    jmp common_stub

.global stub_152
stub_152:
    push 0
    push 152
    jmp common_stub

.global stub_153
stub_153:
    push 0
    push 153
    jmp common_stub

.global stub_154
stub_154:
    push 0
    push 154
    jmp common_stub

.global stub_155
stub_155:
    push 0
    push 155
    jmp common_stub

.global stub_156
stub_156:
    push 0
    push 156
    jmp common_stub

.global stub_157
stub_157:
    push 0
    push 157
    jmp common_stub

.global stub_158
stub_158:
    push 0
    push 158
    jmp common_stub

.global stub_159
stub_159:
    push 0
    push 159
    jmp common_stub

.global stub_160
stub_160:
    push 0
    push 160
    jmp common_stub

.global stub_161
stub_161:
    push 0
    push 161
    jmp common_stub

.global stub_162
stub_162:
    push 0
    push 162
    jmp common_stub

.global stub_163
stub_163:
    push 0
    push 163
    jmp common_stub

.global stub_164
stub_164:
    push 0
    push 164
    jmp common_stub

.global stub_165
stub_165:
    push 0
    push 165
    jmp common_stub

.global stub_166
stub_166:
    push 0
    push 166
    jmp common_stub

.global stub_167
stub_167:
    push 0
    push 167
    jmp common_stub

.global stub_168
stub_168:
    push 0
    push 168
    jmp common_stub

.global stub_169
stub_169:
    push 0
    push 169
    jmp common_stub

.global stub_170
stub_170:
    push 0
    push 170
    jmp common_stub

.global stub_171
stub_171:
    push 0
    push 171
    jmp common_stub

.global stub_172
stub_172:
    push 0
    push 172
    jmp common_stub

.global stub_173
stub_173:
    push 0
    push 173
    jmp common_stub

.global stub_174
stub_174:
    push 0
    push 174
    jmp common_stub

.global stub_175
stub_175:
    push 0
    push 175
    jmp common_stub

.global stub_176
stub_176:
    push 0
    push 176
    jmp common_stub

.global stub_177
stub_177:
    push 0
    push 177
    jmp common_stub

.global stub_178
stub_178:
    push 0
    push 178
    jmp common_stub

.global stub_179
stub_179:
    push 0
    push 179
    jmp common_stub

.global stub_180
stub_180:
    push 0
    push 180
    jmp common_stub

.global stub_181
stub_181:
    push 0
    push 181
    jmp common_stub

.global stub_182
stub_182:
    push 0
    push 182
    jmp common_stub

.global stub_183
stub_183:
    push 0
    push 183
    jmp common_stub

.global stub_184
stub_184:
    push 0
    push 184
    jmp common_stub

.global stub_185
stub_185:
    push 0
    push 185
    jmp common_stub

.global stub_186
stub_186:
    push 0
    push 186
    jmp common_stub

.global stub_187
stub_187:
    push 0
    push 187
    jmp common_stub

.global stub_188
stub_188:
    push 0
    push 188
    jmp common_stub

.global stub_189
stub_189:
    push 0
    push 189
    jmp common_stub

.global stub_190
stub_190:
    push 0
    push 190
    jmp common_stub

.global stub_191
stub_191:
    push 0
    push 191
    jmp common_stub

.global stub_192
stub_192:
    push 0
    push 192
    jmp common_stub

.global stub_193
stub_193:
    push 0
    push 193
    jmp common_stub

.global stub_194
stub_194:
    push 0
    push 194
    jmp common_stub

.global stub_195
stub_195:
    push 0
    push 195
    jmp common_stub

.global stub_196
stub_196:
    push 0
    push 196
    jmp common_stub

.global stub_197
stub_197:
    push 0
    push 197
    jmp common_stub

.global stub_198
stub_198:
    push 0
    push 198
    jmp common_stub

.global stub_199
stub_199:
    push 0
    push 199
    jmp common_stub

.global stub_200
stub_200:
    push 0
    push 200
    jmp common_stub

.global stub_201
stub_201:
    push 0
    push 201
    jmp common_stub

.global stub_202
stub_202:
    push 0
    push 202
    jmp common_stub

.global stub_203
stub_203:
    push 0
    push 203
    jmp common_stub

.global stub_204
stub_204:
    push 0
    push 204
    jmp common_stub

.global stub_205
stub_205:
    push 0
    push 205
    jmp common_stub

.global stub_206
stub_206:
    push 0
    push 206
    jmp common_stub

.global stub_207
stub_207:
    push 0
    push 207
    jmp common_stub

.global stub_208
stub_208:
    push 0
    push 208
    jmp common_stub

.global stub_209
stub_209:
    push 0
    push 209
    jmp common_stub

.global stub_210
stub_210:
    push 0
    push 210
    jmp common_stub

.global stub_211
stub_211:
    push 0
    push 211
    jmp common_stub

.global stub_212
stub_212:
    push 0
    push 212
    jmp common_stub

.global stub_213
stub_213:
    push 0
    push 213
    jmp common_stub

.global stub_214
stub_214:
    push 0
    push 214
    jmp common_stub

.global stub_215
stub_215:
    push 0
    push 215
    jmp common_stub

.global stub_216
stub_216:
    push 0
    push 216
    jmp common_stub

.global stub_217
stub_217:
    push 0
    push 217
    jmp common_stub

.global stub_218
stub_218:
    push 0
    push 218
    jmp common_stub

.global stub_219
stub_219:
    push 0
    push 219
    jmp common_stub

.global stub_220
stub_220:
    push 0
    push 220
    jmp common_stub

.global stub_221
stub_221:
    push 0
    push 221
    jmp common_stub

.global stub_222
stub_222:
    push 0
    push 222
    jmp common_stub

.global stub_223
stub_223:
    push 0
    push 223
    jmp common_stub

.global stub_224
stub_224:
    push 0
    push 224
    jmp common_stub

.global stub_225
stub_225:
    push 0
    push 225
    jmp common_stub

.global stub_226
stub_226:
    push 0
    push 226
    jmp common_stub

.global stub_227
stub_227:
    push 0
    push 227
    jmp common_stub

.global stub_228
stub_228:
    push 0
    push 228
    jmp common_stub

.global stub_229
stub_229:
    push 0
    push 229
    jmp common_stub

.global stub_230
stub_230:
    push 0
    push 230
    jmp common_stub

.global stub_231
stub_231:
    push 0
    push 231
    jmp common_stub

.global stub_232
stub_232:
    push 0
    push 232
    jmp common_stub

.global stub_233
stub_233:
    push 0
    push 233
    jmp common_stub

.global stub_234
stub_234:
    push 0
    push 234
    jmp common_stub

.global stub_235
stub_235:
    push 0
    push 235
    jmp common_stub

.global stub_236
stub_236:
    push 0
    push 236
    jmp common_stub

.global stub_237
stub_237:
    push 0
    push 237
    jmp common_stub

.global stub_238
stub_238:
    push 0
    push 238
    jmp common_stub

.global stub_239
stub_239:
    push 0
    push 239
    jmp common_stub

.global stub_240
stub_240:
    push 0
    push 240
    jmp common_stub

.global stub_241
stub_241:
    push 0
    push 241
    jmp common_stub

.global stub_242
stub_242:
    push 0
    push 242
    jmp common_stub

.global stub_243
stub_243:
    push 0
    push 243
    jmp common_stub

.global stub_244
stub_244:
    push 0
    push 244
    jmp common_stub

.global stub_245
stub_245:
    push 0
    push 245
    jmp common_stub

.global stub_246
stub_246:
    push 0
    push 246
    jmp common_stub

.global stub_247
stub_247:
    push 0
    push 247
    jmp common_stub

.global stub_248
stub_248:
    push 0
    push 248
    jmp common_stub

.global stub_249
stub_249:
    push 0
    push 249
    jmp common_stub

.global stub_250
stub_250:
    push 0
    push 250
    jmp common_stub

.global stub_251
stub_251:
    push 0
    push 251
    jmp common_stub

.global stub_252
stub_252:
    push 0
    push 252
    jmp common_stub

.global stub_253
stub_253:
    push 0
    push 253
    jmp common_stub

.global stub_254
stub_254:
    push 0
    push 254
    jmp common_stub

.global stub_255
stub_255:
    push 0
    push 255
    jmp common_stub

/* The table of stub addresses, in vector order, so Rust names one without
   spelling 256 symbols. */
.section .rodata
.global stub_table
.align 8
stub_table:

    .quad stub_0

    .quad stub_1

    .quad stub_2

    .quad stub_3

    .quad stub_4

    .quad stub_5

    .quad stub_6

    .quad stub_7

    .quad stub_8

    .quad stub_9

    .quad stub_10

    .quad stub_11

    .quad stub_12

    .quad stub_13

    .quad stub_14

    .quad stub_15

    .quad stub_16

    .quad stub_17

    .quad stub_18

    .quad stub_19

    .quad stub_20

    .quad stub_21

    .quad stub_22

    .quad stub_23

    .quad stub_24

    .quad stub_25

    .quad stub_26

    .quad stub_27

    .quad stub_28

    .quad stub_29

    .quad stub_30

    .quad stub_31

    .quad stub_32

    .quad stub_33

    .quad stub_34

    .quad stub_35

    .quad stub_36

    .quad stub_37

    .quad stub_38

    .quad stub_39

    .quad stub_40

    .quad stub_41

    .quad stub_42

    .quad stub_43

    .quad stub_44

    .quad stub_45

    .quad stub_46

    .quad stub_47

    .quad stub_48

    .quad stub_49

    .quad stub_50

    .quad stub_51

    .quad stub_52

    .quad stub_53

    .quad stub_54

    .quad stub_55

    .quad stub_56

    .quad stub_57

    .quad stub_58

    .quad stub_59

    .quad stub_60

    .quad stub_61

    .quad stub_62

    .quad stub_63

    .quad stub_64

    .quad stub_65

    .quad stub_66

    .quad stub_67

    .quad stub_68

    .quad stub_69

    .quad stub_70

    .quad stub_71

    .quad stub_72

    .quad stub_73

    .quad stub_74

    .quad stub_75

    .quad stub_76

    .quad stub_77

    .quad stub_78

    .quad stub_79

    .quad stub_80

    .quad stub_81

    .quad stub_82

    .quad stub_83

    .quad stub_84

    .quad stub_85

    .quad stub_86

    .quad stub_87

    .quad stub_88

    .quad stub_89

    .quad stub_90

    .quad stub_91

    .quad stub_92

    .quad stub_93

    .quad stub_94

    .quad stub_95

    .quad stub_96

    .quad stub_97

    .quad stub_98

    .quad stub_99

    .quad stub_100

    .quad stub_101

    .quad stub_102

    .quad stub_103

    .quad stub_104

    .quad stub_105

    .quad stub_106

    .quad stub_107

    .quad stub_108

    .quad stub_109

    .quad stub_110

    .quad stub_111

    .quad stub_112

    .quad stub_113

    .quad stub_114

    .quad stub_115

    .quad stub_116

    .quad stub_117

    .quad stub_118

    .quad stub_119

    .quad stub_120

    .quad stub_121

    .quad stub_122

    .quad stub_123

    .quad stub_124

    .quad stub_125

    .quad stub_126

    .quad stub_127

    .quad stub_128

    .quad stub_129

    .quad stub_130

    .quad stub_131

    .quad stub_132

    .quad stub_133

    .quad stub_134

    .quad stub_135

    .quad stub_136

    .quad stub_137

    .quad stub_138

    .quad stub_139

    .quad stub_140

    .quad stub_141

    .quad stub_142

    .quad stub_143

    .quad stub_144

    .quad stub_145

    .quad stub_146

    .quad stub_147

    .quad stub_148

    .quad stub_149

    .quad stub_150

    .quad stub_151

    .quad stub_152

    .quad stub_153

    .quad stub_154

    .quad stub_155

    .quad stub_156

    .quad stub_157

    .quad stub_158

    .quad stub_159

    .quad stub_160

    .quad stub_161

    .quad stub_162

    .quad stub_163

    .quad stub_164

    .quad stub_165

    .quad stub_166

    .quad stub_167

    .quad stub_168

    .quad stub_169

    .quad stub_170

    .quad stub_171

    .quad stub_172

    .quad stub_173

    .quad stub_174

    .quad stub_175

    .quad stub_176

    .quad stub_177

    .quad stub_178

    .quad stub_179

    .quad stub_180

    .quad stub_181

    .quad stub_182

    .quad stub_183

    .quad stub_184

    .quad stub_185

    .quad stub_186

    .quad stub_187

    .quad stub_188

    .quad stub_189

    .quad stub_190

    .quad stub_191

    .quad stub_192

    .quad stub_193

    .quad stub_194

    .quad stub_195

    .quad stub_196

    .quad stub_197

    .quad stub_198

    .quad stub_199

    .quad stub_200

    .quad stub_201

    .quad stub_202

    .quad stub_203

    .quad stub_204

    .quad stub_205

    .quad stub_206

    .quad stub_207

    .quad stub_208

    .quad stub_209

    .quad stub_210

    .quad stub_211

    .quad stub_212

    .quad stub_213

    .quad stub_214

    .quad stub_215

    .quad stub_216

    .quad stub_217

    .quad stub_218

    .quad stub_219

    .quad stub_220

    .quad stub_221

    .quad stub_222

    .quad stub_223

    .quad stub_224

    .quad stub_225

    .quad stub_226

    .quad stub_227

    .quad stub_228

    .quad stub_229

    .quad stub_230

    .quad stub_231

    .quad stub_232

    .quad stub_233

    .quad stub_234

    .quad stub_235

    .quad stub_236

    .quad stub_237

    .quad stub_238

    .quad stub_239

    .quad stub_240

    .quad stub_241

    .quad stub_242

    .quad stub_243

    .quad stub_244

    .quad stub_245

    .quad stub_246

    .quad stub_247

    .quad stub_248

    .quad stub_249

    .quad stub_250

    .quad stub_251

    .quad stub_252

    .quad stub_253

    .quad stub_254

    .quad stub_255
