let wasm;

const heap = new Array(128).fill(undefined);

heap.push(undefined, null, true, false);

function getObject(idx) { return heap[idx]; }

let heap_next = heap.length;

function dropObject(idx) {
    if (idx < 132) return;
    heap[idx] = heap_next;
    heap_next = idx;
}

function takeObject(idx) {
    const ret = getObject(idx);
    dropObject(idx);
    return ret;
}

const cachedTextDecoder = (typeof TextDecoder !== 'undefined' ? new TextDecoder('utf-8', { ignoreBOM: true, fatal: true }) : { decode: () => { throw Error('TextDecoder not available') } } );

if (typeof TextDecoder !== 'undefined') { cachedTextDecoder.decode(); };

let cachedUint8ArrayMemory0 = null;

function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function getStringFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

let WASM_VECTOR_LEN = 0;

function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1, 1) >>> 0;
    getUint8ArrayMemory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}

let cachedDataViewMemory0 = null;

function getDataViewMemory0() {
    if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer.detached === true || (cachedDataViewMemory0.buffer.detached === undefined && cachedDataViewMemory0.buffer !== wasm.memory.buffer)) {
        cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
    }
    return cachedDataViewMemory0;
}

function _assertClass(instance, klass) {
    if (!(instance instanceof klass)) {
        throw new Error(`expected instance of ${klass.name}`);
    }
    return instance.ptr;
}

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}

const cachedTextEncoder = (typeof TextEncoder !== 'undefined' ? new TextEncoder('utf-8') : { encode: () => { throw Error('TextEncoder not available') } } );

const encodeString = (typeof cachedTextEncoder.encodeInto === 'function'
    ? function (arg, view) {
    return cachedTextEncoder.encodeInto(arg, view);
}
    : function (arg, view) {
    const buf = cachedTextEncoder.encode(arg);
    view.set(buf);
    return {
        read: arg.length,
        written: buf.length
    };
});

function passStringToWasm0(arg, malloc, realloc) {

    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }

    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = encodeString(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

function addHeapObject(obj) {
    if (heap_next === heap.length) heap.push(heap.length + 1);
    const idx = heap_next;
    heap_next = heap[idx];

    heap[idx] = obj;
    return idx;
}
/**
* Gets feature flags.
*
* Flag | Value
* -----|-------
* 0x01 | `VEX`
* 0x02 | `EVEX`
* 0x04 | `XOP`
* 0x08 | `3DNow!`
* 0x10 | `MVEX`
* @returns {number}
*/
export function getIcedFeatures() {
    const ret = wasm.getIcedFeatures();
    return ret >>> 0;
}

/**
* Mnemonic condition code selector (eg. `JAE` / `JNB` / `JNC`)
*/
export const CC_ae = Object.freeze({
/**
* `JAE`, `CMOVAE`, `SETAE`
*/
ae:0,"0":"ae",
/**
* `JNB`, `CMOVNB`, `SETNB`
*/
nb:1,"1":"nb",
/**
* `JNC`, `CMOVNC`, `SETNC`
*/
nc:2,"2":"nc", });
/**
* Mnemonic condition code selector (eg. `JNE` / `JNZ`)
*/
export const CC_ne = Object.freeze({
/**
* `JNE`, `CMOVNE`, `SETNE`, `LOOPNE`, `REPNE`
*/
ne:0,"0":"ne",
/**
* `JNZ`, `CMOVNZ`, `SETNZ`, `LOOPNZ`, `REPNZ`
*/
nz:1,"1":"nz", });
/**
* Mnemonic condition code selector (eg. `JP` / `JPE`)
*/
export const CC_p = Object.freeze({
/**
* `JP`, `CMOVP`, `SETP`
*/
p:0,"0":"p",
/**
* `JPE`, `CMOVPE`, `SETPE`
*/
pe:1,"1":"pe", });
/**
* Mnemonic condition code selector (eg. `JLE` / `JNG`)
*/
export const CC_le = Object.freeze({
/**
* `JLE`, `CMOVLE`, `SETLE`
*/
le:0,"0":"le",
/**
* `JNG`, `CMOVNG`, `SETNG`
*/
ng:1,"1":"ng", });
/**
* Mnemonic condition code selector (eg. `JG` / `JNLE`)
*/
export const CC_g = Object.freeze({
/**
* `JG`, `CMOVG`, `SETG`
*/
g:0,"0":"g",
/**
* `JNLE`, `CMOVNLE`, `SETNLE`
*/
nle:1,"1":"nle", });
/**
* Mnemonic condition code selector (eg. `JBE` / `JNA`)
*/
export const CC_be = Object.freeze({
/**
* `JBE`, `CMOVBE`, `SETBE`
*/
be:0,"0":"be",
/**
* `JNA`, `CMOVNA`, `SETNA`
*/
na:1,"1":"na", });
/**
* Decoder error
*/
export const DecoderError = Object.freeze({
/**
* No error. The last decoded instruction is a valid instruction
*/
None:0,"0":"None",
/**
* It's an invalid instruction or an invalid encoding of an existing instruction (eg. some reserved bit is set/cleared)
*/
InvalidInstruction:1,"1":"InvalidInstruction",
/**
* There's not enough bytes left to decode the instruction
*/
NoMoreBytes:2,"2":"NoMoreBytes", });
/**
* Formatter syntax (GNU Assembler, Intel XED, masm, nasm)
*/
export const FormatterSyntax = Object.freeze({
/**
* GNU Assembler (AT&T)
*/
Gas:0,"0":"Gas",
/**
* Intel XED
*/
Intel:1,"1":"Intel",
/**
* masm
*/
Masm:2,"2":"Masm",
/**
* nasm
*/
Nasm:3,"3":"Nasm", });
/**
* Mnemonic condition code selector (eg. `JE` / `JZ`)
*/
export const CC_e = Object.freeze({
/**
* `JE`, `CMOVE`, `SETE`, `LOOPE`, `REPE`
*/
e:0,"0":"e",
/**
* `JZ`, `CMOVZ`, `SETZ`, `LOOPZ`, `REPZ`
*/
z:1,"1":"z", });
/**
* Mnemonic condition code selector (eg. `JNP` / `JPO`)
*/
export const CC_np = Object.freeze({
/**
* `JNP`, `CMOVNP`, `SETNP`
*/
np:0,"0":"np",
/**
* `JPO`, `CMOVPO`, `SETPO`
*/
po:1,"1":"po", });
/**
* Mnemonic condition code selector (eg. `JGE` / `JNL`)
*/
export const CC_ge = Object.freeze({
/**
* `JGE`, `CMOVGE`, `SETGE`
*/
ge:0,"0":"ge",
/**
* `JNL`, `CMOVNL`, `SETNL`
*/
nl:1,"1":"nl", });
/**
* Memory size options used by the formatters
*/
export const MemorySizeOptions = Object.freeze({
/**
* Show memory size if the assembler requires it, else don't show anything
*/
Default:0,"0":"Default",
/**
* Always show the memory size, even if the assembler doesn't need it
*/
Always:1,"1":"Always",
/**
* Show memory size if a human can't figure out the size of the operand
*/
Minimal:2,"2":"Minimal",
/**
* Never show memory size
*/
Never:3,"3":"Never", });
/**
* Mnemonic condition code selector (eg. `JA` / `JNBE`)
*/
export const CC_a = Object.freeze({
/**
* `JA`, `CMOVA`, `SETA`
*/
a:0,"0":"a",
/**
* `JNBE`, `CMOVNBE`, `SETNBE`
*/
nbe:1,"1":"nbe", });
/**
* Mnemonic condition code selector (eg. `JL` / `JNGE`)
*/
export const CC_l = Object.freeze({
/**
* `JL`, `CMOVL`, `SETL`
*/
l:0,"0":"l",
/**
* `JNGE`, `CMOVNGE`, `SETNGE`
*/
nge:1,"1":"nge", });
/**
* Decoder options
*/
export const DecoderOptions = Object.freeze({
/**
* No option is enabled
*/
None:0,"0":"None",
/**
* Disable some checks for invalid encodings of instructions, eg. most instructions can't use a `LOCK` prefix so if one is found, they're decoded as [`Code.INVALID`] unless this option is enabled.
*
* [`Code.INVALID`]: enum.Code.html#variant.INVALID
*/
NoInvalidCheck:1,"1":"NoInvalidCheck",
/**
* AMD decoder: allow 16-bit branch/ret instructions in 64-bit mode, no `o64 CALL/JMP FAR [mem], o64 LSS/LFS/LGS`, `UD0` has no modr/m byte, decode `LOCK MOV CR`. The AMD decoder can still decode Intel instructions.
*/
AMD:2,"2":"AMD",
/**
* Decode opcodes `0F0D` and `0F18-0F1F` as reserved-nop instructions (eg. [`Code.Reservednop_rm32_r32_0F1D`])
*
* [`Code.Reservednop_rm32_r32_0F1D`]: enum.Code.html#variant.Reservednop_rm32_r32_0F1D
*/
ForceReservedNop:4,"4":"ForceReservedNop",
/**
* Decode `UMOV` instructions
*/
Umov:8,"8":"Umov",
/**
* Decode `XBTS`/`IBTS`
*/
Xbts:16,"16":"Xbts",
/**
* Decode `0FA6`/`0FA7` as `CMPXCHG`
*/
Cmpxchg486A:32,"32":"Cmpxchg486A",
/**
* Decode some old removed FPU instructions (eg. `FRSTPM`)
*/
OldFpu:64,"64":"OldFpu",
/**
* Decode `PCOMMIT`
*/
Pcommit:128,"128":"Pcommit",
/**
* Decode 286 `STOREALL`/`LOADALL` (`0F04` and `0F05`)
*/
Loadall286:256,"256":"Loadall286",
/**
* Decode 386 `LOADALL`
*/
Loadall386:512,"512":"Loadall386",
/**
* Decode `CL1INVMB`
*/
Cl1invmb:1024,"1024":"Cl1invmb",
/**
* Decode `MOV r32,tr` and `MOV tr,r32`
*/
MovTr:2048,"2048":"MovTr",
/**
* Decode `JMPE` instructions
*/
Jmpe:4096,"4096":"Jmpe",
/**
* Don't decode `PAUSE`, decode `NOP` instead
*/
NoPause:8192,"8192":"NoPause",
/**
* Don't decode `WBNOINVD`, decode `WBINVD` instead
*/
NoWbnoinvd:16384,"16384":"NoWbnoinvd",
/**
* Decode undocumented Intel `RDUDBG` and `WRUDBG` instructions
*/
Udbg:32768,"32768":"Udbg",
/**
* Don't decode `TZCNT`, decode `BSF` instead
*/
NoMPFX_0FBC:65536,"65536":"NoMPFX_0FBC",
/**
* Don't decode `LZCNT`, decode `BSR` instead
*/
NoMPFX_0FBD:131072,"131072":"NoMPFX_0FBD",
/**
* Don't decode `LAHF` and `SAHF` in 64-bit mode
*/
NoLahfSahf64:262144,"262144":"NoLahfSahf64",
/**
* Decode `MPX` instructions
*/
MPX:524288,"524288":"MPX",
/**
* Decode most Cyrix instructions: `FPU`, `EMMI`, `SMM`, `DDI`
*/
Cyrix:1048576,"1048576":"Cyrix",
/**
* Decode Cyrix `SMINT 0F7E` (Cyrix 6x86 or earlier)
*/
Cyrix_SMINT_0F7E:2097152,"2097152":"Cyrix_SMINT_0F7E",
/**
* Decode Cyrix `DMI` instructions (AMD Geode GX/LX)
*/
Cyrix_DMI:4194304,"4194304":"Cyrix_DMI",
/**
* Decode Centaur `ALTINST`
*/
ALTINST:8388608,"8388608":"ALTINST",
/**
* Decode Intel Knights Corner instructions (requires the `mvex` feature)
*/
KNC:16777216,"16777216":"KNC", });
/**
* Format mnemonic options
*/
export const FormatMnemonicOptions = Object.freeze({
/**
* No option is set
*/
None:0,"0":"None",
/**
* Don't add any prefixes
*/
NoPrefixes:1,"1":"NoPrefixes",
/**
* Don't add the mnemonic
*/
NoMnemonic:2,"2":"NoMnemonic", });
/**
* Mnemonic condition code selector (eg. `JB` / `JC` / `JNAE`)
*/
export const CC_b = Object.freeze({
/**
* `JB`, `CMOVB`, `SETB`
*/
b:0,"0":"b",
/**
* `JC`, `CMOVC`, `SETC`
*/
c:1,"1":"c",
/**
* `JNAE`, `CMOVNAE`, `SETNAE`
*/
nae:2,"2":"nae", });

const ConstantOffsetsFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_constantoffsets_free(ptr >>> 0, 1));
/**
* Contains the offsets of the displacement and immediate. Call [`Decoder.getConstantOffsets()`] or
* [`Encoder.getConstantOffsets()`] to get the offsets of the constants after the instruction has been
* decoded/encoded.
*
* [`Decoder.getConstantOffsets()`]: struct.Decoder.html#method.get_constant_offsets
* [`Encoder.getConstantOffsets()`]: struct.Encoder.html#method.get_constant_offsets
*/
export class ConstantOffsets {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(ConstantOffsets.prototype);
        obj.__wbg_ptr = ptr;
        ConstantOffsetsFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        ConstantOffsetsFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_constantoffsets_free(ptr, 0);
    }
    /**
    * The offset of the displacement, if any
    * @returns {number}
    */
    get displacementOffset() {
        const ret = wasm.constantoffsets_displacementOffset(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
    * Size in bytes of the displacement, or 0 if there's no displacement
    * @returns {number}
    */
    get displacementSize() {
        const ret = wasm.constantoffsets_displacementSize(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
    * The offset of the first immediate, if any.
    *
    * This field can be invalid even if the operand has an immediate if it's an immediate that isn't part
    * of the instruction stream, eg. `SHL AL,1`.
    * @returns {number}
    */
    get immediateOffset() {
        const ret = wasm.constantoffsets_immediateOffset(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
    * Size in bytes of the first immediate, or 0 if there's no immediate
    * @returns {number}
    */
    get immediateSize() {
        const ret = wasm.constantoffsets_immediateSize(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
    * The offset of the second immediate, if any.
    * @returns {number}
    */
    get immediateOffset2() {
        const ret = wasm.constantoffsets_immediateOffset2(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
    * Size in bytes of the second immediate, or 0 if there's no second immediate
    * @returns {number}
    */
    get immediateSize2() {
        const ret = wasm.constantoffsets_immediateSize2(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
    * `true` if [`displacementOffset`] and [`displacementSize`] are valid
    *
    * [`displacementOffset`]: #method.displacement_offset
    * [`displacementSize`]: #method.displacement_size
    * @returns {boolean}
    */
    get hasDisplacement() {
        const ret = wasm.constantoffsets_hasDisplacement(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
    * `true` if [`immediateOffset`] and [`immediateSize`] are valid
    *
    * [`immediateOffset`]: #method.immediate_offset
    * [`immediateSize`]: #method.immediate_size
    * @returns {boolean}
    */
    get hasImmediate() {
        const ret = wasm.constantoffsets_hasImmediate(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
    * `true` if [`immediateOffset2`] and [`immediateSize2`] are valid
    *
    * [`immediateOffset2`]: #method.immediate_offset2
    * [`immediateSize2`]: #method.immediate_size2
    * @returns {boolean}
    */
    get hasImmediate2() {
        const ret = wasm.constantoffsets_hasImmediate2(this.__wbg_ptr);
        return ret !== 0;
    }
}

const DecoderFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_decoder_free(ptr >>> 0, 1));
/**
* Decodes 16/32/64-bit x86 instructions
*/
export class Decoder {

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        DecoderFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_decoder_free(ptr, 0);
    }
    /**
    * Creates a decoder
    *
    * # Throws
    *
    * Throws if `bitness` is not one of 16, 32, 64.
    *
    * # Arguments
    *
    * * `bitness`: 16, 32 or 64
    * * `data`: Data to decode
    * * `options`: Decoder options (a [`DecoderOptions`] flags value), `0` or eg. `DecoderOptions.NoInvalidCheck | DecoderOptions.AMD`
    *
    * [`DecoderOptions`]: enum.DecoderOptions.html
    *
    * # Examples
    *
    * ```js
    * const assert = require("assert").strict;
    * const { Code, Decoder, DecoderOptions, Mnemonic } = require("iced-x86");
    *
    * // xchg ah,[rdx+rsi+16h]
    * // xacquire lock add dword ptr [rax],5Ah
    * // vmovdqu64 zmm18{k3}{z},zmm11
    * const bytes = new Uint8Array([0x86, 0x64, 0x32, 0x16, 0xF0, 0xF2, 0x83, 0x00, 0x5A, 0x62, 0xC1, 0xFE, 0xCB, 0x6F, 0xD3]);
    * const decoder = new Decoder(64, bytes, DecoderOptions.None);
    * decoder.ip = 0x12345678n;
    *
    * const instr = decoder.decode();
    * assert.equal(instr.code, Code.Xchg_rm8_r8);
    * assert.equal(instr.mnemonic, Mnemonic.Xchg);
    * assert.equal(instr.length, 4);
    *
    * decoder.decodeOut(instr);
    * assert.equal(instr.code, Code.Add_rm32_imm8);
    * assert.equal(instr.mnemonic, Mnemonic.Add);
    * assert.equal(instr.length, 5);
    *
    * decoder.decodeOut(instr);
    * assert.equal(instr.code, Code.EVEX_Vmovdqu64_zmm_k1z_zmmm512);
    * assert.equal(instr.mnemonic, Mnemonic.Vmovdqu64);
    * assert.equal(instr.length, 6);
    *
    * // Free wasm memory
    * decoder.free();
    * instr.free();
    * ```
    *
    * It's sometimes useful to decode some invalid instructions, eg. `lock add esi,ecx`.
    * Pass in [`DecoderOptions.NoInvalidCheck`] to the constructor and the decoder
    * will decode some invalid encodings.
    *
    * [`DecoderOptions.NoInvalidCheck`]: enum.DecoderOptions.html#variant.NoInvalidCheck
    *
    * ```js
    * const assert = require("assert").strict;
    * const { Code, Decoder, DecoderOptions } = require("iced-x86");
    *
    * // lock add esi,ecx   ; lock not allowed
    * const bytes = new Uint8Array([0xF0, 0x01, 0xCE]);
    * const decoder1 = new Decoder(64, bytes, DecoderOptions.None);
    * decoder1.ip = 0x12345678n;
    * const instr1 = decoder1.decode();
    * assert.equal(instr1.code, Code.INVALID);
    *
    * // We want to decode some instructions with invalid encodings
    * const decoder2 = new Decoder(64, bytes, DecoderOptions.NoInvalidCheck);
    * decoder2.ip = 0x12345678n;
    * const instr2 = decoder2.decode();
    * assert.equal(instr2.code, Code.Add_rm32_r32);
    * assert.ok(instr2.hasLockPrefix);
    *
    * // Free wasm memory
    * decoder1.free();
    * decoder2.free();
    * instr1.free();
    * instr2.free();
    * ```
    * @param {number} bitness
    * @param {Uint8Array} data
    * @param {number} options
    */
    constructor(bitness, data, options) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
            const len0 = WASM_VECTOR_LEN;
            wasm.decoder_new(retptr, bitness, ptr0, len0, options);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            this.__wbg_ptr = r0 >>> 0;
            DecoderFinalization.register(this, this.__wbg_ptr, this);
            return this;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * Gets the current `IP`/`EIP`/`RIP` value, see also [`position`]
    *
    * [`position`]: #method.position
    * @returns {bigint}
    */
    get ip() {
        const ret = wasm.decoder_ip(this.__wbg_ptr);
        return BigInt.asUintN(64, ret);
    }
    /**
    * Sets the current `IP`/`EIP`/`RIP` value, see also [`position`]
    *
    * Writing to this property only updates the IP value, it does not change the data position, use [`position`] to change the position.
    *
    * [`position`]: #method.set_position
    *
    * # Arguments
    *
    * * `new_value`: New IP
    * @param {bigint} new_value
    */
    set ip(new_value) {
        wasm.decoder_set_ip(this.__wbg_ptr, new_value);
    }
    /**
    * Gets the bitness (16, 32 or 64)
    * @returns {number}
    */
    get bitness() {
        const ret = wasm.decoder_bitness(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
    * Gets the max value that can be written to [`position`]. This is the size of the data that gets
    * decoded to instructions and it's the length of the array that was passed to the constructor.
    *
    * [`position`]: #method.set_position
    * @returns {number}
    */
    get maxPosition() {
        const ret = wasm.decoder_maxPosition(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
    * Gets the current data position. This value is always <= [`maxPosition`].
    * When [`position`] == [`maxPosition`], it's not possible to decode more
    * instructions and [`canDecode`] returns `false`.
    *
    * [`maxPosition`]: #method.max_position
    * [`position`]: #method.position
    * [`canDecode`]: #method.can_decode
    * @returns {number}
    */
    get position() {
        const ret = wasm.decoder_position(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
    * Sets the current data position, which is the index into the data passed to the constructor.
    * This value is always <= [`maxPosition`]
    *
    * [`maxPosition`]: #method.max_position
    *
    * # Throws
    *
    * Throws if the new position is invalid.
    *
    * # Arguments
    *
    * * `new_pos`: New position and must be <= [`maxPosition`]
    *
    * # Examples
    *
    * ```js
    * const assert = require("assert").strict;
    * const { Code, Decoder, DecoderOptions } = require("iced-x86");
    *
    * // nop and pause
    * const bytes = new Uint8Array([0x90, 0xF3, 0x90]);
    * const decoder = new Decoder(64, bytes, DecoderOptions.None);
    * decoder.ip = 0x12345678n;
    *
    * assert.equal(decoder.position, 0);
    * assert.equal(decoder.maxPosition, 3);
    * const instr = decoder.decode();
    * assert.equal(decoder.position, 1);
    * assert.equal(instr.code, Code.Nopd);
    *
    * decoder.decodeOut(instr);
    * assert.equal(decoder.position, 3);
    * assert.equal(instr.code, Code.Pause);
    *
    * // Start all over again
    * decoder.position = 0;
    * assert.equal(decoder.position, 0);
    * decoder.decodeOut(instr);
    * assert.equal(instr.code, Code.Nopd);
    * decoder.decodeOut(instr);
    * assert.equal(instr.code, Code.Pause);
    * assert.equal(decoder.position, 3);
    *
    * // Free wasm memory
    * decoder.free();
    * instr.free();
    * ```
    * @param {number} new_pos
    */
    set position(new_pos) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.decoder_set_position(retptr, this.__wbg_ptr, new_pos);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            if (r1) {
                throw takeObject(r0);
            }
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * Returns `true` if there's at least one more byte to decode. It doesn't verify that the
    * next instruction is valid, it only checks if there's at least one more byte to read.
    * See also [`position`] and [`maxPosition`]
    *
    * It's not required to call this method. If this method returns `false`, then [`decodeOut()`]
    * and [`decode()`] will return an instruction whose [`code`] == [`Code.INVALID`].
    *
    * [`position`]: #method.position
    * [`maxPosition`]: #method.max_position
    * [`decodeOut()`]: #method.decode_out
    * [`decode()`]: #method.decode
    * [`code`]: struct.Instruction.html#method.code
    * [`Code.INVALID`]: enum.Code.html#variant.INVALID
    *
    * # Examples
    *
    * ```js
    * const assert = require("assert").strict;
    * const { Code, Decoder, DecoderOptions } = require("iced-x86");
    *
    * // nop and an incomplete instruction
    * const bytes = new Uint8Array([0x90, 0xF3, 0x0F]);
    * const decoder = new Decoder(64, bytes, DecoderOptions.None);
    * decoder.ip = 0x12345678n;
    *
    * // 3 bytes left to read
    * assert.ok(decoder.canDecode);
    * const instr = decoder.decode();
    * assert.equal(instr.code, Code.Nopd);
    *
    * // 2 bytes left to read
    * assert.ok(decoder.canDecode);
    * decoder.decodeOut(instr);
    * // Not enough bytes left to decode a full instruction
    * assert.equal(instr.code, Code.INVALID);
    *
    * // 0 bytes left to read
    * assert.ok(!decoder.canDecode);
    *
    * // Free wasm memory
    * decoder.free();
    * instr.free();
    * ```
    * @returns {boolean}
    */
    get canDecode() {
        const ret = wasm.decoder_canDecode(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
    * Decodes all instructions and returns an array of [`Instruction`]s
    *
    * [`Instruction`]: struct.Instruction.html
    * @returns {Array<any>}
    */
    decodeAll() {
        const ret = wasm.decoder_decodeAll(this.__wbg_ptr);
        return takeObject(ret);
    }
    /**
    * Decodes at most `count` instructions and returns an array of [`Instruction`]s.
    * It returns less than `count` instructions if there's not enough data left to decode.
    *
    * [`Instruction`]: struct.Instruction.html
    *
    * # Arguments
    *
    * - `count`: Max number of instructions to decode
    * @param {number} count
    * @returns {Array<any>}
    */
    decodeInstructions(count) {
        const ret = wasm.decoder_decodeInstructions(this.__wbg_ptr, count);
        return takeObject(ret);
    }
    /**
    * Gets the last decoder error. Unless you need to know the reason it failed,
    * it's better to check [`instruction.isInvalid()`].
    *
    * It returns a [`DecoderError`] enum value.
    *
    * [`instruction.isInvalid()`]: struct.Instruction.html#method.is_invalid
    * [`DecoderError`]: enum.DecoderError.html
    * @returns {DecoderError}
    */
    get lastError() {
        const ret = wasm.decoder_lastError(this.__wbg_ptr);
        return ret;
    }
    /**
    * Decodes and returns the next instruction, see also [`decodeOut()`]
    * which avoids allocating a new instruction.
    * See also [`lastError`].
    *
    * [`decodeOut()`]: #method.decode_out
    * [`lastError`]: #method.last_error
    *
    * # Examples
    *
    * ```js
    * const assert = require("assert").strict;
    * const { Code, Decoder, DecoderOptions, MemorySize, Mnemonic, OpKind, Register } = require("iced-x86");
    *
    * // xrelease lock add [rax],ebx
    * const bytes = new Uint8Array([0xF0, 0xF3, 0x01, 0x18]);
    * const decoder = new Decoder(64, bytes, DecoderOptions.None);
    * decoder.ip = 0x12345678n;
    * const instr = decoder.decode();
    *
    * assert.equal(instr.code, Code.Add_rm32_r32);
    * assert.equal(instr.mnemonic, Mnemonic.Add);
    * assert.equal(instr.length, 4);
    * assert.equal(instr.opCount, 2);
    *
    * assert.equal(instr.op0Kind, OpKind.Memory);
    * assert.equal(instr.memoryBase, Register.RAX);
    * assert.equal(instr.memoryIndex, Register.None);
    * assert.equal(instr.memoryIndexScale, 1);
    * assert.equal(instr.memoryDisplacement, 0);
    * assert.equal(instr.memorySegment, Register.DS);
    * assert.equal(instr.segmentPrefix, Register.None);
    * assert.equal(instr.memorySize, MemorySize.UInt32);
    *
    * assert.equal(instr.op1Kind, OpKind.Register);
    * assert.equal(instr.op1Register, Register.EBX);
    *
    * assert.ok(instr.hasLockPrefix);
    * assert.ok(instr.hasXreleasePrefix);
    *
    * // Free wasm memory
    * decoder.free();
    * instr.free();
    * ```
    * @returns {Instruction}
    */
    decode() {
        const ret = wasm.decoder_decode(this.__wbg_ptr);
        return Instruction.__wrap(ret);
    }
    /**
    * Decodes the next instruction. The difference between this method and [`decode()`] is that this
    * method doesn't need to allocate a new instruction.
    * See also [`lastError`].
    *
    * [`decode()`]: #method.decode
    * [`lastError`]: #method.last_error
    *
    * # Arguments
    *
    * * `instruction`: Updated with the decoded instruction. All fields are initialized (it's an `out` argument)
    *
    * # Examples
    *
    * ```js
    * const assert = require("assert").strict;
    * const { Code, Decoder, DecoderOptions, Instruction, MemorySize, Mnemonic, OpKind, Register } = require("iced-x86");
    *
    * // xrelease lock add [rax],ebx
    * const bytes = new Uint8Array([0xF0, 0xF3, 0x01, 0x18]);
    * const decoder = new Decoder(64, bytes, DecoderOptions.None);
    * decoder.ip = 0x12345678n;
    * const instr = new Instruction();
    * decoder.decodeOut(instr);
    *
    * assert.equal(instr.code, Code.Add_rm32_r32);
    * assert.equal(instr.mnemonic, Mnemonic.Add);
    * assert.equal(instr.length, 4);
    * assert.equal(instr.opCount, 2);
    *
    * assert.equal(instr.op0Kind, OpKind.Memory);
    * assert.equal(instr.memoryBase, Register.RAX);
    * assert.equal(instr.memoryIndex, Register.None);
    * assert.equal(instr.memoryIndexScale, 1);
    * assert.equal(instr.memoryDisplacement, 0);
    * assert.equal(instr.memorySegment, Register.DS);
    * assert.equal(instr.segmentPrefix, Register.None);
    * assert.equal(instr.memorySize, MemorySize.UInt32);
    *
    * assert.equal(instr.op1Kind, OpKind.Register);
    * assert.equal(instr.op1Register, Register.EBX);
    *
    * assert.ok(instr.hasLockPrefix);
    * assert.ok(instr.hasXreleasePrefix);
    *
    * // Free wasm memory
    * decoder.free();
    * instr.free();
    * ```
    * @param {Instruction} instruction
    */
    decodeOut(instruction) {
        _assertClass(instruction, Instruction);
        wasm.decoder_decodeOut(this.__wbg_ptr, instruction.__wbg_ptr);
    }
}

const EncoderFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_encoder_free(ptr >>> 0, 1));
/**
* Encodes instructions decoded by the decoder or instructions created by other code.
* See also [`BlockEncoder`] which can encode any number of instructions.
*
* [`BlockEncoder`]: struct.BlockEncoder.html
*
* ```js
* const assert = require("assert").strict;
* const { Decoder, DecoderOptions, Encoder } = require("iced-x86");
*
* // xchg ah,[rdx+rsi+16h]
* const bytes = new Uint8Array([0x86, 0x64, 0x32, 0x16]);
* const decoder = new Decoder(64, bytes, DecoderOptions.None);
* decoder.ip = 0x12345678n;
* const instr = decoder.decode();
*
* const encoder = new Encoder(64);
* const len = encoder.encode(instr, 0x55555555n);
* assert.equal(len, 4);
* // We're done, take ownership of the buffer
* const buffer = encoder.takeBuffer();
* assert.equal(buffer.length, 4);
* assert.equal(buffer[0], 0x86);
* assert.equal(buffer[1], 0x64);
* assert.equal(buffer[2], 0x32);
* assert.equal(buffer[3], 0x16);
*
* // Free wasm memory
* decoder.free();
* instr.free();
* encoder.free();
* ```
*/
export class Encoder {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(Encoder.prototype);
        obj.__wbg_ptr = ptr;
        EncoderFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        EncoderFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_encoder_free(ptr, 0);
    }
    /**
    * Creates an encoder
    *
    * # Throws
    *
    * Throws if `bitness` is not one of 16, 32, 64.
    *
    * # Arguments
    *
    * * `bitness`: 16, 32 or 64
    * @param {number} bitness
    */
    constructor(bitness) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.encoder_new(retptr, bitness);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            this.__wbg_ptr = r0 >>> 0;
            EncoderFinalization.register(this, this.__wbg_ptr, this);
            return this;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * Creates an encoder with an initial buffer capacity
    *
    * # Throws
    *
    * Throws if `bitness` is not one of 16, 32, 64.
    *
    * # Arguments
    *
    * * `bitness`: 16, 32 or 64
    * * `capacity`: Initial capacity of the `u8` buffer
    * @param {number} bitness
    * @param {number} capacity
    * @returns {Encoder}
    */
    static withCapacity(bitness, capacity) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.encoder_withCapacity(retptr, bitness, capacity);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return Encoder.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * Encodes an instruction and returns the size of the encoded instruction
    *
    * # Throws
    *
    * Throws an error on failure.
    *
    * # Arguments
    *
    * * `instruction`: Instruction to encode
    * * `rip`: `RIP` of the encoded instruction
    *
    * # Examples
    *
    * ```js
    * const assert = require("assert").strict;
    * const { Decoder, DecoderOptions, Encoder } = require("iced-x86");
    *
    * // je short $+4
    * const bytes = new Uint8Array([0x75, 0x02]);
    * const decoder = new Decoder(64, bytes, DecoderOptions.None);
    * decoder.ip = 0x12345678n;
    * const instr = decoder.decode();
    *
    * const encoder = new Encoder(64);
    * // Use a different IP (orig rip + 0x10)
    * const len = encoder.encode(instr, 0x12345688n);
    * assert.equal(len, 2);
    * // We're done, take ownership of the buffer
    * const buffer = encoder.takeBuffer();
    * assert.equal(buffer.length, 2);
    * assert.equal(buffer[0], 0x75);
    * assert.equal(buffer[1], 0xF2);
    *
    * // Free wasm memory
    * decoder.free();
    * encoder.free();
    * instr.free();
    * ```
    * @param {Instruction} instruction
    * @param {bigint} rip
    * @returns {number}
    */
    encode(instruction, rip) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(instruction, Instruction);
            wasm.encoder_encode(retptr, this.__wbg_ptr, instruction.__wbg_ptr, rip);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return r0 >>> 0;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * Writes a byte to the output buffer
    *
    * # Arguments
    *
    * `value`: Value to write
    *
    * # Examples
    *
    * ```js
    * const assert = require("assert").strict;
    * const { Code, Encoder, Instruction, Register } = require("iced-x86");
    *
    * const encoder = new Encoder(64);
    * const instr = Instruction.createRegReg(Code.Add_r64_rm64, Register.R8, Register.RBP);
    * encoder.writeU8(0x90);
    * const len = encoder.encode(instr, 0x55555555n);
    * assert.equal(len, 3);
    * encoder.writeU8(0xCC);
    * // We're done, take ownership of the buffer
    * const buffer = encoder.takeBuffer();
    * assert.equal(buffer.length, 5);
    * assert.equal(buffer[0], 0x90);
    * assert.equal(buffer[1], 0x4C);
    * assert.equal(buffer[2], 0x03);
    * assert.equal(buffer[3], 0xC5);
    * assert.equal(buffer[4], 0xCC);
    *
    * // Free wasm memory
    * encoder.free();
    * instr.free();
    * ```
    * @param {number} value
    */
    writeU8(value) {
        wasm.encoder_writeU8(this.__wbg_ptr, value);
    }
    /**
    * Returns the buffer and initializes the internal buffer to an empty vector. Should be called when
    * you've encoded all instructions and need the raw instruction bytes. See also [`setBuffer()`].
    *
    * [`setBuffer()`]: #method.set_buffer
    * @returns {Uint8Array}
    */
    takeBuffer() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.encoder_takeBuffer(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var v1 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_free(r0, r1 * 1, 1);
            return v1;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * Overwrites the buffer with a new vector. The old buffer is dropped. See also [`takeBuffer()`].
    *
    * [`takeBuffer()`]: #method.take_buffer
    * @param {Uint8Array} buffer
    */
    setBuffer(buffer) {
        const ptr0 = passArray8ToWasm0(buffer, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.encoder_setBuffer(this.__wbg_ptr, ptr0, len0);
    }
    /**
    * Gets the offsets of the constants (memory displacement and immediate) in the encoded instruction.
    * The caller can use this information to add relocations if needed.
    * @returns {ConstantOffsets}
    */
    getConstantOffsets() {
        const ret = wasm.encoder_getConstantOffsets(this.__wbg_ptr);
        return ConstantOffsets.__wrap(ret);
    }
    /**
    * Disables 2-byte VEX encoding and encodes all VEX instructions with the 3-byte VEX encoding
    * @returns {boolean}
    */
    get preventVEX2() {
        const ret = wasm.encoder_preventVEX2(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
    * Disables 2-byte VEX encoding and encodes all VEX instructions with the 3-byte VEX encoding
    *
    * # Arguments
    *
    * * `new_value`: new value
    * @param {boolean} new_value
    */
    set preventVEX2(new_value) {
        wasm.encoder_set_preventVEX2(this.__wbg_ptr, new_value);
    }
    /**
    * Value of the `VEX.W` bit to use if it's an instruction that ignores the bit. Default is 0.
    * @returns {number}
    */
    get VEX_WIG() {
        const ret = wasm.encoder_VEX_WIG(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
    * Value of the `VEX.W` bit to use if it's an instruction that ignores the bit. Default is 0.
    *
    * # Arguments
    *
    * * `new_value`: new value (0 or 1)
    * @param {number} new_value
    */
    set VEX_WIG(new_value) {
        wasm.encoder_set_VEX_WIG(this.__wbg_ptr, new_value);
    }
    /**
    * Value of the `VEX.L` bit to use if it's an instruction that ignores the bit. Default is 0.
    * @returns {number}
    */
    get VEX_LIG() {
        const ret = wasm.encoder_VEX_LIG(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
    * Value of the `VEX.L` bit to use if it's an instruction that ignores the bit. Default is 0.
    *
    * # Arguments
    *
    * * `new_value`: new value (0 or 1)
    * @param {number} new_value
    */
    set VEX_LIG(new_value) {
        wasm.encoder_set_VEX_LIG(this.__wbg_ptr, new_value);
    }
    /**
    * Value of the `EVEX.W` bit to use if it's an instruction that ignores the bit. Default is 0.
    * @returns {number}
    */
    get EVEX_WIG() {
        const ret = wasm.encoder_EVEX_WIG(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
    * Value of the `EVEX.W` bit to use if it's an instruction that ignores the bit. Default is 0.
    *
    * # Arguments
    *
    * * `new_value`: new value (0 or 1)
    * @param {number} new_value
    */
    set EVEX_WIG(new_value) {
        wasm.encoder_set_EVEX_WIG(this.__wbg_ptr, new_value);
    }
    /**
    * Value of the `EVEX.L'L` bits to use if it's an instruction that ignores the bits. Default is 0.
    * @returns {number}
    */
    get EVEX_LIG() {
        const ret = wasm.encoder_EVEX_LIG(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
    * Value of the `EVEX.L'L` bits to use if it's an instruction that ignores the bits. Default is 0.
    *
    * # Arguments
    *
    * * `new_value`: new value (0 or 3)
    * @param {number} new_value
    */
    set EVEX_LIG(new_value) {
        wasm.encoder_set_EVEX_LIG(this.__wbg_ptr, new_value);
    }
    /**
    * Gets the bitness (16, 32 or 64)
    * @returns {number}
    */
    get bitness() {
        const ret = wasm.encoder_bitness(this.__wbg_ptr);
        return ret >>> 0;
    }
}

const FastFormatterFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_fastformatter_free(ptr >>> 0, 1));
/**
* x86 formatter that uses less code (smaller wasm files)
*/
export class FastFormatter {

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        FastFormatterFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_fastformatter_free(ptr, 0);
    }
    /**
    * Creates an x86 formatter
    *
    * # Examples
    *
    * ```js
    * const assert = require("assert").strict;
    * const { Decoder, DecoderOptions, FastFormatter } = require("iced-x86");
    *
    * const bytes = new Uint8Array([0x62, 0xF2, 0x4F, 0xDD, 0x72, 0x50, 0x01]);
    * const decoder = new Decoder(64, bytes, DecoderOptions.None);
    * const instr = decoder.decode();
    *
    * const formatter = new FastFormatter();
    * formatter.spaceAfterOperandSeparator = true;
    * const disasm = formatter.format(instr);
    * assert.equal(disasm, "vcvtne2ps2bf16 zmm2{k5}{z}, zmm6, dword bcst [rax+4h]");
    *
    * // Free wasm memory
    * decoder.free();
    * instr.free();
    * formatter.free();
    * ```
    *
    * [`FormatterSyntax`]: enum.FormatterSyntax.html
    */
    constructor() {
        const ret = wasm.fastformatter_new();
        this.__wbg_ptr = ret >>> 0;
        FastFormatterFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
    * Formats the whole instruction: prefixes, mnemonic, operands
    *
    * # Arguments
    *
    * - `instruction`: Instruction
    * @param {Instruction} instruction
    * @returns {string}
    */
    format(instruction) {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(instruction, Instruction);
            wasm.fastformatter_format(retptr, this.__wbg_ptr, instruction.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
    * Add a space after the operand separator
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `mov rax, rcx`
    * 👍 | `false` | `mov rax,rcx`
    * @returns {boolean}
    */
    get spaceAfterOperandSeparator() {
        const ret = wasm.fastformatter_spaceAfterOperandSeparator(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
    * Add a space after the operand separator
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `mov rax, rcx`
    * 👍 | `false` | `mov rax,rcx`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {boolean} value
    */
    set spaceAfterOperandSeparator(value) {
        wasm.fastformatter_set_spaceAfterOperandSeparator(this.__wbg_ptr, value);
    }
    /**
    * Show `RIP+displ` or the virtual address
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `mov eax,[rip+12345678h]`
    * 👍 | `false` | `mov eax,[1029384756AFBECDh]`
    * @returns {boolean}
    */
    get ripRelativeAddresses() {
        const ret = wasm.fastformatter_ripRelativeAddresses(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
    * Show `RIP+displ` or the virtual address
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `mov eax,[rip+12345678h]`
    * 👍 | `false` | `mov eax,[1029384756AFBECDh]`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {boolean} value
    */
    set ripRelativeAddresses(value) {
        wasm.fastformatter_set_ripRelativeAddresses(this.__wbg_ptr, value);
    }
    /**
    * Use pseudo instructions
    *
    * Default | Value | Example
    * --------|-------|--------
    * 👍 | `true` | `vcmpnltsd xmm2,xmm6,xmm3`
    * _ | `false` | `vcmpsd xmm2,xmm6,xmm3,5`
    * @returns {boolean}
    */
    get usePseudoOps() {
        const ret = wasm.fastformatter_usePseudoOps(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
    * Use pseudo instructions
    *
    * Default | Value | Example
    * --------|-------|--------
    * 👍 | `true` | `vcmpnltsd xmm2,xmm6,xmm3`
    * _ | `false` | `vcmpsd xmm2,xmm6,xmm3,5`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {boolean} value
    */
    set usePseudoOps(value) {
        wasm.fastformatter_set_usePseudoOps(this.__wbg_ptr, value);
    }
    /**
    * Show the original value after the symbol name
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `mov eax,[myfield (12345678)]`
    * 👍 | `false` | `mov eax,[myfield]`
    * @returns {boolean}
    */
    get showSymbolAddress() {
        const ret = wasm.fastformatter_showSymbolAddress(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
    * Show the original value after the symbol name
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `mov eax,[myfield (12345678)]`
    * 👍 | `false` | `mov eax,[myfield]`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {boolean} value
    */
    set showSymbolAddress(value) {
        wasm.fastformatter_set_showSymbolAddress(this.__wbg_ptr, value);
    }
    /**
    * Always show the effective segment register. If the option is `false`, only show the segment register if
    * there's a segment override prefix.
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `mov eax,ds:[ecx]`
    * 👍 | `false` | `mov eax,[ecx]`
    * @returns {boolean}
    */
    get alwaysShowSegmentRegister() {
        const ret = wasm.fastformatter_alwaysShowSegmentRegister(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
    * Always show the effective segment register. If the option is `false`, only show the segment register if
    * there's a segment override prefix.
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `mov eax,ds:[ecx]`
    * 👍 | `false` | `mov eax,[ecx]`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {boolean} value
    */
    set alwaysShowSegmentRegister(value) {
        wasm.fastformatter_set_alwaysShowSegmentRegister(this.__wbg_ptr, value);
    }
    /**
    * Always show the size of memory operands
    *
    * Default | Value | Example | Example
    * --------|-------|---------|--------
    * _ | `true` | `mov eax,dword ptr [ebx]` | `add byte ptr [eax],0x12`
    * 👍 | `false` | `mov eax,[ebx]` | `add byte ptr [eax],0x12`
    * @returns {boolean}
    */
    get alwaysShowMemorySize() {
        const ret = wasm.fastformatter_alwaysShowMemorySize(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
    * Always show the size of memory operands
    *
    * Default | Value | Example | Example
    * --------|-------|---------|--------
    * _ | `true` | `mov eax,dword ptr [ebx]` | `add byte ptr [eax],0x12`
    * 👍 | `false` | `mov eax,[ebx]` | `add byte ptr [eax],0x12`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {boolean} value
    */
    set alwaysShowMemorySize(value) {
        wasm.fastformatter_set_alwaysShowMemorySize(this.__wbg_ptr, value);
    }
    /**
    * Use uppercase hex digits
    *
    * Default | Value | Example
    * --------|-------|--------
    * 👍 | `true` | `0xFF`
    * _ | `false` | `0xff`
    * @returns {boolean}
    */
    get uppercaseHex() {
        const ret = wasm.fastformatter_uppercaseHex(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
    * Use uppercase hex digits
    *
    * Default | Value | Example
    * --------|-------|--------
    * 👍 | `true` | `0xFF`
    * _ | `false` | `0xff`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {boolean} value
    */
    set uppercaseHex(value) {
        wasm.fastformatter_set_uppercaseHex(this.__wbg_ptr, value);
    }
    /**
    * Use a hex prefix (`0x`) or a hex suffix (`h`)
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `0x5A`
    * 👍 | `false` | `5Ah`
    * @returns {boolean}
    */
    get useHexPrefix() {
        const ret = wasm.fastformatter_useHexPrefix(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
    * Use a hex prefix (`0x`) or a hex suffix (`h`)
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `0x5A`
    * 👍 | `false` | `5Ah`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {boolean} value
    */
    set useHexPrefix(value) {
        wasm.fastformatter_set_useHexPrefix(this.__wbg_ptr, value);
    }
}

const FormatterFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_formatter_free(ptr >>> 0, 1));
/**
* x86 formatter that supports GNU Assembler, Intel XED, masm and nasm syntax
*/
export class Formatter {

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        FormatterFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_formatter_free(ptr, 0);
    }
    /**
    * Creates an x86 formatter
    *
    * # Arguments
    *
    * * `syntax`: Formatter syntax, see [`FormatterSyntax`]
    *
    * # Examples
    *
    * ```js
    * const assert = require("assert").strict;
    * const { Decoder, DecoderOptions, Formatter, FormatterSyntax } = require("iced-x86");
    *
    * const bytes = new Uint8Array([0x62, 0xF2, 0x4F, 0xDD, 0x72, 0x50, 0x01]);
    * const decoder = new Decoder(64, bytes, DecoderOptions.None);
    * const instr = decoder.decode();
    *
    * const formatter = new Formatter(FormatterSyntax.Masm);
    * formatter.uppercaseMnemonics = true;
    * const disasm = formatter.format(instr);
    * assert.equal(disasm, "VCVTNE2PS2BF16 zmm2{k5}{z},zmm6,dword bcst [rax+4]");
    *
    * // Free wasm memory
    * decoder.free();
    * instr.free();
    * formatter.free();
    * ```
    *
    * [`FormatterSyntax`]: enum.FormatterSyntax.html
    * @param {FormatterSyntax} syntax
    */
    constructor(syntax) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.formatter_new(retptr, syntax);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            this.__wbg_ptr = r0 >>> 0;
            FormatterFinalization.register(this, this.__wbg_ptr, this);
            return this;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * Formats the whole instruction: prefixes, mnemonic, operands
    *
    * # Arguments
    *
    * - `instruction`: Instruction
    * @param {Instruction} instruction
    * @returns {string}
    */
    format(instruction) {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(instruction, Instruction);
            wasm.formatter_format(retptr, this.__wbg_ptr, instruction.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
    * Formats the mnemonic and any prefixes
    *
    * # Arguments
    *
    * - `instruction`: Instruction
    * @param {Instruction} instruction
    * @returns {string}
    */
    formatMnemonic(instruction) {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(instruction, Instruction);
            wasm.formatter_formatMnemonic(retptr, this.__wbg_ptr, instruction.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
    * Formats the mnemonic and/or any prefixes
    *
    * # Arguments
    *
    * - `instruction`: Instruction
    * - `options`: Options, see [`FormatMnemonicOptions`]
    *
    * [`FormatMnemonicOptions`]: enum.FormatMnemonicOptions.html
    * @param {Instruction} instruction
    * @param {number} options
    * @returns {string}
    */
    formatMnemonicOptions(instruction, options) {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(instruction, Instruction);
            wasm.formatter_formatMnemonicOptions(retptr, this.__wbg_ptr, instruction.__wbg_ptr, options);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
    * Gets the number of operands that will be formatted. A formatter can add and remove operands
    *
    * # Arguments
    *
    * - `instruction`: Instruction
    * @param {Instruction} instruction
    * @returns {number}
    */
    operandCount(instruction) {
        _assertClass(instruction, Instruction);
        const ret = wasm.formatter_operandCount(this.__wbg_ptr, instruction.__wbg_ptr);
        return ret >>> 0;
    }
    /**
    * Converts a formatter operand index to an instruction operand index. Returns `undefined` if it's an operand added by the formatter
    *
    * # Throws
    *
    * Throws if `operand` is invalid
    *
    * # Arguments
    *
    * - `instruction`: Instruction
    * - `operand`: Operand number, 0-based. This is a formatter operand and isn't necessarily the same as an instruction operand. See [`operandCount`]
    *
    * [`operandCount`]: #method.operand_count
    * @param {Instruction} instruction
    * @param {number} operand
    * @returns {number | undefined}
    */
    getInstructionOperand(instruction, operand) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(instruction, Instruction);
            wasm.formatter_getInstructionOperand(retptr, this.__wbg_ptr, instruction.__wbg_ptr, operand);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            return r0 === 0 ? undefined : r1 >>> 0;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * Converts an instruction operand index to a formatter operand index. Returns `undefined` if the instruction operand isn't used by the formatter
    *
    * # Throws
    *
    * Throws if `instructionOperand` is invalid
    *
    * # Arguments
    *
    * - `instruction`: Instruction
    * - `instructionOperand`: Instruction operand
    * @param {Instruction} instruction
    * @param {number} instructionOperand
    * @returns {number | undefined}
    */
    getFormatterOperand(instruction, instructionOperand) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(instruction, Instruction);
            wasm.formatter_getFormatterOperand(retptr, this.__wbg_ptr, instruction.__wbg_ptr, instructionOperand);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            return r0 === 0 ? undefined : r1 >>> 0;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * Formats an operand. This is a formatter operand and not necessarily a real instruction operand.
    * A formatter can add and remove operands.
    *
    * # Throws
    *
    * Throws if `operand` is invalid
    *
    * # Arguments
    *
    * - `instruction`: Instruction
    * - `operand`: Operand number, 0-based. This is a formatter operand and isn't necessarily the same as an instruction operand. See [`operandCount`]
    *
    * [`operandCount`]: #method.operand_count
    * @param {Instruction} instruction
    * @param {number} operand
    * @returns {string}
    */
    formatOperand(instruction, operand) {
        let deferred2_0;
        let deferred2_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(instruction, Instruction);
            wasm.formatter_formatOperand(retptr, this.__wbg_ptr, instruction.__wbg_ptr, operand);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            var ptr1 = r0;
            var len1 = r1;
            if (r3) {
                ptr1 = 0; len1 = 0;
                throw takeObject(r2);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
    * Formats an operand separator
    *
    * # Arguments
    *
    * - `instruction`: Instruction
    * @param {Instruction} instruction
    * @returns {string}
    */
    formatOperandSeparator(instruction) {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(instruction, Instruction);
            wasm.formatter_formatOperandSeparator(retptr, this.__wbg_ptr, instruction.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
    * Formats all operands
    *
    * # Arguments
    *
    * - `instruction`: Instruction
    * @param {Instruction} instruction
    * @returns {string}
    */
    formatAllOperands(instruction) {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(instruction, Instruction);
            wasm.formatter_formatAllOperands(retptr, this.__wbg_ptr, instruction.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
    * Formats a `i8`
    *
    * # Arguments
    *
    * - `value`: Value
    * @param {number} value
    * @returns {string}
    */
    formatI8(value) {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.formatter_formatI8(retptr, this.__wbg_ptr, value);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
    * Formats a `i16`
    *
    * # Arguments
    *
    * - `value`: Value
    * @param {number} value
    * @returns {string}
    */
    formatI16(value) {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.formatter_formatI16(retptr, this.__wbg_ptr, value);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
    * Formats a `i32`
    *
    * # Arguments
    *
    * - `value`: Value
    * @param {number} value
    * @returns {string}
    */
    formatI32(value) {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.formatter_formatI32(retptr, this.__wbg_ptr, value);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
    * Formats a `i64`
    *
    * # Arguments
    *
    * - `value`: Value
    * @param {bigint} value
    * @returns {string}
    */
    formatI64(value) {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.formatter_formatI64(retptr, this.__wbg_ptr, value);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
    * Formats a `u8`
    *
    * # Arguments
    *
    * - `value`: Value
    * @param {number} value
    * @returns {string}
    */
    formatU8(value) {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.formatter_formatU8(retptr, this.__wbg_ptr, value);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
    * Formats a `u16`
    *
    * # Arguments
    *
    * - `value`: Value
    * @param {number} value
    * @returns {string}
    */
    formatU16(value) {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.formatter_formatU16(retptr, this.__wbg_ptr, value);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
    * Formats a `u32`
    *
    * # Arguments
    *
    * - `value`: Value
    * @param {number} value
    * @returns {string}
    */
    formatU32(value) {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.formatter_formatU32(retptr, this.__wbg_ptr, value);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
    * Formats a `u64`
    *
    * # Arguments
    *
    * - `value`: Value
    * @param {bigint} value
    * @returns {string}
    */
    formatU64(value) {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.formatter_formatU64(retptr, this.__wbg_ptr, value);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
    * Prefixes are uppercased
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `REP stosd`
    * 👍 | `false` | `rep stosd`
    * @returns {boolean}
    */
    get uppercasePrefixes() {
        const ret = wasm.formatter_uppercasePrefixes(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
    * Prefixes are uppercased
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `REP stosd`
    * 👍 | `false` | `rep stosd`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {boolean} value
    */
    set uppercasePrefixes(value) {
        wasm.formatter_set_uppercasePrefixes(this.__wbg_ptr, value);
    }
    /**
    * Mnemonics are uppercased
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `MOV rcx,rax`
    * 👍 | `false` | `mov rcx,rax`
    * @returns {boolean}
    */
    get uppercaseMnemonics() {
        const ret = wasm.formatter_uppercaseMnemonics(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
    * Mnemonics are uppercased
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `MOV rcx,rax`
    * 👍 | `false` | `mov rcx,rax`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {boolean} value
    */
    set uppercaseMnemonics(value) {
        wasm.formatter_set_uppercaseMnemonics(this.__wbg_ptr, value);
    }
    /**
    * Registers are uppercased
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `mov RCX,[RAX+RDX*8]`
    * 👍 | `false` | `mov rcx,[rax+rdx*8]`
    * @returns {boolean}
    */
    get uppercaseRegisters() {
        const ret = wasm.formatter_uppercaseRegisters(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
    * Registers are uppercased
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `mov RCX,[RAX+RDX*8]`
    * 👍 | `false` | `mov rcx,[rax+rdx*8]`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {boolean} value
    */
    set uppercaseRegisters(value) {
        wasm.formatter_set_uppercaseRegisters(this.__wbg_ptr, value);
    }
    /**
    * Keywords are uppercased (eg. `BYTE PTR`, `SHORT`)
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `mov BYTE PTR [rcx],12h`
    * 👍 | `false` | `mov byte ptr [rcx],12h`
    * @returns {boolean}
    */
    get uppercaseKeywords() {
        const ret = wasm.formatter_uppercaseKeywords(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
    * Keywords are uppercased (eg. `BYTE PTR`, `SHORT`)
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `mov BYTE PTR [rcx],12h`
    * 👍 | `false` | `mov byte ptr [rcx],12h`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {boolean} value
    */
    set uppercaseKeywords(value) {
        wasm.formatter_set_uppercaseKeywords(this.__wbg_ptr, value);
    }
    /**
    * Uppercase decorators, eg. `{z}`, `{sae}`, `{rd-sae}` (but not opmask registers: `{k1}`)
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `vunpcklps xmm2{k5}{Z},xmm6,dword bcst [rax+4]`
    * 👍 | `false` | `vunpcklps xmm2{k5}{z},xmm6,dword bcst [rax+4]`
    * @returns {boolean}
    */
    get uppercaseDecorators() {
        const ret = wasm.formatter_uppercaseDecorators(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
    * Uppercase decorators, eg. `{z}`, `{sae}`, `{rd-sae}` (but not opmask registers: `{k1}`)
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `vunpcklps xmm2{k5}{Z},xmm6,dword bcst [rax+4]`
    * 👍 | `false` | `vunpcklps xmm2{k5}{z},xmm6,dword bcst [rax+4]`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {boolean} value
    */
    set uppercaseDecorators(value) {
        wasm.formatter_set_uppercaseDecorators(this.__wbg_ptr, value);
    }
    /**
    * Everything is uppercased, except numbers and their prefixes/suffixes
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `MOV EAX,GS:[RCX*4+0ffh]`
    * 👍 | `false` | `mov eax,gs:[rcx*4+0ffh]`
    * @returns {boolean}
    */
    get uppercaseAll() {
        const ret = wasm.formatter_uppercaseAll(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
    * Everything is uppercased, except numbers and their prefixes/suffixes
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `MOV EAX,GS:[RCX*4+0ffh]`
    * 👍 | `false` | `mov eax,gs:[rcx*4+0ffh]`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {boolean} value
    */
    set uppercaseAll(value) {
        wasm.formatter_set_uppercaseAll(this.__wbg_ptr, value);
    }
    /**
    * Character index (0-based) where the first operand is formatted. Can be set to 0 to format it immediately after the mnemonic.
    * At least one space or tab is always added between the mnemonic and the first operand.
    *
    * Default | Value | Example
    * --------|-------|--------
    * 👍 | `0` | `mov•rcx,rbp`
    * _ | `8` | `mov•••••rcx,rbp`
    * @returns {number}
    */
    get firstOperandCharIndex() {
        const ret = wasm.formatter_firstOperandCharIndex(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
    * Character index (0-based) where the first operand is formatted. Can be set to 0 to format it immediately after the mnemonic.
    * At least one space or tab is always added between the mnemonic and the first operand.
    *
    * Default | Value | Example
    * --------|-------|--------
    * 👍 | `0` | `mov•rcx,rbp`
    * _ | `8` | `mov•••••rcx,rbp`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {number} value
    */
    set firstOperandCharIndex(value) {
        wasm.formatter_set_firstOperandCharIndex(this.__wbg_ptr, value);
    }
    /**
    * Size of a tab character or 0 to use spaces
    *
    * - Default: `0`
    * @returns {number}
    */
    get tabSize() {
        const ret = wasm.formatter_tabSize(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
    * Size of a tab character or 0 to use spaces
    *
    * - Default: `0`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {number} value
    */
    set tabSize(value) {
        wasm.formatter_set_tabSize(this.__wbg_ptr, value);
    }
    /**
    * Add a space after the operand separator
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `mov rax, rcx`
    * 👍 | `false` | `mov rax,rcx`
    * @returns {boolean}
    */
    get spaceAfterOperandSeparator() {
        const ret = wasm.formatter_spaceAfterOperandSeparator(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
    * Add a space after the operand separator
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `mov rax, rcx`
    * 👍 | `false` | `mov rax,rcx`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {boolean} value
    */
    set spaceAfterOperandSeparator(value) {
        wasm.formatter_set_spaceAfterOperandSeparator(this.__wbg_ptr, value);
    }
    /**
    * Add a space between the memory expression and the brackets
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `mov eax,[ rcx+rdx ]`
    * 👍 | `false` | `mov eax,[rcx+rdx]`
    * @returns {boolean}
    */
    get spaceAfterMemoryBracket() {
        const ret = wasm.formatter_spaceAfterMemoryBracket(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
    * Add a space between the memory expression and the brackets
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `mov eax,[ rcx+rdx ]`
    * 👍 | `false` | `mov eax,[rcx+rdx]`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {boolean} value
    */
    set spaceAfterMemoryBracket(value) {
        wasm.formatter_set_spaceAfterMemoryBracket(this.__wbg_ptr, value);
    }
    /**
    * Add spaces between memory operand `+` and `-` operators
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `mov eax,[rcx + rdx*8 - 80h]`
    * 👍 | `false` | `mov eax,[rcx+rdx*8-80h]`
    * @returns {boolean}
    */
    get spaceBetweenMemoryAddOperators() {
        const ret = wasm.formatter_spaceBetweenMemoryAddOperators(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
    * Add spaces between memory operand `+` and `-` operators
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `mov eax,[rcx + rdx*8 - 80h]`
    * 👍 | `false` | `mov eax,[rcx+rdx*8-80h]`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {boolean} value
    */
    set spaceBetweenMemoryAddOperators(value) {
        wasm.formatter_set_spaceBetweenMemoryAddOperators(this.__wbg_ptr, value);
    }
    /**
    * Add spaces between memory operand `*` operator
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `mov eax,[rcx+rdx * 8-80h]`
    * 👍 | `false` | `mov eax,[rcx+rdx*8-80h]`
    * @returns {boolean}
    */
    get spaceBetweenMemoryMulOperators() {
        const ret = wasm.formatter_spaceBetweenMemoryMulOperators(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
    * Add spaces between memory operand `*` operator
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `mov eax,[rcx+rdx * 8-80h]`
    * 👍 | `false` | `mov eax,[rcx+rdx*8-80h]`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {boolean} value
    */
    set spaceBetweenMemoryMulOperators(value) {
        wasm.formatter_set_spaceBetweenMemoryMulOperators(this.__wbg_ptr, value);
    }
    /**
    * Show memory operand scale value before the index register
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `mov eax,[8*rdx]`
    * 👍 | `false` | `mov eax,[rdx*8]`
    * @returns {boolean}
    */
    get scaleBeforeIndex() {
        const ret = wasm.formatter_scaleBeforeIndex(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
    * Show memory operand scale value before the index register
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `mov eax,[8*rdx]`
    * 👍 | `false` | `mov eax,[rdx*8]`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {boolean} value
    */
    set scaleBeforeIndex(value) {
        wasm.formatter_set_scaleBeforeIndex(this.__wbg_ptr, value);
    }
    /**
    * Always show the scale value even if it's `*1`
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `mov eax,[rbx+rcx*1]`
    * 👍 | `false` | `mov eax,[rbx+rcx]`
    * @returns {boolean}
    */
    get alwaysShowScale() {
        const ret = wasm.formatter_alwaysShowScale(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
    * Always show the scale value even if it's `*1`
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `mov eax,[rbx+rcx*1]`
    * 👍 | `false` | `mov eax,[rbx+rcx]`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {boolean} value
    */
    set alwaysShowScale(value) {
        wasm.formatter_set_alwaysShowScale(this.__wbg_ptr, value);
    }
    /**
    * Always show the effective segment register. If the option is `false`, only show the segment register if
    * there's a segment override prefix.
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `mov eax,ds:[ecx]`
    * 👍 | `false` | `mov eax,[ecx]`
    * @returns {boolean}
    */
    get alwaysShowSegmentRegister() {
        const ret = wasm.formatter_alwaysShowSegmentRegister(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
    * Always show the effective segment register. If the option is `false`, only show the segment register if
    * there's a segment override prefix.
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `mov eax,ds:[ecx]`
    * 👍 | `false` | `mov eax,[ecx]`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {boolean} value
    */
    set alwaysShowSegmentRegister(value) {
        wasm.formatter_set_alwaysShowSegmentRegister(this.__wbg_ptr, value);
    }
    /**
    * Show zero displacements
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `mov eax,[rcx*2+0]`
    * 👍 | `false` | `mov eax,[rcx*2]`
    * @returns {boolean}
    */
    get showZeroDisplacements() {
        const ret = wasm.formatter_showZeroDisplacements(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
    * Show zero displacements
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `mov eax,[rcx*2+0]`
    * 👍 | `false` | `mov eax,[rcx*2]`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {boolean} value
    */
    set showZeroDisplacements(value) {
        wasm.formatter_set_showZeroDisplacements(this.__wbg_ptr, value);
    }
    /**
    * Hex number prefix or an empty string, eg. `"0x"`
    *
    * - Default: `""` (masm/nasm/intel), `"0x"` (gas)
    * @returns {string}
    */
    get hexPrefix() {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.formatter_hexPrefix(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
    * Hex number prefix or an empty string, eg. `"0x"`
    *
    * - Default: `""` (masm/nasm/intel), `"0x"` (gas)
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {string} value
    */
    set hexPrefix(value) {
        const ptr0 = passStringToWasm0(value, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.formatter_set_hexPrefix(this.__wbg_ptr, ptr0, len0);
    }
    /**
    * Hex number suffix or an empty string, eg. `"h"`
    *
    * - Default: `"h"` (masm/nasm/intel), `""` (gas)
    * @returns {string}
    */
    get hexSuffix() {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.formatter_hexSuffix(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
    * Hex number suffix or an empty string, eg. `"h"`
    *
    * - Default: `"h"` (masm/nasm/intel), `""` (gas)
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {string} value
    */
    set hexSuffix(value) {
        const ptr0 = passStringToWasm0(value, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.formatter_set_hexSuffix(this.__wbg_ptr, ptr0, len0);
    }
    /**
    * Size of a digit group, see also [`digitSeparator`]
    *
    * [`digitSeparator`]: #method.digit_separator
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `0` | `0x12345678`
    * 👍 | `4` | `0x1234_5678`
    * @returns {number}
    */
    get hexDigitGroupSize() {
        const ret = wasm.formatter_hexDigitGroupSize(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
    * Size of a digit group, see also [`digitSeparator`]
    *
    * [`digitSeparator`]: #method.digit_separator
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `0` | `0x12345678`
    * 👍 | `4` | `0x1234_5678`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {number} value
    */
    set hexDigitGroupSize(value) {
        wasm.formatter_set_hexDigitGroupSize(this.__wbg_ptr, value);
    }
    /**
    * Decimal number prefix or an empty string
    *
    * - Default: `""`
    * @returns {string}
    */
    get decimalPrefix() {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.formatter_decimalPrefix(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
    * Decimal number prefix or an empty string
    *
    * - Default: `""`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {string} value
    */
    set decimalPrefix(value) {
        const ptr0 = passStringToWasm0(value, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.formatter_set_decimalPrefix(this.__wbg_ptr, ptr0, len0);
    }
    /**
    * Decimal number suffix or an empty string
    *
    * - Default: `""`
    * @returns {string}
    */
    get decimalSuffix() {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.formatter_decimalSuffix(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
    * Decimal number suffix or an empty string
    *
    * - Default: `""`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {string} value
    */
    set decimalSuffix(value) {
        const ptr0 = passStringToWasm0(value, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.formatter_set_decimalSuffix(this.__wbg_ptr, ptr0, len0);
    }
    /**
    * Size of a digit group, see also [`digitSeparator`]
    *
    * [`digitSeparator`]: #method.digit_separator
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `0` | `12345678`
    * 👍 | `3` | `12_345_678`
    * @returns {number}
    */
    get decimalDigitGroupSize() {
        const ret = wasm.formatter_decimalDigitGroupSize(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
    * Size of a digit group, see also [`digitSeparator`]
    *
    * [`digitSeparator`]: #method.digit_separator
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `0` | `12345678`
    * 👍 | `3` | `12_345_678`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {number} value
    */
    set decimalDigitGroupSize(value) {
        wasm.formatter_set_decimalDigitGroupSize(this.__wbg_ptr, value);
    }
    /**
    * Octal number prefix or an empty string
    *
    * - Default: `""` (masm/nasm/intel), `"0"` (gas)
    * @returns {string}
    */
    get octalPrefix() {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.formatter_octalPrefix(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
    * Octal number prefix or an empty string
    *
    * - Default: `""` (masm/nasm/intel), `"0"` (gas)
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {string} value
    */
    set octalPrefix(value) {
        const ptr0 = passStringToWasm0(value, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.formatter_set_octalPrefix(this.__wbg_ptr, ptr0, len0);
    }
    /**
    * Octal number suffix or an empty string
    *
    * - Default: `"o"` (masm/nasm/intel), `""` (gas)
    * @returns {string}
    */
    get octalSuffix() {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.formatter_octalSuffix(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
    * Octal number suffix or an empty string
    *
    * - Default: `"o"` (masm/nasm/intel), `""` (gas)
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {string} value
    */
    set octalSuffix(value) {
        const ptr0 = passStringToWasm0(value, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.formatter_set_octalSuffix(this.__wbg_ptr, ptr0, len0);
    }
    /**
    * Size of a digit group, see also [`digitSeparator`]
    *
    * [`digitSeparator`]: #method.digit_separator
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `0` | `12345670`
    * 👍 | `4` | `1234_5670`
    * @returns {number}
    */
    get octalDigitGroupSize() {
        const ret = wasm.formatter_octalDigitGroupSize(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
    * Size of a digit group, see also [`digitSeparator`]
    *
    * [`digitSeparator`]: #method.digit_separator
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `0` | `12345670`
    * 👍 | `4` | `1234_5670`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {number} value
    */
    set octalDigitGroupSize(value) {
        wasm.formatter_set_octalDigitGroupSize(this.__wbg_ptr, value);
    }
    /**
    * Binary number prefix or an empty string
    *
    * - Default: `""` (masm/nasm/intel), `"0b"` (gas)
    * @returns {string}
    */
    get binaryPrefix() {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.formatter_binaryPrefix(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
    * Binary number prefix or an empty string
    *
    * - Default: `""` (masm/nasm/intel), `"0b"` (gas)
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {string} value
    */
    set binaryPrefix(value) {
        const ptr0 = passStringToWasm0(value, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.formatter_set_binaryPrefix(this.__wbg_ptr, ptr0, len0);
    }
    /**
    * Binary number suffix or an empty string
    *
    * - Default: `"b"` (masm/nasm/intel), `""` (gas)
    * @returns {string}
    */
    get binarySuffix() {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.formatter_binarySuffix(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
    * Binary number suffix or an empty string
    *
    * - Default: `"b"` (masm/nasm/intel), `""` (gas)
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {string} value
    */
    set binarySuffix(value) {
        const ptr0 = passStringToWasm0(value, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.formatter_set_binarySuffix(this.__wbg_ptr, ptr0, len0);
    }
    /**
    * Size of a digit group, see also [`digitSeparator`]
    *
    * [`digitSeparator`]: #method.digit_separator
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `0` | `11010111`
    * 👍 | `4` | `1101_0111`
    * @returns {number}
    */
    get binaryDigitGroupSize() {
        const ret = wasm.formatter_binaryDigitGroupSize(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
    * Size of a digit group, see also [`digitSeparator`]
    *
    * [`digitSeparator`]: #method.digit_separator
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `0` | `11010111`
    * 👍 | `4` | `1101_0111`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {number} value
    */
    set binaryDigitGroupSize(value) {
        wasm.formatter_set_binaryDigitGroupSize(this.__wbg_ptr, value);
    }
    /**
    * Digit separator or an empty string. See also eg. [`hexDigitGroupSize`]
    *
    * [`hexDigitGroupSize`]: #method.hex_digit_group_size
    *
    * Default | Value | Example
    * --------|-------|--------
    * 👍 | `""` | `0x12345678`
    * _ | `"_"` | `0x1234_5678`
    * @returns {string}
    */
    get digitSeparator() {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.formatter_digitSeparator(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
    * Digit separator or an empty string. See also eg. [`hexDigitGroupSize`]
    *
    * [`hexDigitGroupSize`]: #method.hex_digit_group_size
    *
    * Default | Value | Example
    * --------|-------|--------
    * 👍 | `""` | `0x12345678`
    * _ | `"_"` | `0x1234_5678`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {string} value
    */
    set digitSeparator(value) {
        const ptr0 = passStringToWasm0(value, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.formatter_set_digitSeparator(this.__wbg_ptr, ptr0, len0);
    }
    /**
    * Add leading zeros to hexadecimal/octal/binary numbers.
    * This option has no effect on branch targets and displacements, use [`branchLeadingZeros`]
    * and [`displacementLeadingZeros`].
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `0x0000000A`/`0000000Ah`
    * 👍 | `false` | `0xA`/`0Ah`
    *
    * [`branchLeadingZeros`]: #method.branch_leading_zeros
    * [`displacementLeadingZeros`]: #method.displacement_leading_zeros
    * @returns {boolean}
    */
    get leadingZeros() {
        const ret = wasm.formatter_leadingZeros(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
    * Add leading zeros to hexadecimal/octal/binary numbers.
    * This option has no effect on branch targets and displacements, use [`branchLeadingZeros`]
    * and [`displacementLeadingZeros`].
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `0x0000000A`/`0000000Ah`
    * 👍 | `false` | `0xA`/`0Ah`
    *
    * [`branchLeadingZeros`]: #method.branch_leading_zeros
    * [`displacementLeadingZeros`]: #method.displacement_leading_zeros
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {boolean} value
    */
    set leadingZeros(value) {
        wasm.formatter_set_leadingZeros(this.__wbg_ptr, value);
    }
    /**
    * Use uppercase hex digits
    *
    * Default | Value | Example
    * --------|-------|--------
    * 👍 | `true` | `0xFF`
    * _ | `false` | `0xff`
    * @returns {boolean}
    */
    get uppercaseHex() {
        const ret = wasm.formatter_uppercaseHex(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
    * Use uppercase hex digits
    *
    * Default | Value | Example
    * --------|-------|--------
    * 👍 | `true` | `0xFF`
    * _ | `false` | `0xff`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {boolean} value
    */
    set uppercaseHex(value) {
        wasm.formatter_set_uppercaseHex(this.__wbg_ptr, value);
    }
    /**
    * Small hex numbers (-9 .. 9) are shown in decimal
    *
    * Default | Value | Example
    * --------|-------|--------
    * 👍 | `true` | `9`
    * _ | `false` | `0x9`
    * @returns {boolean}
    */
    get smallHexNumbersInDecimal() {
        const ret = wasm.formatter_smallHexNumbersInDecimal(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
    * Small hex numbers (-9 .. 9) are shown in decimal
    *
    * Default | Value | Example
    * --------|-------|--------
    * 👍 | `true` | `9`
    * _ | `false` | `0x9`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {boolean} value
    */
    set smallHexNumbersInDecimal(value) {
        wasm.formatter_set_smallHexNumbersInDecimal(this.__wbg_ptr, value);
    }
    /**
    * Add a leading zero to hex numbers if there's no prefix and the number starts with hex digits `A-F`
    *
    * Default | Value | Example
    * --------|-------|--------
    * 👍 | `true` | `0FFh`
    * _ | `false` | `FFh`
    * @returns {boolean}
    */
    get addLeadingZeroToHexNumbers() {
        const ret = wasm.formatter_addLeadingZeroToHexNumbers(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
    * Add a leading zero to hex numbers if there's no prefix and the number starts with hex digits `A-F`
    *
    * Default | Value | Example
    * --------|-------|--------
    * 👍 | `true` | `0FFh`
    * _ | `false` | `FFh`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {boolean} value
    */
    set addLeadingZeroToHexNumbers(value) {
        wasm.formatter_set_addLeadingZeroToHexNumbers(this.__wbg_ptr, value);
    }
    /**
    * Number base (`2`, `8`, `10`, `16`)
    *
    * - Default: `16`
    * @returns {number}
    */
    get numberBase() {
        const ret = wasm.formatter_numberBase(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
    * Number base (`2`, `8`, `10`, `16`)
    *
    * - Default: `16`
    *
    * # Throws
    *
    * Throws if `value` is not `2`, `8`, `10`, `16`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {number} value
    */
    set numberBase(value) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.formatter_set_numberBase(retptr, this.__wbg_ptr, value);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            if (r1) {
                throw takeObject(r0);
            }
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * Add leading zeros to branch offsets. Used by `CALL NEAR`, `CALL FAR`, `JMP NEAR`, `JMP FAR`, `Jcc`, `LOOP`, `LOOPcc`, `XBEGIN`
    *
    * Default | Value | Example
    * --------|-------|--------
    * 👍 | `true` | `je 00000123h`
    * _ | `false` | `je 123h`
    * @returns {boolean}
    */
    get branchLeadingZeros() {
        const ret = wasm.formatter_branchLeadingZeros(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
    * Add leading zeros to branch offsets. Used by `CALL NEAR`, `CALL FAR`, `JMP NEAR`, `JMP FAR`, `Jcc`, `LOOP`, `LOOPcc`, `XBEGIN`
    *
    * Default | Value | Example
    * --------|-------|--------
    * 👍 | `true` | `je 00000123h`
    * _ | `false` | `je 123h`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {boolean} value
    */
    set branchLeadingZeros(value) {
        wasm.formatter_set_branchLeadingZeros(this.__wbg_ptr, value);
    }
    /**
    * Show immediate operands as signed numbers
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `mov eax,-1`
    * 👍 | `false` | `mov eax,FFFFFFFF`
    * @returns {boolean}
    */
    get signedImmediateOperands() {
        const ret = wasm.formatter_signedImmediateOperands(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
    * Show immediate operands as signed numbers
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `mov eax,-1`
    * 👍 | `false` | `mov eax,FFFFFFFF`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {boolean} value
    */
    set signedImmediateOperands(value) {
        wasm.formatter_set_signedImmediateOperands(this.__wbg_ptr, value);
    }
    /**
    * Displacements are signed numbers
    *
    * Default | Value | Example
    * --------|-------|--------
    * 👍 | `true` | `mov al,[eax-2000h]`
    * _ | `false` | `mov al,[eax+0FFFFE000h]`
    * @returns {boolean}
    */
    get signedMemoryDisplacements() {
        const ret = wasm.formatter_signedMemoryDisplacements(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
    * Displacements are signed numbers
    *
    * Default | Value | Example
    * --------|-------|--------
    * 👍 | `true` | `mov al,[eax-2000h]`
    * _ | `false` | `mov al,[eax+0FFFFE000h]`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {boolean} value
    */
    set signedMemoryDisplacements(value) {
        wasm.formatter_set_signedMemoryDisplacements(this.__wbg_ptr, value);
    }
    /**
    * Add leading zeros to displacements
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `mov al,[eax+00000012h]`
    * 👍 | `false` | `mov al,[eax+12h]`
    * @returns {boolean}
    */
    get displacementLeadingZeros() {
        const ret = wasm.formatter_displacementLeadingZeros(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
    * Add leading zeros to displacements
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `mov al,[eax+00000012h]`
    * 👍 | `false` | `mov al,[eax+12h]`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {boolean} value
    */
    set displacementLeadingZeros(value) {
        wasm.formatter_set_displacementLeadingZeros(this.__wbg_ptr, value);
    }
    /**
    * Options (a [`MemorySizeOptions`] flags value) that control if the memory size (eg. `DWORD PTR`) is shown or not.
    * This is ignored by the gas (AT&T) formatter.
    *
    * - Default: [`Default`]
    *
    * [`MemorySizeOptions`]: enum.MemorySizeOptions.html
    * [`Default`]: enum.MemorySizeOptions.html#variant.Default
    * @returns {MemorySizeOptions}
    */
    get memorySizeOptions() {
        const ret = wasm.formatter_memorySizeOptions(this.__wbg_ptr);
        return ret;
    }
    /**
    * Options (a [`MemorySizeOptions`] flags value) that control if the memory size (eg. `DWORD PTR`) is shown or not.
    * This is ignored by the gas (AT&T) formatter.
    *
    * - Default: [`Default`]
    *
    * [`MemorySizeOptions`]: enum.MemorySizeOptions.html
    * [`Default`]: enum.MemorySizeOptions.html#variant.Default
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {MemorySizeOptions} value
    */
    set memorySizeOptions(value) {
        wasm.formatter_set_memorySizeOptions(this.__wbg_ptr, value);
    }
    /**
    * Show `RIP+displ` or the virtual address
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `mov eax,[rip+12345678h]`
    * 👍 | `false` | `mov eax,[1029384756AFBECDh]`
    * @returns {boolean}
    */
    get ripRelativeAddresses() {
        const ret = wasm.formatter_ripRelativeAddresses(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
    * Show `RIP+displ` or the virtual address
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `mov eax,[rip+12345678h]`
    * 👍 | `false` | `mov eax,[1029384756AFBECDh]`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {boolean} value
    */
    set ripRelativeAddresses(value) {
        wasm.formatter_set_ripRelativeAddresses(this.__wbg_ptr, value);
    }
    /**
    * Show `NEAR`, `SHORT`, etc if it's a branch instruction
    *
    * Default | Value | Example
    * --------|-------|--------
    * 👍 | `true` | `je short 1234h`
    * _ | `false` | `je 1234h`
    * @returns {boolean}
    */
    get showBranchSize() {
        const ret = wasm.formatter_showBranchSize(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
    * Show `NEAR`, `SHORT`, etc if it's a branch instruction
    *
    * Default | Value | Example
    * --------|-------|--------
    * 👍 | `true` | `je short 1234h`
    * _ | `false` | `je 1234h`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {boolean} value
    */
    set showBranchSize(value) {
        wasm.formatter_set_showBranchSize(this.__wbg_ptr, value);
    }
    /**
    * Use pseudo instructions
    *
    * Default | Value | Example
    * --------|-------|--------
    * 👍 | `true` | `vcmpnltsd xmm2,xmm6,xmm3`
    * _ | `false` | `vcmpsd xmm2,xmm6,xmm3,5`
    * @returns {boolean}
    */
    get usePseudoOps() {
        const ret = wasm.formatter_usePseudoOps(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
    * Use pseudo instructions
    *
    * Default | Value | Example
    * --------|-------|--------
    * 👍 | `true` | `vcmpnltsd xmm2,xmm6,xmm3`
    * _ | `false` | `vcmpsd xmm2,xmm6,xmm3,5`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {boolean} value
    */
    set usePseudoOps(value) {
        wasm.formatter_set_usePseudoOps(this.__wbg_ptr, value);
    }
    /**
    * Show the original value after the symbol name
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `mov eax,[myfield (12345678)]`
    * 👍 | `false` | `mov eax,[myfield]`
    * @returns {boolean}
    */
    get showSymbolAddress() {
        const ret = wasm.formatter_showSymbolAddress(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
    * Show the original value after the symbol name
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `mov eax,[myfield (12345678)]`
    * 👍 | `false` | `mov eax,[myfield]`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {boolean} value
    */
    set showSymbolAddress(value) {
        wasm.formatter_set_showSymbolAddress(this.__wbg_ptr, value);
    }
    /**
    * (gas only): If `true`, the formatter doesn't add `%` to registers
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `mov eax,ecx`
    * 👍 | `false` | `mov %eax,%ecx`
    * @returns {boolean}
    */
    get gasNakedRegisters() {
        const ret = wasm.formatter_gasNakedRegisters(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
    * (gas only): If `true`, the formatter doesn't add `%` to registers
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `mov eax,ecx`
    * 👍 | `false` | `mov %eax,%ecx`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {boolean} value
    */
    set gasNakedRegisters(value) {
        wasm.formatter_set_gasNakedRegisters(this.__wbg_ptr, value);
    }
    /**
    * (gas only): Shows the mnemonic size suffix even when not needed
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `movl %eax,%ecx`
    * 👍 | `false` | `mov %eax,%ecx`
    * @returns {boolean}
    */
    get gasShowMnemonicSizeSuffix() {
        const ret = wasm.formatter_gasShowMnemonicSizeSuffix(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
    * (gas only): Shows the mnemonic size suffix even when not needed
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `movl %eax,%ecx`
    * 👍 | `false` | `mov %eax,%ecx`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {boolean} value
    */
    set gasShowMnemonicSizeSuffix(value) {
        wasm.formatter_set_gasShowMnemonicSizeSuffix(this.__wbg_ptr, value);
    }
    /**
    * (gas only): Add a space after the comma if it's a memory operand
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `(%eax, %ecx, 2)`
    * 👍 | `false` | `(%eax,%ecx,2)`
    * @returns {boolean}
    */
    get gasSpaceAfterMemoryOperandComma() {
        const ret = wasm.formatter_gasSpaceAfterMemoryOperandComma(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
    * (gas only): Add a space after the comma if it's a memory operand
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `(%eax, %ecx, 2)`
    * 👍 | `false` | `(%eax,%ecx,2)`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {boolean} value
    */
    set gasSpaceAfterMemoryOperandComma(value) {
        wasm.formatter_set_gasSpaceAfterMemoryOperandComma(this.__wbg_ptr, value);
    }
    /**
    * (masm only): Add a `DS` segment override even if it's not present. Used if it's 16/32-bit code and mem op is a displ
    *
    * Default | Value | Example
    * --------|-------|--------
    * 👍 | `true` | `mov eax,ds:[12345678]`
    * _ | `false` | `mov eax,[12345678]`
    * @returns {boolean}
    */
    get masmAddDsPrefix32() {
        const ret = wasm.formatter_masmAddDsPrefix32(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
    * (masm only): Add a `DS` segment override even if it's not present. Used if it's 16/32-bit code and mem op is a displ
    *
    * Default | Value | Example
    * --------|-------|--------
    * 👍 | `true` | `mov eax,ds:[12345678]`
    * _ | `false` | `mov eax,[12345678]`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {boolean} value
    */
    set masmAddDsPrefix32(value) {
        wasm.formatter_set_masmAddDsPrefix32(this.__wbg_ptr, value);
    }
    /**
    * (masm only): Show symbols in brackets
    *
    * Default | Value | Example
    * --------|-------|--------
    * 👍 | `true` | `[ecx+symbol]` / `[symbol]`
    * _ | `false` | `symbol[ecx]` / `symbol`
    * @returns {boolean}
    */
    get masmSymbolDisplInBrackets() {
        const ret = wasm.formatter_masmSymbolDisplInBrackets(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
    * (masm only): Show symbols in brackets
    *
    * Default | Value | Example
    * --------|-------|--------
    * 👍 | `true` | `[ecx+symbol]` / `[symbol]`
    * _ | `false` | `symbol[ecx]` / `symbol`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {boolean} value
    */
    set masmSymbolDisplInBrackets(value) {
        wasm.formatter_set_masmSymbolDisplInBrackets(this.__wbg_ptr, value);
    }
    /**
    * (masm only): Show displacements in brackets
    *
    * Default | Value | Example
    * --------|-------|--------
    * 👍 | `true` | `[ecx+1234h]`
    * _ | `false` | `1234h[ecx]`
    * @returns {boolean}
    */
    get masmDisplInBrackets() {
        const ret = wasm.formatter_masmDisplInBrackets(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
    * (masm only): Show displacements in brackets
    *
    * Default | Value | Example
    * --------|-------|--------
    * 👍 | `true` | `[ecx+1234h]`
    * _ | `false` | `1234h[ecx]`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {boolean} value
    */
    set masmDisplInBrackets(value) {
        wasm.formatter_set_masmDisplInBrackets(this.__wbg_ptr, value);
    }
    /**
    * (nasm only): Shows `BYTE`, `WORD`, `DWORD` or `QWORD` if it's a sign extended immediate operand value
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `or rcx,byte -1`
    * 👍 | `false` | `or rcx,-1`
    * @returns {boolean}
    */
    get nasmShowSignExtendedImmediateSize() {
        const ret = wasm.formatter_nasmShowSignExtendedImmediateSize(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
    * (nasm only): Shows `BYTE`, `WORD`, `DWORD` or `QWORD` if it's a sign extended immediate operand value
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `or rcx,byte -1`
    * 👍 | `false` | `or rcx,-1`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {boolean} value
    */
    set nasmShowSignExtendedImmediateSize(value) {
        wasm.formatter_set_nasmShowSignExtendedImmediateSize(this.__wbg_ptr, value);
    }
    /**
    * Use `st(0)` instead of `st` if `st` can be used. Ignored by the nasm formatter.
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `fadd st(0),st(3)`
    * 👍 | `false` | `fadd st,st(3)`
    * @returns {boolean}
    */
    get preferSt0() {
        const ret = wasm.formatter_preferSt0(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
    * Use `st(0)` instead of `st` if `st` can be used. Ignored by the nasm formatter.
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `fadd st(0),st(3)`
    * 👍 | `false` | `fadd st,st(3)`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {boolean} value
    */
    set preferSt0(value) {
        wasm.formatter_set_preferSt0(this.__wbg_ptr, value);
    }
    /**
    * Show useless prefixes. If it has useless prefixes, it could be data and not code.
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `es rep add eax,ecx`
    * 👍 | `false` | `add eax,ecx`
    * @returns {boolean}
    */
    get showUselessPrefixes() {
        const ret = wasm.formatter_showUselessPrefixes(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
    * Show useless prefixes. If it has useless prefixes, it could be data and not code.
    *
    * Default | Value | Example
    * --------|-------|--------
    * _ | `true` | `es rep add eax,ecx`
    * 👍 | `false` | `add eax,ecx`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {boolean} value
    */
    set showUselessPrefixes(value) {
        wasm.formatter_set_showUselessPrefixes(this.__wbg_ptr, value);
    }
    /**
    * Mnemonic condition code selector (eg. `JB` / `JC` / `JNAE`)
    *
    * The value is a [`CC_b`] enum value.
    *
    * [`CC_b`]: enum.CC_b.html
    *
    * Default: `JB`, `CMOVB`, `SETB`
    * @returns {CC_b}
    */
    get cc_b() {
        const ret = wasm.formatter_cc_b(this.__wbg_ptr);
        return ret;
    }
    /**
    * Mnemonic condition code selector (eg. `JB` / `JC` / `JNAE`)
    *
    * The value is a [`CC_b`] enum value.
    *
    * [`CC_b`]: enum.CC_b.html
    *
    * Default: `JB`, `CMOVB`, `SETB`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {CC_b} value
    */
    set cc_b(value) {
        wasm.formatter_set_cc_b(this.__wbg_ptr, value);
    }
    /**
    * Mnemonic condition code selector (eg. `JAE` / `JNB` / `JNC`)
    *
    * The value is a [`CC_ae`] enum value.
    *
    * [`CC_ae`]: enum.CC_ae.html
    *
    * Default: `JAE`, `CMOVAE`, `SETAE`
    * @returns {CC_ae}
    */
    get cc_ae() {
        const ret = wasm.formatter_cc_ae(this.__wbg_ptr);
        return ret;
    }
    /**
    * Mnemonic condition code selector (eg. `JAE` / `JNB` / `JNC`)
    *
    * The value is a [`CC_ae`] enum value.
    *
    * [`CC_ae`]: enum.CC_ae.html
    *
    * Default: `JAE`, `CMOVAE`, `SETAE`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {CC_ae} value
    */
    set cc_ae(value) {
        wasm.formatter_set_cc_ae(this.__wbg_ptr, value);
    }
    /**
    * Mnemonic condition code selector (eg. `JE` / `JZ`)
    *
    * The value is a [`CC_e`] enum value.
    *
    * [`CC_e`]: enum.CC_e.html
    *
    * Default: `JE`, `CMOVE`, `SETE`, `LOOPE`, `REPE`
    * @returns {CC_e}
    */
    get cc_e() {
        const ret = wasm.formatter_cc_e(this.__wbg_ptr);
        return ret;
    }
    /**
    * Mnemonic condition code selector (eg. `JE` / `JZ`)
    *
    * The value is a [`CC_e`] enum value.
    *
    * [`CC_e`]: enum.CC_e.html
    *
    * Default: `JE`, `CMOVE`, `SETE`, `LOOPE`, `REPE`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {CC_e} value
    */
    set cc_e(value) {
        wasm.formatter_set_cc_e(this.__wbg_ptr, value);
    }
    /**
    * Mnemonic condition code selector (eg. `JNE` / `JNZ`)
    *
    * The value is a [`CC_ne`] enum value.
    *
    * [`CC_ne`]: enum.CC_ne.html
    *
    * Default: `JNE`, `CMOVNE`, `SETNE`, `LOOPNE`, `REPNE`
    * @returns {CC_ne}
    */
    get cc_ne() {
        const ret = wasm.formatter_cc_ne(this.__wbg_ptr);
        return ret;
    }
    /**
    * Mnemonic condition code selector (eg. `JNE` / `JNZ`)
    *
    * The value is a [`CC_ne`] enum value.
    *
    * [`CC_ne`]: enum.CC_ne.html
    *
    * Default: `JNE`, `CMOVNE`, `SETNE`, `LOOPNE`, `REPNE`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {CC_ne} value
    */
    set cc_ne(value) {
        wasm.formatter_set_cc_ne(this.__wbg_ptr, value);
    }
    /**
    * Mnemonic condition code selector (eg. `JBE` / `JNA`)
    *
    * The value is a [`CC_be`] enum value.
    *
    * [`CC_be`]: enum.CC_be.html
    *
    * Default: `JBE`, `CMOVBE`, `SETBE`
    * @returns {CC_be}
    */
    get cc_be() {
        const ret = wasm.formatter_cc_be(this.__wbg_ptr);
        return ret;
    }
    /**
    * Mnemonic condition code selector (eg. `JBE` / `JNA`)
    *
    * The value is a [`CC_be`] enum value.
    *
    * [`CC_be`]: enum.CC_be.html
    *
    * Default: `JBE`, `CMOVBE`, `SETBE`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {CC_be} value
    */
    set cc_be(value) {
        wasm.formatter_set_cc_be(this.__wbg_ptr, value);
    }
    /**
    * Mnemonic condition code selector (eg. `JA` / `JNBE`)
    *
    * The value is a [`CC_a`] enum value.
    *
    * [`CC_a`]: enum.CC_a.html
    *
    * Default: `JA`, `CMOVA`, `SETA`
    * @returns {CC_a}
    */
    get cc_a() {
        const ret = wasm.formatter_cc_a(this.__wbg_ptr);
        return ret;
    }
    /**
    * Mnemonic condition code selector (eg. `JA` / `JNBE`)
    *
    * The value is a [`CC_a`] enum value.
    *
    * [`CC_a`]: enum.CC_a.html
    *
    * Default: `JA`, `CMOVA`, `SETA`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {CC_a} value
    */
    set cc_a(value) {
        wasm.formatter_set_cc_a(this.__wbg_ptr, value);
    }
    /**
    * Mnemonic condition code selector (eg. `JP` / `JPE`)
    *
    * The value is a [`CC_p`] enum value.
    *
    * [`CC_p`]: enum.CC_p.html
    *
    * Default: `JP`, `CMOVP`, `SETP`
    * @returns {CC_p}
    */
    get cc_p() {
        const ret = wasm.formatter_cc_p(this.__wbg_ptr);
        return ret;
    }
    /**
    * Mnemonic condition code selector (eg. `JP` / `JPE`)
    *
    * The value is a [`CC_p`] enum value.
    *
    * [`CC_p`]: enum.CC_p.html
    *
    * Default: `JP`, `CMOVP`, `SETP`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {CC_p} value
    */
    set cc_p(value) {
        wasm.formatter_set_cc_p(this.__wbg_ptr, value);
    }
    /**
    * Mnemonic condition code selector (eg. `JNP` / `JPO`)
    *
    * The value is a [`CC_np`] enum value.
    *
    * [`CC_np`]: enum.CC_np.html
    *
    * Default: `JNP`, `CMOVNP`, `SETNP`
    * @returns {CC_np}
    */
    get cc_np() {
        const ret = wasm.formatter_cc_np(this.__wbg_ptr);
        return ret;
    }
    /**
    * Mnemonic condition code selector (eg. `JNP` / `JPO`)
    *
    * The value is a [`CC_np`] enum value.
    *
    * [`CC_np`]: enum.CC_np.html
    *
    * Default: `JNP`, `CMOVNP`, `SETNP`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {CC_np} value
    */
    set cc_np(value) {
        wasm.formatter_set_cc_np(this.__wbg_ptr, value);
    }
    /**
    * Mnemonic condition code selector (eg. `JL` / `JNGE`)
    *
    * The value is a [`CC_l`] enum value.
    *
    * [`CC_l`]: enum.CC_l.html
    *
    * Default: `JL`, `CMOVL`, `SETL`
    * @returns {CC_l}
    */
    get cc_l() {
        const ret = wasm.formatter_cc_l(this.__wbg_ptr);
        return ret;
    }
    /**
    * Mnemonic condition code selector (eg. `JL` / `JNGE`)
    *
    * The value is a [`CC_l`] enum value.
    *
    * [`CC_l`]: enum.CC_l.html
    *
    * Default: `JL`, `CMOVL`, `SETL`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {CC_l} value
    */
    set cc_l(value) {
        wasm.formatter_set_cc_l(this.__wbg_ptr, value);
    }
    /**
    * Mnemonic condition code selector (eg. `JGE` / `JNL`)
    *
    * The value is a [`CC_ge`] enum value.
    *
    * [`CC_ge`]: enum.CC_ge.html
    *
    * Default: `JGE`, `CMOVGE`, `SETGE`
    * @returns {CC_ge}
    */
    get cc_ge() {
        const ret = wasm.formatter_cc_ge(this.__wbg_ptr);
        return ret;
    }
    /**
    * Mnemonic condition code selector (eg. `JGE` / `JNL`)
    *
    * The value is a [`CC_ge`] enum value.
    *
    * [`CC_ge`]: enum.CC_ge.html
    *
    * Default: `JGE`, `CMOVGE`, `SETGE`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {CC_ge} value
    */
    set cc_ge(value) {
        wasm.formatter_set_cc_ge(this.__wbg_ptr, value);
    }
    /**
    * Mnemonic condition code selector (eg. `JLE` / `JNG`)
    *
    * The value is a [`CC_le`] enum value.
    *
    * [`CC_le`]: enum.CC_le.html
    *
    * Default: `JLE`, `CMOVLE`, `SETLE`
    * @returns {CC_le}
    */
    get cc_le() {
        const ret = wasm.formatter_cc_le(this.__wbg_ptr);
        return ret;
    }
    /**
    * Mnemonic condition code selector (eg. `JLE` / `JNG`)
    *
    * The value is a [`CC_le`] enum value.
    *
    * [`CC_le`]: enum.CC_le.html
    *
    * Default: `JLE`, `CMOVLE`, `SETLE`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {CC_le} value
    */
    set cc_le(value) {
        wasm.formatter_set_cc_le(this.__wbg_ptr, value);
    }
    /**
    * Mnemonic condition code selector (eg. `JG` / `JNLE`)
    *
    * The value is a [`CC_g`] enum value.
    *
    * [`CC_g`]: enum.CC_g.html
    *
    * Default: `JG`, `CMOVG`, `SETG`
    * @returns {CC_g}
    */
    get cc_g() {
        const ret = wasm.formatter_cc_g(this.__wbg_ptr);
        return ret;
    }
    /**
    * Mnemonic condition code selector (eg. `JG` / `JNLE`)
    *
    * The value is a [`CC_g`] enum value.
    *
    * [`CC_g`]: enum.CC_g.html
    *
    * Default: `JG`, `CMOVG`, `SETG`
    *
    * # Arguments
    *
    * * `value`: New value
    * @param {CC_g} value
    */
    set cc_g(value) {
        wasm.formatter_set_cc_g(this.__wbg_ptr, value);
    }
}

const InstructionFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_instruction_free(ptr >>> 0, 1));
/**
* A 16/32/64-bit x86 instruction. Created by [`Decoder`] or by `Instruction.with*()` methods.
*
* [`Decoder`]: struct.Decoder.html
*/
export class Instruction {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(Instruction.prototype);
        obj.__wbg_ptr = ptr;
        InstructionFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        InstructionFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_instruction_free(ptr, 0);
    }
    /**
    * Creates an empty `Instruction` (all fields are cleared). See also the `create*()` constructor methods.
    */
    constructor() {
        const ret = wasm.instruction_new();
        this.__wbg_ptr = ret >>> 0;
        InstructionFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
    * Gets the 64-bit IP of the instruction
    * @returns {bigint}
    */
    get ip() {
        const ret = wasm.instruction_ip(this.__wbg_ptr);
        return BigInt.asUintN(64, ret);
    }
    /**
    * Gets the length of the instruction, 0-15 bytes. This is just informational. If you modify the instruction
    * or create a new one, this method could return the wrong value.
    * @returns {number}
    */
    get length() {
        const ret = wasm.instruction_length(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
    * Gets the default disassembly string
    * @returns {string}
    */
    toString() {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.instruction_toString(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
}

async function __wbg_load(module, imports) {
    if (typeof Response === 'function' && module instanceof Response) {
        if (typeof WebAssembly.instantiateStreaming === 'function') {
            try {
                return await WebAssembly.instantiateStreaming(module, imports);

            } catch (e) {
                if (module.headers.get('Content-Type') != 'application/wasm') {
                    console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                } else {
                    throw e;
                }
            }
        }

        const bytes = await module.arrayBuffer();
        return await WebAssembly.instantiate(bytes, imports);

    } else {
        const instance = await WebAssembly.instantiate(module, imports);

        if (instance instanceof WebAssembly.Instance) {
            return { instance, module };

        } else {
            return instance;
        }
    }
}

function __wbg_get_imports() {
    const imports = {};
    imports.wbg = {};
    imports.wbg.__wbg_new_796382978dfd4fb0 = function(arg0, arg1) {
        const ret = new Error(getStringFromWasm0(arg0, arg1));
        return addHeapObject(ret);
    };
    imports.wbg.__wbg_new_a220cf903aa02ca2 = function() {
        const ret = new Array();
        return addHeapObject(ret);
    };
    imports.wbg.__wbg_instruction_new = function(arg0) {
        const ret = Instruction.__wrap(arg0);
        return addHeapObject(ret);
    };
    imports.wbg.__wbg_push_37c89022f34c01ca = function(arg0, arg1) {
        const ret = getObject(arg0).push(getObject(arg1));
        return ret;
    };
    imports.wbg.__wbindgen_object_drop_ref = function(arg0) {
        takeObject(arg0);
    };
    imports.wbg.__wbindgen_throw = function(arg0, arg1) {
        throw new Error(getStringFromWasm0(arg0, arg1));
    };

    return imports;
}

function __wbg_init_memory(imports, memory) {

}

function __wbg_finalize_init(instance, module) {
    wasm = instance.exports;
    __wbg_init.__wbindgen_wasm_module = module;
    cachedDataViewMemory0 = null;
    cachedUint8ArrayMemory0 = null;



    return wasm;
}

function initSync(module) {
    if (wasm !== undefined) return wasm;


    if (typeof module !== 'undefined' && Object.getPrototypeOf(module) === Object.prototype)
    ({module} = module)
    else
    console.warn('using deprecated parameters for `initSync()`; pass a single object instead')

    const imports = __wbg_get_imports();

    __wbg_init_memory(imports);

    if (!(module instanceof WebAssembly.Module)) {
        module = new WebAssembly.Module(module);
    }

    const instance = new WebAssembly.Instance(module, imports);

    return __wbg_finalize_init(instance, module);
}

async function __wbg_init(module_or_path) {
    if (wasm !== undefined) return wasm;


    if (typeof module_or_path !== 'undefined' && Object.getPrototypeOf(module_or_path) === Object.prototype)
    ({module_or_path} = module_or_path)
    else
    console.warn('using deprecated parameters for the initialization function; pass a single object instead')

    if (typeof module_or_path === 'undefined') {
        module_or_path = new URL('iced_x86_bg.wasm', import.meta.url);
    }
    const imports = __wbg_get_imports();

    if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
        module_or_path = fetch(module_or_path);
    }

    __wbg_init_memory(imports);

    const { instance, module } = await __wbg_load(await module_or_path, imports);

    return __wbg_finalize_init(instance, module);
}

export { initSync };
export default __wbg_init;
