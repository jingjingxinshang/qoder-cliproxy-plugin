// Package qoderwasm runs Qoder's signing WASM (`qoder_auth_wasm_bg.wasm`) from Go.
//
// The module is a black box: its internals are never inspected. Everything here
// exists to satisfy the wasm-bindgen ABI the module was compiled against, in the
// same way its generated JavaScript glue would:
//
//   - an object heap, because the ABI passes JavaScript values as i32 slots
//   - a small JavaScript value model (Error, Map, Uint8Array, functions, global)
//   - memory helpers for strings and byte arrays
//   - the wasm-bindgen ABI helpers, which the CLI build exports under obfuscated
//     names (`__wbindgen_export`, `__wbindgen_export2`, `__wbindgen_export3`,
//     `__wbindgen_export4`): exn_store, malloc, realloc and free respectively.
//
// The mapping of those obfuscated names, the import implementations and the
// call conventions below were read from the glue code inside the official CLI
// bundle (`package/bundle/qodercli.js`), not guessed.
package qoderwasm

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// importModule is the module name the wasm imports its glue from.
const importModule = "./qoder_auth_wasm_bg.js"

// Static heap slots. The glue seeds its heap with `new Array(1024).fill(void 0)`
// followed by `push(void 0, null, true, false)`, and refuses to recycle indices
// below 1028 — so these four indices are permanent and must answer the same way
// here, because the module compares against them.
const (
	staticUndefined = 1024
	staticNull      = 1025
	staticTrue      = 1026
	staticFalse     = 1027
	staticSlots     = 1028
)

// DebugCall, when set, receives every exported call with its argument vector.
// It exists for ABI diagnostics: a trap inside the module is otherwise opaque.
var DebugCall func(name string, params []uint64)

// Module is a loaded and instantiated auth wasm.
type Module struct {
	runtime  wazero.Runtime
	mod      api.Module
	heap     []any
	freeList []int32
	pending  any // last value stored through exn_store
}

// jsValue shapes exchanged with the module. They are deliberately minimal: only
// what the glue touches is modelled.
type (
	jsUndefined struct{}
	jsNullT     struct{}
	jsBool      bool
	jsNumber    float64
	jsString    string
	jsError     struct{ message string }
	jsBytes     struct{ data []byte }
	jsFunction  struct {
		name string
		call func(this any, args []any) (any, error)
	}
	jsMap struct {
		keys   []string
		values map[string]any
	}
	jsGlobal struct{}
)

// jsThrow is a JavaScript exception travelling out of an import call. The module
// raises these through `__wbg___wbindgen_throw`, which in JavaScript is a real
// `throw`; wazero surfaces the panic as an error instead of unwinding the world.
type jsThrow struct {
	message string
}

func (e jsThrow) Error() string { return e.message }

// errSignatureInvalid is the upstream answer when the signing context is wrong.
var errSignatureInvalid = errors.New("signature invalid")

// LoadOption configures Load.
type LoadOption func(*loadConfig)

type loadConfig struct {
	debugInfo bool
}

// WithDebugInfo keeps function names in the compiled module so a wasm trap
// reports where it happened. It costs memory and is meant for diagnostics.
func WithDebugInfo() LoadOption {
	return func(config *loadConfig) { config.debugInfo = true }
}

// Load instantiates the auth wasm. The bytes are the black box; nothing in this
// package interprets them.
func Load(ctx context.Context, wasm []byte, options ...LoadOption) (*Module, error) {
	config := loadConfig{}
	for _, option := range options {
		option(&config)
	}
	m := &Module{
		heap:     make([]any, staticSlots),
		freeList: nil,
	}
	m.heap[staticUndefined] = jsUndefined{}
	m.heap[staticNull] = jsNullT{}
	m.heap[staticTrue] = jsBool(true)
	m.heap[staticFalse] = jsBool(false)

	r := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithDebugInfoEnabled(config.debugInfo))
	m.runtime = r

	if err := m.registerImports(ctx); err != nil {
		_ = r.Close(ctx)
		return nil, err
	}

	compiled, err := r.CompileModule(ctx, wasm)
	if err != nil {
		_ = r.Close(ctx)
		return nil, fmt.Errorf("compile qoder auth wasm: %w", err)
	}
	mod, err := r.InstantiateModule(ctx, compiled, wazero.NewModuleConfig().WithStartFunctions())
	if err != nil {
		_ = r.Close(ctx)
		return nil, fmt.Errorf("instantiate qoder auth wasm: %w", err)
	}
	m.mod = mod
	return m, nil
}

// Close releases the runtime.
func (m *Module) Close(ctx context.Context) error {
	if m == nil || m.runtime == nil {
		return nil
	}
	return m.runtime.Close(ctx)
}

// ── heap ─────────────────────────────────────────────────────────────────────

// add stores a JavaScript value and returns its slot, mirroring the glue's
// `addHeapObject`.
func (m *Module) add(v any) int32 {
	if len(m.freeList) > 0 {
		idx := m.freeList[len(m.freeList)-1]
		m.freeList = m.freeList[:len(m.freeList)-1]
		m.heap[idx] = v
		return idx
	}
	m.heap = append(m.heap, v)
	return int32(len(m.heap) - 1)
}

// get reads a slot, mirroring `getObject`.
func (m *Module) get(idx int32) any {
	if idx < 0 || int(idx) >= len(m.heap) {
		return jsUndefined{}
	}
	return m.heap[idx]
}

// drop recycles a slot, mirroring `dropObject`: the static slots are permanent,
// which is exactly the `if (idx < 1028) return` in the glue.
func (m *Module) drop(idx int32) {
	if idx < staticSlots {
		return
	}
	m.heap[idx] = jsUndefined{}
	m.freeList = append(m.freeList, idx)
}

// take reads a slot and drops it, mirroring `takeObject` (the glue's `Gb`).
func (m *Module) take(idx int32) any {
	v := m.get(idx)
	m.drop(idx)
	return v
}

// ── memory helpers ───────────────────────────────────────────────────────────

func (m *Module) read(offset, length int32) ([]byte, error) {
	if length == 0 {
		return nil, nil
	}
	buf, ok := m.mod.Memory().Read(uint32(offset), uint32(length))
	if !ok {
		return nil, fmt.Errorf("wasm memory read out of range (offset=%d length=%d)", offset, length)
	}
	// The slice is only valid until the next memory growth, so copy.
	out := make([]byte, len(buf))
	copy(out, buf)
	return out, nil
}

func (m *Module) readString(offset, length int32) (string, error) {
	buf, err := m.read(offset, length)
	if err != nil {
		return "", err
	}
	if !utf8.Valid(buf) {
		// The module always hands back UTF-8, but never fail a signing call over
		// one malformed sequence.
		return strings.ToValidUTF8(string(buf), "\uFFFD"), nil
	}
	return string(buf), nil
}

func (m *Module) readI32(offset int32) int32 {
	buf, ok := m.mod.Memory().Read(uint32(offset), 4)
	if !ok {
		return 0
	}
	return int32(binary.LittleEndian.Uint32(buf))
}

func (m *Module) writeBytes(offset int32, data []byte) bool {
	return m.mod.Memory().Write(uint32(offset), data)
}

// call invokes an exported function, converting a wasm trap or a JavaScript
// throw into an error.
func (m *Module) call(name string, params ...uint64) ([]uint64, error) {
	fn := m.mod.ExportedFunction(name)
	if fn == nil {
		return nil, fmt.Errorf("qoder auth wasm does not export %s", name)
	}
	if DebugCall != nil {
		DebugCall(name, params)
	}
	var (
		results []uint64
		errCall error
	)
	func() {
		defer func() {
			if r := recover(); r != nil {
				if t, ok := r.(jsThrow); ok {
					errCall = t
					return
				}
				panic(r)
			}
		}()
		results, errCall = fn.Call(context.Background(), params...)
	}()
	if errCall != nil {
		var t jsThrow
		if errors.As(errCall, &t) {
			return nil, t
		}
		return nil, errCall
	}
	// An import can also park an exception instead of throwing, which the glue
	// would have stored through `__wbindgen_export`. Surface it like a throw.
	if m.pending != nil {
		pending := m.pending
		m.pending = nil
		if e, ok := pending.(jsError); ok {
			return nil, jsThrow{message: e.message}
		}
	}
	return results, nil
}

// ── wasm-bindgen ABI helpers ─────────────────────────────────────────────────

// u64 widens a signed i32 argument into the ABI's stack word. The indirection is
// not cosmetic: Go rejects a direct `uint64(uint32(-16))` because the negative
// constant overflows before the conversion.
func u64(v int32) uint64 { return uint64(uint32(v)) }

// malloc calls the obfuscated `__wbindgen_malloc`.
func (m *Module) malloc(size, align int32) (int32, error) {
	res, err := m.call("__wbindgen_export2", u64(size), u64(align))
	if err != nil {
		return 0, err
	}
	if len(res) == 0 {
		return 0, errors.New("__wbindgen_malloc returned nothing")
	}
	return int32(uint32(res[0])), nil
}

// free calls the obfuscated `__wbindgen_free`.
func (m *Module) free(ptr, size, align int32) {
	_, _ = m.call("__wbindgen_export4", u64(ptr), u64(size), u64(align))
}

// pushString copies a Go string into wasm memory, mirroring `passStringToWasm0`.
// The caller must NOT free the result: these buffers become `String` parameters
// on the module side, which takes ownership and drops them itself. The glue
// frees nothing here either — it only frees values the module hands back.
func (m *Module) pushString(value string) (int32, int32, error) {
	data := []byte(value)
	ptr, err := m.malloc(int32(len(data)), 1)
	if err != nil {
		return 0, 0, err
	}
	if len(data) > 0 && !m.writeBytes(ptr, data) {
		return 0, 0, fmt.Errorf("wasm memory write out of range (offset=%d length=%d)", ptr, len(data))
	}
	return ptr, int32(len(data)), nil
}

// stackPointer reserves the 16-byte result area the ABI writes into, mirroring
// `__wbindgen_add_to_stack_pointer(-16)`.
func (m *Module) stackPush() (int32, error) {
	res, err := m.call("__wbindgen_add_to_stack_pointer", u64(-16))
	if err != nil {
		return 0, err
	}
	if len(res) == 0 {
		return 0, errors.New("__wbindgen_add_to_stack_pointer returned nothing")
	}
	return int32(uint32(res[0])), nil
}

func (m *Module) stackPop() {
	_, _ = m.call("__wbindgen_add_to_stack_pointer", u64(16))
}

// readResult decodes the 16-byte ABI result area: (valuePtr, valueLen,
// errorPtr, errorLen). A non-zero error length is a JavaScript exception that
// the module raised instead of returning a value.
func (m *Module) readResult(area int32) (string, error) {
	valuePtr := m.readI32(area)
	valueLen := m.readI32(area + 4)
	errPtr := m.readI32(area + 8)
	errLen := m.readI32(area + 12)

	if errLen != 0 {
		message, errRead := m.readString(errPtr, errLen)
		m.free(errPtr, errLen, 1)
		if errRead != nil {
			return "", errRead
		}
		return "", jsThrow{message: message}
	}
	out, errRead := m.readString(valuePtr, valueLen)
	m.free(valuePtr, valueLen, 1)
	if errRead != nil {
		return "", errRead
	}
	return out, nil
}

// callString1 calls `fn(arg string) -> string`.
func (m *Module) callString1(name, arg string) (string, error) {
	area, err := m.stackPush()
	if err != nil {
		return "", err
	}
	defer m.stackPop()

	ptr, length, err := m.pushString(arg)
	if err != nil {
		return "", err
	}
	// The argument is not freed: the module owns its String parameters.

	if _, errCall := m.call(name, u64(area), u64(ptr), u64(length)); errCall != nil {
		return "", errCall
	}
	return m.readResult(area)
}

// callString2 calls `fn(first string, second string) -> string`.
func (m *Module) callString2(name, first, second string) (string, error) {
	area, err := m.stackPush()
	if err != nil {
		return "", err
	}
	defer m.stackPop()

	firstPtr, firstLen, err := m.pushString(first)
	if err != nil {
		return "", err
	}
	// Arguments are not freed; see callResourceArgs for why.
	secondPtr, secondLen, err := m.pushString(second)
	if err != nil {
		return "", err
	}

	if _, errCall := m.call(name,
		u64(area),
		u64(firstPtr), u64(firstLen),
		u64(secondPtr), u64(secondLen),
	); errCall != nil {
		return "", errCall
	}
	return m.readResult(area)
}

// ── public signing API ───────────────────────────────────────────────────────

// GenerateRuntimeAuthFields derives the `encrypt_user_info` and `key` fields a
// signed request needs. Passing the user info JSON keeps behaviour identical to
// the CLI, which feeds the same object in.
func (m *Module) GenerateRuntimeAuthFields(authPayloadJSON string) (string, error) {
	return m.callString1("generate_runtime_auth_fields", authPayloadJSON)
}

// CredentialStorageEncrypt encrypts a credential blob the way the CLI stores it,
// mirroring `credential_storage_encrypt(plain, key)`.
func (m *Module) CredentialStorageEncrypt(plainText, key string) (string, error) {
	return m.callString2("credential_storage_encrypt", plainText, key)
}

// CredentialStorageDecrypt reverses CredentialStorageEncrypt.
func (m *Module) CredentialStorageDecrypt(cipherText, key string) (string, error) {
	return m.callString2("credential_storage_decrypt", cipherText, key)
}

// DecryptServerResponse decrypts an encrypted response envelope.
func (m *Module) DecryptServerResponse(text string) (string, error) {
	return m.callString1("decrypt_server_response", text)
}

// ── imports ──────────────────────────────────────────────────────────────────

// registerImports installs the JavaScript glue the module expects. Each function
// mirrors the bundle's implementation of the same name; see /tmp notes in the
// package doc for provenance.
func (m *Module) registerImports(ctx context.Context) error {
	b := m.runtime.NewHostModuleBuilder(importModule)

	i32 := api.ValueTypeI32
	f64 := api.ValueTypeF64

	fn := func(name string, params []api.ValueType, results []api.ValueType, impl any) {
		b.NewFunctionBuilder().WithGoModuleFunction(
			api.GoModuleFunc(func(_ context.Context, mod api.Module, stack []uint64) {
				m.invoke(name, params, results, stack, impl)
			}),
			params, results,
		).Export(name)
	}

	// Primitives.
	fn("__wbg_now_88621c9c9a4f3ffc", nil, []api.ValueType{f64}, func() float64 {
		return Now()
	})
	fn("__wbg___wbindgen_is_object_40c5a80572e8f9d3", []api.ValueType{i32}, []api.ValueType{i32},
		func(idx int32) int32 { return bool32(m.isObject(m.get(idx))) })
	fn("__wbg___wbindgen_is_string_b29b5c5a8065ba1a", []api.ValueType{i32}, []api.ValueType{i32},
		func(idx int32) int32 { _, ok := m.get(idx).(jsString); return bool32(ok) })
	fn("__wbg___wbindgen_is_function_49868bde5eb1e745", []api.ValueType{i32}, []api.ValueType{i32},
		func(idx int32) int32 { _, ok := m.get(idx).(jsFunction); return bool32(ok) })
	fn("__wbg___wbindgen_is_undefined_c0cca72b82b86f4d", []api.ValueType{i32}, []api.ValueType{i32},
		func(idx int32) int32 { _, ok := m.get(idx).(jsUndefined); return bool32(ok) })

	// Errors and throws.
	fn("__wbg_Error_2e59b1b37a9a34c3", []api.ValueType{i32, i32}, []api.ValueType{i32},
		func(ptr, length int32) int32 {
			message, _ := m.readString(ptr, length)
			return m.add(jsError{message: message})
		})
	fn("__wbg___wbindgen_throw_81fc77679af83bc6", []api.ValueType{i32, i32}, nil,
		func(ptr, length int32) {
			message, _ := m.readString(ptr, length)
			panic(jsThrow{message: message})
		})

	// Object heap.
	fn("__wbindgen_object_clone_ref", []api.ValueType{i32}, []api.ValueType{i32},
		func(idx int32) int32 { return m.add(m.get(idx)) })
	fn("__wbindgen_object_drop_ref", []api.ValueType{i32}, nil,
		func(idx int32) { m.drop(idx) })
	fn("__wbindgen_cast_0000000000000001", []api.ValueType{i32, i32}, []api.ValueType{i32},
		func(ptr, length int32) int32 { return m.add(m.bytesView(ptr, length)) })
	fn("__wbindgen_cast_0000000000000002", []api.ValueType{i32, i32}, []api.ValueType{i32},
		func(ptr, length int32) int32 {
			value, _ := m.readString(ptr, length)
			return m.add(jsString(value))
		})

	// Uint8Array.
	fn("__wbg_new_with_length_9cedd08484b73942", []api.ValueType{i32}, []api.ValueType{i32},
		func(length int32) int32 {
			return m.add(jsBytes{data: make([]byte, uint32(length))})
		})
	fn("__wbg_length_0c32cb8543c8e4c8", []api.ValueType{i32}, []api.ValueType{i32},
		func(idx int32) int32 {
			if b, ok := m.get(idx).(jsBytes); ok {
				return int32(len(b.data))
			}
			if arr, ok := m.get(idx).([]any); ok {
				return int32(len(arr))
			}
			return 0
		})
	fn("__wbg_subarray_0f98d3fb634508ad", []api.ValueType{i32, i32, i32}, []api.ValueType{i32},
		func(idx, start, end int32) int32 {
			if b, ok := m.get(idx).(jsBytes); ok {
				return m.add(jsBytes{data: subarray(b.data, start, end)})
			}
			return m.add(jsBytes{})
		})
	fn("__wbg_prototypesetcall_3e05eb9545565046", []api.ValueType{i32, i32, i32}, nil,
		func(ptr, length, srcIdx int32) {
			target := m.bytesView(ptr, length).data
			src, _ := m.get(srcIdx).(jsBytes)
			copy(target, src.data)
		})

	// Map.
	fn("__wbg_new_99cabae501c0a8a0", nil, []api.ValueType{i32},
		func() int32 { return m.add(newJsMap()) })
	fn("__wbg_set_08463b1df38a7e29", []api.ValueType{i32, i32, i32}, []api.ValueType{i32},
		func(idx, keyIdx, valueIdx int32) int32 {
			return m.add(m.setProperty(idx, m.get(keyIdx), m.get(valueIdx)))
		})

	// Calls.
	fn("__wbg_call_d578befcc3145dee", []api.ValueType{i32, i32, i32}, []api.ValueType{i32},
		func(fnIdx, thisIdx, argIdx int32) int32 {
			return m.callFunction(fnIdx, thisIdx, argIdx)
		})

	// crypto / node globals. The Rust `getrandom` crate probes these in order;
	// supplying a working `crypto.getRandomValues` is what makes signing work.
	fn("__wbg_crypto_38df2bab126b63dc", []api.ValueType{i32}, []api.ValueType{i32},
		func(idx int32) int32 { return m.add(m.property(idx, "crypto")) })
	fn("__wbg_msCrypto_bd5a034af96bcba6", []api.ValueType{i32}, []api.ValueType{i32},
		func(idx int32) int32 { return m.add(m.property(idx, "msCrypto")) })
	fn("__wbg_process_44c7a14e11e9f69e", []api.ValueType{i32}, []api.ValueType{i32},
		func(idx int32) int32 { return m.add(m.property(idx, "process")) })
	fn("__wbg_versions_276b2795b1c6a219", []api.ValueType{i32}, []api.ValueType{i32},
		func(idx int32) int32 { return m.add(m.property(idx, "versions")) })
	fn("__wbg_node_84ea875411254db1", []api.ValueType{i32}, []api.ValueType{i32},
		func(idx int32) int32 { return m.add(m.property(idx, "node")) })
	fn("__wbg_require_b4edbdcf3e2a1ef0", nil, []api.ValueType{i32},
		func() int32 { return m.add(requireFunction()) })
	fn("__wbg_getRandomValues_d49329ff89a07af1", []api.ValueType{i32, i32}, nil,
		func(ptr, length int32) {
			buf := m.bytesView(ptr, length).data
			if _, err := rand.Read(buf); err != nil {
				m.storeException(jsError{message: err.Error()})
			}
		})
	fn("__wbg_getRandomValues_c44a50d8cfdaebeb", []api.ValueType{i32, i32}, nil,
		func(_ int32, arrIdx int32) {
			if arr, ok := m.get(arrIdx).(jsBytes); ok {
				if _, err := rand.Read(arr.data); err != nil {
					m.storeException(jsError{message: err.Error()})
				}
			}
		})
	fn("__wbg_randomFillSync_6c25eac9869eb53c", []api.ValueType{i32, i32}, nil,
		func(_ int32, arrIdx int32) {
			if arr, ok := m.get(arrIdx).(jsBytes); ok {
				if _, err := rand.Read(arr.data); err != nil {
					m.storeException(jsError{message: err.Error()})
				}
			} else {
				m.storeException(jsError{message: "randomFillSync: not a Uint8Array"})
			}
		})

	// globalThis accessors.
	globalAccessor := func() int32 { return m.add(jsGlobal{}) }
	fn("__wbg_static_accessor_GLOBAL_THIS_a1248013d790bf5f", nil, []api.ValueType{i32}, globalAccessor)
	fn("__wbg_static_accessor_GLOBAL_f2e0f995a21329ff", nil, []api.ValueType{i32}, globalAccessor)
	fn("__wbg_static_accessor_SELF_24f78b6d23f286ea", nil, []api.ValueType{i32}, globalAccessor)
	fn("__wbg_static_accessor_WINDOW_59fd959c540fe405", nil, []api.ValueType{i32}, globalAccessor)

	_, err := b.Instantiate(ctx)
	return err
}

// invoke adapts a plain Go function to the raw wasm stack the host module gets,
// so each import can be written with real Go signatures.
// DebugImport, when set, is called for every host import the module invokes,
// before the implementation runs. It exists to be read while chasing a trap
// inside the module: the last imports called are the ones whose return values
// the module was about to dereference.
var DebugImport func(name string, params []uint64)

// Now supplies the wall clock the module signs with, mirroring the glue's
// `__wbg_now_...: function() { return Date.now() }` (milliseconds since the
// epoch, as a double). It is a variable because the signing result varies with
// it, which is worth being able to pin from a test.
var Now = func() float64 { return float64(time.Now().UnixMilli()) }

func (m *Module) invoke(name string, params, results []api.ValueType, stack []uint64, impl any) {
	if DebugImport != nil {
		n := len(params)
		if n > len(stack) {
			n = len(stack)
		}
		DebugImport(name, append([]uint64(nil), stack[:n]...))
	}
	switch f := impl.(type) {
	case func():
		f()
	case func() float64:
		stack[0] = math.Float64bits(f())
	case func() int32:
		stack[0] = uint64(uint32(f()))
	case func(int32) int32:
		stack[0] = uint64(uint32(f(int32(uint32(stack[0])))))
	case func(int32):
		f(int32(uint32(stack[0])))
	case func(int32, int32) int32:
		stack[0] = uint64(uint32(f(int32(uint32(stack[0])), int32(uint32(stack[1])))))
	case func(int32, int32):
		f(int32(uint32(stack[0])), int32(uint32(stack[1])))
	case func(int32, int32, int32) int32:
		stack[0] = uint64(uint32(f(int32(uint32(stack[0])), int32(uint32(stack[1])), int32(uint32(stack[2])))))
	case func(int32, int32, int32):
		f(int32(uint32(stack[0])), int32(uint32(stack[1])), int32(uint32(stack[2])))
	default:
		panic(fmt.Sprintf("qoderwasm: import %s has an unsupported signature %T", name, impl))
	}
}

// ── JavaScript value semantics ───────────────────────────────────────────────

func bool32(v bool) int32 {
	if v {
		return 1
	}
	return 0
}

// bytesView returns a Uint8Array that ALIASES wasm memory, mirroring the glue's
// `kke(ptr, len)`. It must not copy: the module writes through these views (the
// randomness buffer above all) and expects the bytes to land in its own memory.
// Copying them here made the RNG buffer look frozen and the module spun forever.
func (m *Module) bytesView(ptr, length int32) jsBytes {
	data, ok := m.mod.Memory().Read(uint32(ptr), uint32(length))
	if !ok {
		return jsBytes{}
	}
	return jsBytes{data: data}
}

func subarray(data []byte, start, end int32) []byte {
	length := int32(len(data))
	if start < 0 {
		start = 0
	}
	if start > length {
		start = length
	}
	if end < start || end > length {
		end = length
	}
	out := make([]byte, end-start)
	copy(out, data[start:end])
	return out
}

func newJsMap() jsMap {
	return jsMap{values: map[string]any{}}
}

func (m *Module) isObject(v any) bool {
	switch v.(type) {
	case jsError, jsBytes, jsMap, jsGlobal:
		return true
	default:
		return false
	}
}

// property reads a named property, answering `undefined` for anything unknown.
func (m *Module) property(idx int32, name string) any {
	switch v := m.get(idx).(type) {
	case jsGlobal:
		switch name {
		case "crypto":
			return cryptoObject()
		case "process":
			return m.processObject()
		case "globalThis":
			return jsGlobal{}
		}
	case jsMap:
		if value, ok := v.values[name]; ok {
			return value
		}
	case jsError:
		if name == "message" {
			return jsString(v.message)
		}
	}
	return jsUndefined{}
}

// cryptoObject is the WebCrypto surface the module uses for randomness.
func cryptoObject() jsMap {
	obj := newJsMap()
	obj.set("getRandomValues", jsFunction{
		name: "getRandomValues",
		call: func(_ any, args []any) (any, error) {
			if len(args) == 0 {
				return jsUndefined{}, nil
			}
			arr, ok := args[0].(jsBytes)
			if !ok {
				return jsUndefined{}, nil
			}
			if _, err := rand.Read(arr.data); err != nil {
				return nil, err
			}
			return arr, nil
		},
	})
	obj.set("randomFillSync", jsFunction{
		name: "randomFillSync",
		call: func(_ any, args []any) (any, error) {
			if len(args) == 0 {
				return jsUndefined{}, nil
			}
			arr, ok := args[0].(jsBytes)
			if !ok {
				return jsUndefined{}, nil
			}
			if _, err := rand.Read(arr.data); err != nil {
				return nil, err
			}
			return arr, nil
		},
	})
	return obj
}

// processObject satisfies the Node probe the module performs before falling back
// to `crypto.getRandomValues`.
func (m *Module) processObject() jsMap {
	versions := newJsMap()
	versions.set("node", jsString("20.11.1"))
	process := newJsMap()
	process.set("versions", versions)
	return process
}

// requireFunction answers `require("crypto")` with the same crypto surface.
func requireFunction() jsFunction {
	return jsFunction{
		name: "require",
		call: func(_ any, args []any) (any, error) {
			if len(args) > 0 {
				if name, ok := args[0].(jsString); ok && strings.TrimSpace(string(name)) == "crypto" {
					return cryptoObject(), nil
				}
			}
			return jsUndefined{}, nil
		},
	}
}

func (m *jsMap) set(key string, value any) {
	if m.values == nil {
		m.values = map[string]any{}
	}
	if _, exists := m.values[key]; !exists {
		m.keys = append(m.keys, key)
	}
	m.values[key] = value
}

// setProperty implements the glue's `__wbg_set`, which is `receiver.set(k, v)`
// for both Map (returns the map) and Uint8Array (copies bytes, returns undefined).
func (m *Module) setProperty(idx int32, key, value any) any {
	switch target := m.get(idx).(type) {
	case jsMap:
		name := "undefined"
		if s, ok := key.(jsString); ok {
			name = string(s)
		}
		target.set(name, value)
		m.heap[idx] = target
		return target
	case jsBytes:
		src, ok := value.(jsBytes)
		if !ok {
			return jsUndefined{}
		}
		offset := 0
		if n, ok := key.(jsNumber); ok {
			offset = int(n)
		}
		if offset < 0 {
			offset = 0
		}
		if offset < len(target.data) {
			copy(target.data[offset:], src.data)
		}
		return jsUndefined{}
	default:
		return jsUndefined{}
	}
}

// callFunction implements `__wbg_call(fn, this, arg)`.
func (m *Module) callFunction(fnIdx, thisIdx, argIdx int32) int32 {
	fn, ok := m.get(fnIdx).(jsFunction)
	if !ok {
		m.storeException(jsError{message: "not a function"})
		return 0
	}
	result, err := fn.call(m.get(thisIdx), []any{m.get(argIdx)})
	if err != nil {
		m.storeException(jsError{message: err.Error()})
		return 0
	}
	return m.add(result)
}

// storeException mirrors the glue's `jVe` catch: the value is parked for the
// module to pick up rather than unwinding the host call.
func (m *Module) storeException(value any) {
	m.pending = value
}

// Describe is a small helper for diagnostics.
func (m *Module) Describe() string {
	return strconv.Itoa(len(m.heap)) + " heap slots"
}
