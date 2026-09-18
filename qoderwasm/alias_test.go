package qoderwasm

import "testing"

// The host writes into wasm memory in three places: passStringToWasm0-style
// buffers, the randomness buffer, and Uint8Array.prototype.set. All of them go
// through bytesView, which is documented as aliasing the module's memory because
// the module must observe the bytes. If api.Memory.Read hands back a copy, every
// one of those writes is silently discarded and the module signs with whatever
// was already there, so this asserts the aliasing actually holds rather than
// trusting the comment.
func TestMemoryReadAliasesModuleMemory(t *testing.T) {
	mod := testModule(t)

	ptr, err := mod.malloc(16, 1)
	if err != nil {
		t.Fatalf("malloc: %v", err)
	}
	if ptr == 0 {
		t.Fatal("malloc returned a null pointer")
	}

	view := mod.bytesView(ptr, 16)
	if len(view.data) != 16 {
		t.Fatalf("bytesView returned %d bytes, want 16", len(view.data))
	}
	view.data[0] = 0xAB
	view.data[1] = 0xCD

	// Read the same address again through an independent call. If the first read
	// handed back a copy, the module's memory still holds the original bytes.
	back, ok := mod.mod.Memory().Read(uint32(ptr), 4)
	if !ok {
		t.Fatal("re-reading the buffer failed")
	}
	t.Logf("wrote ab cd, re-read %x, readI32=%#x", back[:4], mod.readI32(ptr))
	if back[0] != 0xAB || back[1] != 0xCD {
		t.Fatalf("api.Memory.Read does not alias: wrote ab cd, re-read %x — every host write into wasm memory is being dropped", back[:4])
	}
}
