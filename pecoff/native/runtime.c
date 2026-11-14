// SPDX-License-Identifier: Apache-2.0
// Bao's per-image Windows lifecycle and compiler TLS adapter. No CRT dependency.
typedef unsigned long DWORD;
typedef unsigned long long SIZE;
typedef void (*FN)(void);
typedef void (*TLSFN)(void *, DWORD, void *);
#define DLL __declspec(dllimport)
DLL void *GetProcessHeap(void);
DLL void *HeapAlloc(void *, DWORD, SIZE);
DLL int HeapFree(void *, DWORD, void *);
DLL DWORD FlsAlloc(void (*)(void *));
DLL void *FlsGetValue(DWORD);
DLL int FlsSetValue(DWORD, void *);
DLL int FlsFree(DWORD);
DLL void RaiseFailFastException(void *, void *, DWORD);
DLL void Sleep(DWORD);
DLL void RaiseException(DWORD, DWORD, DWORD, const SIZE *);
DLL void free(void *);

struct exit_entry { struct exit_entry *next; FN function; void (*cxa)(void *); void *arg; };
struct emu_entry { struct emu_entry *next; void *control; void *data; };
struct fls_registration {struct fls_registration *next; DWORD key; int allocated; void (*callback)(void *);};
struct fls_value {struct fls_value *next; struct fls_registration *registration; void *value; int active;};
struct block { void *base; struct exit_entry *dtors; struct emu_entry *emulated; struct fls_value *fls; };
static struct fls_registration *fls_registrations;
static DWORD key = 0xffffffff;
static void *heap;
static const unsigned char *template_data;
static SIZE template_size, template_align;
static TLSFN *callbacks;
static SIZE callback_count;
static void *image_base;
static int starting;
static FN *dynamic_initializers;
static SIZE dynamic_count;
static struct exit_entry *exits;
static volatile long exit_lock;
static volatile long live_blocks, destroyed_blocks;
static int stopped;
DWORD _tls_index; // All translated TLS accesses use our private one-slot array.
__declspec(thread) unsigned char __tls_guard;
__declspec(thread) int _Init_thread_epoch=(-2147483647-1);
int _Init_global_epoch=(-2147483647-1);

static void fail(void) { RaiseFailFastException(0, 0, 0); __builtin_trap(); }
static void *allocate(SIZE n) { void *p = HeapAlloc(heap, 8, n); if (!p) fail(); return p; }
static void lock(void) { while (__sync_val_compare_and_swap(&exit_lock, 0, 1)) Sleep(0); }
static void unlock(void) { __sync_lock_release(&exit_lock); }
// MSVC's function-local static guards use a process epoch and a native TLS epoch.
void _Init_thread_header(int *guard) {
    lock();
    while(*guard==-1){unlock();Sleep(1);lock();}
    if(*guard==0)*guard=-1;else _Init_thread_epoch=_Init_global_epoch;
    unlock();
}
void _Init_thread_footer(int *guard) {
    lock();*guard=++_Init_global_epoch;_Init_thread_epoch=_Init_global_epoch;unlock();
}
void _Init_thread_abort(int *guard) {lock();*guard=0;unlock();}
static void run_entries(struct exit_entry **head) {
    while (*head) {
        struct exit_entry *e = *head; *head = e->next;
        if (e->cxa) e->cxa(e->arg); else e->function();
        HeapFree(heap, 0, e);
    }
}
void **bao_winrt_tls_array(void);
// Keep native FLS destructor callbacks inside this image's TLS lifetime.
// OS callback order is unspecified: Rust's callback must not observe a template
// that our earlier FLS callback already freed. Values remain private to this
// image; do not pass these FLS keys to code outside the translated image.
static struct fls_registration *find_fls(DWORD index) {
    lock(); struct fls_registration *r=fls_registrations;
    while(r && (!r->allocated || r->key!=index))r=r->next;
    unlock();return r;
}
static void fls_callback(void *opaque) {
    struct fls_value *e=opaque;
    if(!e || !e->active)return;
    void *value=e->value;e->active=0;e->value=0;
    FlsSetValue(e->registration->key,0);
    if(e->registration->callback)e->registration->callback(value);
}
DWORD bao_winrt_fls_alloc(void (*callback)(void *)) {
    struct fls_registration *r=allocate(sizeof(*r));
    r->key=FlsAlloc(fls_callback);
    if(r->key==0xffffffff){HeapFree(heap,0,r);return 0xffffffff;}
    r->allocated=1;r->callback=callback;
    lock();r->next=fls_registrations;fls_registrations=r;unlock();return r->key;
}
void *bao_winrt_fls_get(DWORD index) {
    if(!find_fls(index))return FlsGetValue(index);
    struct fls_value *e=FlsGetValue(index);
    return e && e->active ? e->value : 0;
}
int bao_winrt_fls_set(DWORD index,void *value) {
    struct fls_registration *r=find_fls(index);
    if(!r)return FlsSetValue(index,value);
    if(!value){struct fls_value *e=FlsGetValue(index);if(e){e->active=0;e->value=0;}return FlsSetValue(index,0);}
    bao_winrt_tls_array();struct block *b=FlsGetValue(key);
    struct fls_value *e=b->fls;
    while(e && e->registration!=r)e=e->next;
    if(!e){e=allocate(sizeof(*e));e->registration=r;e->next=b->fls;b->fls=e;}
    e->value=value;e->active=1;
    if(!FlsSetValue(index,e)){e->value=0;e->active=0;return 0;}return 1;
}
int bao_winrt_fls_free(DWORD index) {
    struct fls_registration *r=find_fls(index);
    int result=FlsFree(index);
    if(r && result){lock();r->allocated=0;unlock();}return result;
}
static void drain_fls(struct block *b) {
    for(int pass=0;pass<4;pass++){
        int pending=0;
        for(struct fls_value *e=b->fls;e;e=e->next)if(e->active){pending=1;fls_callback(e);}
        if(b->dtors)pending=1;
        run_entries(&b->dtors);
        if(!pending)return;
    }
    for(struct fls_value *e=b->fls;e;e=e->next)if(e->active)fail();
    if(b->dtors)fail();
}
static void destroy(void *value) {
    struct block *b = value;
    if (!b) return;
    // Keep the slot available during destructors and compiler TLS callbacks.
    FlsSetValue(key, b);
    drain_fls(b);
    for (SIZE i = callback_count; i; --i) callbacks[i-1](image_base, 3, 0);
    drain_fls(b);
    while(b->fls){struct fls_value *e=b->fls;b->fls=e->next;HeapFree(heap,0,e);}
    while (b->emulated) {struct emu_entry *e=b->emulated;b->emulated=e->next;HeapFree(heap,0,e);}
    FlsSetValue(key, 0);
    HeapFree(heap, 0, b);
    __sync_sub_and_fetch(&live_blocks, 1);
    __sync_add_and_fetch(&destroyed_blocks, 1);
}
void **bao_winrt_tls_array(void) {
    struct block *b;
    if (key == 0xffffffff || stopped) fail();
    b = FlsGetValue(key);
    if (!b) {
        b = allocate(sizeof(*b) + template_size + template_align);
        b->base = (void *)(((SIZE)(b + 1) + template_align - 1) & ~(template_align - 1));
        for (SIZE i = 0; i < template_size; ++i) ((unsigned char *)b->base)[i] = template_data[i];
        if (!FlsSetValue(key, b)) fail();
        __sync_add_and_fetch(&live_blocks, 1);
        if(!starting)for (SIZE i = 0; i < callback_count; ++i) callbacks[i](image_base, 2, 0);
        for (SIZE i = 0; i < dynamic_count; ++i) dynamic_initializers[i]();
    }
    return &b->base;
}
void bao_winrt_initialize(const void *data, SIZE size, SIZE alignment,
                          TLSFN *functions, SIZE count, FN *dynamic, SIZE dyn_count,void *module) {
    if (key != 0xffffffff) fail();
    heap = GetProcessHeap(); template_data = data; template_size = size;
    template_align = alignment ? alignment : 8;
    callbacks = functions; callback_count = count;
    dynamic_initializers = dynamic; dynamic_count = dyn_count;
    key = FlsAlloc(destroy); if (key == 0xffffffff) fail();
    image_base=module;starting=1;
    for(SIZE i=0;i<callback_count;i++)callbacks[i](image_base,1,0);
    starting=0;
}
void bao_winrt_tls_finalize(void) { destroy(FlsGetValue(key)); }
SIZE bao_winrt_tls_live(void) { return live_blocks; }
SIZE bao_winrt_tls_destroyed(void) { return destroyed_blocks; }
int bao_winrt_shutdown(void) {
    if (stopped) return 0;
    if (live_blocks > (FlsGetValue(key) ? 1 : 0)) return -1;
    bao_winrt_tls_finalize();
    run_entries(&exits);
    return 0;
}
void bao_winrt_finish(void) {
    for(SIZE i=callback_count;i;i--)callbacks[i-1](image_base,0,0);
    // MSVC's TLS destructor callback reads the caller's TLS on process detach,
    // recreating the block shutdown released; release it again.
    destroy(FlsGetValue(key));
    if(live_blocks)fail();
    stopped=1;FlsFree(key);key=0xffffffff;
    while(fls_registrations){struct fls_registration *r=fls_registrations;fls_registrations=r->next;if(r->allocated)FlsFree(r->key);HeapFree(heap,0,r);}
}
int atexit(FN function) {
    struct exit_entry *e = allocate(sizeof(*e)); e->function = function;
    lock(); if (stopped) { unlock(); HeapFree(heap, 0, e); return -1; }
    e->next = exits; exits = e; unlock(); return 0;
}
FN _onexit(FN function) { return atexit(function) ? (FN)0 : function; }
int __cxa_atexit(void (*function)(void *), void *arg, void *dso) {
    struct exit_entry *e = allocate(sizeof(*e)); (void)dso;
    e->cxa = function; e->arg = arg;
    lock(); if (stopped) { unlock(); HeapFree(heap, 0, e); return -1; }
    e->next = exits; exits = e; unlock(); return 0;
}
int __tlregdtor(FN function) {
    bao_winrt_tls_array(); struct block *b = FlsGetValue(key);
    struct exit_entry *e = allocate(sizeof(*e)); e->function = function;
    e->next = b->dtors; b->dtors = e; return 0;
}
int __cxa_thread_atexit(void (*function)(void *), void *arg, void *dso) {
    (void)dso; bao_winrt_tls_array(); struct block *b=FlsGetValue(key);
    struct exit_entry *e=allocate(sizeof(*e));e->cxa=function;e->arg=arg;
    e->next=b->dtors;b->dtors=e;return 0;
}
// GCC's Windows targets default to emulated TLS. Use the same FLS lifetime as
// compiler-native TLS while keeping each control's allocation image-private.
void *__emutls_get_address(void *control) {
    struct emutls {SIZE size, alignment; void *object; const unsigned char *value;};
    struct emutls *c=control;
    bao_winrt_tls_array();struct block *b=FlsGetValue(key);
    for(struct emu_entry *e=b->emulated;e;e=e->next) if(e->control==control)return e->data;
    if(c->size>(64ULL<<20)||!c->alignment||c->alignment>8192||(c->alignment&(c->alignment-1)))fail();
    struct emu_entry *e=allocate(sizeof(*e)+c->size+c->alignment);
    e->data=(void *)(((SIZE)(e+1)+c->alignment-1)&~(c->alignment-1));e->control=control;
    if(c->value)for(SIZE i=0;i<c->size;i++)((unsigned char *)e->data)[i]=c->value[i];
    e->next=b->emulated;b->emulated=e;return e->data;
}
void *__dso_handle=&__dso_handle;
// MSVC's type_info vftable is a static-library definition, not a DLL export.
// Its sole virtual slot is the scalar deleting destructor. The EH runtime
// compares decorated names in the compiler's TypeDescriptor records.
static void *type_info_delete(void *object, unsigned flags) {
    void **data=object;
    if(data[1]) {free(data[1]);data[1]=0;}
    if(flags&1) free(object);
    return object;
}
void *bao_type_info_vtable[] __asm__("??_7type_info@@6B@") = {(void *)type_info_delete};
// The compiler may call this eagerly/on demand as well as through .CRT$XL.
// Its own per-thread guard protects dynamic initialization from repetition.
void __dyn_tls_init(void *module, DWORD reason, void *reserved) {
    (void)module; (void)reserved;
    if (reason == 2) bao_winrt_tls_array();
}
void __dyn_tls_on_demand_init(void) { bao_winrt_tls_array(); }
int (*const __imp_atexit)(FN) = atexit;
FN (*const __imp__onexit)(FN) = _onexit;
int (*const __imp___tlregdtor)(FN) = __tlregdtor;

// A DLL that Bao loads into private memory is outside every Windows image.
// MSVC's C++ throw finds the throwing module's base with RtlPcToFileHeader,
// which reports no image there; catch matching then resolves the thrown
// type's image-relative records against zero. These replace the DLL's
// imports of RtlPcToFileHeader and _CxxThrowException so the DLL's own base
// is reported. Unwind lookup already gets that base from the DLL's function
// table, which is registered with it.
static char *dll_base;
static SIZE dll_size;
static void *(*dll_pc_to_file_header)(void *, void **);
static void (*dll_cxx_throw)(void *, const DWORD *);
void bao_winrt_dll_configure(char *base, SIZE size, void *pc_to_file_header, void *cxx_throw) {
    dll_base = base; dll_size = size;
    dll_pc_to_file_header = pc_to_file_header; dll_cxx_throw = cxx_throw;
}
static int in_dll(const void *p) { return (const char *)p >= dll_base && (const char *)p < dll_base + dll_size; }
void *bao_winrt_pc_to_file_header(void *pc, void **base) {
    if (in_dll(pc)) { *base = dll_base; return dll_base; }
    if (!dll_pc_to_file_header) { *base = 0; return 0; }
    return dll_pc_to_file_header(pc, base);
}
// Mirrors vcruntime's _CxxThrowException for a ThrowInfo inside the DLL:
// EH_MAGIC_NUMBER1, or EH_PURE_MAGIC_NUMBER1 for TI_IsPure (0x8); WinRT
// exceptions (TI_IsWinRT, 0x10) and rethrows go to the original.
void bao_winrt_cxx_throw(void *object, const DWORD *info) {
    if (info && in_dll(info) && !(info[0] & 0x10)) {
        SIZE params[4] = {(info[0] & 8) ? 0x01994000 : 0x19930520, (SIZE)object, (SIZE)info, (SIZE)dll_base};
        RaiseException(0xE06D7363, 1, 4, params);
    }
    if (!dll_cxx_throw) fail();
    dll_cxx_throw(object, info);
    fail();
}
