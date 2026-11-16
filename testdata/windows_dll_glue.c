// Relocatable glue combined with windows_dll.cpp's DLL (bao build
// -windows-dll). It calls and reads the DLL's exports, wraps the CreateThread
// calls of both itself and the DLL (-wrap CreateThread), and has thread-local
// variables of its own beside the DLL's. Prototypes are spelled out so the
// freestanding compile needs no SDK headers.
#ifdef _MSC_VER
#define THREAD_LOCAL __declspec(thread)
#else
#define THREAD_LOCAL __thread
#endif

typedef unsigned long (*start_routine)(void *);
void *CreateThread(void *, unsigned long long, start_routine, void *, unsigned long, unsigned long *);
void *__real_CreateThread(void *, unsigned long long, start_routine, void *, unsigned long, unsigned long *);
unsigned long WaitForSingleObject(void *, unsigned long);
int CloseHandle(void *);

__declspec(dllimport) int dll_threads(int n);
__declspec(dllimport) extern int dll_value;

static THREAD_LOCAL int depth;
static THREAD_LOCAL int seeded = 11;
static int wrapped;
static int worker_result;

// Thread starts all come from the thread that calls glue_check.
void *__wrap_CreateThread(void *attributes, unsigned long long stack, start_routine start, void *arg, unsigned long flags, unsigned long *id) {
    wrapped++;
    return __real_CreateThread(attributes, stack, start, arg, flags, id);
}

static unsigned long worker(void *arg) {
    depth += (int)(long long)arg;
    worker_result = depth + seeded;
    return 0;
}

// out: the DLL's thread sum, wrapped thread starts, a new thread's glue TLS,
// this thread's glue TLS, and the DLL's data export.
void glue_check(int n, int *out) {
    depth = 5;
    void *thread = CreateThread(0, 0, worker, (void *)3, 0, 0);
    WaitForSingleObject(thread, 0xffffffff);
    CloseHandle(thread);
    out[0] = dll_threads(n);
    out[1] = wrapped;
    out[2] = worker_result;
    out[3] = depth + seeded;
    out[4] = dll_value;
}
