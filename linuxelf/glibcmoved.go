package linuxelf

import "strings"

// glibc 2.34 moved these libraries' symbols into libc.so.6, keeping their
// old versions there as compat symbols. An import capped below GLIBC_2.34
// must still name its original library: an older glibc defines the symbol
// only there, and glibc 2.34 and later keep that library as a stub that
// defines the same version nodes, so the symbol is then found in libc.so.6.
//
// The names are those that glibc 2.33's libpthread, libdl, librt, libutil
// and libanl abilist files export, outside GLIBC_PRIVATE, for aarch64,
// x86_64 and powerpc64le, and that libc.so.6's do not. loong64 support
// began with glibc 2.36, after the move.
var glibcMovedSymbols = func() map[string]string {
	m := map[string]string{}
	for library, names := range map[string]string{
		"libpthread.so.0": "__pthread_cleanup_routine __pthread_getspecific __pthread_key_create " +
			"__pthread_mutex_destroy __pthread_mutex_init __pthread_mutex_lock " +
			"__pthread_mutex_trylock __pthread_mutex_unlock " +
			"__pthread_mutexattr_destroy __pthread_mutexattr_init " +
			"__pthread_mutexattr_settype __pthread_once __pthread_register_cancel " +
			"__pthread_register_cancel_defer __pthread_rwlock_destroy " +
			"__pthread_rwlock_init __pthread_rwlock_rdlock __pthread_rwlock_tryrdlock " +
			"__pthread_rwlock_trywrlock __pthread_rwlock_unlock " +
			"__pthread_rwlock_wrlock __pthread_setspecific " +
			"__pthread_unregister_cancel __pthread_unregister_cancel_restore " +
			"__pthread_unwind_next __send _pthread_cleanup_pop " +
			"_pthread_cleanup_pop_restore _pthread_cleanup_push " +
			"_pthread_cleanup_push_defer call_once cnd_broadcast cnd_destroy cnd_init " +
			"cnd_signal cnd_timedwait cnd_wait mtx_destroy mtx_init mtx_lock " +
			"mtx_timedlock mtx_trylock mtx_unlock pthread_atfork " +
			"pthread_attr_getaffinity_np pthread_attr_getguardsize " +
			"pthread_attr_getstack pthread_attr_getstackaddr " +
			"pthread_attr_getstacksize pthread_attr_setguardsize " +
			"pthread_attr_setstack pthread_attr_setstackaddr " +
			"pthread_attr_setstacksize pthread_barrier_destroy pthread_barrier_init " +
			"pthread_barrier_wait pthread_barrierattr_destroy " +
			"pthread_barrierattr_getpshared pthread_barrierattr_init " +
			"pthread_barrierattr_setpshared pthread_cancel pthread_clockjoin_np " +
			"pthread_cond_clockwait pthread_condattr_getclock " +
			"pthread_condattr_getpshared pthread_condattr_setclock " +
			"pthread_condattr_setpshared pthread_create pthread_detach " +
			"pthread_getattr_default_np pthread_getconcurrency pthread_getcpuclockid " +
			"pthread_getname_np pthread_getspecific pthread_join pthread_key_create " +
			"pthread_key_delete pthread_kill pthread_kill_other_threads_np " +
			"pthread_mutex_clocklock pthread_mutex_consistent " +
			"pthread_mutex_consistent_np pthread_mutex_getprioceiling " +
			"pthread_mutex_setprioceiling pthread_mutex_timedlock " +
			"pthread_mutex_trylock pthread_mutexattr_destroy " +
			"pthread_mutexattr_getkind_np pthread_mutexattr_getprioceiling " +
			"pthread_mutexattr_getprotocol pthread_mutexattr_getpshared " +
			"pthread_mutexattr_getrobust pthread_mutexattr_getrobust_np " +
			"pthread_mutexattr_gettype pthread_mutexattr_init " +
			"pthread_mutexattr_setkind_np pthread_mutexattr_setprioceiling " +
			"pthread_mutexattr_setprotocol pthread_mutexattr_setpshared " +
			"pthread_mutexattr_setrobust pthread_mutexattr_setrobust_np " +
			"pthread_mutexattr_settype pthread_once pthread_rwlock_clockrdlock " +
			"pthread_rwlock_clockwrlock pthread_rwlock_destroy pthread_rwlock_init " +
			"pthread_rwlock_rdlock pthread_rwlock_timedrdlock " +
			"pthread_rwlock_timedwrlock pthread_rwlock_tryrdlock " +
			"pthread_rwlock_trywrlock pthread_rwlock_unlock pthread_rwlock_wrlock " +
			"pthread_rwlockattr_destroy pthread_rwlockattr_getkind_np " +
			"pthread_rwlockattr_getpshared pthread_rwlockattr_init " +
			"pthread_rwlockattr_setkind_np pthread_rwlockattr_setpshared " +
			"pthread_setaffinity_np pthread_setattr_default_np pthread_setconcurrency " +
			"pthread_setname_np pthread_setschedprio pthread_setspecific " +
			"pthread_sigqueue pthread_spin_destroy pthread_spin_init " +
			"pthread_spin_lock pthread_spin_trylock pthread_spin_unlock " +
			"pthread_testcancel pthread_timedjoin_np pthread_tryjoin_np pthread_yield " +
			"sem_clockwait sem_close sem_destroy sem_getvalue sem_init sem_open " +
			"sem_post sem_timedwait sem_trywait sem_unlink sem_wait thrd_create " +
			"thrd_detach thrd_exit thrd_join tss_create tss_delete tss_get tss_set ",
		"libdl.so.2": "dladdr dladdr1 dlclose dlerror dlinfo dlmopen dlopen dlsym dlvsym ",
		"librt.so.1": "__mq_open_2 aio_cancel aio_cancel64 aio_error aio_error64 aio_fsync " +
			"aio_fsync64 aio_init aio_read aio_read64 aio_return aio_return64 " +
			"aio_suspend aio_suspend64 aio_write aio_write64 lio_listio lio_listio64 " +
			"mq_close mq_getattr mq_notify mq_open mq_receive mq_send mq_setattr " +
			"mq_timedreceive mq_timedsend mq_unlink shm_open shm_unlink timer_create " +
			"timer_delete timer_getoverrun timer_gettime timer_settime ",
		"libutil.so.1": "forkpty login login_tty logout logwtmp openpty ",
		"libanl.so.1":  "gai_cancel gai_error gai_suspend getaddrinfo_a ",
	} {
		for _, name := range strings.Fields(names) {
			m[name] = library
		}
	}
	return m
}()
