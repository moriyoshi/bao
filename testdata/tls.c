static _Thread_local unsigned long counter = 41;

unsigned long bao_tls_next(void) {
    return ++counter;
}
