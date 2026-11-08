// SPDX-License-Identifier: Apache-2.0
// Ordinary C++ executable baseline, independent of Bao and Go.
#include <cstdint>
#include <cstdio>
#include <thread>
extern "C" std::uint64_t bao_example_run();
#if defined(BAO_CPP_TLS) || defined(BAO_CPP_RUNTIME)
extern "C" std::uint64_t bao_example_check_finalized();
#endif
#if defined(BAO_CPP_STATIC) || defined(BAO_CPP_RUNTIME)
extern "C" std::uint64_t bao_example_finalize();
#endif
int main(int argc, char **) {
    std::uint64_t result = 0;
#if defined(BAO_CPP_TLS) || defined(BAO_CPP_RUNTIME)
    std::thread worker([&] { result = bao_example_run(); });
    worker.join();
    const auto finalized = bao_example_check_finalized();
    if (result != 42 || finalized != 42) {
        std::printf("CPP_NATIVE_RESULT:%llu; TLS_FINALIZED:%llu\n",
            static_cast<unsigned long long>(result), static_cast<unsigned long long>(finalized));
        return 1;
    }
#else
    result = bao_example_run();
    if (result != 42) return 2;
#endif
#if defined(BAO_CPP_RUNTIME)
    if (bao_example_finalize() != 42) return 3;
#elif defined(BAO_CPP_STATIC)
    if (argc > 1 && bao_example_finalize() != 42) return 3;
#endif
    std::puts("PASS: native C++ control");
}
