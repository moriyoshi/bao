// SPDX-License-Identifier: Apache-2.0
namespace fixture { struct Spec { static int method(int value); }; }
int fixture::Spec::method(int value) { return value + 42; }
extern "C" int infer_spec(int value) { return fixture::Spec::method(value); }
extern "C" unsigned long long infer_reference(const unsigned long long &value) { return value; }
