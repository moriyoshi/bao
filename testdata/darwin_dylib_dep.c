// Dependency of darwin_dylib.cpp, linked with install name @rpath/libdep.dylib
// and found through the fixture's @executable_path rpath.
__attribute__((visibility("default"))) int dylib_dep_value(void) { return 5; }
