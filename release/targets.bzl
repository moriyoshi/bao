"""Pure Go CLI distributions; native translation targets are a separate list."""

load("@rules_go//go:def.bzl", "go_binary")

def release_binaries():
    for target in ["darwin_arm64", "darwin_amd64", "linux_amd64", "linux_arm64", "linux_loong64", "linux_ppc64le"]:
        goos, goarch = target.split("_")
        go_binary(
            name = "release_" + target,
            embed = [":bao_lib"],
            goos = goos,
            goarch = goarch,
            pure = "on",
            x_defs = {
                "github.com/moriyoshi/bao/cmd/bao.version": "{STABLE_BAO_VERSION}",
                "github.com/moriyoshi/bao/cmd/bao.commit": "{STABLE_BAO_COMMIT}",
            },
            visibility = ["//visibility:public"],
        )
