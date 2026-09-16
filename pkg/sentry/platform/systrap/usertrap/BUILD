load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "usertrap",
    srcs = [
        "arm64_branch.go",
        "arm64_bootstrap.go",
        "arm64_specialization.go",
        "usertrap.go",
        "usertrap_amd64.go",
        "usertrap_amd64_unsafe.go",
        "usertrap_arm64.go",
    ],
    marshal = True,
    visibility = ["//pkg/sentry/platform/systrap:__pkg__"],
    deps = [
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/hostarch",
        "//pkg/marshal/primitive",
        "//pkg/rand",
        "//pkg/sentry/arch",
        "//pkg/sentry/kernel",
        "//pkg/sentry/memmap",
        "//pkg/sentry/platform/systrap/sysmsg",
        "//pkg/sync",
        "//pkg/usermem",
        "@org_golang_x_sys//unix:go_default_library",
        "@org_golang_x_time//rate:go_default_library",
    ],
)

go_test(
    name = "usertrap_arm64_test",
    size = "small",
    srcs = ["usertrap_arm64_test.go"],
    library = ":usertrap",
)
