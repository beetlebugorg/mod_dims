# The soak client.
#
# It is an operational tool, not a case. ctest never runs it: a soak takes
# hours and needs a corpus that is not in the repository. It builds with
# everything else so the compiler checks it.
#
#   bash test/endurance/run.sh

add_executable(dims_soak
    soak.c
    gen.c
    sign.c
    corpus.c
    image.c)

target_link_libraries(dims_soak PRIVATE
    PkgConfig::CURL
    PkgConfig::CRYPTO)

target_compile_definitions(dims_soak PRIVATE _GNU_SOURCE)

dims_set_warnings(dims_soak)
dims_set_hardening(dims_soak)
dims_set_sanitizers(dims_soak)
