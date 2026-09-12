#include <cstdint>
#include <cstdio>
#include <cstdlib>

#include <rust/RustBridge.h>

namespace stellar
{
namespace rust_bridge
{

bool
verify_ed25519_signature_dalek(const ::std::uint8_t *, const ::std::uint8_t *,
                               const ::std::uint8_t *, ::std::size_t) noexcept
{
    std::fprintf(stderr,
                 "core-oracle: verify_ed25519_signature_dalek was called. This "
                 "oracle links only the quorum predicates and stubs the rust "
                 "bridge, so any answer would be meaningless.\n");
    std::abort();
}

void
init_logging(::stellar::LogLevel)
{
}

}

void
printCurrentBacktrace()
{
    std::fprintf(stderr, "core-oracle: backtrace unavailable in this build\n");
}

}
