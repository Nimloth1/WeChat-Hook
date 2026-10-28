#pragma once
#include <cstddef>
#include <cstdint>
#include <stdexcept>

namespace send_fix {
// The verified constructor copies argument six into its output as a uint64_t.
// Validate/read the source slot; do not treat the copied value as an address.
template<class Reader>
std::uint64_t ReadSendContextValue(std::uint64_t slot, Reader&& reader)
{
    std::uint64_t value = 0;
    std::size_t bytes = 0;
    if (!reader(slot,&value,sizeof(value),bytes) || bytes != sizeof(value))
        throw std::runtime_error("send_context_unavailable");
    return value;
}
} // namespace send_fix
