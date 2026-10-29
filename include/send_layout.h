#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace send_fix {
// 保留上游 x64 布局；容量单位分别是字节和 UTF-16 code unit。
struct NarrowString {
    union { char local[16]; char* heap; } data;
    std::uint64_t length;
    std::uint64_t capacity;
};
struct WideString {
    union { char16_t local[8]; char16_t* heap; } data;
    std::uint64_t length;
    std::uint64_t capacity;
};
static_assert(sizeof(void*) == 8 && sizeof(NarrowString) == 32 && sizeof(WideString) == 32);

inline std::u16string Utf16(const std::string& source)
{
    std::u16string result;
    for (std::size_t i = 0; i < source.size();) {
        const auto first = static_cast<unsigned char>(source[i++]);
        std::uint32_t cp = 0;
        unsigned int tail = 0;
        if (first < 0x80) cp = first;
        else if (first >= 0xc2 && first <= 0xdf) { cp = first & 31; tail = 1; }
        else if (first >= 0xe0 && first <= 0xef) { cp = first & 15; tail = 2; }
        else if (first >= 0xf0 && first <= 0xf4) { cp = first & 7; tail = 3; }
        else throw std::invalid_argument("invalid_utf8");
        const unsigned int count = tail;
        while (tail--) {
            if (i == source.size()) throw std::invalid_argument("invalid_utf8");
            const auto next = static_cast<unsigned char>(source[i++]);
            if ((next & 0xc0) != 0x80) throw std::invalid_argument("invalid_utf8");
            cp = (cp << 6) | (next & 63);
        }
        if (!cp || (count == 1 && cp < 0x80) || (count == 2 && cp < 0x800)
            || (count == 3 && cp < 0x10000) || cp > 0x10ffff
            || (cp >= 0xd800 && cp <= 0xdfff)) throw std::invalid_argument("invalid_utf8_or_nul");
        if (cp <= 0xffff) result.push_back(static_cast<char16_t>(cp));
        else {
            cp -= 0x10000;
            result.push_back(static_cast<char16_t>(0xd800 + (cp >> 10)));
            result.push_back(static_cast<char16_t>(0xdc00 + (cp & 1023)));
        }
    }
    return result;
}

struct Heap {
    virtual ~Heap() = default;
    virtual void* Allocate(std::size_t bytes) = 0;
    virtual void Free(void* pointer) noexcept = 0;
};

class Arena {
    Heap& heap_;
    std::vector<void*> owned_;
    std::size_t bytes_ = 0;
    bool retain_ = false;
public:
    explicit Arena(Heap& heap) : heap_(heap) { owned_.reserve(32); }
    ~Arena() { if (!retain_) for (void* pointer : owned_) heap_.Free(pointer); }
    Arena(const Arena&) = delete;
    Arena& operator=(const Arena&) = delete;
    void* Allocate(std::size_t bytes) {
        if (!bytes || bytes > 128 * 1024 - bytes_) throw std::bad_alloc();
        void* pointer = heap_.Allocate(bytes);
        if (!pointer) throw std::bad_alloc();
        try { owned_.push_back(pointer); }
        catch (...) { heap_.Free(pointer); throw; }
        bytes_ += bytes;
        std::memset(pointer, 0, bytes);
        return pointer;
    }
    void RetainOnNativeEntry() noexcept { retain_ = true; }
    std::size_t Bytes() const { return bytes_; }
};

inline NarrowString MakeNarrow(Arena& arena, const std::string& source)
{
    NarrowString result{};
    result.length = source.size();
    result.capacity = 15;
    if (source.size() <= 15) std::memcpy(result.data.local, source.data(), source.size());
    else {
        if (source.size() > 32768) throw std::invalid_argument("string_too_large");
        result.capacity = (source.size() | std::size_t(15));
        result.data.heap = static_cast<char*>(arena.Allocate(result.capacity + 1));
        std::memcpy(result.data.heap, source.data(), source.size());
    }
    return result;
}

inline WideString MakeWide(Arena& arena, const std::u16string& source)
{
    WideString result{};
    result.length = source.size();
    result.capacity = 7;
    if (source.size() <= 7) std::memcpy(result.data.local, source.data(), source.size() * 2);
    else {
        if (source.size() > 4096) throw std::invalid_argument("path_too_large");
        result.capacity = (source.size() | std::size_t(7));
        result.data.heap = static_cast<char16_t*>(arena.Allocate((result.capacity + 1) * 2));
        std::memcpy(result.data.heap, source.data(), source.size() * 2);
    }
    return result;
}

struct Addresses {
    std::uint64_t text_vtable = 0;
    std::uint64_t image_vtable = 0;
    std::uint64_t image_vtable2 = 0;
    std::uint64_t param1_vtable = 0;
    std::uint64_t param2_vtables[3]{};
    std::uint64_t context = 0; // Opaque argument-six value, not a pointer to dereference.
};

struct Frame {
    void* object = nullptr;
    std::uint64_t* arg1 = nullptr;
    std::uint64_t* arg2 = nullptr;
    std::uint64_t* nodes[3]{};
    void* scratch = nullptr;
    NarrowString receiver{};
    NarrowString text{};
    bool image = false;
};

inline void Put64(void* destination, std::size_t offset, std::uint64_t value)
{ std::memcpy(static_cast<char*>(destination) + offset, &value, sizeof(value)); }

inline Frame BuildFrame(Arena& arena, const Addresses& address, const std::string& recipient,
    const std::string& text, const std::u16string* image_path, std::uint64_t file_bytes,
    const std::string& uuid)
{
    Frame frame;
    frame.image = image_path != nullptr;
    frame.receiver = MakeNarrow(arena, recipient);
    // 原文本对象的分配量是 0x768 个 uint64_t；未获 ABI 证据前不擅自缩小。
    frame.object = arena.Allocate(frame.image ? 0x7c0 : 0x768 * sizeof(std::uint64_t));
    if (frame.image) {
        Put64(frame.object, 0, address.image_vtable);
        Put64(frame.object, 8, 0x200000006);
        Put64(frame.object, 16, address.image_vtable2);
        for (auto offset : {0x40,0x60,0x80,0xa0,0x130,0x170,0x1b8,0x668,0x688,
                            0x6b0,0x6f0,0x710,0x738,0x760,0x780,0x7a0}) Put64(frame.object, offset, 15);
        Put64(frame.object, 0xa8, 0x0000000100000000);
        Put64(frame.object, 0xb0, 0x0000000700000000);
        Put64(frame.object, 0xe8, 3); // 仅 PNG/JPEG/BMP，不猜测 GIF 或普通文件类型。
        Put64(frame.object, 0x150, 7);
        Put64(frame.object, 0x198, file_bytes);
        auto wide = MakeWide(arena, *image_path);
        auto guid = MakeNarrow(arena, uuid);
        std::memcpy(static_cast<char*>(frame.object) + 0xc0, &frame.receiver, 32);
        std::memcpy(static_cast<char*>(frame.object) + 0xf0, &wide, 32);
        std::memcpy(static_cast<char*>(frame.object) + 0x6b8, &guid, 32);
        // 不再用 UTF-8 路径长度覆盖宽字符串的 length/capacity。
    } else {
        Put64(frame.object, 0, address.text_vtable);
        Put64(frame.object, 8, 0x200000005);
        frame.text = MakeNarrow(arena, text);
    }
    auto inner = static_cast<std::uint64_t*>(arena.Allocate(0x20 * sizeof(std::uint64_t)));
    inner[0] = reinterpret_cast<std::uint64_t>(frame.object) + 16;
    inner[1] = reinterpret_cast<std::uint64_t>(frame.object);
    frame.arg1 = static_cast<std::uint64_t*>(arena.Allocate(0x28 * sizeof(std::uint64_t)));
    frame.arg1[0] = address.param1_vtable;
    frame.arg1[1] = reinterpret_cast<std::uint64_t>(inner);
    frame.arg1[2] = frame.arg1[3] = reinterpret_cast<std::uint64_t>(inner) + 16;
    frame.arg1[4] = 1;
    frame.arg2 = static_cast<std::uint64_t*>(arena.Allocate(0xe8 * sizeof(std::uint64_t)));
    frame.scratch = arena.Allocate(128); // 两条路径统一采用上游较大的分配，不缩成 16 字节。
    for (unsigned int i = 0; i < 3; ++i) {
        frame.nodes[i] = static_cast<std::uint64_t*>(arena.Allocate(512));
        frame.nodes[i][0] = address.param2_vtables[i];
        frame.nodes[i][7] = reinterpret_cast<std::uint64_t>(frame.nodes[i]);
    }
    return frame;
}

inline void FinishTextFrame(Frame& frame)
{
    // 文本构造器先运行；只接受空字符串，避免覆盖未知构造器拥有的堆对象。
    auto object = static_cast<char*>(frame.object) + 16;
    for (auto offset : {0xb0, 0x708}) {
        NarrowString existing{};
        std::memcpy(&existing, object + offset, 32);
        if (existing.length || existing.capacity > 15) throw std::runtime_error("unexpected_text_constructor_layout");
    }
    std::memcpy(object + 0xb0, &frame.receiver, 32);
    std::memcpy(object + 0x708, &frame.text, 32);
    Put64(object, 0xd8, 1);
    Put64(object, 0x188, frame.text.length);
}

struct Invoker {
    virtual ~Invoker() = default;
    virtual bool RetainsArguments() const = 0;
    virtual bool InitText(std::uint64_t object) = 0;
    virtual bool CreateParams(std::uint64_t out, std::uint64_t node0, std::uint64_t node1,
        std::uint64_t node2, std::uint64_t scratch, std::uint64_t context) = 0;
    virtual bool Submit(std::uint64_t arg1, std::uint64_t arg2) = 0;
};
enum class FrameResult { constructor_fault, constructor_layout_unknown, params_fault, submit_fault, unconfirmed };

inline FrameResult ExecuteFrame(Arena& arena, Frame& frame, const Addresses& address, Invoker& invoke)
{
    // 微信异步持有参数的释放契约未公开；禁止在私有函数进入后擅自释放这些参数。
    // 每帧最多 128 KiB；生产 NativePrepared 另行预留进程累计预算，不能据此声称安全回收。
    if (invoke.RetainsArguments()) arena.RetainOnNativeEntry();
    if (!frame.image) {
        if (!invoke.InitText(reinterpret_cast<std::uint64_t>(frame.object) + 16))
            return FrameResult::constructor_fault;
        try { FinishTextFrame(frame); }
        catch (...) { return FrameResult::constructor_layout_unknown; }
    }
    if (!invoke.CreateParams(reinterpret_cast<std::uint64_t>(frame.arg2),
        reinterpret_cast<std::uint64_t>(frame.nodes[0]), reinterpret_cast<std::uint64_t>(frame.nodes[1]),
        reinterpret_cast<std::uint64_t>(frame.nodes[2]), reinterpret_cast<std::uint64_t>(frame.scratch), address.context))
        return FrameResult::params_fault;
    if (!invoke.Submit(reinterpret_cast<std::uint64_t>(frame.arg1), reinterpret_cast<std::uint64_t>(frame.arg2)))
        return FrameResult::submit_fault;
    return FrameResult::unconfirmed;
}
} // namespace send_fix
