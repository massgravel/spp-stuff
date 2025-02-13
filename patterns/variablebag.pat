#include <std/mem.pat>

struct varbag_entry {
    u32 crc32;
    u32 unk1;
    u32 len_name;
    u32 len_val;
    char16 name[len_name/2];
    padding[-$&7];
    u8 value[len_val];
    padding[-$&7];
};

varbag_entry entries[while($ < std::mem::size())] @ 0x0;