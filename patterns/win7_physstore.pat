#include <std/mem.pat>

struct tsd_data {
    u32 val_type; // 0 None, 1 Named, 2 Attribute, 3 Timer
    u32 flags;
    u32 len_key;
    u32 len_val;
    u32 len_data;
    char16 key[len_key/2];
    u8 value[len_val];
    u8 data[len_data];
    padding[-$&3];
};

tsd_data store[while($ < std::mem::size())] @ 0x8;