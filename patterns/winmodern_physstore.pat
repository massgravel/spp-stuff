struct tsd_header {
    u32 len_name;
    char16 name[len_name/2];
    u32 num_entries;
    padding[-$&3];
};

struct tsd_data {
    u32 unk1;
    u32 unk2;
    u32 len_name;
    u32 len_val;
    u32 unk3;
    char16 name[len_name/2];
    u8 value[len_val];
    padding[-$&3];
};

struct tsentry {
    tsd_header header;
    tsd_data data[header.num_entries];
};

struct data_store {
    u32 num_entries;
    tsentry entries[num_entries];
};

data_store store @ 0x8;