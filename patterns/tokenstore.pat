struct EntryContent {
    u8 header[32];
    u32 data_len;
    u8 sha256[32];
    u8 data[data_len];
    u8 footer[32];
};

struct Metadata {
    u32 entry_off;
    u32 populated;
    u32 content_off;
    u32 content_len;
    u32 alloc_len;
    char16 name[65];
    char16 ext[4];

    if (populated == 1) {
        EntryContent content @ content_off;
    }
};

struct Block {
    u32 self_off;
    u32 next_off;
    Metadata metadata[103];
    padding[16384 - sizeof(self_off) - sizeof(next_off) - sizeof(metadata)];
    u8 sha256[32];

    if (next_off != 0) {
        Block next @ next_off;
    }
};

struct FileHeader {
    u32 version;
    u8 sha256[32];
    Block block;
};

FileHeader fileheader @ 0x00;