#include <aos/aos.h>
#include <fs/fat32.h>


static inline bool valid_fat32_fname_char(char c, int index_in_fname)
{
    if (c == 0x05 && index_in_fname == 0) {
        return true;
    }

    if (c == 0x20 && index_in_fname == 0) {
        return false;
    }

    if (c < 0x20) {
        return false;
    }

    switch (c) {
    case 0x22:
    case 0x2A:
    case 0x2B:
    case 0x2C:
    case 0x2E:
    case 0x2F:
    case 0x3A:
    case 0x3B:
    case 0x3C:
    case 0x3D:
    case 0x3E:
    case 0x3F:
    case 0x5B:
    case 0x5C:
    case 0x5D:
    case 0x7C:
        return false;
    default:
        return true;
    }
}

static void copy_fname_suffix(char *from, char *to, int limit)
{
    int i;
    for (i = 0; i < limit; i++) {
        if (from[i] != ' ') {
            to[i] = from[i];
        } else {
            to[i] = 0;
            break;
        }
    }
    to[i] = 0;
}

// TODO spaces in original name
void fat32_decode_fname(char *encoded, char *decoded)
{
    char candidate[12];
    memcpy(candidate, encoded, 11);
    if (candidate[0] == 0x05) {
        candidate[0] = 0xE5;
    }

    for (int i = 0; i < 11; i++) {
        candidate[i] = tolower(candidate[i]);
    }

    // find last whitespace position starting from padding
    int i;
    int extension_start_index = 8;
    for (i = extension_start_index - 1; i >= 0; i--) {
        if (candidate[i] != ' ') {
            break;
        }
    }

    memcpy(decoded, candidate, i + 1);
    if (i != extension_start_index - 1 && candidate[extension_start_index] != ' ') {
        decoded[i + 1] = '.';
        copy_fname_suffix(candidate + extension_start_index, decoded + i + 2, 3);
    } else {
        // no dot in resulting file name
        copy_fname_suffix(candidate + i + 1, decoded + i + 1, 11 - (i + 1));
    }
}

bool fat32_encode_fname(char *old, char *new_name)
{
    int N = strlen(old);
    if (N > 12) {
        return false;
    }

    if (N == 0) {
        return false;
    }

    if (old[0] == '.') {
        if (N == 1) {
            memcpy(new_name, ".          ", 11);
            return true;
        } else if (N == 2 && old[1] == '.') {
            memcpy(new_name, "..         ", 11);
            return true;
        }
    }

    char candidate[12];
    memset(candidate, 0x20, 12);
    memcpy(candidate, old, N);
    memset(new_name, 0x20, 11);

    // check if there is a dot in the name
    int dot_position = -1;
    for (int i = N - 1; i >= 1; i--) {
        if (candidate[i] == '.') {
            dot_position = i;
            candidate[i] = 0x20;
            break;
        }
    }

    if (dot_position == -1 && N > 11) {
        return false;
    }

    if (candidate[0] == 0xE5) {
        candidate[0] = 0x05;
    }

    // to uppercase & validate each char
    for (int i = 0; i < N; i++) {
        candidate[i] = (char)toupper(candidate[i]);
        if (!valid_fat32_fname_char(candidate[i], i)) {
            DEBUG_PRINTF("invalid char: %c\n", candidate[i]);
            return false;
        }
    }

    // copy everything from the last dot to the end
    if (dot_position != -1) {
        // TODO: what if extension is too long or multiple dots?
        assert(N - dot_position - 1 <= 3);

        int chars_after_dot = N - dot_position - 1;
        memcpy(new_name + 8, candidate + dot_position + 1, chars_after_dot);
        memcpy(new_name, candidate, dot_position);
    } else {
        memcpy(new_name, candidate, N);
    }

    return true;
}