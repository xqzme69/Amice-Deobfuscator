#pragma section(".str.amice", read, write)

struct ReverseNote {
    char text[16];
};

__declspec(allocate(".str.amice")) static ReverseNote cpp_note = {"cpp deobf"};
__declspec(allocate(".str.amice")) static ReverseNote cpp_meme = {"cpp static gang"};

extern "C" int puts(const char *text);

__attribute__((noinline, annotate("+vm_virtualize"))) static int cpp_vm_math(int value) {
    int mixed = (value ^ 0x33) + 5;
    return (mixed & 1) != 0 ? mixed * 9 : mixed - 13;
}

int main(int argc, char **argv) {
    int first = puts(cpp_note.text);
    int second = puts(cpp_meme.text);
    return (first == -1 || second == -1) ? 1 : cpp_vm_math(argc + (argv != nullptr));
}
