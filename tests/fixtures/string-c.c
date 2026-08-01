#pragma section(".str.amice", read, write)

__declspec(allocate(".str.amice")) static char c_note[] = "c deobf";
__declspec(allocate(".str.amice")) static char c_meme[] = "c static gang";

int puts(const char *text);

__attribute__((noinline, annotate("+vm_virtualize"))) static int c_vm_math(int value) {
    int mixed = (value ^ 0x55) + 3;
    return (mixed & 1) != 0 ? mixed * 7 : mixed - 11;
}

int main(int argc, char **argv) {
    int first = puts(c_note);
    int second = puts(c_meme);
    return (first == -1 || second == -1) ? 1 : c_vm_math(argc + (argv != 0));
}
