__attribute__((noinline))
static int native_mix(int value) {
    return value + 3;
}

__attribute__((noinline, annotate("+vm_virtualize")))
static int simple_vm(int value) {
    return (native_mix(value) * 7) ^ 0x55;
}

__attribute__((
    noinline,
    annotate("+vm_virtualize,vm_profile_path=../amice/crates/amice-vm/profiles/ruoke")
))
static int ruoke_vm(int value) {
    return (native_mix(value) + 11) ^ 0x33;
}

int main(int argc, char **argv) {
    return simple_vm(argc) + ruoke_vm(argv != 0);
}
