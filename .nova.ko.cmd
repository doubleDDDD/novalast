cmd_fs/nova/nova.ko := ld -r -m elf_x86_64  -z max-page-size=0x200000 -T ./scripts/module-common.lds  --build-id  -o fs/nova/nova.ko fs/nova/nova.o fs/nova/nova.mod.o ;  true
