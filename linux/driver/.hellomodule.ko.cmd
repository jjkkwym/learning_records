cmd_/home/flc/learning_records/linux/driver/hellomodule.ko := ld -r -m elf_x86_64  -z max-page-size=0x200000 -T ./scripts/module-common.lds --build-id  -o /home/flc/learning_records/linux/driver/hellomodule.ko /home/flc/learning_records/linux/driver/hellomodule.o /home/flc/learning_records/linux/driver/hellomodule.mod.o