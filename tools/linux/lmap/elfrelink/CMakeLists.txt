add_definitions(-std=c99 -Wall -Wextra -ggdb)

add_library(elfrelink elfrelink.c elf_object.c elf_sections.c elf_symbols.c elf_relocations.c)

target_link_libraries(elfrelink log)
