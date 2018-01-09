# These are plugins to examine ELF files.

from rekall import plugin
from rekall.plugins.addrspaces import standard
from rekall.plugins.overlays.linux import elf


class ELFPlugins(plugin.TypedProfileCommand,
                 plugin.Command):
    """Baseclass for all ELF plugins."""
    PROFILE_REQUIRED = False

    __args = [
        dict(name="binary_path", default=None, positional=True, required=False,
             help="Path to the ELF binary."),

        dict(name="header_offset", default=0, type="IntParser",
             help="Offset to the ELF header."),
    ]

    def _get_elf_header(self):
        if self.plugin_args.binary_path:
            address_space = standard.FileAddressSpace(
                session=self.session,
                filename=self.plugin_args.binary_path)
        else:
            address_space = self.session.GetParameter("default_address_space")

        if address_space == None:
            address_space = self.session.GetParameter("physical_address_space")

        return elf.ELFProfile(session=self.session).elf64_hdr(
            vm=address_space, offset=self.plugin_args.header_offset)


class ELFSections(ELFPlugins):
    name = "elf_sections"

    table_header = [
        dict(name="elf64_shdr", style="address"),
        dict(name="No", width=3),
        dict(name="Name", width=20),
        dict(name="Type", width=20),
        dict(name="Offset", style="address"),
        dict(name="Size", style="address"),
    ]

    def collect(self):
        for i, section in enumerate(self._get_elf_header().sections):
            yield dict(elf64_shdr=section,
                       No=i,
                       Name=section.name,
                       Type=section.sh_type,
                       Offset=section.sh_offset,
                       Size=section.sh_size)


class ELFVerNeeded(ELFPlugins):
    name = "elf_versions_needed"

    table_header = [
        dict(name="divider", type="Divider"),
        dict(name="elf64_verneed", style="address"),
        dict(name="elf64_vernaux", style="address"),
        dict(name="version", width=20),
        dict(name="other_id", width=10)
    ]

    def collect(self):
        verneed = self._get_elf_header().section_by_name(".gnu.version_r").get_section()
        for needed in verneed:
            yield dict(divider=needed.file)
            for aux in needed.aux:
                yield dict(elf64_verneed=needed,
                           elf64_vernaux=aux,
                           version=aux.name,
                           other_id=aux.vna_other)


class ELFVerSymbols(ELFPlugins):
    name = "elf_versions_symbols"

    table_header = [
        dict(name="elf64_sym", style="address"),
        dict(name="other_id", width=5),
        dict(name="file", width=20),
        dict(name="Version", width=20),
        dict(name="Symbol"),
    ]

    def collect(self):
        # The version needed records and the version symbols are
        # joined on the other field.
        needed_other_map = {}
        hdr = self._get_elf_header()
        verneed = hdr.section_by_name(".gnu.version_r").get_section()
        for needed in verneed:
            for aux in needed.aux:
                needed_other_map[aux.vna_other] = (needed, aux)

        # The versyms section refers to symbols defined in the linked section.
        versyms = hdr.section_by_name(".gnu.version")
        dynamic_symbol_table = versyms.get_linked_section().get_section()

        for i, other_ref in enumerate(versyms.get_section()):
            symbol_record = dynamic_symbol_table[i]

            if other_ref == 1 or other_ref == 0:
                continue

            # The symbol record is versioned.
            try:
                needed, aux = needed_other_map[other_ref]
                filename = needed.file
                symbol_name = aux.name
            except KeyError:
                needed = aux = None
                filename = symbol_name = ""

            yield dict(elf64_sym=symbol_record,
                       file=filename,
                       Version=symbol_name,
                       other_id=other_ref,
                       Symbol=symbol_record.name)
