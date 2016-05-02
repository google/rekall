from rekall.plugins.overlays.windows import win8

win10_undocumented_amd64 = {
    # wi10.raw 18:05:45> dis "nt!MiSessionInsertImage"
    #        call 0xf8014a9d4e80                      nt!memset
    # ...    or rax, 3    <---- Base address is ORed with 3.
    #        mov dword ptr [rbp + 0x3c], 1   <--- ImageCountInThisSession
    #        mov qword ptr [rbp + 0x28], rax  <---- Address
    '_IMAGE_ENTRY_IN_SESSION': [None, {
        'Address': [0x28, ["_EX_FAST_REF"]],
        }],
    }

win10_undocumented_i386 = {
    '_IMAGE_ENTRY_IN_SESSION': [None, {
        'Address': [0x14, ["Pointer"]],
        }],
    }

win10_overlays = {
    '_MM_SESSION_SPACE': [None, {
        # Specialized iterator to produce all the _IMAGE_ENTRY_IN_SESSION
        # records. In Win10 these are stored in an AVL tree instead.
        'ImageIterator': lambda x: x.ImageTree.Root.traverse(
            type="_IMAGE_ENTRY_IN_SESSION")
    }],

    "_UNLOADED_DRIVERS": [None, {
        "CurrentTime": [None, ["WinFileTime"]],
    }],

    "_MI_HARDWARE_STATE": [None, {
        "SystemNodeInformation": [None, ["Pointer", dict(
            target="Array",
            target_args=dict(
                target="_MI_SYSTEM_NODE_INFORMATION",
                count=lambda x: x.obj_profile.get_constant_object(
                    "KeNumberNodes", "unsigned int").v(),
            )
        )]],
    }],
}


def InitializeWindows10Profile(profile):
    """Initialize windows 10 profiles."""
    win8.InitializeWindows8Profile(profile)
    profile.add_overlay(win10_overlays)

    if profile.metadata("arch") == "AMD64":
        profile.add_overlay(win10_undocumented_amd64)
    else:
        profile.add_overlay(win10_undocumented_i386)

    # Older Win10 releases include SystemNodeInformation inside
    # _MI_SYSTEM_INFORMATION
    if not profile.has_type("_MI_HARDWARE_STATE"):
        profile.add_overlay({
            "_MI_SYSTEM_INFORMATION": [None, {
                "SystemNodeInformation": [None, ["Pointer", dict(
                    target="Array",
                    target_args=dict(
                        target="_MI_SYSTEM_NODE_INFORMATION",
                        count=lambda x: x.obj_profile.get_constant_object(
                            "KeNumberNodes", "unsigned int").v(),
                    )
                )]],
            }],
        })
