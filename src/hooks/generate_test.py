from rekall import utils
import subprocess
import re
import yaml

def ExtractTestCases(data):
    test_cases = []

    # The start of the section is at this file offset. This is mapped into
    # memory at the .text segment (which is at offset 0).
    m = re.search("__start__", data)
    origin = m.start()

    for match in re.finditer(
        r"(---.*?\.\.\.)\n<bin>(.+?)</bin>", data, re.M | re.S):
        offset, _ = match.span(2)

        # Replace the assembled segment with a base64 equivalent.
        segment = yaml.safe_load(match.group(1))
        segment["offset"] = offset - origin
        segment["data"] = match.group(2).encode("base64").strip()
        test_cases.append(segment)

    return test_cases

def BuildTestCases(filename, output="tmp.o"):
    if "64" in filename:
        mode = "elf64"
    else:
        mode = "elf"

    subprocess.check_call(["nasm", "-f", mode, "-O0", filename, "-o", output])

    return ExtractTestCases(open(output, "rb").read())

profile = dict(AMD64=BuildTestCases("amd64.asm"),
               I386=BuildTestCases("i386.asm"))

profile["$METADATA"] = dict(
    ProfileClass="TestProfile"
    )

print(utils.PPrint(profile))

