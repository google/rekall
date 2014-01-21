// pe.cpp : Defines the entry point for the console application.
//
#define WIN32_LEAN_AND_MEAN

#include <windows.h>

int main(int argc, char* argv[])
{
	char data[1000];
	IMAGE_OPTIONAL_HEADER *a11 = &data;
	IMAGE_FILE_HEADER *a12 = &data;
	IMAGE_SECTION_HEADER *a13 = &data;
	IMAGE_IMPORT_DESCRIPTOR *a14 = &data;
	IMAGE_EXPORT_DIRECTORY *a15 = &data;
	IMAGE_THUNK_DATA *a16 = &data;
	IMAGE_THUNK_DATA64 *a17 = &data;
	IMAGE_NT_HEADERS *a18 = &data;
	IMAGE_RESOURCE_DIRECTORY *a19 = &data;
	IMAGE_RESOURCE_DIRECTORY_ENTRY *a1a = &data;
	IMAGE_DOS_HEADER *a1b = &data;
	IMAGE_SECTION_HEADER *a1c = &data;
	IMAGE_IMPORT_BY_NAME *a1d = &data;
	IMAGE_NT_HEADERS *a1e = &data;
	IMAGE_NT_HEADERS64 *a1f = &data;
	IMAGE_OPTIONAL_HEADER64 *a1g = &data;
	IMAGE_OPTIONAL_HEADER *a1h = &data;
	IMAGE_DEBUG_DIRECTORY *a1i = &data;
	GUID *a1j = &data;
	// Not a real struct.
	// VS_VERSIONINFO a1k;
	VS_FIXEDFILEINFO *a1l = &data;

	int i;
	unsigned char c=0;

	for(i=0; i<sizeof(data); i++) {
		data[i] = c++;
	};

	return 0;
}

