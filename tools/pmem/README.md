# Pmem Memory acquisition Suite

Version 2.0rc1
Copyright 2015 Google Inc. All rights reserved.

Author: Michael Cohen <scudette@google.com>

The Pmem physical memory acquisition tools are advanced memory acquisition
tools. The acquisition tool is build around the standard AFF4 imager and
provides all of its standard functionality. However, additionally, the pmem tool
is also able to acquire physical memory on all platforms, as well as the page
file.

## How to use the pmem acquisition tool.

By default the pmem acquisition tool will write an AFF4 volume. AFF4 volumes can
contain multiple streams of data, each identified by a unique name. Pmem will
add a physical memory stream to the volume, as well as the pagefile if
requested, and other important system files which may be required during
analysis.

Currently the AFF4 library supports three types of compression:

- "snappy" compression is based on Google's snappy compressor. The compression
  ratio is somewhat less than zlib provides, but acquisition speed is very
  high. For some indicative numbers, On my system snappy compressed images are
  acquired at around 300-350mb/s (of raw data). A 16Gb memory image is written
  in approximately 50 seconds and the resulting image is around 6.7Gb.

- "zlib" compression is the default compression used by AFF4. On my system zlib
  compressed images are acquired at approximately 90MiB/s. The same 16Gb image
  is aquired in 2:55 (175 sec) and the resulting image is around 5.0Gb.

- "none" compression is uncompressed data. An AFF4 image is still written but no
  compression is applied. It is typically slightly slower than snappy due to the
  higher IO demands.

For memory images we recommend the "snappy" compression as the best tradeoff
between speed of acquisition (to minimize smear) and final image size.


### To acquire memory to a new AFF4 volume:

```
# pmem_imager -o /tmp/myimage.aff4 -c snappy -t
```

The -o option specifies the output volume to write. The -c option specifies the
compression algorithm and the -t option specifies to truncate the output
file.

### Adding logical files to the AFF4 volume.

By default AFF4 imagers do not truncate the output volume in order to allow
additional streams to be added to a volume at a later time. Thus if you find
that you want to add another logical file acquisition to the image after
acquiring the image, you can simply do so without deleting the existing memory
image. e.g. to acquire all the files in the /boot/ directory:

```
# pmem_imager -i /boot/* -o /tmp/myimage.aff4
```

Note that pmem will not re-acquire memory if there is already a physical memory
stream in the volume unless provided with the -m option.

### Inspecting the contents of an AFF4 volume.

To inspect the content of an AFF4 volume, you can simply use the -V flag:
```
# ./pmem_imager -V /tmp/test.zip
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
@prefix aff4: <http://aff4.org/Schema#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .

<aff4://eaab0ac2-fc70-4060-9af8-c122e8aca072/boot/System.map-3.13.0-44-generic>
    aff4:chunk_size 32768 ;
    aff4:chunks_per_segment 1024 ;
    aff4:compression <https://github.com/google/snappy> ;
    aff4:size 3388834 ;
    aff4:stored <aff4://eaab0ac2-fc70-4060-9af8-c122e8aca072> ;
    a aff4:image .

<aff4://eaab0ac2-fc70-4060-9af8-c122e8aca072/proc/kcore>
    aff4:category <http://aff4.org/Schema#memory/physical> ;
    aff4:stored <aff4://eaab0ac2-fc70-4060-9af8-c122e8aca072> ;
    a aff4:map .

<aff4://eaab0ac2-fc70-4060-9af8-c122e8aca072/proc/kcore/data>
    aff4:chunk_size 32768 ;
    aff4:chunks_per_segment 1024 ;
    aff4:compression <https://github.com/google/snappy> ;
    aff4:size 17071980544 ;
    aff4:stored <aff4://eaab0ac2-fc70-4060-9af8-c122e8aca072> ;
    a aff4:image .
```

You can see one stream for each object stored in the volume. The physical memory
segment is denoted by the stream with the category of *memory/physical*. Since
physical memory is sparse, the physical memory stream is usually an *aff4:map*
(which can be sparse). The actual data is stored in the *aff4:image* which has a
name ending with /data.

### Extracting a stream from a volume.

While it is possible to just use the AFF4 volume normally in Rekall, it is also
possible to extract any stream directly:

```
# pmem_imager -e boot/vmlinuz-3.13.0-44-generic -o /tmp/vmlinuz-3.13.0-44-generic /tmp/myimage.aff4
```
