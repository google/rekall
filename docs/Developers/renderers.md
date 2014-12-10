---
layout: docs
title: The Rekall Rendering framework.
author: Michael Cohen <scudette@gmail.com>
---

One of Rekall's primary goals is to provide an API so that external tools may
use it as a library. To this end, Rekall aims to provide a flexible output
mechanism which is custimizable by external code, while remaining easy to use.

Most of Rekall's functionality comes about through the use of plugins. A
plugin's output is designed to be viewable in a wide range of scenarios, without
burdening the plugin itself with the task of customizing output for different
scenarios.

For example, consider running the `pslist` plugin. This plugin produces a
tabular output in the TextRenderer. However, when viewed using the Web Console,
the output is formatted using stylized HTML. Furthermore, the web console UI is
able to interact with the table in a more natural way - for example, right
clicking brings up further context sensitive menus.

Another example is the storage and transmission of plugin results using external
sources. In previous versions of the software, the only way to capture the
output of the plugin was to parse the textual output. This is error prone and
usually requires specialized parsers to be written for each Rekall plugin. Using
the current model, it is possible to store, and later recreate, precisely all
the objects within the Rekall session. This allows the Rekall session to be
permanently stored and many items can be cached within it.

The main motivation of the Rekall renderer design is the separation of data and
visualization. The plugin provides raw data to the rendering layer, which is
responsible for rendering the data. This is a similar idea to the separation of
content and layout which occurs in HTML/CSS designs. Having the freedom to
custimize the layout independently from the data allows for much more powerful
visualization frameworks.

## Renderer architecture overview.

These are the main components of the Rekall renderer design:

1. The Rekall plugin is a class which extends `rekall.plugin.Command()`. The
   plugin contains the code which performs the analysis. The framework is
   responsible for instantiating the plugin with user provided parameters.

2. The plugin is provided with a "renderer" - which is a class extending
   `rekall.ui.renderer.BaseRenderer()`. The renderer is responsible for layout
   and visualization of the data. Hence this forms a natural separation between
   data (produced by the plugin) and layout (provided by the renderer).

     Note that the plugin sends the renderer arbitrary objects - the plugin must
     not perform any formatting by itself. So for example, the plugin must send
     the renderer an `_EPROCESS()` instance rather than the integer offset
     (`proc.obj_offset`)

3. Finally, the renderer delegates specific visualization of objects to an
   instance of `ObjectRenderer()`. The ObjectRenderer is a special class which
   knows how to format a specific object using a specific renderer.

Let us consider each of these types with an example.

### The Renderer interface.

The renderer API is defined in the class `BaseRenderer()`. The plugin produces
output by calling methods on the renderer.

Consider the `pslist` plugin. This is the default output (using the
TextRenderer):

```python
_EPROCESS          Name          PID   PPID   Thds    Hnds    Sess  Wow64           Start                     Exit
---------- -------------------- ----- ------ ------ -------- ------ ------ ------------------------ ------------------------
0x823c8a00 System               4          0     57      671      -  False -                        -
0x82129370 svchost.exe          364      744      4       88      0  False 2010-09-02 12:25:33+0000 -
0x82189530 prl_tools_servi      436      744      3       78      0  False 2010-09-02 12:25:36+0000 -
0x82089558 jqs.exe              472      744      5      146      0  False 2010-09-02 12:25:33+0000 -
0x8208abf0 sqlservr.exe         488      744     25      306      0  False 2010-09-02 12:25:33+0000 -
0x82077da0 coherence.exe        572      744      4       51      0  False 2010-09-02 12:25:36+0000 -
0x82292da0 smss.exe             596        4      3       19      -  False 2010-09-02 12:25:18+0000 -
```

and this is the code which produces this output:

```
#!python
    def render(self, renderer):
        renderer.table_header([
            dict(name="_EPROCESS", type="_EPROCESS"),
            dict(name="PPID", cname="ppid", formatstring=">6"),
            dict(name="Thds", cname="thread_count", formatstring=">6"),
            dict(name="Hnds", cname="handle_count", formatstring=">8"),
            dict(name="Sess", cname="session_id", formatstring=">6"),
            dict(name="Wow64", cname="wow64", formatstring=">6"),
            dict(name="Start", cname="process_create_time", formatstring="24"),
            dict(name="Exit", cname="process_exit_time", formatstring="24")])

        for task in self.filter_processes():
            renderer.table_row(task,
                               task.InheritedFromUniqueProcessId,
                               task.ActiveThreads,
                               task.ObjectTable.m("HandleCount"),
                               task.SessionId,
                               task.IsWow64,
                               task.CreateTime,
                               task.ExitTime,
                               )
```

The plugin receives a renderer object and calls the `table_header()` method on
it. This effectively defines a record format for the plugin output, with each
column representing a field.

The first field is named `_EPROCESS` and will receive an `_EPROCESS` object (the
task). The type of this field is also declared in the column header.

Additionally the column definition contains a number of options. Options can
influence the rendering of each column, depending on which renderer is used. For
example, the "formatstring" option is only meaningful to the TextRenderer, and
specifies the width of each column in characters (it is not meaningful for the
JsonRenderer for example, and it is ignored if the JsonRenderer is used).

After defining the table headers, the plugin then goes on to populate each row
in the table using the `render_row()` method. Each row represents a single
record of data. Note that the plugin provides a complete object for each cell
and does not attempt to format the data in any way.

### Object renderers.

You might also notice that there is a discrepancy between the code and the
output above. The output contains 3 columns which are not provided by the
code. We can see that the TextRenderer displays a column named "_EPROCESS",
"Name" and "PID", but the code only declares a single column. What is going on?

Since the renderer receives python objects for each field, but must emit
renderer specific output, there must be a way to convert from a python object to
renderer specific output. For example, for the TextRenderer, the _EPROCESS()
object must be converted to some text representation which can be rendered in
the table.

The TextRenderer itself does not have any specific knowledge of how to render an
_EPROCESS object. To do this, the TextRenderer must delegate rendering to an
`ObjectRenderer()` class.

Here is what the `EPROCESS_ObjectRenderer()` class looks like:

```
#!python
class EPROCESS_ObjectRenderer(renderer.ObjectRenderer):
    renders_type = "_EPROCESS"
    renderers = ["TextRenderer"]

    def __init__(self, *args, **options):
        """We make a sub table for rendering the _EPROCESS."""
        super(EPROCESS_ObjectRenderer, self).__init__(*args, **options)
        self.table = text.TextTable(
            columns=[
                ("_EPROCESS", "eprocess", "[addrpad]"),
                ("Name", "name", "20s"),
                ("PID", "pid", "5s")],
            renderer=self.renderer,
            session=self.session)

    def render_header(self, name, **options):
        self.name = name
        return self.table.render_header()

    def render_row(self, target, **options):
        cells = self.table.get_row(target.obj_offset, target.name, target.pid)

        return text.Cell.Join(cells)
```

In the above code, lines 2 and 3 declare this `ObjectRenderer` as being
responsible for rendering an "_EPROCESS" object under the "TextRenderer"
renderer. Note that the ObjectRenderer acts specifically on both the object type
*and* the renderer.

The `EPROCESS_ObjectRenderer()` goes on to create a subtable with three columns,
and then provides two methods - one to render the headers and another to render
each row. This is how three columns appear to describe a single _EPROCESS
column. Note that this particular layout is specific to the TextRenderer
only. This is the output using the `WideTextRenderer()` renderer (A renderer
which displays each record in a 2 column display):

```
#!text  guess_lang=False
_EPROCESS       csrss.exe Pid: 668 (@0x821f2978)
PPID            596
Thds            14
Hnds            471
Sess            0
Wow64            False
Start           2010-09-02 12:25:21+0000
Exit            -
```

We see that in this example, the `_EPROCESS` field is described using a format
string with interpolated values containing the name, pid and offset. To achieve
this effect we must define a specific `EPROCESS_WideTextObjectRenderer()`:

```
#!python guess_lang=False
class EPROCESS_WideTextObjectRenderer(renderer.ObjectRenderer):
    renders_type = "_EPROCESS"
    renderers = ["WideTextRenderer"]

    def render_row(self, target, **_):
        return text.Cell.FromString(
            self.formatter.format("{0:s} Pid: {1:s} (@{2:#x})",
                                  target.name, target.pid, target))
```

### Object Renderer selection.

We saw in the last section, that the Renderer delegates the conversion of a
python object to an ObjectRenderer class. The ObjectRenderer chosen is specific
both to the Renderer used, and the object type to be rendered.

However, it would be extremely tedious if we had to define a new
`ObjectRenderer()` class for each possible object type and renderer type. In
order to make this more efficient, we must consider exactly how the renderer
chooses the correct ObjectRenderer() class to use.

When a Renderer needs to convert from a python object to a renderer specific
output, it searches for an ObjectRenderer along the inheritance tree of both the
python object to be rendered and the renderer class itself (in python speak, the
inheritance tree is called the MRO - method resolution order). Here is the code
that does it:

```
#!python
        # Search for a handler which supports both the renderer and the object
        # type.
        for mro_cls in cls.get_mro(target):
            for renderer_cls in cls.get_mro(renderer):
                handler = cls._RENDERER_CACHE.get((mro_cls, renderer_cls))
                if handler:
                    return handler
```

For example, consider rendering the "Start" column which contains the process start time:

```
#!python
zeus2x4.vmem.E01 02:18:30> from rekall.ui import  renderer
zeus2x4.vmem.E01 02:18:32> task = profile._EPROCESS(0x8208abf0)
zeus2x4.vmem.E01 02:18:32> task.CreateTime
                    Out<4>  [WinFileTime:CreateTime]: 0x4C7F97BD (2010-09-02 12:25:33+0000)

zeus2x4.vmem.E01 02:18:39> renderer.ObjectRenderer.ForTarget(task.CreateTime, "TextRenderer")
                    Out<3> rekall.plugins.renderers.windows.UnixTimestampObjectRenderer
zeus2x4.vmem.E01 02:21:56> task.CreateTime.__class__.__mro__
                    Out<5>
(rekall.plugins.overlays.basic.WinFileTime,
 rekall.plugins.overlays.basic.UnixTimeStamp,
 rekall.obj.NativeType,
 rekall.obj.NumericProxyMixIn,
 rekall.obj.BaseObject,
 object)
```

As we can see the `task.CreateTime` member is an instance of the `WinFileTime()`
class. However, the object renderer chosen is `UnixTimestampObjectRenderer()`
since it is used to render a `UnixTimeStamp()` instance.

The `ObjectRenderer()` are essentially chosen from in the most specific to least
specific order.

### The JsonRenderer

As an example, let us examine the JsonRenderer. This renderer is designed to
store objects in a json stream in such a way that they can be decoded and
restored at a later time. At a later time, we re-create the object using the
same memory image, address spaces etc.

```
#!bash
$ rekall -v --de -f zeus2x4.vmem.E01 --renderer JsonRenderer pslist | json_pp
   {
....
            "vm" : {
               "base" : {
                  "filename" : [
                     "*",
                     "zeus2x4.vmem.E01"
                  ],
                  "id" : 7131,
                  "type" : "EWFAddressSpace,CachingAddressSpaceMixIn,FDAddressSpace,BaseAddressSpace,object"
               },
               "dtb" : 233472,
               "id" : 7158,
               "type" : "IA32PagedMemory,PagedReader,BaseAddressSpace,object"
            },
            "type_name" : "_EPROCESS",
            "profile" : {
               "name" : "nt/GUID/1B2D0DFE2FB942758D615C901BE046922",
               "id" : 740,
               "type" : "Nt,Ntoskrnl,BasicPEProfile,RelativeOffsetMixin,BasicClasses,Profile,object"
            },
            "name" : "_EPROCESS",
            "id" : 54334,
            "type" : "_EPROCESS,Struct,BaseAddressComparisonMixIn,BaseObject,object",
            "offset" : 2185005568
         },
...
```

The code above shows the JSON output for a single `_EPROCESS()` object. We store
the offset, and the full MRO for the `_EPROCESS()` object, as well as the full
profile name, address space etc. Using the information above we are able to
exactly reconstruct the `_EPROCESS()` instance.

The JsonRenderer uses specialized `ObjectRenderer()` classes to control
serializing and unserializing a python object into JSON format. For example,
this is how we serialize a `BaseObject()` instance (which _EPROCESS subclasses):

```
#!python
class BaseObjectRenderer(StateBasedObjectRenderer):
    renders_type = "BaseObject"
    renderers = ["JsonRenderer"]

    def DecodeFromJsonSafe(self, value):
        value = super(BaseObjectRenderer, self).DecodeFromJsonSafe(value)

        profile = value.pop("profile")
        value.pop("type")
        return profile.Object(**value)

    def GetState(self, item):
        return dict(offset=item.obj_offset,
                    type_name=unicode(item.obj_type),
                    name=unicode(item.obj_name),
                    vm=item.obj_vm,
                    profile=item.obj_profile
                    )
```

Since JSON can only handle dicts of simple objects, the `GetState()` method
creates a dict capturing the essence of a `BaseObject()` (i.e. all that is
required to instantiate it - the offset, address space and profile).

The `DecodeFromJsonSafe()` method is then used to convert from a pure Json safe
dictionary to a `BaseObject()` instance. In this case, we need to instantiate it
through the profile object.

The JsonRenderer is used to serialize the session when specifying the `-s`
parameter. In this case, the session's internal caches are all saved to disk and
restored at a later time. This makes startup times much faster and provides a
mechanism for plugins to store intermediate cached data.

## The data export renderer.

While the purpose of the `JsonRenderer` was to be able to exactly recreate the
serialized objects upon deserialization - this is not always desired. In order
to recreate the same `BaseObject()` instance, one needs to have access to the
same address space, and therefore the original image.

When Rekall is used as a library, often callers require the data to be exported
in a tool neutral way. The data export renderer does just that - it attempts to
produce meaningful output from the exported data. This necessarily means that
the exported data can not be re-imported into Rekall to produce the same
objects!

The `DataExportRenderer()` simply extends the JsonRenderer, and can be specified
on the command line using the "-r data" flag. This renderer employs the
`ObjectRenderer` mechanism above to ensure suitable exported objects are
produced for the various objects Rekall creates.

For example, here is an exported `_EPROCESS()` object:

```
[
      "r",
      {
         "session_id" : 0,
         "wow64" : false,
         "thread_count" : 8,
         "_EPROCESS" : {
            "vm" : "IA32PagedMemory@0x00039000 (Kernel AS@0x39000)",
            "type_name" : "_EPROCESS",
            "name" : "_EPROCESS",
            "Cybox" : {
               "Image_Info" : {
                  "Path" : "C:\\WINDOWS\\system32\\wuauclt.exe",
                  "File_Name" :
"\\Device\\HarddiskVolume1\\WINDOWS\\system32\\wuauclt.exe",
                  "type" : "ProcessObj:ImageInfoType",
                  "Command_Line" : "\"C:\\WINDOWS\\system32\\wuauclt.exe\"
/RunStoreAsComServer Local\\[43c]SUSDS82f0c54ad7b58b46a717b19ec999e73f"
               },
               "PID" : 3984,
               "Parent_PID" : 1084,
               "Creation_Time" : {
                  "type_name" : "UnixTimeStamp",
                  "value" : 1284061965,
                  "string_value" : "2010-09-09 19:52:45+0000"
               },
               "type" : "ProcessObj:ProcessObjectType",
               "Name" : "wuauclt.exe"
            },
            "offset" : 2179642104
         },
         "process_create_time" : {
            "type_name" : "UnixTimeStamp",
            "value" : 1284061965,
            "string_value" : "2010-09-09 19:52:45+0000"
         },
         "process_exit_time" : {
            "type_name" : "UnixTimeStamp",
            "value" : 0,
            "string_value" : "-"
         },
         "handle_count" : 325,
         "ppid" : 1084
      }
   ]
```

We can see that the data rendering system recognizes the `_EPROCESS` object
specifically and creates a "Cybox" like object to represent it. We expect in
future to support standardized representations of exporting memory artifacts,
such as the Cybox effort.
