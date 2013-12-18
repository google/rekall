/**********************************************
  This module contains C support modules for the rest of Rekall.

  In order to increase performance we include a bunch of classes implemented in
  C here. These are intended to be drop in replacesments to the python
  implemented classes.
*/
#include "support.h"


static int _read_from_python_base(AMD64PagedMemory *self,
                                  uint64_t offset,
                                  uint64_t length, char *out) {
  PyObject *buffer = PyObject_CallMethod(self->base, "read", "Ki", offset,
                                         length);
  char *data;
  Py_ssize_t buffer_length;

  if (!buffer) goto error;

  PyString_AsStringAndSize(buffer, &data, &buffer_length);

  memcpy(out, data, MIN(length, buffer_length));

  Py_DecRef(buffer);

  return buffer_length;

 error:
  return 0;
}


static int AMD64PagedMemory_init(AMD64PagedMemory *self, PyObject *args,
                                 PyObject *kwds) {
  static char *kwlist[] = {"base", "dtb", NULL};

  self->base = NULL;
  self->dtb = 0;

  if(!PyArg_ParseTupleAndKeywords(args, kwds, "OK", kwlist,
                                  &self->base, &self->dtb))
    goto error;

  self->_read = _read_from_python_base;

  Py_IncRef(self->base);

  return 0;

 error:
  return -1;
};


static uint64_t _unpack_uint64(unsigned char *str) {
  uint64_t decoded = 0;
  int i;

  // Little endian decoding: 8 bytes for 64 bits.
  for (i=0; i < 8; i++) {
    decoded |= ((uint64_t)str[i]) << (8*i);
  }

  return decoded;
}

/* Read a single 64 bit int from the image.

 */
static uint64_t _read_long_long_phys(AMD64PagedMemory *self, uint64_t address) {
  unsigned char result[sizeof(uint64_t)];

  // Read directly into the buffer.
  if (!self->_read(self, address, sizeof(result), (char *)result))
    goto error;

  // Decode as a uint64_t.
  return _unpack_uint64(result);

  error:
    // An error occured in the base address space. We ignore the error and just
    // return 0.
    PyErr_Clear();
    return 0;
};

static uint64_t get_two_meg_paddr(uint64_t vaddr, uint64_t pde) {
  return (pde & 0xfffffffe00000) | (vaddr & 0x1fffff);
}

static uint64_t get_one_gig_paddr(AMD64PagedMemory *self, uint64_t vaddr,
                                  uint64_t pdpte) {

  return (pdpte & 0xfffffc0000000) | (vaddr & 0x3fffffff);
}

static uint64_t get_phys_addr(uint64_t vaddr, uint64_t pte_value) {

  return (pte_value & 0xfffff000) | (vaddr & 0xfff);
}

static bool entry_present(uint64_t entry) {
  if (entry & 1) {
    return true;

    // The page is in transition and not a prototype.
    // Thus, we will treat it as present.
  } else if ((entry & (1 << 11)) && !(entry & (1 << 10))) {
    return true;
  }

  return false;
}

static bool page_size_flag(uint64_t entry) {
  return (entry & (1 << 7));
}

static void _add_range(PyObject *result,
                       uint64_t virt_addr, uint64_t length, uint64_t phys_addr,
                       uint64_t *last_virt_address, uint64_t *last_length,
                       uint64_t *last_physical_address) {
  if(*last_virt_address + *last_length == virt_addr &&
     *last_physical_address + *last_length == phys_addr) {
    *last_length += length;
  } else {

    // Skip zero length regions.
    if (*last_length > 0) {
      // Flush the last entry to the result list.
      PyObject *list=PyTuple_New(3);
      PyTuple_SET_ITEM(list, 0,
                       PyLong_FromUnsignedLongLong(*last_virt_address));

      PyTuple_SET_ITEM(list, 1,
                       PyLong_FromUnsignedLongLong(*last_length));

      PyTuple_SET_ITEM(list, 2,
                       PyLong_FromUnsignedLongLong(*last_physical_address));

      PyList_Append(result, list);
    };

    *last_virt_address = virt_addr;
    *last_length = length;
    *last_physical_address = phys_addr;
  }
};


static PyObject *_get_memory_map(AMD64PagedMemory *self, uint64_t start,
                                 Py_ssize_t length) {
  PyObject *result = PyList_New(0);
  page_table_lookup lookup;
  uint64_t pml4e_addr, pml4e_value, pdpte_addr, pdpte_value;
  uint64_t pde_addr, pde_value, pte_addr, pte_table_addr;
  uint64_t last_virt_address = 0;
  uint64_t last_physical_address = 0;
  uint64_t last_length = 0;
  uint64_t total_length = 0;

  unsigned char pte_table[0x1000];
  uint64_t pml4e_start, vaddr;

  memset(&lookup, 0, sizeof(lookup));

  /* Even if the initial memory range is invalid, the lookup should contain
     partial data.
  */
  _vtop(self, start, &lookup);

  pml4e_start = lookup.pml4e_addr;
  if (pml4e_start == 0) {
    pml4e_start = self->dtb & 0xffffffffff000;
  }

  // Pages that hold PDEs and PTEs are 0x1000 bytes each.
  // Each PDE and PTE is eight bytes. Thus there are 0x1000 / 8 = 0x200
  // PDEs and PTEs we must test.
  for (pml4e_addr = pml4e_start;
       pml4e_addr < (self->dtb & 0xffffffffff000) + 0x1000; // Last entry in pml4e.
       pml4e_addr += 8) {
    uint64_t pdpte_start = lookup.pdpte_addr;

    pml4e_value = _read_long_long_phys(self, pml4e_addr);

    if (!entry_present(pml4e_value))
      continue;

    if (pdpte_start == 0) {
      pdpte_start = pml4e_value & 0xffffffffff000;
    }

    for (pdpte_addr=pdpte_start;
         pdpte_addr<(pml4e_value & 0xffffffffff000) + 0x1000;
         pdpte_addr+=8) {
      uint64_t pde_start = lookup.pde_addr;

      pdpte_value = _read_long_long_phys(self, pdpte_addr);
      if (!entry_present(pdpte_value))
        continue;

      // One gig pages.
      if (page_size_flag(pdpte_value)) {
        vaddr = ((pml4e_addr & 0xff8) << 36 |
                 (pdpte_addr & 0xff8) << 27);

        _add_range(result, vaddr, 0x40000000,
                   get_one_gig_paddr(self, vaddr, pdpte_value),
                   &last_virt_address, &last_length, &last_physical_address);

        total_length += 0x40000000;
        if (length && total_length > length) goto done;
        continue;
      };

      if (pde_start == 0) {
        pde_start = pdpte_value & 0xffffffffff000;
      }

      for (pde_addr=pde_start;
           pde_addr<(pdpte_value & 0xffffffffff000) + 0x1000;
           pde_addr+=8) {
        uint64_t pte_start = lookup.pte_addr;

        pde_value = _read_long_long_phys(self, pde_addr);
        if (!entry_present(pde_value))
          continue;

        // 2mb pages.
        if (page_size_flag(pde_value)) {
          vaddr = ((pml4e_addr & 0xff8) << 36 |
                   (pdpte_addr & 0xff8) << 27 |
                   (pde_addr   & 0xff8) << 18);

          _add_range(result, vaddr, 0x200000, get_two_meg_paddr(vaddr, pde_value),
                     &last_virt_address, &last_length, &last_physical_address);
          total_length += 0x200000;
          if (length && total_length > length) goto done;

          continue;
        };


        // This reads the entire PTE table at once - On windows where IO is
        // extremely expensive, its about 10 times more efficient than reading
        // it one value at the time - and this loop is HOT!
        pte_table_addr = pde_value & 0xffffffffff000;
        if(!self->_read(self, pte_table_addr, sizeof(pte_table),
                        (char *)pte_table))
          goto error;

        if (pte_start == 0) {
          pte_start = pde_value & 0xffffffffff000;
        }

        for (pte_addr=pte_start;
             pte_addr<(pde_value & 0xffffffffff000) + 0x1000;
             pte_addr+=8) {

          uint64_t pte_value = _unpack_uint64(pte_table +
                                              (pte_addr - pte_table_addr));

          if (entry_present(pte_value)) {
            vaddr = ((pml4e_addr & 0xff8) << 36 |
                     (pdpte_addr & 0xff8) << 27 |
                     (pde_addr   & 0xff8) << 18 |
                     (pte_addr   & 0xff8) << 9);

            _add_range(result, vaddr, 0x1000,
                       get_phys_addr(vaddr, pte_value),
                       &last_virt_address, &last_length, &last_physical_address);
            total_length += 0x1000;
            if (length && total_length > length) goto done;
          }
        };

        // Next time around the loop - start at the begining.
        lookup.pte_addr = 0;
      }

      // Next time around the loop - start at the begining.
      lookup.pde_addr = 0;
    }

    // Next time around the loop - start at the begining.
    lookup.pdpte_addr = 0;
  }


 done:
  // Include the last range.
  _add_range(result, -1, -1, -1,
             &last_virt_address, &last_length, &last_physical_address);

  return result;

 error:
  // Delete the result.
  Py_DecRef(result);

  return NULL;
};

static PyObject *AMD64PagedMemory_get_available_addresses(AMD64PagedMemory *self,
                                                          PyObject *args,
                                                          PyObject *kwds) {
  static char *kwlist[] = {"start", "length", NULL};
  uint64_t start = 0;
  uint64_t length = -1;

  if(!PyArg_ParseTupleAndKeywords(args, kwds, "|KK", kwlist, &start, &length))
    goto error;

  return _get_memory_map(self, start, length);

 error:
  return NULL;
}


static int _vtop(AMD64PagedMemory *self, uint64_t vaddr,
                 page_table_lookup *result) {

  result->pml4e_addr = ((self->dtb & 0xffffffffff000) |
                        ((vaddr & 0xff8000000000) >> 36));

  result->pml4e = _read_long_long_phys(self, result->pml4e_addr);
  if (!entry_present(result->pml4e)) {
    goto invalid;
  }

  result->pdpte_addr = ((result->pml4e & 0xffffffffff000) |
                        ((vaddr & 0x7fc0000000) >> 27));
  result->pdpte = _read_long_long_phys(self, result->pdpte_addr);
  if (!entry_present(result->pdpte)) {
    goto invalid;
  }

  if (page_size_flag(result->pdpte)) {
    result->paddr = get_one_gig_paddr(self, vaddr, result->pdpte);
    goto ok;
  }

  result->pde_addr = ((result->pdpte & 0xffffffffff000) |
                      ((vaddr & 0x3fe00000) >> 18));
  result->pde = _read_long_long_phys(self, result->pde_addr);
  if (!entry_present(result->pde)) {
    goto invalid;
  }

  if (page_size_flag(result->pde)) {
    result->paddr = get_two_meg_paddr(vaddr, result->pde);
    goto ok;
  }

  result->pte_addr = ((result->pde & 0xffffffffff000) |
                      ((vaddr & 0x1ff000) >> 9));
  result->pte = _read_long_long_phys(self, result->pte_addr);
  if (!entry_present(result->pte)) {
    goto invalid;
  }

  result->paddr = ((result->pte & 0xfffff000) |
                   (vaddr & 0xfff));

 ok:
  return 1;

 invalid:
  return 0;
}

static PyObject *AMD64PagedMemory_vtop(AMD64PagedMemory *self, PyObject *args,
                                       PyObject *kwds) {
  static char *kwlist[] = {"offset", NULL};
  uint64_t vaddr = 0;
  page_table_lookup result;

  if(!PyArg_ParseTupleAndKeywords(args, kwds, "K", kwlist, &vaddr))
    goto error;

  if(!_vtop(self, vaddr, &result))
    goto invalid;

  PyErr_Clear();
  return PyLong_FromUnsignedLongLong(result.paddr);

 invalid:
  Py_RETURN_NONE;

 error:
  return 0;
};





static PyObject *AMD64PagedMemory_read(AMD64PagedMemory *self, PyObject *args, PyObject *kwds) {
  static char *kwlist[] = {"offset", "length", NULL};
  uint64_t offset = 0;
  Py_ssize_t length = 0;
  PyObject *result, *map;
  char *out_buffer;
  int out_index = 0;
  int i;

  if(!PyArg_ParseTupleAndKeywords(args, kwds, "KI", kwlist,
                                  &offset, &length))
    goto error;

  if (length > MAX_READ_LENGTH) {
    PyErr_Format(PyExc_IOError, "Read buffer size too large (%lu).", length);
    goto error;
  };

  // Since we are reading from memory we can never actually fail this read -
  // even if the pages are not mapped, we just zero pad them. Therefore we just
  // allocate the entire buffer here and clear it.
  result = PyString_FromStringAndSize(NULL, length);
  if (!result) goto error;

  out_buffer = PyString_AS_STRING(result);

  // Clear the buffer.
  memset(out_buffer, 0, length);

  // Get the memory map for the next read.
  map = _get_memory_map(self, offset, length);
  if(!map) goto error_with_result;

  // Use the map to read as much as we need.
  for(i=0; i<PyList_Size(map); i++) {
    PyObject *item = PyList_GetItem(map, i);
    uint64_t virt_addr = PyLong_AsLongLong(PyTuple_GetItem(item, 0));
    uint64_t range_length = PyLong_AsLongLong(PyTuple_GetItem(item, 1));
    uint64_t physical_addr = PyLong_AsLongLong(PyTuple_GetItem(item, 2));
    Py_ssize_t available_to_read;
    int chunk_offset;
    int data_read;

    // We are reading before the next available range - we just skip up to it.
    if(virt_addr > offset) {
      length -= virt_addr - offset;
      out_index += virt_addr - offset;
      offset = virt_addr;
    };

    // We are done reading.
    if (length <= 0) break;

    // The relative offset inside the chunk.
    chunk_offset = offset - virt_addr;

    // How much data is in this memory range?
    available_to_read = MIN(length, range_length - chunk_offset);

    // Read the chunk from the base address space.
    data_read = self->_read(self, physical_addr + chunk_offset,
                            available_to_read, out_buffer + out_index);
    if (!data_read)
      goto error_with_map;

    // Advance the destination buffer pointer.
    out_index += data_read;

    // Adjust the offset and length in the virtual address space.
    length -= data_read;
    offset += data_read;
  };

  Py_DecRef(map);

  return result;

 error_with_map:
  Py_DecRef(map);

 error_with_result:
  Py_DecRef(result);

 error:
  return 0;
};

static PyMethodDef AMD64PagedMemory_methods[] = {
  {"read",(PyCFunction)AMD64PagedMemory_read, METH_VARARGS|METH_KEYWORDS,
   "Read a buffer from the base address space.\n"},

  {"vtop",(PyCFunction)AMD64PagedMemory_vtop, METH_VARARGS|METH_KEYWORDS,
   "Converts a virtual offset to a physical offset. Returns None if invalid.\n"},

  {"get_available_addresses",(PyCFunction)AMD64PagedMemory_get_available_addresses,
   METH_VARARGS|METH_KEYWORDS,
   "Returns a list of lists of available memory ranges.\n"},

  {NULL}  /* Sentinel */
};


static PyTypeObject AMD64PagedMemory_Type = {
    PyObject_HEAD_INIT(NULL)
    0,                         /* ob_size */
    "support.AMD64PagedMemory",               /* tp_name */
    sizeof(AMD64PagedMemory),            /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor)0,             /* tp_dealloc */
    0,                         /* tp_print */
    0,                         /* tp_getattr */
    0,                         /* tp_setattr */
    0,                         /* tp_compare */
    0,                         /* tp_repr */
    0,                         /* tp_as_number */
    0,                         /* tp_as_sequence */
    0,                         /* tp_as_mapping */
    0,                         /* tp_hash */
    0,                         /* tp_call */
    0,                         /* tp_str */
    (getattrofunc)0,           /* tp_getattro */
    0,                         /* tp_setattro */
    0,                         /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,        /* tp_flags */
    AMD64PagedMemory__doc__,   /* tp_doc */
    0,	                       /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    (getiterfunc)0,            /* tp_iter */
    (iternextfunc)0,           /* tp_iternext */
    AMD64PagedMemory_methods,  /* tp_methods */
    0,                         /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)AMD64PagedMemory_init,      /* tp_init */
    0,                         /* tp_alloc */
    0,                         /* tp_new */
};


static PyMethodDef supportMethods[] = {
  {NULL, NULL, 0, NULL}
};


PyMODINIT_FUNC initsupport(void) {
  PyGILState_STATE gstate;

  /* create module */
  PyObject *m = Py_InitModule("support", supportMethods);

  /* Make sure threads are enabled */
  PyEval_InitThreads();
  gstate = PyGILState_Ensure();

  AMD64PagedMemory_Type.tp_new = PyType_GenericNew;
  if (PyType_Ready(&AMD64PagedMemory_Type) < 0)
    goto exit;

  Py_IncRef((PyObject *)&AMD64PagedMemory_Type);
  PyModule_AddObject(m, "AMD64PagedMemory", (PyObject *)&AMD64PagedMemory_Type);

 exit:
  PyGILState_Release(gstate);
}
