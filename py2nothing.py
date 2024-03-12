import tkinter as tk
from tkinter import filedialog, messagebox
import imp
import marshal
import os
import struct
import time
import pefile
import uncompyle6

IGNORE = [
    '<install zipextimporter>.pyc',
]

def __timestamp():
    today = time.time()
    ret = struct.pack('=L', int(today))
    return ret

def __build_magic(magic):
    return struct.pack('Hcc', magic, b'\r', b'\n')

def __current_magic():
    return imp.get_magic()

versions = {
    '1.5': __build_magic(20121),
    '1.6': __build_magic(50428),
    '2.0': __build_magic(50823),
    '2.1': __build_magic(60202),
    '2.2': __build_magic(60717),
    '2.3': __build_magic(62011),
    '2.4': __build_magic(62061),
    '2.5': __build_magic(62131),
    '2.6': __build_magic(62161),
    '2.7': __build_magic(62191),
}

def get_scripts_resource(pe):
    res = None
    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if entry.name and entry.name.string == b"PYTHONSCRIPT":
            res = entry.directory.entries[0].directory.entries[0]
            break
    return res

def resource_dump(pe, res):
    rva = res.data.struct.OffsetToData
    size = res.data.struct.Size

    dump = pe.get_data(rva, size)
    return dump

def get_co_from_dump(data):
    current = struct.calcsize('iiii')
    metadata = struct.unpack('iiii', data[:current])

    arcname = ""
    while data[current] != b"\000":
        arcname += data[current]
        current += 1

    code_bytes = data[current + 1:-2]

    code_objects = marshal.loads(code_bytes)
    return code_objects

def save_co_to_pyc(co, version, output_dir):
    pyc_header = version + __timestamp()
    pyc_basename = os.path.basename(co.co_filename)
    pyc_name = pyc_basename + '.pyc'

    if pyc_name not in IGNORE:
        destination = os.path.join(output_dir, pyc_name)
        with open(destination, 'wb') as pyc:
            pyc.write(pyc_header)
            marshaled_code = marshal.dumps(co)
            pyc.write(marshaled_code)
        return destination

def decompile_pyc(pyc_filename, output_dir):
    py_filename = pyc_filename[:-1]
    with open(py_filename, 'w') as py_file:
        uncompyle6.decompile_file(pyc_filename, py_file)

def unpy2exe(filename, python_version=None, output_dir=None, decompile=False):
    try:
        if python_version is None:
            version = __current_magic()
        else:
            version = versions.get(python_version, __current_magic())

        if output_dir is None:
            output_dir = '.'
        elif not os.path.exists(output_dir):
            os.makedirs(output_dir)

        pe = pefile.PE(filename)
        script_res = get_scripts_resource(pe)
        dump = resource_dump(pe, script_res)
        code_objects = get_co_from_dump(dump)
        for co in code_objects:
            pyc_filename = save_co_to_pyc(co, version, output_dir)
            if decompile:
                decompile_pyc(pyc_filename, output_dir)
        messagebox.showinfo("Success", "Extraction completed successfully")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def browse_file():
    filename = filedialog.askopenfilename()
    if filename:
        unpy2exe(filename, output_dir='.', decompile=True)

root = tk.Tk()
root.title("changed!!!")
button = tk.Button(root, text="Browse files", command=browse_file)
button.pack()

root.mainloop()
