#!/usr/bin/env python
"""
  Copyright (c) 2019 Trail of Bits, Inc.
 
  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at
 
      http://www.apache.org/licenses/LICENSE-2.0
 
  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
"""
from binaryninja import *
from os import listdir
from sys import argv

"""
this program assumes that the memory file provided is in the workspace and only on 64 bit linux
"""

if len(argv) < 2:
    print("please specify the location of the memory directory and build directory")
    print("Example: `python locate_traces.py ./ws/memory/` ./remill-build")
    exit(1)

memory_directory_path = argv[1]
if memory_directory_path[-1] != "/":
    memory_directory_path += "/"

traces = set()
Settings().set_bool("analysis.linearSweep.autorun", True)

def u64(data):
    return struct.unpack( "<Q", data)[0]

def create_functions_from_signature_scan(bv, entry_point, plat):
    sig = ['\x55', '\x48','\x89', '\xe5']
    end = bv.end
    if bv.view_type == "ELF":
        end = bv.get_segment_at(bv.entry_point).end
    else:
        return
    curr = entry_point
    while curr <= end:
        check = map(lambda x: x[0] == x[1], \
                zip(bv.read(curr, len(sig)), sig))
        if len(check) and all(check):
            binaryninja.core.BNAddFunctionForAnalysis(bv.handle, plat.handle, curr)
            curr += len(sig)
        else:
            curr += 1
    return bv

def create_functions_in_binaryview(mapping):
    bv = binaryview.BinaryViewType["Raw"].open(memory_directory_path + mapping)
    arch = binaryninja.Architecture["x86_64"]
    plat = binaryninja.Platform["linux-x86_64"]
    entry_point = u64(bv.read(0x18, arch.address_size)) # parse entry point from elf
    print("entrypoint was {}".format(hex(entry_point)))
    binaryninja.core.BNAddFunctionForAnalysis(bv.handle, plat.handle, entry_point)
    return create_functions_from_signature_scan(bv, entry_point, plat)

def mark_traces_in_mapping(mapping):
    path = "/" + "/".join(mapping.split(" ")[6:])
    bv = binaryview.BinaryViewType["ELF"].open(path)
    if not bv:
        return
    print(path)
    
    bv.update_analysis_and_wait()

    base = int(mapping.split(" ")[0].split("-")[0], 16)
    pc = base
    for func in bv.functions:
        for bb in func:
            # make the beginning of basic blocks a trace
            pc = bb.start if bb.start > base else base + bb.start
            traces.add(pc)
            for ins in bb:
                # this loop is for marking in the return addresses of function calls
                ins_array, size = ins
                pc += size
                if ins_array[0].text == 'call':
                    traces.add(pc)

def is_executable(mapping):
    umask = "".join(mapping.split(" ")[1:3])
    return "x" in umask

def mark_all_traces():
    for mapping in listdir(memory_directory_path):
        if is_executable(mapping):
            mark_traces_in_mapping(mapping)

def write_all_traces_to_file():
    workspace = "/".join(memory_directory_path.split("/")[:-2])
    print("workspace: {}".format(workspace))
    with open(workspace + "/trace_list","a+") as trace_file:
        trace_file.write("======TRACE=ADDRESSES======\n")
        for trace in sorted(traces):
            trace_file.write(hex(trace).strip("L") + '\n')

if __name__  == "__main__":
    mark_all_traces()
    write_all_traces_to_file()
