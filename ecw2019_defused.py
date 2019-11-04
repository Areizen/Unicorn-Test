#!/usr/bin/python3
# Solution for the challenge Defused from ECW 
# did it afterward with Unicorn for learning 
# and for the lulz
# Author : Areizen

from __future__ import print_function
import sys

# Emulation
from unicorn import *
from unicorn.arm_const import *

# Disassembly / Assembly
from capstone import *

# Setting up capstone arch
disassembler = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
emulator     = Uc(UC_ARCH_ARM, UC_MODE_THUMB)

VERBOSE = True

# memory address
CODE =  open('defused.bin','rb').read()

# Global constants
ADDRESS = 0x20000000
STACK_ADDR =  0x08000000
UNKNOWN_ADDR = 0x40000000

# SIZE INFO
STACK_SIZE = UNKNOWN_SIZE = CODE_SIZE = 2 * 1024 * 1024

# FUNCTION INFO
FUNCTION_START = ADDRESS + 0x26
FUNCTION_END   = ADDRESS + 0x14A

FLAG = ""

def read_string(emulator, address):
    '''
    Read a string at a given address
    :param emulator: unicorn engine
    :param address: address to read from
    :return string: string read from the address
    '''
    ret = ""
    c = emulator.mem_read(address, 1)[0]
    read_bytes = 1
    while c != 0x0:
        ret += chr(c)
        c = emulator.mem_read(address + read_bytes, 1)[0]
        read_bytes += 1
    return ret


def print_register(emulator, name, register):
    '''
    Print register value and try to read a string at
    the value
    :param emulator: unicorn engine
    :param name: name of the register
    :param register: register enum (UC_[ARCH]_REG_[REGISTER])
    '''
    # Case EIP, not a string
    if name == "PC" :
        print(">>> %s = 0x%x" % (name, emulator.reg_read(register), ) )
        return
    
    # Printing all the other registers
    try:
        data = read_string(emulator, emulator.reg_read(register))
        print(">>> %s = 0x%x #%s" % (name, emulator.reg_read(register), data, ) )
    except UcError as e:
        print(">>> %s = 0x%x" % (name, emulator.reg_read(register), ) )

def print_all_registers(emulator):
    '''
    Print all arm registers
    :param emulator: unicorn engine
    '''
    print_register(emulator, "R0", UC_ARM_REG_R0)
    print_register(emulator, "R1", UC_ARM_REG_R1)
    print_register(emulator, "R2", UC_ARM_REG_R2)
    print_register(emulator, "R3", UC_ARM_REG_R3)
    print_register(emulator, "R4", UC_ARM_REG_R4)
    print_register(emulator, "R5", UC_ARM_REG_R5)
    print_register(emulator, "R6", UC_ARM_REG_R6)
    print_register(emulator, "R7", UC_ARM_REG_R7)
    print_register(emulator, "R8", UC_ARM_REG_R8)
    print_register(emulator, "R9", UC_ARM_REG_R9)
    print_register(emulator, "SP", UC_ARM_REG_R13)
    print_register(emulator, "PC", UC_ARM_REG_PC)

# hook the code at each instruction
def hook_code(emulator, current_addr, size, user_data):
    '''
    Callback at each instructions
    :param emulator: unicorn engine
    :param current_addr: addr in the code
    :param size: size of the current instruction
    :param user_data: user defined data
    '''
    global FLAG
    code_addr = (current_addr) - ADDRESS
    
    # Pass the check 
    if(code_addr == 0x7E):
        emulator.reg_write(UC_ARM_REG_R2, 1)
    
    # Pass the check
    elif(code_addr == 0x70):
        emulator.reg_write(UC_ARM_REG_R2, 0)


    # Pass the check
    elif (code_addr == 0x8c):
        emulator.reg_write(UC_ARM_REG_R3, 0)

    # Pass the check
    elif (code_addr == 0x92):
        emulator.reg_write(UC_ARM_REG_R6, 0)

    # Check addr we can see the good value
    elif(code_addr == 0xF8):
        r4 = emulator.reg_read(UC_ARM_REG_R4)
        r3 = emulator.reg_read(UC_ARM_REG_R3)
        FLAG += str(r3 ^ 0x2A ) + "-"
        emulator.reg_write(UC_ARM_REG_R4, r3)

    # Called when the code is valid : it stop the emulation
    elif(code_addr == 0x120):
        emulator.emu_stop()

    if(VERBOSE == True):
        print("=" * 20)
        
        print(">>> Tracing instruction at 0x%x, instruction size = %u" %( code_addr, size ))    
        current_instruction = list(disassembler.disasm(CODE[code_addr:code_addr+size],0))[0]
        print("Current instruction : %s %s" % (current_instruction.mnemonic, current_instruction.op_str))
        print_all_registers(emulator)

# setup the initial state of emulation
def emulate():

    # map 2MB memory for this emulation
    emulator.mem_map(ADDRESS, CODE_SIZE)
    emulator.mem_map(STACK_ADDR - 1024*1024, STACK_SIZE)

    # setting up stack infos
    emulator.reg_write(UC_ARM_REG_SP, STACK_ADDR )

    # setting up unknown infos
    emulator.mem_map(UNKNOWN_ADDR, UNKNOWN_SIZE)

    # write machine code to be emulated to memory
    emulator.mem_write(ADDRESS, CODE)
    emulator.mem_write(STACK_ADDR, CODE)
   
    # creating hooks
    emulator.hook_add(UC_HOOK_CODE, hook_code)

    # emulate code in infinite time & unlimited instructions
    emulator.emu_start(FUNCTION_START|1, FUNCTION_END)

    print("Flag : ECW{%s}" % FLAG[:-1])

if __name__ == '__main__':
    emulate()

