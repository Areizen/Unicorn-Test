from __future__ import print_function
import os
import sys

# Emulation
from unicorn import *
from unicorn.x86_const import *

# Disassembly / Assembly
from capstone import *
from struct import pack

# Setting up capstone arch
disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
emulator     = Uc(UC_ARCH_X86, UC_MODE_32)

VERBOSE = False

# memory address
CODE =  open('crypto.bin','rb').read()

# Global constants
ADDRESS = 0x1000000
CODE_SIZE = 2 * 1024 * 1024
STACK_ADDR = ADDRESS + CODE_SIZE
STACK_SIZE = CODE_SIZE

# Crypto function start
FUNCTION_OFFSET = ADDRESS + 0x000011ad
# Crypto ret addr
FUNCTION_END = ADDRESS + 0x000011e7

IGNORE_INSTR = [0x000011b3]

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
    if name == "EIP" :
        print(">>> %s = 0x%x" % (name, emulator.reg_read(register), ) )
        return
    
    # Printing all the other registers
    try:
        data = read_string(emulator, emulator.reg_read(register))
        if(data != ''):
            print(">>> %s = 0x%x #%s" % (name, emulator.reg_read(register), data, ) )
        else:
            print(">>> %s = 0x%x" % (name, emulator.reg_read(register), ) )
    except UcError as e:
        print(">>> %s = 0x%x" % (name, emulator.reg_read(register), ) )

def print_all_registers(emulator):
    '''
    Print all x86 registers
    :param emulator: unicorn engine
    '''
    print_register(emulator, "EAX", UC_X86_REG_EAX)
    print_register(emulator, "EBX", UC_X86_REG_EBX)
    print_register(emulator, "ECX", UC_X86_REG_ECX)
    print_register(emulator, "EDX", UC_X86_REG_EDX)
    print_register(emulator, "EBP", UC_X86_REG_EBP)
    print_register(emulator, "ESP", UC_X86_REG_ESP)
    print_register(emulator, "EIP", UC_X86_REG_EIP)

# hook interrupt to handle them
def hook_intr(emulator, interrupt_number, user_data):
    '''
    Callback when an interrupt is called
    :param emulator: unicorn engine
    :param interrupt_number: number of the interrupt
    :param user_data: user defined data
    '''
    eax = emulator.reg_read(UC_X86_REG_EAX)
    eip = emulator.reg_read(UC_X86_REG_EIP)
  
    # Handle all syscalls
    if(interrupt_number == 0x80):
        
        if(eax == 4):
            # Handle in case it's SYS_WRITE
            ebx = emulator.reg_read(UC_X86_REG_EBX)
            ecx = ADDRESS + emulator.reg_read(UC_X86_REG_ECX)
            ecx_value = read_string(emulator, ADDRESS + emulator.reg_read(UC_X86_REG_ECX))
            edx = emulator.reg_read(UC_X86_REG_EDX)
            print("Calling syscall : SYS_WRITE(fd=0x%x,str=0x%x,size=0x%x)" 
                    % (ebx, ecx,edx) )
            print(ecx_value, end='')

        elif(eax == 11):
            # Handle in case it's SYS_EXECVE
            ebx = emulator.reg_read(UC_X86_REG_EBX)
            filename = read_string(emulator, ebx)
            print("Calling syscall : SYS_EXECV(filename=\"%s\")" % filename)
            os.system(filename)
        elif (eax == 1):
            ebx = emulator.reg_read(UC_X86_REG_EBX)
            print("Calling syscall : SYS_EXIT(%d)" % ebx)
            emulator.emu_stop()
        else:
            print("Syscall not handled : %d ???" % eax)
            emulator.emu_stop()
            return
    else:
        print("Error : Unknown interrupt : 0x%x ???" % interrupt_number)
        emulator.emu_stop()    
        return

# hook the code at each instruction
def hook_code(emulator, current_addr, size, user_data):
    '''
    Callback at each instructions
    :param emulator: unicorn engine
    :param current_addr: addr in the code
    :param size: size of the current instruction
    :param user_data: user defined data
    '''
    code_addr = current_addr - ADDRESS
    current_instruction = list(disassembler.disasm(CODE[code_addr:code_addr+size],0))[0]

    if(VERBOSE == True):
        print("=" * 20)
        print(">>> Tracing instruction at 0x%x, instruction size = %u" %( code_addr, size ))    
        print_all_registers(emulator)
        print("Current instruction : %s %s" % (current_instruction.mnemonic, current_instruction.op_str))

    if(code_addr in IGNORE_INSTR):
        if(VERBOSE == True):
            print("SKIPPED ...")
        emulator.reg_write(UC_X86_REG_EIP, current_addr+size) 


# setup the initial state of emulation
def emulate():
    # map 2MB memory for this emulation
    emulator.mem_map(ADDRESS, CODE_SIZE)

    emulator.mem_map(STACK_ADDR, STACK_SIZE)
    emulator.reg_write(UC_X86_REG_ESP, STACK_ADDR )
    
    # Setting up the stack for the function call
    CLEARTEXT = sys.argv[1].encode()
    emulator.mem_write(STACK_ADDR + 4, pack("<I",STACK_ADDR+8))
    emulator.mem_write(STACK_ADDR + 8, CLEARTEXT)



    # write machine code to be emulated to memory
    emulator.mem_write(ADDRESS, CODE )

    # hook code
    emulator.hook_add(UC_HOOK_INTR, hook_intr)
    emulator.hook_add(UC_HOOK_CODE, hook_code)

    # emulate code in infinite time & unlimited instructions
    emulator.emu_start(FUNCTION_OFFSET, FUNCTION_END)
    print("CIPHERTEXT : %s" % emulator.mem_read(STACK_ADDR + 8, 
        len(CLEARTEXT) ).decode())


if __name__ == '__main__':
    if(len(sys.argv) < 2):
        print("Usage : %s <data to cipher>"% sys.argv[0])
        sys.exit(-1)
    emulate()
