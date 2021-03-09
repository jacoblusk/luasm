inspect = require("inspect")

function deepcopy(orig)
    local orig_type = type(orig)
    local copy
    if orig_type == 'table' then
        copy = { }
        for orig_key, orig_value in next, orig, nil do
            copy[deepcopy(orig_key)] = deepcopy(orig_value)
        end
        setmetatable(copy, deepcopy(getmetatable(orig)))
    else
        copy = orig
    end
    return copy
end

local register_encoding <const> = {
    rax = {0, 0},
    rcx = {0, 1},
    rdx = {0, 2},
    rbx = {0, 3},
    rsp = {0, 4},
    rbp = {0, 5},
    rsi = {0, 6},
    rdi = {0, 7},
    r8  = {1, 0},
    r9  = {1, 1},
    r10 = {1, 2},
    r11 = {1, 3},
    r12 = {1, 4},
    r13 = {1, 5},
    r14 = {1, 6},
    r15 = {1, 7}
}

local X86_INSTRUCTIONS <const> = {
    ADD = {
        Eb_Gb = 0x00,
        Ev_Gv = 0x01,
        Gv_Gv = 0x01, --- FIX
        Gb_Eb = 0x02,
        Gv_Ev = 0x03,
        Ev_Iz = 0x81,
        Gv_Iz = 0x81, --- FIX
    },
    MOV = {
        Eb_Gb = 0x88,
        Ev_Gv = 0x89,
        Gv_Gv = 0x89,
        Gv_Ev = 0x8B
    }
}

local register_memory_metamethods
register_memory_metamethods = {
    __add = function(reg_or_mem, base_or_disp)
        local memory
        if reg_or_mem.register then
            memory = { }

            if not math.tointeger(base_or_disp) then
                memory.sib_index = reg_or_mem
                memory.sib_value = 0
            end
            setmetatable(memory, register_memory_metamethods)
        else
            memory = reg_or_mem
        end

        if not math.tointeger(base_or_disp) then
            memory.sib_base = base_or_disp
        else
            memory.displacement = (memory.displacement or 0)
                                  + base_or_disp
        end

        return memory
    end, 
    __mul = function(register, value)
        if not register.register then
            error("can't multiply memory object.")
        end

        if not math.tointeger(value) then
            error("can't multiply two non-scalar objects.")
        end

        local memory = { }

        setmetatable(memory, register_memory_metamethods)

        local sib_index = register
        local sib_value = math.log(value, 2)

        if not math.tointeger(sib_value) or sib_value > 3 then
            error("SIB value must be multiple power of 2 less than 8.")
        end

        memory.sib_value = math.floor(sib_value)
        memory.sib_index = sib_index
        
        return memory
    end
}

local Register = register_memory_metamethods
function Register:new(name, size)
    local register = { }

    setmetatable(register, Register)
    register.register = name
    register.size     = size

    return register
end

local rax = Register:new("rax", 64)
local rcx = Register:new("rcx", 64)
local rdx = Register:new("rdx", 64)
local rbx = Register:new("rbx", 64)
local rsp = Register:new("rsp", 64)
local rbp = Register:new("rbp", 64)
local rsi = Register:new("rsi", 64)
local rdi = Register:new("rdi", 64)
local r8  = Register:new("r8" , 64)
local r9  = Register:new("r9" , 64)
local r10 = Register:new("r10", 64)
local r11 = Register:new("r11", 64)
local r12 = Register:new("r12", 64)
local r13 = Register:new("r13", 64)
local r14 = Register:new("r14", 64)
local r15 = Register:new("r15", 64)

local MemorySize = {
    __index = function(self, index)
        local memory = deepcopy(index)
        memory.size = self.size
        memory.type = "memory"
        return memory
    end
}

function MemorySize:new(size)
    local memory_size = { }

    setmetatable(memory_size, MemorySize)
    memory_size.size = size
    return memory_size
end

local qword = MemorySize:new(64)
local dword = MemorySize:new(32)
local word  = MemorySize:new(16)
local byte  = MemorySize:new( 8)

local Instruction = { }
Instruction.__index = Instruction

function Instruction:new(mnemonic)
    local function _f(...)
        local operands = { ... }
        local instruction = { }

        setmetatable(instruction, self)

        instruction.mnemonic = mnemonic
        instruction.operands = operands

        local signature_builder = { }

        for i = 1, #operands do
            local operand = operands[i]
            if type(operand) == "table" then
                if operand.type == "memory" then
                    signature_builder[#signature_builder + 1] = "Ev"
                elseif operand.register then
                    signature_builder[#signature_builder + 1] = "Gv"
                end
            elseif type(operand) == "number" then
                signature_builder[#signature_builder + 1] = "Iz"
            end
        end

        --[[
        local signatures = { { } }
        for i = 1, #signature_builder do
            local operand_signature = signature_builder[i]
            if type(operand_signature) == "table" then
                for j = 1, #operand_signature - 1 do
                    signatures[#signatures + 1] = deepcopy(signatures[#signatures])
                end

                for j = 1, #signatures do
                    signatures[j][#signatures[j] + 1] = operand_signature[j]
                end
            else
                for j = 1, #signatures do
                    signatures[j][#signatures[j] + 1] = operand_signature
                end
            end
        end

        for i = 1, #signatures do
            local signature = table.concat(signatures[i], '_')
            local potential_opcode = X86_INSTRUCTIONS[mnemonic][signature]
            if potential_opcode then
                instruction.opcode = potential_opcode
                instruction.signature = signature
            end
        end

        --]]

        local signature = table.concat(signature_builder, '_')

        instruction.opcode = X86_INSTRUCTIONS[mnemonic][signature]

        if not instruction.opcode then
            error("invalid signature (" .. inspect(signature)
                   .. ") for mnemonic " .. mnemonic)
        end

        return instruction
    end

    return _f
end

local function int2le(int)
    local b = { }

    b[1] = int & 0xFF
    b[2] = (int >> 8) & 0xFF
    b[3] = (int >> 16) & 0xFF
    b[4] = (int >> 24) & 0xFF

    return b
end


function Instruction:encode()
    local rex = { }

    assert(#self.operands == 2)

    local mod = 0
    if (self.operands[1].type ~= "memory" and tonumber(self.operands[2]))
    or (self.operands[1].type ~= "memory" and self.operands[2].type ~= "memory") then
        mod = 3
    end

    rex.w = 1 -- default to 64bit
    rex.r = register_encoding[self.operands[1].register][1]
    rex.x = 0

    rex.b = 0
    if not tonumber(self.operands[2]) then 
        rex.b = register_encoding[self.operands[2].register][1]
    end

    local rex_byte = (0x4 << 4)
                   | (rex.w << 3)
                   | (rex.r << 2)
                   | (rex.x << 1)
                   | (rex.b)

    local reg = 0
    if not math.tointeger(self.operands[2]) then
        reg = register_encoding[self.operands[2].register][2]
    end

    local r_m = 0
    if not math.tointeger(self.operands[1]) then
        r_m = register_encoding[self.operands[1].register][2]
    end

    local opcode = self.opcode

    local mod_rm_byte = mod << 6 | reg << 3 | r_m

    local instruction_bytes = { rex_byte, opcode, mod_rm_byte }

    if math.tointeger(self.operands[2]) then
        local displacement_bytes = int2le(self.operands[2])
        for i = 1, #displacement_bytes do
            instruction_bytes[#instruction_bytes + 1] = displacement_bytes[i]
        end
    end

    return instruction_bytes
end

local ADD = Instruction:new("ADD")
local MOV = Instruction:new("MOV")

local function tohex(v)
    return string.format("%02X", v)
end

local function apply(t, fn)
    for i = 1, #t do
        t[i] = fn(t[i])
    end
end

local instruction = MOV(rax, rbx)
local bytes = instruction:encode()

print(inspect(instruction, {process = function(item, path)
    if path[#path] ~= inspect.METATABLE then
        return item
    end
end}))

apply(bytes, tohex)
print(table.unpack(bytes))