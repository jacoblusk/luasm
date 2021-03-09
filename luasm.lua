inspect = require("inspect")

function deepcopy(orig)
    local orig_type = type(orig)
    local copy
    if orig_type == 'table' then
        copy = {}
        for orig_key, orig_value in next, orig, nil do
            copy[deepcopy(orig_key)] = deepcopy(orig_value)
        end
        setmetatable(copy, deepcopy(getmetatable(orig)))
    else -- number, string, boolean, etc
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
		Gb_Eb = 0x02,
		Gv_Ev = 0x03,
		Ev_Iz = 0x81,
		Gv_Iz = 0x81 
	}
}


local function encode_instruction(instruction, ...)
	local rex = { }

	rex.w = 1
	rex.r = register_encoding.r8[1]
	rex.x = 0
	rex.b = register_encoding.rdi[1]

	local rex_byte = (0x4 << 4) | (rex.w << 3)
				| (rex.r << 2)
				| (rex.x << 1)
				| (rex.b)

	local mod = 1
	local reg = register_encoding.r8[2]
	local r_m = register_encoding.rdi[2]
	local opcode = 0x03
	local displacement = 0xa

	local mod_rm_byte = mod << 6 | reg << 3 | r_m

	local instruction_bytes = {rex_byte, opcode, mod_rm_byte, displacement}

	return instruction_bytes
end

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

local rbx = Register:new("rbx", 64)
local rcx = Register:new("rcx", 64)

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

local Instruction = { }
function Instruction:new(mnemonic)
	local function _f(...)
		local operands = { ... }
		local instruction = { }

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

		signature = table.concat(signature_builder, '_')
		print("signature", signature)

		instruction.opcode = X86_INSTRUCTIONS[mnemonic][signature]

		if not instruction.opcode then
			error("invalid signature (" .. signature
			       .. ") for mnemonic " .. mnemonic)
		end

		return instruction
	end

	return _f
end

local ADD = Instruction:new("ADD")
local instruction = ADD(rbx, qword[rcx * 8 + rbx + 32])

print(inspect(instruction, {process = function(item, path)
	if path[#path] ~= inspect.METATABLE then
		return item
	end
end}))

local function tohex(v)
	return string.format("%02X", v)
end

local function apply(t, fn)
	for i = 1, #t do
		t[i] = fn(t[i])
	end
end

bytes = encode_instruction()
apply(bytes, tohex)
print(table.unpack(bytes))