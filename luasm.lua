local function make_registers(names)
	local e_t <const> = { }
	for i = 1, #names do
		e_t[names[i]] = { names[i] } 
		setmetatable(e_t[names[i]], {
			__tostring = function(register) return register[1] end,
			__add = function (register, immediate)
				if not register.memory then
					error("needs to be dereferenced")
				end
				register.displacement = immediate
				return register
			end,
			__len = function (register)
				register.memory = true
				return register
			end
		})
	end

	return e_t
end

local _registers = {
	"rax", "rcx", "rdx"
}

local instructions = {
	mov = "mov",
	add = "add",
	inc = "inc",
	dec = "dec"
}

local i = instructions

local deref

local registers = make_registers(_registers)
local r = register

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

function encode_instruction(instruction, ...)
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

local function tohex(v)
	return string.format("%02X", v)
end

local function apply(t, fn)
	for i = 1, #t do
		t[i] = fn(t[i])
	end
end

encode_instruction(i.mov, r.eax, #r.ebx + 1)

bytes = encode_instruction()
apply(bytes, tohex)
print(table.unpack(bytes))