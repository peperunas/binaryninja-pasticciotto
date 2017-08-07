from binaryninja import *
from struct import unpack

# name, size, value
ops = [["movi", "imm2reg", 0],
       ["movr", "reg2reg", 0],
       ["lodi", "imm2reg", 0],
       ["lodr", "reg2reg", 0],
       ["stri", "reg2imm", 0],
       ["strr", "reg2reg", 0],
       ["addi", "imm2reg", 0],
       ["addr", "reg2reg", 0],
       ["subi", "imm2reg", 0],
       ["subr", "reg2reg", 0],
       ["andi", "byt2reg", 0],
       ["andw", "imm2reg", 0],
       ["andr", "reg2reg", 0],
       ["yorb", "byt2reg", 0],
       ["yorw", "imm2reg", 0],
       ["yorr", "reg2reg", 0],
       ["xorb", "byt2reg", 0],
       ["xorw", "imm2reg", 0],
       ["xorr", "reg2reg", 0],
       ["notr", "regonly", 0],
       ["muli", "imm2reg", 0],
       ["mulr", "reg2reg", 0],
       ["divi", "imm2reg", 0],
       ["divr", "reg2reg", 0],
       ["shli", "imm2reg", 0],
       ["shlr", "reg2reg", 0],
       ["shri", "imm2reg", 0],
       ["shrr", "reg2reg", 0],
       ["push", "regonly", 0],
       ["poop", "regonly", 0],
       ["cmpb", "byt2reg", 0],
       ["cmpw", "imm2reg", 0],
       ["cmpr", "reg2reg", 0],
       ["jmpi", "jump", 0],
       ["jmpr", "jump", 0],
       ["jpai", "jump", 0],
       ["jpar", "jump", 0],
       ["jpbi", "jump", 0],
       ["jpbr", "jump", 0],
       ["jpei", "jump", 0],
       ["jper", "jump", 0],
       ["jpni", "jump", 0],
       ["jpnr", "jump", 0],
       ["call", "jump", 0],
       ["retn", "single", 0],
       ["shit", "single", 0],
       ["nope", "single", 0],
       ["grmn", "single", 0]]

doub_oper = [x[0] for x in ops if "2" in x[1]]  # man, this sucks

op_sizes = {"reg2reg": 2,
            "imm2reg": 4,
            "reg2imm": 4,
            "byt2reg": 3,
            "regonly": 2,
            "immonly": 3,
            "jump": 3,
            "single": 1}

op_tokens = {"reg":
             lambda reg, value: [
                 InstructionTextToken(
                     InstructionTextTokenType.RegisterToken, reg)
             ],
             "imm": lambda reg, value: [
                 InstructionTextToken(
                     InstructionTextTokenType.PossibleAddressToken, hex(value), value)
             ]
             }


def encrypt_ops(key):
    key_ba = bytearray(key, 'utf-8')
    arr = [i for i in range(256)]
    j = 0

    for i in range(len(arr)):
        j = (j + arr[i] + key_ba[i % len(key)]) % len(arr)
        arr[i], arr[j] = arr[j], arr[i]

    for i in range(len(ops)):
        ops[i][2] = arr[i]


class Pasticciotto(Architecture):
    name = 'pasticciotto'
    address_size = 2
    default_int_size = 2

    regs = {
        'r0': RegisterInfo('r0', 2),
        'r1': RegisterInfo('r1', 2),
        'r2': RegisterInfo('r2', 2),
        'r3': RegisterInfo('r3', 2),
        's0': RegisterInfo('s0', 2),
        's1': RegisterInfo('s1', 2),
        's2': RegisterInfo('s2', 2),
        's3': RegisterInfo('s3', 2),
        'ip': RegisterInfo('ip', 2),
        'rp': RegisterInfo('rp', 2),
        'sp': RegisterInfo('sp', 2),
    }

    reg_names = ["R0", "R1", "R2", "R3", "R0",
                 "S1", "S2", "S3", "IP", "RP", "SP"]
    stack_pointer = 'sp'
    link_reg = 'rp'
    ops_encrypted = False

    def parse(self, data):
        data_op = None
        if not self.ops_encrypted:
            op_key = get_text_line_input("Opcodes key:", "")
            encrypt_ops(op_key)
            self.ops_encrypted = True

        for x in ops:
            if x[2] == unpack("B", data[0])[0]:
                data_op = x
                break
        if not data_op:
            raise Exception("Invalid opcode. Wrong key maybe?")

        instr = data_op[0]
        tokens = [InstructionTextToken(
            InstructionTextTokenType.TextToken, '{:7s}'.format(instr))]

        if data_op[1] == "reg2reg":
            length = op_sizes["reg2reg"]
            src_val = unpack("B", data[1])[0] & 0b00001111
            dst_val = (unpack("B", data[1])[0] & 0b11110000) >> 4
            src = [r for i, r in enumerate(self.reg_names) if i == src_val][0]
            dst = [r for i, r in enumerate(self.reg_names) if i == dst_val][0]
            src_tk = op_tokens["reg"](src, src_val)
            dst_tk = op_tokens["reg"](dst, dst_val)
        elif data_op[1] == "imm2reg":
            length = op_sizes["imm2reg"]
            src_val = unpack("<H", data[2:4])[0]
            dst_val = unpack("B", data[1])[0]
            src = src_val
            dst = [r for i, r in enumerate(self.reg_names) if i == dst_val][0]
            src_tk = op_tokens["imm"](src, src_val)
            dst_tk = op_tokens["reg"](dst, dst_val)
        elif data_op[1] == "reg2imm":
            length = op_sizes["reg2imm"]
            src_val = unpack("B", data[1])[0]
            dst_val = unpack("<H", data[2:4])[0]
            src = [r for i, r in enumerate(self.reg_names) if i == src_val][0]
            dst = dst_val
            src_tk = op_tokens["reg"](src, src_val)
            dst_tk = op_tokens["imm"](dst, dst_val)
        elif data_op[1] == "byt2reg":
            length = op_sizes["byt2reg"]
            src_val = unpack("B", data[2])[0]
            dst_val = unpack("B", data[1])[0]
            src = src_val
            dst = [r for i, r in enumerate(self.reg_names) if i == dst_val][0]
            src_tk = op_tokens["imm"](src, src_val)
            dst_tk = op_tokens["reg"](dst, dst_val)
        elif data_op[1] == "regonly":
            length = op_sizes["regonly"]
            dst_val = unpack("B", data[1])[0]
            src = src_val = src_tk = None
            dst = [r for i, r in enumerate(self.reg_names) if i == dst_val][0]
            dst_tk = op_tokens["reg"](dst, dst_val)
        elif data_op[1] == "immonly":
            length = op_sizes["immonly"]
            dst_val = unpack("<H", data[1:3])[0]
            src = src_val = src_tk = None
            dst = dst_val
            dst_tk = op_tokens["imm"](dst, dst_val)
        elif data_op[1] == "jump":
            length = op_sizes["jump"]
            dst_val = unpack("<H", data[1:3])[0]
            src = src_val = src_tk = None
            dst = dst_val
            dst_tk = op_tokens["imm"](dst, dst_val)
        elif data_op[1] == "single":
            length = op_sizes["single"]
            src = src_val = src_tk = None
            dst = dst_val = dst_tk = None

        if instr in doub_oper:
            tokens += dst_tk
            tokens += [InstructionTextToken(
                InstructionTextTokenType.TextToken, ', ')]
            tokens += src_tk
        elif data_op[1] != "single":
            tokens += dst_tk

        return instr, src, dst, src_val, dst_val, length, tokens

    def perform_get_instruction_info(self, data, addr):
        instr, src, dst, src_val, dst_val, length, _ = self.parse(data)
        result = InstructionInfo()
        result.length = length

        if instr in ["shit", "retn"]:
            result.add_branch(BranchType.FunctionReturn)
        elif instr in ['jmpr', 'jmpi'] and dst_val is not None:
            result.add_branch(BranchType.UnconditionalBranch, dst_val)
        elif instr in ['jpai', 'jpar', 'jpbi', 'jpbr', 'jpei', 'jper', 'jpni', 'jpnr']:
            result.add_branch(BranchType.TrueBranch, dst_val)
            result.add_branch(BranchType.FalseBranch, addr + length)
        elif instr == 'call' and dst_val is not None:
            result.add_branch(BranchType.CallDestination, dst_val)
        return result

    def perform_get_instruction_text(self, data, addr):
        _, _, _, _, _, length, tokens = self.parse(data)
        return tokens, length


class DefaultCallingConvention(CallingConvention):
    name = 'default'
    int_arg_regs = ['r0', 'r1', 'r2', 'r3']
    int_return_reg = 'r0'
    high_int_return_reg = 'r1'


Pasticciotto.register()
arch = Architecture['pasticciotto']
arch.register_calling_convention(DefaultCallingConvention(arch))
standalone = arch.standalone_platform
standalone.default_calling_convention = arch.calling_conventions['default']
