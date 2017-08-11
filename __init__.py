from binaryninja import *
from struct import pack, unpack
import re


re_width_8 = ".*[bB]$"
reg_names = ["r0", "r1", "r2", "r3", "s0",
             "s1", "s2", "s3", "ip", "rp", "sp"]
data_va = 0x10000000
data_size = 0x100000
stack_va = 0x20000000
stack_size = 0x100000

# name, size, value
ops = [
    ["movi", "imm2reg", 0],
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
    ["grmn", "single", 0]
]

doub_oper = [x[0] for x in ops if "2" in x[1]]  # man, this sucks

op_sizes = {
    "reg2reg": 2,
    "imm2reg": 4,
    "reg2imm": 4,
    "byt2reg": 3,
    "regonly": 2,
    "immonly": 3,
    "jump": 3,
    "single": 1
}

op_tokens = {
    "reg":
    lambda reg, value: [
        InstructionTextToken(
            InstructionTextTokenType.RegisterToken, reg)
    ],
    "data": lambda reg, value: [
        InstructionTextToken(InstructionTextTokenType.TextToken, "data["),
        InstructionTextToken(
            InstructionTextTokenType.PossibleAddressToken, hex(value), data_va + value),
        InstructionTextToken(InstructionTextTokenType.TextToken, "]"),

    ],
    "datareg": lambda reg, value: [
        InstructionTextToken(InstructionTextTokenType.TextToken, "data["),
        InstructionTextToken(
            InstructionTextTokenType.RegisterToken, reg),
        InstructionTextToken(InstructionTextTokenType.TextToken, "]"),

    ],
    "imm": lambda reg, value: [
        InstructionTextToken(
            InstructionTextTokenType.IntegerToken, hex(value))
    ]
}

il_dst = {
    "reg": lambda il, width, dst, value: il.set_reg(2, dst, value),
    "data": lambda il, width, dst, value: il.store(width, il.const_pointer(width, data_va + dst), value),
    "imm": lambda il, width, dst, value: il.const(width, value)
}
il_src = {
    "reg": lambda il, width, src, value: il.reg(2, src),
    "data": lambda il, width, src, value: il.load(width, il.const_pointer(width, data_va + value)),
    "imm": lambda il, width, src, value: il.const(width, value)
}

il_ops = {
    "movi": lambda il, width, src, src_value, dst, dst_value:
    il_dst["reg"](il, width, dst, il_src["imm"](il, width, src, src_value)),
    "movr": lambda il, width, src, src_value, dst, dst_value:
    il_dst["reg"](il, width, dst, il_src["reg"](il, width, src, src_value)),
    "lodi": lambda il, width, src, src_value, dst, dst_value:
    il_dst["reg"](il, width, dst, il_src["data"](il, width, src, src_value)),
    "lodr": 0,
    "stri": lambda il, width, src, src_value, dst, dst_value:
    il_dst["data"](il, width, dst, il_src["reg"](il, width, src, src_value)),
    "strr": 0,
    "addi": lambda il, width, src, src_value, dst, dst_value:
    il_dst["reg"](il, width, dst, il.add(width, il_src["reg"](il, width, dst, dst_value), il_src["imm"](
        il, width, src, src_value))),
    "addr": lambda il, width, src, src_value, dst, dst_value:
    il_dst["reg"](il, width, dst, il.add(width, il_src["reg"](il, width, dst, dst_value), il_src["reg"](
        il, width, src, src_value))),
    "subi": lambda il, width, src, src_value, dst, dst_value:
    il_dst["reg"](il, width, dst, il.sub(width, il_src["reg"](
        il, width, dst, dst_value), il_src["imm"](il, width, src, src_value))),
    "subr": lambda il, width, src, src_value, dst, dst_value:
    il_dst["reg"](il, width, dst, il.sub(width, il_src["reg"](
        il, width, dst, dst_value), il_src["reg"](il, width, src, src_value))),
    "andi": lambda il, width, src, src_value, dst, dst_value:
    il_dst["reg"](il, width, dst, il.and_expr(width, il_src["reg"](
        il, width, dst, dst_value), il_src["imm"](il, width, src, src_value))),
    "andw": lambda il, width, src, src_value, dst, dst_value:
    il_dst["reg"](il, width, dst, il.and_expr(width, il_src["reg"](
        il, width, dst, dst_value), il_src["imm"](il, width, src, src_value))),
    "andr": lambda il, width, src, src_value, dst, dst_value:
    il_dst["reg"](il, width, dst, il.and_expr(width, il_src["reg"](
        il, width, dst, dst_value), il_src["reg"](il, width, src, src_value))),
    "yorb": lambda il, width, src, src_value, dst, dst_value:
    il_dst["reg"](il, width, dst, il.or_expr(width, il_src["reg"](
        il, width, dst, dst_value), il_src["imm"](il, width, src, src_value))),
    "yorw": lambda il, width, src, src_value, dst, dst_value:
    il_dst["reg"](il, width, dst, il.or_expr(width, il_src["reg"](
        il, width, dst, dst_value), il_src["imm"](il, width, src, src_value))),
    "yorr": lambda il, width, src, src_value, dst, dst_value:
    il_dst["reg"](il, width, dst, il.or_expr(width, il_src["reg"](
        il, width, dst, dst_value), il_src["reg"](il, width, src, src_value))),
    "xorb": lambda il, width, src, src_value, dst, dst_value:
    il_dst["reg"](il, width, dst, il.xor_expr(width, il_src["reg"](
        il, width, dst, dst_value), il_src["imm"](il, width, src, src_value))),
    "xorw": lambda il, width, src, src_value, dst, dst_value:
    il_dst["reg"](il, width, dst, il.xor_expr(width, il_src["reg"](
        il, width, dst, dst_value), il_src["imm"](il, width, src, src_value))),
    "xorr": lambda il, width, src, src_value, dst, dst_value:
    il_dst["reg"](il, width, dst, il.xor_expr(width, il_src["reg"](
        il, width, dst, dst_value), il_src["reg"](il, width, src, src_value))),
    "notr": lambda il, width, src, src_value, dst, dst_value:
    il_dst["reg"](il, width, dst, il.neg_expr(
        il_src["reg"](il, width, dst, dst_value))),
    "muli": lambda il, width, src, src_value, dst, dst_value:
    il_dst["reg"](il, width, dst, il.mult(width, il_src["reg"](il, width, dst, dst_value), il_src["imm"](
        il, width, src, src_value))),
    "mulr": lambda il, width, src, src_value, dst, dst_value:
    il_dst["reg"](il, width, dst, il.mult(width, il_src["reg"](il, width, dst, dst_value), il_src["reg"](
        il, width, src, src_value))),
    "divi": lambda il, width, src, src_value, dst, dst_value:
    il_dst["reg"](il, width, dst, il.div_unsigned(width, il_src["reg"](il, width, dst, dst_value), il_src["imm"](
        il, width, src, src_value))),
    "divr": lambda il, width, src, src_value, dst, dst_value:
    il_dst["reg"](il, width, dst, il.div_unsigned(width, il_src["reg"](il, width, dst, dst_value), il_src["reg"](
        il, width, src, src_value))),
    "shli": lambda il, width, src, src_value, dst, dst_value:
    il_dst["reg"](il, width, dst, il.shift_left(width, il_src["reg"](
        il, width, dst, dst_value), il_src["imm"](il, width, src, src_value))),
    "shlr": lambda il, width, src, src_value, dst, dst_value:
    il_dst["reg"](il, width, dst, il.shift_left(width, il_src["reg"](
        il, width, dst, dst_value), il_src["reg"](il, width, src, src_value))),
    "shri": lambda il, width, src, src_value, dst, dst_value:
    il_dst["reg"](il, width, dst, il.logical_shift_right(width, il_src["reg"](
        il, width, dst, dst_value), il_src["imm"](il, width, src, src_value))),
    "shrr": lambda il, width, src, src_value, dst, dst_value:
    il_dst["reg"](il, width, dst, il.logical_shift_right(width, il_src["reg"](
        il, width, dst, dst_value), il_src["reg"](il, width, src, src_value))),
    "push": lambda il, width, src, src_value, dst, dst_value: il.push(width, il_src["reg"](il, width, dst, dst_value)),
    "poop": lambda il, width, src, src_value, dst, dst_value: il_dst["reg"](il, width, dst, il.pop(2)),
    "cmpb": 0,
    "cmpw": 0,
    "cmpr": 0,
    "jmpi": 0,
    "jmpr": 0,
    "jpai": 0,
    "jpar": 0,
    "jpbi": 0,
    "jpbr": 0,
    "jpei": 0,
    "jper": 0,
    "jpni": 0,
    "jpnr": 0,
    "call": lambda il, width, src, src_value, dst, dst_value: il.call(il_dst["imm"](il, width, dst, dst_value)),
    "retn": lambda il, width, src, src_value, dst, dst_value: [il_dst["reg"](il, width, "rp", il.pop(2)), il.ret(il_src["reg"](il, width, "rp", "rp"))],
    "shit": lambda il, width, src, src_value, dst, dst_value: il.ret(il.pop(2)),
    "nope": lambda il, width, src, src_value, dst, dst_value: il.nop(),
    "grmn": lambda il, width, src, src_value, dst, dst_value: [il_dst["reg"](il, width, x, il.const(2, 0x42)) for x in reg_names if x not in ["sp", "rp", "ip"]]
}


def cond_branch(il, cond, dest):
    ret = []
    t = il.get_label_for_address(
        Architecture['pasticciotto'], il[dest].constant)

    if t is None:
        # t is not an address in the current function scope.
        t = LowLevelILLabel()
        indirect = True
    else:
        indirect = False

    f_label_found = True

    f = il.get_label_for_address(
        Architecture['pasticciotto'], il.current_address + 2)

    if f is None:
        f = LowLevelILLabel()
        f_label_found = False

    ret.append(il.if_expr(cond, t, f))

    if indirect:
        # If the destination is not in the current function,
        # then a jump, rather than a goto, needs to be added to
        # the IL.
        il.mark_label(t)
        ret.append(il.jump(dest))

    if not f_label_found:
        il.mark_label(f)

    return ret


def cmp(il, width, src, src_value, dst, dst_value):
    ret = []
    if dst_value == src_value:
        ret.append(il.flag_bit(width, 'z', 1))
    else:
        ret.append(il.flag_bit(width, 'z', 0))
    if dst_value > src_value:
        ret.append(il.flag_bit(width, 'c', 0))
    else:
        ret.append(il.flag_bit(width, 'c', 1))
    return ret


def jump(il, dest):
    label = None

    if il[dest].operation == LowLevelILOperation.LLIL_CONST:
        label = il.get_label_for_address(
            Architecture['pasticciotto'], il[dest].constant)

    if label is None:
        return il.jump(dest)
    else:
        return il.goto(label)


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

    stack_pointer = 'sp'
    link_reg = 'rp'
    flags = ['c', 'z']
    flag_roles = {
        'c': FlagRole.CarryFlagRole,
        'z': FlagRole.ZeroFlagRole
    }
    flags_required_for_flag_condition = {
        LowLevelILFlagCondition.LLFC_E: ['z'],
        LowLevelILFlagCondition.LLFC_NE: ['z'],
        LowLevelILFlagCondition.LLFC_UGE: ['c'],
        LowLevelILFlagCondition.LLFC_ULE: ['c']
    }
    flags_written_by_flag_write_type = {
        '*': ['c', 'z'],
        'c': ['c'],
        'z': ['z']
    }
    # The first flag write type is ignored currently.
    # See: https://github.com/Vector35/binaryninja-api/issues/513
    flag_write_types = ['', '*', 'c', 'z']

    ops_encrypted = False

    def get_opcode_key(self):
        op_key = None
        choice = get_choice_input(
            "Opcodes key format:", "", ["String", "File"])
        if choice == 0:  # string
            op_key = get_text_line_input("Opcodes key:", "")
        elif choice == 1:  # file
            filename = get_open_filename_input("Opcodes key file")
            with open(filename, "rb") as f:
                op_key = f.read()
        if not op_key:
            raise Exception("Opcodes key not defined!")

        return op_key

    def parse(self, data):
        cre_width_8 = re.compile(re_width_8)
        data_op = None

        if not self.ops_encrypted:
            op_key = self.get_opcode_key()
            encrypt_ops(op_key)
            self.ops_encrypted = True

        for x in ops:
            if x[2] == unpack("B", data[0])[0]:
                data_op = x
                break
        if not data_op:
            raise Exception("Invalid opcode. Wrong key maybe?")

        instr = data_op[0]
        if cre_width_8.match(instr):
            width = 1
        else:
            width = 2

        tokens = [InstructionTextToken(
            InstructionTextTokenType.TextToken, '{:7s}'.format(instr))]

        if data_op[1] == "reg2reg":
            length = op_sizes["reg2reg"]
            src_val = unpack("B", data[1])[0] & 0b00001111
            dst_val = (unpack("B", data[1])[0] & 0b11110000) >> 4
            src = [r for i, r in enumerate(reg_names) if i == src_val][0]
            dst = [r for i, r in enumerate(reg_names) if i == dst_val][0]
            if instr in ["lodr", "strr"]:
                src_tk = op_tokens["datareg"](src, src_val)
            else:
                src_tk = op_tokens["reg"](src, src_val)
            dst_tk = op_tokens["reg"](dst, dst_val)
        elif data_op[1] == "imm2reg":
            length = op_sizes["imm2reg"]
            src_val = unpack("<H", data[2: 4])[0]
            dst_val = unpack("B", data[1])[0]
            src = src_val
            dst = [r for i, r in enumerate(reg_names) if i == dst_val][0]
            if instr == "lodi":
                src_tk = op_tokens["data"](src, src_val)
            else:
                src_tk = op_tokens["imm"](src, src_val)
            dst_tk = op_tokens["reg"](dst, dst_val)
        elif data_op[1] == "reg2imm":
            length = op_sizes["reg2imm"]
            src_val = unpack("B", data[3])[0]
            dst_val = unpack("<H", data[1:3])[0]
            src = [r for i, r in enumerate(reg_names) if i == src_val][0]
            dst = dst_val
            src_tk = op_tokens["reg"](src, src_val)
            if instr == "stri":
                dst_tk = op_tokens["data"](dst, dst_val)
            else:
                dst_tk = op_tokens["imm"](dst, dst_val)
        elif data_op[1] == "byt2reg":
            length = op_sizes["byt2reg"]
            src_val = unpack("B", data[2])[0]
            dst_val = unpack("B", data[1])[0]
            src = src_val
            dst = [r for i, r in enumerate(reg_names) if i == dst_val][0]
            src_tk = op_tokens["imm"](src, src_val)
            dst_tk = op_tokens["reg"](dst, dst_val)
        elif data_op[1] == "regonly":
            length = op_sizes["regonly"]
            dst_val = unpack("B", data[1])[0]
            src = src_val = src_tk = None
            dst = [r for i, r in enumerate(reg_names) if i == dst_val][0]
            dst_tk = op_tokens["reg"](dst, dst_val)
        elif data_op[1] == "immonly":
            length = op_sizes["immonly"]
            dst_val = unpack("<H", data[1: 3])[0]
            src = src_val = src_tk = None
            dst = dst_val
            dst_tk = op_tokens["imm"](dst, dst_val)
        elif data_op[1] == "jump":
            length = op_sizes["jump"]
            dst_val = unpack("<H", data[1: 3])[0]
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

        return instr, width, src, dst, src_val, dst_val, length, tokens

    def perform_get_instruction_info(self, data, addr):
        instr, _, src, dst, src_val, dst_val, length, _ = self.parse(data)
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
        _, _, _, _, _, _, length, tokens = self.parse(data)
        return tokens, length

    def perform_get_instruction_low_level_il(self, data, addr, il):
        instr, width, src, dst, src_val, dst_val, length, _ = self.parse(data)

        if il_ops.get(instr) is None or il_ops.get(instr) == 0:
            il.append(il.unimplemented())
        else:
            il_instr = il_ops[instr](il, width, src, src_val, dst, dst_val)
            if isinstance(il_instr, list):
                for x in il_instr:
                    il.append(x)
            else:
                il.append(il_instr)
        return length


class DefaultCallingConvention(CallingConvention):
    name = 'default'
    int_arg_regs = ['r0', 'r1', 'r2', 'r3']
    int_return_reg = 'r0'
    high_int_return_reg = 'r1'


class PasticciottoView(BinaryView):
    def __init__(self, data):
        BinaryView.__init__(self, file_metadata=data.file, parent_view=data)
        self.raw = data
        self.platform = Architecture["pasticciotto"].standalone_platform
        self.add_auto_segment(
            0x0, 0x3000, 0, len(data), SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable)
        # Add data segment
        self.add_auto_segment(
            data_va, data_size, 0, 0, SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable)
        # Add stack segment
        self.add_auto_segment(stack_va, stack_size, 0, 0, SegmentFlag.SegmentReadable |
                              SegmentFlag.SegmentWritable | SegmentFlag.SegmentExecutable)
        self.add_entry_point(0x0)

    @classmethod
    def is_valid_for_data(self, data):
        return True

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return 0


class PasticciottoAppView(PasticciottoView):
    name = "Pasticciotto"
    long_name = "Pasticciotto"


Pasticciotto.register()
arch = Architecture['pasticciotto']
arch.register_calling_convention(DefaultCallingConvention(arch))
standalone = arch.standalone_platform
standalone.default_calling_convention = arch.calling_conventions['default']
PasticciottoAppView.register()
