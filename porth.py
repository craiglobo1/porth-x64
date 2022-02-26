
import sys
from enum import Enum,auto,IntEnum
import subprocess
from os import path, getcwd
import time
from dataclasses import dataclass, field
from typing import *
from copy import copy

EXPANSION_LIMIT = 1000
X86_32_RET_STACK_CAP = 4000

class TokenType(Enum):
    INT = auto()
    WORD = auto()
    STR = auto()
    CHAR = auto()
    SYSPORT_CALL = auto()
    KEYWORD = auto()

# TODOOO: Implement let and peek functionality
class Keyword(Enum):
    # blocks
    IF = auto()
    ELSE = auto()
    ELIF = auto()
    WHILE = auto()
    DO = auto()
    MACRO = auto()
    PROC= auto()
    MEMORY = auto()
    CONST = auto()
    INCLUDE = auto()
    SYSPORT = auto()
    BREAK = auto()
    TYPE_BREAK = auto()
    END = auto()
    LET=auto()
    IN= auto()
    DASHDASH = auto()

class Intrinsic(Enum):
    # win32 api operations
    STDOUT = auto()
    DUMP = auto()
    EXIT = auto()
    # arithmetic operations
    ADD = auto()
    PTR_ADD = auto()
    SUB = auto()
    DIVMOD = auto()
    MUL = auto()
    # logical operations
    TRUE = auto()
    FALSE = auto()
    EQUAL = auto()
    NE = auto()
    GT = auto()
    LT = auto()
    GTE= auto()
    LTE = auto()
    # stack operations
    DROP= auto()
    DUP = auto()
    DUP2=auto()
    OVER= auto()
    OVER2= auto()
    SWAP = auto()
    # mem operations
    STORE = auto()
    LOAD = auto()
    STORE32 = auto()
    STOREINT = auto()
    STOREPTR = auto()

    LOAD32 = auto()
    LOADINT = auto()
    LOADPTR = auto()
    MEMCPY = auto()
    # bitwise operations
    SHL= auto()
    SHR = auto()
    BAND = auto()
    BOR = auto()
    BXOR = auto()
    # cast operations
    CAST_INT = auto()
    CAST_BOOL = auto()
    CAST_PTR = auto()
    STRLEN = auto()

class OpType(Enum):
    # stack operations
    PUSH_INT = auto()
    PUSH_STR = auto()
    PUSH_MEM = auto()
    # syscall
    SYSCALL = auto()
    SYSVAL = auto()
    # blocks
    IF = auto()
    ELSE = auto()
    ELIF = auto()
    WHILE = auto()
    DO = auto()
    BIND = auto()
    PUSH_BIND = auto()
    UNBIND = auto()
    END = auto()
    BREAK = auto()
    TYPE_BREAK = auto() 
    INTRINSIC = auto()
    SKIP_PROC=auto()
    RET=auto()
    CALL=auto()

assert len(Keyword) == 17, f"Exhaustive handling in KEYWORD NAMES {len(Keyword)}"
KEYWORD_NAMES = {
    "if"    :   Keyword.IF,
    "else"  :   Keyword.ELSE,
    "elif"    :   Keyword.ELIF,
    "while" :   Keyword.WHILE,
    "do"    :   Keyword.DO,
    "macro" :   Keyword.MACRO,
    "proc" :   Keyword.PROC,
    "memory" : Keyword.MEMORY,
    "const" : Keyword.CONST,
    "include":  Keyword.INCLUDE,
    "sysport":  Keyword.SYSPORT,
    "let" : Keyword.LET,
    "break":  Keyword.BREAK,
    "tbreak":  Keyword.TYPE_BREAK,
    "end"   :   Keyword.END,
    "in"   :   Keyword.IN,
    "--"   :   Keyword.DASHDASH,
}

assert len(Intrinsic) == 40 , f"Exhaustive handling in INTRINSIC_WORDS {len(Intrinsic)}"
INTRINSIC_WORDS = {
    "stdout" : Intrinsic.STDOUT,
    "dump" : Intrinsic.DUMP,
    "exit"  : Intrinsic.EXIT,
    "+"     : Intrinsic.ADD,
    "ptr+"     : Intrinsic.PTR_ADD,
    "strlen"     : Intrinsic.STRLEN,
    "-"     : Intrinsic.SUB,
    "divmod": Intrinsic.DIVMOD,
    "*"     : Intrinsic.MUL,
    "true" : Intrinsic.TRUE,
    "false" : Intrinsic.FALSE,
    "="     : Intrinsic.EQUAL,
    "!="    : Intrinsic.NE,
    ">"     : Intrinsic.GT,
    "<"     : Intrinsic.LT,
    ">="     : Intrinsic.GTE,
    "<="     : Intrinsic.LTE,
    "drop"  : Intrinsic.DROP,
    "dup"   : Intrinsic.DUP,
    "2dup"  : Intrinsic.DUP2,
    "swap"  : Intrinsic.SWAP,
    "over"  : Intrinsic.OVER,
    "2over" : Intrinsic.OVER2,
    "!8"     : Intrinsic.STORE,
    "!char"     : Intrinsic.STORE,
    "@8"     : Intrinsic.LOAD,
    "@char"     : Intrinsic.LOAD,
    "!32":Intrinsic.STORE32,
    "!int":Intrinsic.STOREINT,
    "!ptr":Intrinsic.STOREPTR,
    "@32": Intrinsic.LOAD32,
    "@int": Intrinsic.LOAD32,
    "@ptr": Intrinsic.LOAD32,
    "memcpy" : Intrinsic.MEMCPY,
    "shl"   : Intrinsic.SHL,
    "shr"   : Intrinsic.SHR,
    "bor"   : Intrinsic.BOR,
    "band"  : Intrinsic.BAND,
    "bxor"  : Intrinsic.BXOR,
    "<int>"  : Intrinsic.CAST_INT,
    "<bool>"  : Intrinsic.CAST_BOOL,
    "<ptr>"  : Intrinsic.CAST_PTR
}
INTRINSIC_WORDS_TO_INTRINSIC = { val:key for key, val in INTRINSIC_WORDS.items() }

SYSPORT_FUNCS = {
    "kernel32" : {"GetStdHandle", "WriteConsoleA", "ExitProcess"}
}
SYSPORT_USED = {"GetStdHandle", "WriteConsoleA", "ExitProcess"}

Loc=Tuple[str, int, int]

assert len(TokenType) == 6, "Exhaustive Token type definition. The `value` field of the Token dataclass may require an update"
@dataclass
class Token:
    type: TokenType
    text: str
    loc: Loc
    value: Union[int, str, Keyword]
    # https://www.python.org/dev/peps/pep-0484/#forward-references
    expanded_from: Optional['Token'] = None
    expanded: int = 0

OpAddr=int
MemAddr=int

@dataclass
class SyscallData:
    name : str
    no_of_args : int


class DataType(Enum):
    INT=auto()
    PTR=auto()
    BOOL=auto()

DATATYPE_BY_NAME = {
    "int" : DataType.INT,
    "bool" : DataType.BOOL,
    "ptr" : DataType.PTR,
}
DATATYPE_NAMES = { val : key for key, val in DATATYPE_BY_NAME.items()}

DataStack=List[Tuple[DataType, Loc]]

@dataclass
class Contract:
    ins :  List[DataStack]
    outs : List[DataStack]

@dataclass
class Proc:
    name : str
    ip : int
    contract : Contract
    local_mems : Dict[str, int]
    local_mem_cap : int = 0
    ret_ip : int = 0

@dataclass
class Op:
    type: OpType
    token: Token 
    operand: Optional[Union[int, str, Intrinsic, OpAddr, SyscallData, Proc]] = None

@dataclass
class MemData:
    name : str
    addr : int
    space : str = "global"

@dataclass
class Program:
    ops : List[Op]
    procs : List[Proc]
    lp_variables : List[Token]
    consts : Dict[str, int] = field(default_factory= lambda : {})
    memories : List[MemData] = field(default_factory= lambda: [])
    offset_value : int = 0
    memory_capacity : int = 0


# ---------------------------- Lexer ----------------------------

def find_col(line : str, start : int, predicate : Callable[[str], bool]) -> int:
    while start < len(line) and predicate(line[start]):
        start += 1
    return start

def unescape_string(s: str) -> str:
    # NOTE: unicode_escape assumes latin-1 encoding, so we kinda have
    # to do this weird round trip
    return s.encode('utf-8').decode('unicode_escape').encode('latin-1').decode('utf-8')

def lex_lines(file_path : str, lines : List[str]) -> Generator[Token, None, None]:
    for row, line in enumerate(lines):
        col = find_col(line, 0, lambda x: x.isspace())
        assert len(TokenType) == 6, "Exahuastive handling of tokens in lex_lines"
        comment = False
        while col < len(line) and not comment:
            loc = (file_path, row + 1, col + 1)

            # TODO: Add support for binary and hexadecimal numbers
            # TODOOOO: Fix bug for unescaping quotes (\")
            if line[col] == '"':
                col_end = find_col(line, col+1, lambda x: not x == '"')
                if col_end >= len(line) or line[col_end] != '"':
                    print("%s:%d:%d error: string literal not closed" % loc )
                text_of_token = line[col+1:col_end]
                yield Token(TokenType.STR, text_of_token, loc, unescape_string(text_of_token))
                col = find_col(line, col_end+1, lambda x: x.isspace())

            elif line[col] == "'":
                col_end = find_col(line, col+1, lambda x: not x == "'")
                if col_end >= len(line) or line[col_end] != "'":
                    print("%s:%d:%d error: char literal not closed" % loc )
                text_of_token = line[col+1:col_end]
                char = unescape_string(text_of_token)
                if len(char) != 1:
                    sys.exit("%s:%d:%d only a single byte is allowed inside of a character literal" % loc)
                yield Token(TokenType.CHAR, text_of_token, loc, ord(char))
                col = find_col(line, col_end+1, lambda x: x.isspace())
            
            elif line[col] == "[":
                col_end = find_col(line, col+1, lambda x: not x == ']')
                if col_end >= len(line) or line[col_end] != ']':
                    compiler_error(loc, "sysport port literal not closed")
                text_of_token = line[col+1:col_end]
                yield Token(TokenType.SYSPORT_CALL, text_of_token, loc, text_of_token)
                col = find_col(line, col_end+1, lambda x: x.isspace())

            else:
                col_end = find_col(line, col, lambda x: not x.isspace())
                text_of_token = line[col:col_end]
                try:
                    yield Token(TokenType.INT, text_of_token, loc, int(text_of_token))
                except ValueError:
                    if text_of_token in KEYWORD_NAMES:
                        yield Token(TokenType.KEYWORD, text_of_token, loc, KEYWORD_NAMES[text_of_token])
                    else:
                        comment = text_of_token.startswith('//')
                        if not comment:
                            yield Token(TokenType.WORD, text_of_token, loc, text_of_token)
                col = find_col(line, col_end, lambda x: x.isspace())

def lex_file(file_path : str) -> List[Token]:
    with open(file_path, "r") as f:
        ans = [token for token in lex_lines(file_path, f.readlines())]
        return ans

def expandMacro(token : Token) -> Token:
    token.expanded += 1
    return token

#---------------------------- Macro ----------------------------
@dataclass
class Macro:
    loc: Loc
    tokens: List[Token]

def readable_enum(enum_val):
    return str(enum_val).split(".")[-1].lower()

#---------------------------- Compliler Errors ----------------------------

def compiler_diagnostic(loc: Loc, tag: str, message: str, exits : bool =True):
    print("./%s:%d:%d: %s: %s" % (loc + (tag, message)), file=sys.stderr)
    if exits:
        exit(1)

def compiler_error(loc: Loc, message: str, exits : bool = True):
    """
    Prints a compiler error message given a loc and a message
    """
    compiler_diagnostic(loc, 'ERROR', message, exits)

def compiler_note(loc: Loc, message: str, exits : bool = True):
    compiler_diagnostic(loc, 'NOTE', message,exits)


#---------------------------- Constants Eval ----------------------------

def evaluate_constant_from_tokens(rtokens : List[Token], consts : Dict[str, int], offsetValue : int) -> Tuple[int, int]:
    stack : List[int] = []
    while len(rtokens) > 0:
        token = rtokens.pop()
        if token.type == TokenType.KEYWORD:
            if token.value == Keyword.END:
                break
            else:
                sys.exit("%s:%d:%d unsupported keyword `%s` in constant evaluation" % (token.loc + (token.text,)))
        elif token.type == TokenType.INT:
            assert isinstance(token.value, int)
            stack.append(token.value)
        elif token.type == TokenType.WORD:
            if token.value in consts:
                stack.append(consts[token.value])
            elif token.value == INTRINSIC_WORDS_TO_INTRINSIC[Intrinsic.ADD]:
                a = stack.pop()
                b = stack.pop()
                stack.append(a + b)
            elif token.value == INTRINSIC_WORDS_TO_INTRINSIC[Intrinsic.MUL]:
                a = stack.pop()
                b = stack.pop()
                stack.append(a*b)
            elif token.value == "offset":
                a = stack.pop()
                stack.append(offsetValue)
                offsetValue += a
            elif token.value == "reset":
                stack.append(offsetValue)
                offsetValue = 0
            else:
                compiler_error(token.loc, f"unsupported word `{token.text}` in constant evaluation")
        else:
            sys.exit("%s:%d:%d unsupported token `%s` in constant evaluation" % (token.loc + (token.text,)))

    if len(stack) != 1:
        sys.exit("%s:%d:%d memory definition expects one int" % token.loc)
    return stack.pop(), offsetValue

def read_till_breaker(rtokens : List[Token], breaker: str, loc : Loc) -> Tuple[List[Token], List[Token]]:
    tokens_till = []
    while len(rtokens) > 0:
        token = rtokens.pop()

        if token.text == breaker:
            return rtokens, tokens_till
        elif token.text == "end":
            compiler_error(loc, f"the keyword `{breaker}` is missing")

        tokens_till.append(token.value)
    compiler_error(loc, f"the keyword {breaker} is missing")


@dataclass
class Context:
    stack : DataStack
    ip : int
    lp_stack : DataStack
    proc_outs : List[DataType]

def type_check_contract(intro_token: Token, ctx: Context, contract: Contract):
    ins = list(contract.ins)
    stack = copy(ctx.stack)
    arg_count = 0
    while len(stack) > 0 and len(ins) > 0:
        actual, actual_loc = stack.pop()
        expected, expected_loc = ins.pop()
        if actual != expected:
            compiler_error(intro_token.loc, f"Argument {arg_count} of `{intro_token.text}` is expected to be type `{DATATYPE_NAMES[expected]}` but got type `{DATATYPE_NAMES[actual]}`")
            compiler_note(actual_loc, f"Argument {arg_count} was provided here")
            compiler_note(expected_loc, f"Expected type was declared here")
            exit(1)
        arg_count += 1

    if len(stack) < len(ins):
        print(ins)
        compiler_error(intro_token.loc, f"Not enough arguments provided for `{intro_token.value}`. Expected {len(contract.ins)} but got {arg_count}.");
        compiler_note(intro_token.loc, f"Not provided arguments:")
        while len(ins) > 0:
            typ, loc = ins.pop()
            compiler_note(loc, f"`{DATATYPE_NAMES[typ]}`")
        exit(1)
    
    for typ, loc in contract.outs:
        stack.append((typ, intro_token.loc))
    ctx.stack = stack

#---------------------------- Typecheck Program ----------------------------

def type_check_program(program : Program):
    """
    given a program it type checks the stack for each operation
    """
    visited_dos : Dict[OpAddr, DataStack] = {}
    contexts : List[Context] = [Context(stack=[], lp_stack=[],  ip=0, proc_outs=[])]
    breakpoint : bool = False
    
    for proc in program.procs:
        cur_ctx = Context(stack=copy(proc.contract.ins), lp_stack=[], ip=copy(proc.ip), proc_outs=copy(proc.contract.outs))
        contexts.append(cur_ctx)

    assert len(OpType) == 20, f"Exhaustive handling of ops in type_check_program {len(OpType)}"
    while len(contexts) > 0:
        ctx = contexts[-1]
        if ctx.ip >= len(program.ops):
            if len(ctx.stack) != 0:
                compiler_error(ctx.stack[0][1], f"unhandled values in the stack of {[readable_enum(val[0]) for val in ctx.stack]} at the end of the program")
            contexts.pop()
            continue
        op = program.ops[ctx.ip]

        if op.type == OpType.PUSH_INT:
            ctx.stack.append((DataType.INT, op.token.loc))
            ctx.ip += 1
        elif op.type == OpType.PUSH_STR:
            ctx.stack.append((DataType.PTR, op.token.loc))
            ctx.ip += 1
        elif op.type == OpType.PUSH_MEM:
            ctx.stack.append((DataType.PTR, op.token.loc))
            ctx.ip += 1
        elif op.type == OpType.SYSCALL:
            no_of_args = op.operand
            if len(ctx.stack) < no_of_args:
                compiler_error(op.token.loc, f"Not enough arguments for syscall `{op.token.value}` required {no_of_args} got {len(ctx.stack)}")
            for i in range(no_of_args):
                ctx.stack.pop()
            ctx.stack.append((DataType.INT, op.token.loc))
            ctx.ip += 1
        elif op.type == OpType.SYSVAL:
            ctx.stack.append((DataType.INT, op.token.loc))
            ctx.ip += 1
        elif op.type == OpType.IF:
            type_check_contract(op.token, ctx, Contract(ins=[(DataType.BOOL,  op.token.loc)], outs=[]))
            ctx.ip += 1
            contexts.append(Context(stack=copy(ctx.stack), lp_stack=copy(ctx.lp_stack), proc_outs=copy(ctx.proc_outs), ip=op.operand))
            ctx = contexts[-1]
        elif op.type == OpType.ELSE:
            ctx.ip = op.operand
        elif op.type == OpType.ELIF:
            type_check_contract(op.token, ctx, Contract(ins=[(DataType.BOOL,  op.token.loc)], outs=[]))
            ctx.ip += 1
            contexts.append(Context(stack=copy(ctx.stack), lp_stack=copy(ctx.lp_stack), proc_outs=copy(ctx.proc_outs), ip=op.operand))
            ctx = contexts[-1]
        elif op.type == OpType.WHILE:
            ctx.ip += 1
        elif op.type == OpType.DO:
            type_check_contract(op.token, ctx, Contract(ins=[(DataType.BOOL,  op.token.loc)], outs=[]))

            if ctx.ip in visited_dos:
                expected_types = list(map(lambda x: x[0], visited_dos[ctx.ip]))
                actual_types = list(map(lambda x: x[0], ctx.stack))
                if expected_types != actual_types:
                    compiler_error(op.token.loc, 'Loops are not allowed to alter types and amount of elements on the stack between iterations!', exits=False)
                    compiler_note(op.token.loc, '-- Stack BEFORE a single iteration --', exits=False)

                    if len(visited_dos[ctx.ip]) == 0:
                        compiler_note(op.token.loc, '<empty>', exits=False)
                    else:
                        for typ, loc in visited_dos[ctx.ip]:
                            compiler_note(loc, readable_enum(typ), exits=False)
                    compiler_note(op.token.loc, '-- Stack AFTER a single iteration --', exits=False)
                    if len(ctx.stack) == 0:
                        compiler_note(op.token.loc, '<empty>', exits=False)
                    else:
                        for typ, loc in ctx.stack:
                            compiler_note(loc, readable_enum(typ), exits=False)
                    exit(1)
                else:
                    contexts.pop()
            

            else:
                visited_dos[ctx.ip] = copy(ctx.stack)
                ctx.ip += 1
                contexts.append(Context(stack=copy(ctx.stack), lp_stack=copy(ctx.lp_stack), ip=op.operand, proc_outs=copy(ctx.proc_outs)))
                ctx = contexts[-1]

        elif op.type == OpType.PUSH_BIND:
            ctx.stack.append(ctx.lp_stack[-op.operand])
            ctx.ip += 1

        elif op.type == OpType.BIND:
            bindings = []
            if len(ctx.stack) < op.operand:
                compiler_error(op.token.loc, "Not enough arguments in stack for let bindinga")
            for i in range(op.operand):
                bindings.append(ctx.stack.pop())
            ctx.lp_stack += bindings
            ctx.ip += 1

        elif op.type == OpType.UNBIND:
            for i in range(op.operand):
                ctx.lp_stack.pop(0)
            ctx.ip += 1
    
        elif op.type == OpType.END:
            assert isinstance(op.operand, OpAddr)
            ctx.ip = op.operand
        elif op.type == OpType.BREAK:
            ctx.ip += 1

        elif op.type == OpType.TYPE_BREAK:
            breakpoint = True
            ctx.ip += 1

        elif op.type == OpType.SKIP_PROC:
            ctx.ip = op.operand.ret_ip

        elif op.type == OpType.CALL:
            type_check_contract(op.token, ctx, op.operand.contract)
            # contexts[-1] = ctx
            ctx.ip += 1

        elif op.type == OpType.RET:
            type_check_context_outs(ctx)
            contexts.pop()

        elif op.type == OpType.INTRINSIC:
            assert len(Intrinsic) == 40, f"Exhaustive handling of Intrinsics in type_check_program {len(Intrinsic)}"
                # win32 api operations
            if op.operand == Intrinsic.STDOUT:
                type_check_contract(op.token, ctx, Contract(ins=[(DataType.PTR,  op.token.loc)], outs=[]))                 
                ctx.ip += 1
            
            elif op.operand == Intrinsic.CAST_INT:
                if len(ctx.stack) < 1:
                    compiler_error(op.token.loc, f"not enough arguments for {readable_enum(op.operand)} Intrinsic")
                a_type, a_loc = ctx.stack.pop()
                ctx.stack.append((DataType.INT, a_loc))
                ctx.ip += 1
            elif op.operand == Intrinsic.DUMP:
                type_check_contract(op.token, ctx, Contract(ins=[(DataType.INT,  op.token.loc)], outs=[]))
                ctx.ip += 1

            elif op.operand == Intrinsic.CAST_BOOL:
                if len(ctx.stack) < 1:
                    compiler_error(op.token.loc, f"not enough arguments for {readable_enum(op.operand)} Intrinsic")
                a_type, a_loc = ctx.stack.pop()
                ctx.stack.append((DataType.BOOL, a_loc))            
                ctx.ip += 1
            elif op.operand == Intrinsic.CAST_PTR:
                if len(ctx.stack) < 1:
                    compiler_error(op.token.loc, f"not enough arguments for {readable_enum(op.operand)} Intrinsic")
                a_type, a_loc = ctx.stack.pop()
                ctx.stack.append((DataType.PTR, a_loc))
                ctx.ip += 1
            elif op.operand == Intrinsic.EXIT:
                return

            elif op.operand == Intrinsic.TRUE or op.operand == Intrinsic.FALSE:
                type_check_contract(op.token, ctx, Contract(ins=[], outs=[(DataType.BOOL,  op.token.loc)]))
                ctx.ip += 1
            elif op.operand == Intrinsic.ADD:
                type_check_contract(op.token, ctx, Contract(ins=[(DataType.INT,  op.token.loc), (DataType.INT,  op.token.loc)], outs=[(DataType.INT,  op.token.loc)]))
                ctx.ip += 1
            elif op.operand == Intrinsic.PTR_ADD:
                type_check_contract(op.token, ctx, Contract(ins=[(DataType.PTR,  op.token.loc), (DataType.INT,  op.token.loc)], outs=[(DataType.PTR,  op.token.loc)]))
                ctx.ip += 1
            elif op.operand == Intrinsic.SUB:
                type_check_contract(op.token, ctx, Contract(ins=[(DataType.INT,  op.token.loc), (DataType.INT,  op.token.loc)], outs=[(DataType.INT,  op.token.loc)]))
                ctx.ip += 1

            elif op.operand == Intrinsic.DIVMOD:
                type_check_contract(op.token, ctx, Contract(ins=[(DataType.INT,  op.token.loc), (DataType.INT,  op.token.loc)], outs=[(DataType.INT,  op.token.loc), (DataType.INT,  op.token.loc)]))
                ctx.ip += 1

            elif op.operand == Intrinsic.MUL:
                type_check_contract(op.token, ctx, Contract(ins=[(DataType.INT,  op.token.loc), (DataType.INT,  op.token.loc)], outs=[(DataType.INT,  op.token.loc)]))
                ctx.ip += 1
                
            elif op.operand == Intrinsic.EQUAL:
                type_check_contract(op.token, ctx, Contract(ins=[(DataType.INT,  op.token.loc), (DataType.INT,  op.token.loc)], outs=[(DataType.BOOL,  op.token.loc)]))
                ctx.ip += 1

            elif op.operand == Intrinsic.NE:
                type_check_contract(op.token, ctx, Contract(ins=[(DataType.INT,  op.token.loc), (DataType.INT,  op.token.loc)], outs=[(DataType.BOOL,  op.token.loc)]))
                ctx.ip += 1
            elif op.operand == Intrinsic.GT:
                type_check_contract(op.token, ctx, Contract(ins=[(DataType.INT,  op.token.loc), (DataType.INT,  op.token.loc)], outs=[(DataType.BOOL,  op.token.loc)]))
                ctx.ip += 1
            elif op.operand == Intrinsic.LT:
                type_check_contract(op.token, ctx, Contract(ins=[(DataType.INT,  op.token.loc), (DataType.INT,  op.token.loc)], outs=[(DataType.BOOL,  op.token.loc)]))
                ctx.ip += 1

            elif op.operand == Intrinsic.GTE:
                type_check_contract(op.token, ctx, Contract(ins=[(DataType.INT,  op.token.loc), (DataType.INT,  op.token.loc)], outs=[(DataType.BOOL,  op.token.loc)]))
                ctx.ip += 1
            elif op.operand == Intrinsic.LTE:
                type_check_contract(op.token, ctx, Contract(ins=[(DataType.INT,  op.token.loc), (DataType.INT,  op.token.loc)], outs=[(DataType.BOOL,  op.token.loc)]))
                # ctx.stack.append((DataType.BOOL, op.token.loc))
                ctx.ip += 1

            elif op.operand == Intrinsic.DROP:
                if len(ctx.stack) < 1:
                    compiler_error(op.token.loc, f"Error: not enough arguments for {readable_enum(op.operand)} Intrinsic")
                ctx.stack.pop()
                ctx.ip += 1

            elif op.operand == Intrinsic.DUP:
                if len(ctx.stack) < 1:
                    compiler_error(op.token.loc, f"Error: not enough arguments for {readable_enum(op.operand)} Intrinsic")
                a_type, a_loc = ctx.stack.pop()
                ctx.stack.append((a_type, a_loc))
                ctx.stack.append((a_type, op.token.loc))
                ctx.ip += 1

            elif op.operand == Intrinsic.DUP2:
                if len(ctx.stack) < 2:
                    compiler_error(op.token.loc, f"Error: not enough arguments for {readable_enum(op.operand)} Intrinsic")
                a_type, a_loc  = ctx.stack.pop()
                b_type, b_loc = ctx.stack.pop()
                ctx.stack.append((b_type, b_loc))
                ctx.stack.append((a_type, a_loc))
                ctx.stack.append((b_type, op.token.loc))
                ctx.stack.append((a_type, op.token.loc))
                ctx.ip += 1
            elif op.operand == Intrinsic.OVER:
                if len(ctx.stack) < 2:
                     compiler_error(op.token.loc, f"Error: not enough arguments for {readable_enum(op.operand)} Intrinsic")
                a = ctx.stack.pop()
                b_type, b_loc = ctx.stack.pop()
                ctx.stack.append((b_type, b_loc))
                ctx.stack.append(a)
                ctx.stack.append((b_type, op.token.loc))
                ctx.ip += 1
            elif op.operand == Intrinsic.OVER2:
                if len(ctx.stack) < 3:
                    compiler_error(op.token.loc, f"Error: not enough arguments for {readable_enum(op.operand)} Intrinsic")
                a = ctx.stack.pop()
                b = ctx.stack.pop()
                c = ctx.stack.pop()
                ctx.stack.append(c)
                ctx.stack.append(b)
                ctx.stack.append(a)
                ctx.stack.append(c)
                ctx.ip += 1
            elif op.operand == Intrinsic.SWAP:
                if len(ctx.stack) < 2:
                    compiler_error(op.token.loc, f"Error: not enough arguments for {readable_enum(op.operand)} Intrinsic")
                a = ctx.stack.pop()
                b = ctx.stack.pop()
                ctx.stack.append(a)
                ctx.stack.append(b)
                ctx.ip += 1
            elif op.operand == Intrinsic.STORE:
                type_check_contract(op.token, ctx, Contract(ins=[(DataType.INT,  op.token.loc), (DataType.PTR,  op.token.loc)], outs=[]))
                ctx.ip += 1

            elif op.operand == Intrinsic.LOAD:
                type_check_contract(op.token, ctx, Contract(ins=[(DataType.PTR,  op.token.loc)], outs=[(DataType.INT,  op.token.loc)]))
                ctx.ip += 1

            elif op.operand == Intrinsic.STORE32:
                type_check_contract(op.token, ctx, Contract(ins=[(DataType.INT,  op.token.loc), (DataType.PTR,  op.token.loc)], outs=[]))
                ctx.ip += 1

            elif op.operand == Intrinsic.STOREINT:
                type_check_contract(op.token, ctx, Contract(ins=[(DataType.INT,  op.token.loc), (DataType.PTR,  op.token.loc)], outs=[]))
                ctx.ip += 1

            elif op.operand == Intrinsic.STOREPTR:
                type_check_contract(op.token, ctx, Contract(ins=[(DataType.PTR,  op.token.loc), (DataType.PTR,  op.token.loc)], outs=[]))
                ctx.ip += 1

            elif op.operand == Intrinsic.LOAD32:
                type_check_contract(op.token, ctx, Contract(ins=[(DataType.PTR,  op.token.loc)], outs=[(DataType.INT,  op.token.loc)]))
                ctx.ip += 1
            
            elif op.operand == Intrinsic.LOADINT:
                type_check_contract(op.token, ctx, Contract(ins=[(DataType.PTR,  op.token.loc)], outs=[(DataType.INT,  op.token.loc)]))
                ctx.ip += 1

            elif op.operand == Intrinsic.LOADPTR:
                type_check_contract(op.token, ctx, Contract(ins=[(DataType.PTR,  op.token.loc)], outs=[(DataType.PTR,  op.token.loc)]))
                ctx.ip += 1

            elif op.operand == Intrinsic.MEMCPY:
                type_check_contract(op.token, ctx, Contract(ins=[(DataType.INT, op.token.loc), (DataType.PTR , op.token.loc) , (DataType.PTR, op.token.loc)], outs=[]))
                ctx.ip += 1

            elif op.operand == Intrinsic.SHL:
                type_check_contract(op.token, ctx, Contract(ins=[(DataType.INT,  op.token.loc), (DataType.INT,  op.token.loc)], outs=[(DataType.INT,  op.token.loc)]))
                ctx.ip += 1

            elif op.operand == Intrinsic.SHR:
                type_check_contract(op.token, ctx, Contract(ins=[(DataType.INT,  op.token.loc), (DataType.INT,  op.token.loc)], outs=[(DataType.INT,  op.token.loc)]))
                ctx.ip += 1
            elif op.operand == Intrinsic.BAND:
                type_check_contract(op.token, ctx, Contract(ins=[(DataType.INT,  op.token.loc), (DataType.INT,  op.token.loc)], outs=[(DataType.INT,  op.token.loc)]))
                ctx.ip += 1

            elif op.operand == Intrinsic.BOR:
                type_check_contract(op.token, ctx, Contract(ins=[(DataType.INT,  op.token.loc), (DataType.INT,  op.token.loc)], outs=[(DataType.INT,  op.token.loc)]))
                ctx.ip += 1
                
            elif op.operand == Intrinsic.BXOR:
                type_check_contract(op.token, ctx, Contract(ins=[(DataType.INT,  op.token.loc), (DataType.INT,  op.token.loc)], outs=[(DataType.INT,  op.token.loc)]))
                ctx.ip += 1
            
            elif op.operand == Intrinsic.STRLEN:
                type_check_contract(op.token, ctx, Contract(ins=[(DataType.PTR,  op.token.loc)], outs=[(DataType.INT,  op.token.loc)]))
                ctx.ip += 1

        if breakpoint:
            operand = op.operand
            if isinstance(operand, Proc):
                operand = op.operand.name
            compiler_note(op.token.loc, f"{ctx.ip}: {readable_enum(op.type)} {operand}: {[ readable_enum(val[0]) for val in ctx.stack]}", exits=False)
            flags = input()

def type_check_context_outs(ctx: Context):
    while len(ctx.stack) > 0 and len(ctx.proc_outs) > 0:
        actual_typ, actual_loc = ctx.stack.pop()
        expected_typ, expected_loc = ctx.proc_outs.pop()
        if expected_typ != actual_typ:
            compiler_error(actual_loc, f"Unexpected type `{DATATYPE_NAMES[actual_typ]}` on the stack", exits=False)
            compiler_note(expected_loc, f"Expected type `{DATATYPE_NAMES[expected_typ]}`")

    if len(ctx.stack) > len(ctx.proc_outs):
        top_typ, top_loc = ctx.stack.pop()
        compiler_error(top_loc, f"Unhandled data on the stack:",exits=False)
        compiler_note(top_loc, f"type `{DATATYPE_NAMES[top_typ]}`",exits=False)
        while len(ctx.stack) > 0:
            typ, loc = ctx.stack.pop()
            compiler_note(loc, f"type `{DATATYPE_NAMES[typ]}`",exits=False)
        exit(1)
    elif len(ctx.stack) < len(ctx.proc_outs):
        top_typ, top_loc = ctx.proc_outs.pop()
        compiler_error(top_loc, f"Insufficient data on the stack. Expected:", exits=False)
        compiler_note(top_loc, f"type `{DATATYPE_NAMES[top_typ]}`", exits=False)
        while len(ctx.proc_outs) > 0:
            typ, loc = ctx.proc_outs.pop()
            compiler_note(loc, f"and type `{DATATYPE_NAMES[typ]}`", exits=False)
        exit(1)

#---------------------------- Contract Parsing ----------------------------

def parse_contract_list(rtokens: List[Token], stoppers: List[Keyword]) -> Tuple[List[Tuple[DataType, Loc]], Keyword]:
    args: List[Tuple[DataType, Loc]] = []
    while len(rtokens) > 0:
        token = rtokens.pop()
        if token.type == TokenType.WORD:
            assert isinstance(token.value, str)
            if token.value in DATATYPE_BY_NAME:
                args.append((DATATYPE_BY_NAME[token.value], token.loc))
            else:
                compiler_error(token.loc, f"Unknown data type {token.value}")
                exit(1)
        elif token.type == TokenType.KEYWORD:
            assert isinstance(token.value, Keyword)
            if token.value in stoppers:
                return (args, token.value)
            else:
                compiler_error(token.loc, f"Unexpected keyword {KEYWORD_NAMES[token.text]}")
                exit(1)
        else:
            compiler_error(token.loc, f"{readable_enum(token.type)} are not allowed in procedure definition.")
            exit(1)

    compiler_error(token.loc, f"Unexpected end of file. Expected keywords: ")
    for keyword in stoppers:
        compiler_note(token.loc, f"  {KEYWORD_NAMES[keyword]}")
    exit(1)

def parse_proc_contract(rtokens : List[Token]) -> Contract:
    contract = Contract(ins=[], outs=[])
    contract.ins, stopper = parse_contract_list(rtokens, [Keyword.DASHDASH, Keyword.IN])
    if stopper == Keyword.IN:
        return contract
    contract.outs, stopper = parse_contract_list(rtokens, [Keyword.IN])
    assert stopper == Keyword.IN
    return contract


def check_word_redefinition(token : Token, current_proc : Optional[Proc], program : Program, macros : List[Macro]):
    name = token.value

    if name in INTRINSIC_WORDS:
        compiler_error(token.loc, f"redefinition of a builtin word `{name}`")

    # for global variables
    if  current_proc is None and name in [ val.name for val in program.memories if val.space == "global"]:
        compiler_error(token.loc, f"redefinition of an memory keyword `{name}`")
    elif current_proc is not None:
        if name in [ val.name for val in program.memories if val.space == "global" or val.space == current_proc.name]:
            compiler_error(token.loc, f"redefinition of an memory keyword `{name}`")
        

    if name in [val.name for val in program.procs]:
        compiler_error(token.loc, f"redefinition of an existing proc keyword`{name}`")

    if name in program.consts:
        compiler_error(token.loc, f"redefinition of an existing proc keyword`{name}`")
        compiler_note(program.consts[token.value].loc, f"the first definition is located here")

    if name in macros:
        assert isinstance(token.value, str)
        compiler_error(token.loc, f"redefinition of an existing keyword of a macro `{name}`")
        compiler_note(macros[token.value].loc, f"the first definition is located here")


#---------------------------- Intermidate Represention ----------------------------

def compile_tokens_to_program(tokens : List[Token], includePaths : List[str]=[]) -> Tuple[Program, Dict[str, OpAddr]]:
    stack : List[OpAddr] = []
    program: Program = Program(ops=[], lp_variables=[], memory_capacity=0, procs=[])
    rtokens : List[Token] = list(reversed(tokens))
    macros: Dict[str, Macro] = {}
    current_proc : Optional[Proc] = None
    ip : OpAddr = 0
    while len(rtokens) > 0:
        token : Token = rtokens.pop()

        assert len(TokenType) == 6, "Exhaustive token handling in compile_tokens_to_program"
        if token.type == TokenType.WORD:
            assert isinstance(token.value, str), "This could be a bug in the lexer"
            if token.value in INTRINSIC_WORDS:
                op = Op(OpType.INTRINSIC, token, INTRINSIC_WORDS[token.value])
                program.ops.append(op)
                ip += 1

            elif token.value in program.lp_variables:
                bindIdx = len(program.lp_variables) - program.lp_variables.index(token.value)
                # print(program.lp_variables, bindIdx, program.lp_variables[-bindIdx])
                op = Op(OpType.PUSH_BIND, token, bindIdx)
                program.ops.append(op)
                ip += 1

            elif token.value in macros:
                mtkGen =  map(expandMacro, reversed(macros[token.value].tokens))
                mtk = list(mtkGen)

                if len(list(mtk)) == 0:
                    compiler_error(token.loc, "macro is empty")

                if len(list(mtk)) != 0:
                    rtokens += mtk

                    if EXPANSION_LIMIT < rtokens[-1].expanded:
                        compiler_error(token.loc, f"macro exansion limit of {EXPANSION_LIMIT} exceeded")
                    continue
            
            elif token.value in [val.name for val in program.memories]:
                space = "global"
                if current_proc is not None:
                    space = current_proc.name

                if  current_proc is None:
                    addr = [ val.addr for val in program.memories if val.space == "global" and val.name == token.value]
                else:
                    addr = [ val.addr for val in program.memories if val.space == "global" and val.name == token.value or val.space == current_proc.name and val.name == token.value]
                 
                op = Op(OpType.PUSH_MEM, token, addr[0])
                program.ops.append(op)
                ip += 1

            elif token.value in program.consts:
                op = Op(OpType.PUSH_INT, token, program.consts[token.value])
                # compiler_note(token.loc, f"This is the const push for {token.value}",exits=False)
                program.ops.append(op)
                ip += 1
            

            elif token.value in map(lambda x : x.name , program.procs):
                current_proc_found = list(filter(lambda x : x.name == token.value, program.procs))[0]
                program.ops.append(Op(OpType.CALL, token, current_proc_found))
                ip +=1
            else:
                # print(program.memories,[ tok.text for tok in rtokens])
                compiler_error(token.loc, f"unknown word `{token.text}`")
            

        elif token.type == TokenType.INT:
            assert isinstance(token.value, int), "This could be a bug in the lexer"
            op = Op(OpType.PUSH_INT, token, token.value)
            program.ops.append(op)
            ip += 1

        elif token.type == TokenType.STR:
            assert isinstance(token.value, str), "This could be a bug in the lexer"
            op = Op(OpType.PUSH_STR , token, token.value)
            program.ops.append(op)
            ip += 1

        elif token.type == TokenType.SYSPORT_CALL:
            assert isinstance(token.value, str), "This could be a bug in the lexer"
            if len(rtokens) < 1:
                compiler_error(token.loc, "No syscall arguments provided")
            
            noOfArgs = rtokens.pop()
            SYSPORT_USED.add(token.value)
            op = Op(OpType.SYSCALL , token, noOfArgs.value)
            program.ops.append(op)
            ip += 1

        elif token.type == TokenType.CHAR:
            assert isinstance(token.value, int), "This could be a bug in the lexer"
            op = Op(OpType.PUSH_INT, token, token.value)
            program.ops.append(op)
            ip += 1

        elif token.type == TokenType.KEYWORD:
            assert len(Keyword) == 17, "Exhaustive ops handling in compile_tokens_to_program. Only ops that form blocks must be handled"


            if token.value == Keyword.WHILE:
                op = Op(OpType.WHILE, token)
                program.ops.append(op)
                stack.append(ip)
                ip += 1

            elif token.value == Keyword.DO:

                program.ops.append(Op(type=OpType.DO, token=token))
                if len(stack) == 0:
                    compiler_error(token.loc, "`do` is not preceded by `while`")

                while_ip = stack.pop()
                if program.ops[while_ip].type != OpType.WHILE:
                    compiler_error(token.loc, "`do` is not preceded by `while`")

                program.ops[ip].operand = while_ip
                stack.append(ip)
                ip += 1

            elif token.value == Keyword.IF:
                program.ops.append(Op(type=OpType.IF, token=token))
                stack.append(ip)
                ip += 1

            elif token.value == Keyword.ELIF:
                if len(stack) == 0:
                    compiler_error(token.loc, '`elif` can only come after `else`')

                else_ip = stack[-1]
                if program.ops[else_ip].type != OpType.ELSE:
                    compiler_error(program.ops[else_ip].token.loc, '`elif` can only come after `else`')

                program.ops.append(Op(type=OpType.ELIF, token=token))
                stack.append(ip)
                ip += 1

            elif token.value == Keyword.ELSE:
                if len(stack) == 0:
                    compiler_error(token.loc, '`else` can only come after `if` or `elif`')
                    exit(1)

                if_ip = stack.pop()
                if program.ops[if_ip].type == OpType.IF:
                    program.ops[if_ip].operand = ip + 1
                    stack.append(ip)
                    program.ops.append(Op(type=OpType.ELSE, token=token))
                    ip += 1

                elif program.ops[if_ip].type == OpType.ELIF:
                    else_before_elif_ip = None if len(stack) == 0 else stack.pop()
                    assert else_before_elif_ip is not None and program.ops[else_before_elif_ip].type == OpType.ELSE, "At this point we should've already checked that `if*` comes after `else`. Otherwise this is a compiler bug."

                    program.ops[if_ip].operand = ip + 1
                    program.ops[else_before_elif_ip].operand = ip

                    stack.append(ip)
                    program.ops.append(Op(type=OpType.ELSE, token=token))
                    ip += 1
                else:
                    compiler_error(program.ops[if_ip].token.loc, f'`else` can only come after `if` or `elif`')


            elif token.value == Keyword.END:
                if len(stack) < 1:
                    compiler_error(token.loc, "No starting token for end")
                block_ip = stack.pop()

                if program.ops[block_ip].type == OpType.ELSE:
                    program.ops.append(Op(OpType.END, token))
                    program.ops[block_ip].operand = ip
                    program.ops[ip].operand = ip + 1
                
                elif program.ops[block_ip].type == OpType.IF:
                    program.ops.append(Op(OpType.END, token))
                    program.ops[ip].operand = ip + 1
                    program.ops[block_ip].operand = ip + 1
                
                elif program.ops[block_ip].type == OpType.DO:
                    program.ops.append(Op(OpType.END, token))
                    assert isinstance(program.ops[block_ip].operand, int)
                    while_ip = program.ops[block_ip].operand

                    assert isinstance(while_ip, OpAddr)
                    if program.ops[while_ip].type != OpType.WHILE:
                        compiler_error(program.ops[while_ip].token.loc, '`end` can only close `do` blocks that are preceded by `while`')

                    program.ops[ip].operand = while_ip
                    program.ops[block_ip].operand = ip + 1
                
                elif program.ops[block_ip].type == OpType.ELIF:
                    program.ops.append(Op(OpType.END, token))
                    else_before_elif_ip = None if len(stack) == 0 else stack.pop()
                    assert else_before_elif_ip is not None and program.ops[else_before_elif_ip].type == OpType.ELSE, "At this point we should've already checked that `if*` comes after `else`. Otherwise this is a compiler bug."
                    program.ops[block_ip].operand = ip
                    program.ops[else_before_elif_ip].operand = ip
                    program.ops[ip].operand = ip + 1

                elif program.ops[block_ip].type == OpType.SKIP_PROC:
                    program.ops.append(Op(OpType.RET, token, program.ops[block_ip].operand))
                    program.ops[block_ip].operand.ret_ip = ip + 1
                    current_proc = None
                    # assert False, "Not implemented"
                elif program.ops[block_ip].type == OpType.BIND:
                    program.ops.append(Op(OpType.UNBIND, token, program.ops[block_ip].operand))
                    program.lp_variables = program.lp_variables[:-program.ops[block_ip].operand]

                else:
                    compiler_error(program.ops[block_ip].token.loc, "`end` can only close `if`, `else`, `do`, `proc` or `macro` blocks for now")
                ip += 1

            #TODO: add show stack after break
            elif token.value == Keyword.BREAK:
                op = Op(OpType.BREAK, token)
                program.ops.append(op)
                ip += 1
            
            elif token.value == Keyword.TYPE_BREAK:
                op = Op(OpType.TYPE_BREAK, token)
                program.ops.append(op)
                ip += 1

            elif token.value == Keyword.SYSPORT:
                if len(rtokens) == 0:
                    compiler_error(token.loc, "No sysport functions given")
                
                sysport_call_funcs = set()

                func = rtokens.pop()
                while func.text != "from":
                    if func.type != TokenType.STR:
                        compiler_error(func.loc, "Expected sysport function name to be string token")
                    
                    sysport_call_funcs.add(func.text)

                    if len(rtokens) < 1:
                        compiler_error(func.loc, "Expected `from` for sysport dll library name")

                    func = rtokens.pop()
                
                if len(rtokens) == 0 :
                    compiler_error(func.loc, "No sysport dll library given")

                lib = rtokens.pop()
                if lib.type != TokenType.STR:
                    compiler_error(lib.loc, "Expected dll library name to be string token")
                
                if lib.text in SYSPORT_FUNCS:
                    SYSPORT_FUNCS[lib.text].update(sysport_call_funcs)
                else:
                    SYSPORT_FUNCS[lib.text] = sysport_call_funcs

            elif token.value == Keyword.INCLUDE:
                if len(rtokens) == 0:
                    compiler_error(token.loc, "expected include path but found nothing")

                token = rtokens.pop()
                if token.type != TokenType.STR:
                    compiler_error(token.loc, f"expected include path to be {readable_enum(TokenType.STR)} but found {readable_enum(token.type)}")

                fileIncluded = False
                for p in includePaths:
                    try:
                        assert isinstance(token.value, str)
                        rtokens += reversed(lex_file(path.join(p, token.value)))
                        # print([token.text for token in list(lex_file(path.join(p, token.value)))])
                        fileIncluded = True
                        break
                    except FileNotFoundError:
                        continue
                
                if not fileIncluded:
                    compiler_error(token.loc, f"`{token.value}` file not found")            

            elif token.value == Keyword.MEMORY:
                if len(rtokens) == 0:
                    compiler_error(token.loc, f"expected memory name but found nothing")
                
                token = rtokens.pop()
                if token.type != TokenType.WORD:
                    compiler_error(token.loc, f"expected memory name to be {readable_enum(TokenType.WORD)} but found {readable_enum(token.type)}")
                
                check_word_redefinition(token, current_proc, program, macros)

                assert isinstance(token.value, str)
                memory_name : str = token.value
                

                mem_size, program.offset_value = evaluate_constant_from_tokens(rtokens, program.consts, program.offset_value)

                space = "global"
                if current_proc is not None:
                    space = current_proc.name

                program.memories.append( MemData(memory_name, program.memory_capacity, space) )
                program.memory_capacity += mem_size

            elif token.value == Keyword.CONST:
                if len(rtokens) == 0:
                    compiler_error(token.loc, f"expected constant's name but found nothing")
                
                token = rtokens.pop()
                if token.type != TokenType.WORD:
                    compiler_error(token.loc, f"expected constant's name to be {readable_enum(TokenType.WORD)} but found {readable_enum(token.type)}")

                check_word_redefinition(token, current_proc, program, macros)

                const_name = token.value
                
                const_value, program.offset_value = evaluate_constant_from_tokens(rtokens, program.consts, program.offset_value)
                program.consts[const_name] = const_value            
            
            elif token.value == Keyword.LET:
                loc = token.loc
                if len(rtokens) == 0:
                    compiler_error(token.loc, f"expected indentifer's name but found nothing")

                rtokens, lp_identifiers = read_till_breaker(rtokens, "in", token.loc)
                for val in lp_identifiers:
                    check_word_redefinition(Token(TokenType.WORD, val, loc, val), current_proc, program, macros)
                
                program.lp_variables += lp_identifiers[::-1]
                op = Op(type=OpType.BIND, token=token, operand=len(lp_identifiers))
                program.ops.append(op)
                stack.append(ip)
                ip += 1

            elif token.value == Keyword.PROC:
                if current_proc is None:
                    if len(rtokens) == 0:
                        compiler_error(token.loc, "expected procedure name but found nothing")
                    token = rtokens.pop()

                    if token.type != TokenType.WORD:
                        compiler_error(token.loc, f"expected procedure name to be a word but found {readable_enum(token.type)}")
                    
                    check_word_redefinition(token, current_proc, program, macros)

                    proc_name = token.value

                    contract = parse_proc_contract(rtokens)
                    proc = Proc(proc_name, ip + 1, contract, {})
                    program.procs.append(proc)
                    current_proc = proc
                    op = Op(type=OpType.SKIP_PROC, token=token, operand=proc)
                    program.ops.append(op)
                    stack.append(ip)
                    ip += 1

                else:
                    compiler_error(token.loc, "defining procedures in a procedure is not allowed", exits=False)
                    compiler_note(program.ops[current_proc.ip].token.loc, "the current_proc starts here")

            elif token.value == Keyword.MACRO:
                if len(rtokens) == 0:
                    sys.exit("%s:%d:%d: ERROR: expected macro name but found nothing" % token.loc)
                token = rtokens.pop()

                if token.type != TokenType.WORD:
                    sys.exit("%s:%d:%d: ERROR: expected macro name to be %s but found %s" % (token.loc + (readable_enum(TokenType.WORD), readable_enum(token.type))))

                check_word_redefinition(token, current_proc, program, macros)

                macro = Macro(token.loc, [])
                macros[token.value] = macro

                nestAmt = 0
                while len(rtokens) > 0:
                    token = rtokens.pop()
                    assert len(Keyword) == 18, f"Exaustive handling of keywords with `end` in compile_tokens_to_program for end type starters like Keyword.IF, Keyword.DO {len(Keyword)}"
                    if token.type == TokenType.KEYWORD and token.value in [Keyword.IF, Keyword.WHILE, Keyword.PROC, Keyword.MEMORY, Keyword.CONST, Keyword.MACRO, Keyword.LET]:
                        nestAmt += 1

                    macro.tokens.append(token)

                    if token.type == TokenType.KEYWORD and token.value == Keyword.END:
                        if nestAmt == 0:
                            break
                        elif nestAmt > 0:
                            nestAmt -= 1
                        else:
                            sys.exit(f"Error: nest amt is below zero {nestAmt}")

                if token.type != TokenType.KEYWORD or token.value != Keyword.END:
                    sys.exit("%s:%d:%d: ERROR: expected `end` at the end of the macro definition of `%s`" % (token.loc + (token.value, )))
                else:
                    macro.tokens = macro.tokens[:-1]

            elif token.value in [Keyword.IN, Keyword.DASHDASH]:
                compiler_error(token.loc, f"unexpected keyword {token.value}")

            else:
                assert False, 'unreachable'
        else:
            assert False, 'unreachable'

    if len(stack) > 0:
        opIdx = stack.pop()
        sys.exit('%s:%d:%d: ERROR: unclosed block `%s`' % (program.ops[opIdx].token.loc + (readable_enum(program.ops[opIdx].type),)))
    return program

def load_program(file_path : str ,includePaths : List[str]=[]) -> Program:
    tokens = lex_file(file_path)
    program : Program  = compile_tokens_to_program(tokens, includePaths)
    return program


def compile_program_fasm64(program : Program, outFilePath : str) -> None:
    content : Dict[str:str] = {"main" : "", "procs" : "", "strs" : ""}
    current_proc = ""
    writer : str = "main"
    no_of_strs : int = 0
    call_reg_order = ["rcx", "rdx", "r8", "r9"]

    for i, op in enumerate(program.ops):
        content[writer] += f";----{readable_enum(op.type)}: {readable_enum(op.operand)}\n"
        content[writer] += f"addr_{i}:\n"
        # assert len(OpType) == 20, f"Exhaustive handling of operations whilst compiling {len(OpType)}"
        if op.type == OpType.PUSH_INT:
            valToPush = op.operand
            content[writer] += f"mov rax, {valToPush}\n"
            content[writer] += f"push rax\n"

        elif op.type == OpType.PUSH_STR:
            no_of_strs += 1
            valToPush = op.operand
            assert isinstance(valToPush, str)
            content[writer] += f"lea rdi, [str_{no_of_strs}]\n"
            # content[writer] += f"      push {len(valToPush)}\n"
            content[writer] += f"push rdi\n"
            str_as_nums = ", ".join(map(str,list(bytes(valToPush, "utf-8"))))
            content["strs"] += f"str_{no_of_strs} db {str_as_nums}, 0 \n"
        
        elif op.type == OpType.PUSH_MEM:
            content[writer] += f";-- push mem {op.token.value}--\n"
            content[writer] += f"lea  rdi, [mem]\n"
            content[writer] += f"add  rdi, {op.operand}\n"
            content[writer] += f"push rdi\n"

        elif op.type in [OpType.IF, OpType.ELIF]:
            jmp_idx = op.operand
            content[writer] += f"pop rax\n"
            content[writer] += f"cmp rax, 1\n"
            content[writer] += f"jne addr_{jmp_idx}\n"

        elif op.type == OpType.ELSE:
            if not op.operand:
                compiler_error(op.token.loc, "`else` can only be used when an `end` is mentioned" )
            jmpArg = op.operand
            content[writer] += f"jmp addr_{jmpArg}\n"
        
        elif op.type == OpType.WHILE:
            content[writer] += f"; -- while --\n"

        elif op.type == OpType.DO:
            if not op.operand:
                compiler_error(op.token.loc, " ERROR: `do` can only be used when an `end` is mentioned")
            jmp_idx = op.operand
            content[writer] += f"pop rax\n"
            content[writer] += f"cmp rax, 1\n"
            content[writer] += f"jne addr_{jmp_idx}\n"
            
        elif op.type == OpType.END:
            assert isinstance(op.operand, int)
            jmp_idx = op.operand
            if jmp_idx:
                content[writer] += f"jmp addr_{jmp_idx}\n"

        # # TODO: proc break if any values left on stack
        elif op.type == OpType.SKIP_PROC:
            content[writer] += f";-- skip proc --\n"
            writer = "procs"
            current_proc = op.token.value
            content[writer] += f"\n{current_proc}:\n"

            
            for i in range(len(op.operand.contract.ins)-1,-1,-1):
                content[writer] += f"push {call_reg_order[i]}\n"
                content[writer] += f"xor {call_reg_order[i]}, {call_reg_order[i]}\n"


        elif op.type == OpType.RET:
            for i in range(len(op.operand.contract.outs)-1,-1,-1):
                content[writer] += f"pop {call_reg_order[i]}\n"
            
            content[writer] += f"ret\n"
            writer = "main"
        
        elif op.type == OpType.CALL:
            for i in range(len(op.operand.contract.ins)):
                content[writer] += f"pop {call_reg_order[i]}\n"
            content[writer] += f"call {op.token.value}\n"
            for i in range(len(op.operand.contract.outs)):
                content[writer] += f"push {call_reg_order[i]}\n"
                content[writer] += f"xor {call_reg_order[i]}, {call_reg_order[i]}\n"

        elif op.type == OpType.SYSCALL:
            no_of_args = op.operand

            if no_of_args <= 4:
                regargs = no_of_args
                stackargs = 0
            else:
                regargs = 4
                stackargs = no_of_args - 4

            for i in range(regargs):
                content[writer] += f"pop {call_reg_order[i]}\n"
            
            for i in range(stackargs):
                content[writer] += f"pop rax\n"
                content[writer] += f"mov [arg_{i}], rax\n"

            content[writer] += f"sub rsp, 32\n"

            for i in range(stackargs-1, -1, -1):
                content[writer] += f"mov rax, [arg_{i}]\n"
                content[writer] += f"push rax\n"

            syscall_name = op.token.value
            content[writer] += f"call [{syscall_name}]\n"
            content[writer] += f"add rsp, {no_of_args}*8\n"
            content[writer] += f"push rax\n"

        elif op.type == OpType.PUSH_BIND:
            # assert False, "Not Implemented"
            bind_offset : int = op.operand
            content[writer] += f"lea  rdi, [bindStack]\n"
            content[writer] += f"add  rdi, [bindPtr]\n"
            content[writer] += f"sub  rdi, {bind_offset*8}\n"
            content[writer] += f"mov  rax, [rdi]\n"
            content[writer] += f"push rax\n"

        elif op.type == OpType.BIND:
            vals_to_bind : int = op.operand
            content[writer] += f"lea rdi, [bindStack]\n"
            content[writer] += f"add rdi, [bindPtr]\n"
            for i in range(vals_to_bind):
                # content[writer] += f"add bindPtr, {vals_to_bind} eax\n"
                content[writer] += f"pop rax\n"
                content[writer] += f"mov [rdi], rax\n"# stores stack val in bindstack
                content[writer] += f"add rdi, 8\n"
            content[writer] += f"add [bindPtr], {vals_to_bind*8}\n"


        elif op.type == OpType.UNBIND:
            vals_to_bind : int = op.operand
            content[writer] += f"mov rax, 0\n"
            content[writer] += f"lea rdi, [bindStack]\n"
            content[writer] += f"add rdi, [bindPtr]\n"
            for i in range(vals_to_bind):
                content[writer] += f"sub  rdi, 8\n"
                content[writer] += f"mov  [rdi], rax\n"# stores stack val in bindstack
            content[writer] += f"sub [bindPtr], {vals_to_bind*8}\n"



        # elif op.type == OpType.SYSVAL:
        #     sysval = op.operand
        #     content[writer] += f"; -- sysval {sysval} --\n"
        #     content[writer] += f"push {sysval}\n"

        elif op.type == OpType.BREAK:
            pass

        elif op.type == OpType.TYPE_BREAK:
            pass

        elif op.type == OpType.INTRINSIC:
            assert len(Intrinsic) == 40, f"Exhaustive handling of Intrinsics in compile fasm64 {len(Intrinsic)}"
            if op.operand == Intrinsic.DUMP:
                content[writer] += f"pop    rax\n"
                content[writer] += f"call   dump\n"

            elif op.operand == Intrinsic.STDOUT:
                content[writer] += f"pop     rbx\n"
                content[writer] += f"mov     r9d,   0\n"
                content[writer] += f"lea     rdi,   [rbx]\n"
                content[writer] += f"call    strlen\n"
                content[writer] += f"mov     r8,    rax\n"
                content[writer] += f"lea     rdx,   [rdi]\n"
                content[writer] += f"mov     rcx, [std_handle]\n"
                content[writer] += f"call    [WriteConsoleA]\n"
            
            elif op.operand in [Intrinsic.CAST_INT, Intrinsic.CAST_BOOL, Intrinsic.CAST_PTR]:
                pass

            elif op.operand == Intrinsic.EXIT:
                content[writer] += f"mov     ecx,eax\n"
                content[writer] += f"call    [ExitProcess]\n"

            elif op.operand == Intrinsic.DROP:
                content[writer] += "pop rax\n"

            elif op.operand == Intrinsic.TRUE:
                content[writer] += "push 1\n"

            elif op.operand == Intrinsic.FALSE:
                content[writer] += "push 0\n"

            elif op.operand == Intrinsic.ADD or op.operand == Intrinsic.PTR_ADD:
                content[writer] += "pop   rax\n"
                content[writer] += "pop   rbx\n"
                content[writer] += "add   rax,    rbx\n"
                content[writer] += "push  rax\n"


            elif op.operand == Intrinsic.SUB:
                content[writer] += "pop   rbx\n"
                content[writer] += "pop   rax\n"
                content[writer] += "sub   rax,   rbx\n"
                content[writer] += "push  rax\n"

            elif op.operand == Intrinsic.DIVMOD:
                # 10 50 -> 50/10
                content[writer] += "xor   rdx, rdx\n"
                content[writer] += "pop   rbx\n"
                content[writer] += "pop   rax\n"
                content[writer] += "div   rbx\n"
                content[writer] += "push  rax\n"
                content[writer] += "push  rdx\n"
                
            elif op.operand == Intrinsic.MUL:
                content[writer] += "pop  rax\n"
                content[writer] += "pop  rbx\n"
                content[writer] += "mul  rbx\n"
                content[writer] += "push rax\n"

            elif op.operand == Intrinsic.EQUAL:
                content[writer] += f"pop rax\n"
                content[writer] += f"pop rbx\n"
                content[writer] += f"cmp rax, rbx\n"
                content[writer] += f"jne ZERO{i}\n"
                content[writer] += f"push 1\n"
                content[writer] += f"jmp END{i}\n"
                content[writer] += f"ZERO{i}:\n"
                content[writer] += f"push 0\n"
                content[writer] += f"END{i}:\n"
                            
            elif op.operand == Intrinsic.NE:
                content[writer] += f"pop rax\n"
                content[writer] += f"pop rbx\n"
                content[writer] += f"cmp rax, rbx\n"
                content[writer] += f"je ZERO{i}\n"
                content[writer] += f"push 1\n"
                content[writer] += f"jmp END{i}\n"
                content[writer] += f"ZERO{i}:\n"
                content[writer] += f"push 0\n"
                content[writer] += f"END{i}:\n"


            elif op.operand == Intrinsic.GT:
                content[writer] += f"pop rax\n"
                content[writer] += f"pop rbx\n"
                content[writer] += f"cmp rax, rbx\n"
                content[writer] += f"jge ZERO{i}\n"
                content[writer] += f"push 1\n"
                content[writer] += f"jmp END{i}\n"
                content[writer] += f"ZERO{i}:\n"
                content[writer] += f"push 0\n"
                content[writer] += f"END{i}:\n"

            elif op.operand == Intrinsic.LT:
                content[writer] += f"; -- less than --\n"
                content[writer] += f"pop rax\n"
                content[writer] += f"pop rbx\n"
                content[writer] += f"cmp rax, rbx\n"
                content[writer] += f"jle ZERO{i}\n"
                content[writer] += f"push 1\n"
                content[writer] += f"jmp END{i}\n"
                content[writer] += f"ZERO{i}:\n"
                content[writer] += f"push 0\n"
                content[writer] += f"END{i}:\n"
            
            elif op.operand == Intrinsic.GTE:
                content[writer] += f"pop rax\n"
                content[writer] += f"pop rbx\n"
                content[writer] += f"cmp rax, rbx\n"
                content[writer] += f"jg ZERO{i}\n"
                content[writer] += f"push 1\n"
                content[writer] += f"jmp END{i}\n"
                content[writer] += f"ZERO{i}:\n"
                content[writer] += f"push 0\n"
                content[writer] += f"END{i}:\n"

            elif op.operand == Intrinsic.LTE:
                content[writer] += f"pop rbx\n"
                content[writer] += f"pop rax\n"
                content[writer] += f"cmp rax, rbx\n"
                content[writer] += f"jg ZERO{i}\n"
                content[writer] += f"push 1\n"
                content[writer] += f"jmp END{i}\n"
                content[writer] += f"ZERO{i}:\n"
                content[writer] += f"push 0\n"
                content[writer] += f"END{i}:\n"

            elif op.operand == Intrinsic.DUP:
                content[writer] += "pop   rax\n"
                content[writer] += "push  rax\n"
                content[writer] += "push  rax\n"

            elif op.operand == Intrinsic.DUP2:
                content[writer] += "pop   rax\n"
                content[writer] += "pop   rbx\n"
                content[writer] += "push  rbx\n"
                content[writer] += "push  rax\n"
                content[writer] += "push  rbx\n"
                content[writer] += "push  rax\n"

            elif op.operand == Intrinsic.OVER:
                content[writer] += "pop   rax\n"
                content[writer] += "pop   rbx\n"
                content[writer] += "push  rbx\n"
                content[writer] += "push  rax\n"
                content[writer] += "push  rbx\n"

            elif op.operand == Intrinsic.OVER2:
                content[writer] += "pop   rax\n"
                content[writer] += "pop   rbx\n"
                content[writer] += "pop   rcx\n"
                content[writer] += "push  rcx\n"
                content[writer] += "push  rbx\n"
                content[writer] += "push  rax\n"
                content[writer] += "push  rcx\n"

            elif op.operand == Intrinsic.SWAP:
                content[writer] += "pop  rax\n"
                content[writer] += "pop  rbx\n"
                content[writer] += "push rax\n"
                content[writer] += "push rbx\n"

            elif op.operand == Intrinsic.LOAD:
                content[writer] += "pop   rax\n"
                content[writer] += "xor   rbx, rbx\n"
                content[writer] += "mov   bl, [rax]\n"
                content[writer] += "push  rbx\n"
        
            elif op.operand == Intrinsic.LOADINT or op.operand == Intrinsic.LOADPTR:
                content[writer] += "pop   rax\n"
                content[writer] += "mov   rbx, [rax]\n"
                content[writer] += "push  rbx\n"

            elif op.operand == Intrinsic.LOAD32:
                content[writer] += "pop   rax\n"
                content[writer] += "xor   rbx, rbx\n"
                content[writer] += "mov   ebx, [rax]\n"
                content[writer] += "push  rbx\n"

            elif op.operand == Intrinsic.STORE:
                content[writer] += "pop  rax\n"#ptr
                content[writer] += "pop  rbx\n"#int
                content[writer] += "mov  byte [rax], bl\n"

            elif op.operand == Intrinsic.STOREINT or op.operand == Intrinsic.STOREPTR:
                content[writer] += ";-- store32 --\n"
                content[writer] += "pop  rax\n"#ptr
                content[writer] += "pop  rbx\n"#int
                content[writer] += "mov  [rax], rbx\n"
            
            if op.operand == Intrinsic.STORE32:
                content[writer] += "pop  rax\n"#ptr
                content[writer] += "pop  rbx\n"#int
                content[writer] += "mov  dword [rax], ebx\n"

            # # size from to
            if op.operand == Intrinsic.MEMCPY:
                content[writer] += "cld\n"
                content[writer] += "pop rdi\n"
                content[writer] += "pop rsi\n"
                content[writer] += "pop rax\n"
                content[writer] += "mov rcx, rax\n"
                content[writer] += "rep movsb\n"


            if op.operand == Intrinsic.SHL:
                content[writer] += "pop rcx\n"
                content[writer] += "pop rbx\n"
                content[writer] += "shl rbx, cl\n"
                content[writer] += "push rbx\n"


            if op.operand == Intrinsic.SHR:
                content[writer] += "pop rcx\n"
                content[writer] += "pop rbx\n"
                content[writer] += "shr rbx, cl\n"
                content[writer] += "push rbx\n"

            if op.operand == Intrinsic.BOR:
                content[writer] += "pop   rax\n"
                content[writer] += "pop   rbx\n"
                content[writer] += "or    rbx, rax\n"
                content[writer] += "push  rbx\n"

            if op.operand == Intrinsic.BAND:
                content[writer] += "pop   rax\n"
                content[writer] += "pop   rbx\n"
                content[writer] += "and   rbx, rax\n"
                content[writer] += "push  rbx\n"

            if op.operand == Intrinsic.BXOR:
                content[writer] += "pop   rax\n"
                content[writer] += "pop   rbx\n"
                content[writer] += "xor   rbx, rax\n"
                content[writer] += "push  rbx\n"
            if op.operand == Intrinsic.STRLEN:
                content[writer] += "pop   rax\n"
                content[writer] += "lea   rdi, [rax]\n"
                content[writer] += "call  strlen\n"
                content[writer] += "sub   rax, 1\n"
                content[writer] += "push  rax\n"
        else:
            compiler_note(op.token.loc, f"{op.token.text} is not implemented",exits=False)
    content[writer] += f"addr_{len(program.ops)}:\n"

    with open(outFilePath,"w+") as wf:
        wf.write("format PE64 console\n")

        wf.write("macro import_directory_table [lib] {\n")
        wf.write("        ; for each lib, define an IDT entry\n")
        wf.write("        forward\n")
        wf.write("                ; note that IAT and ILT are the same.\n")
        wf.write("                ; IAT is defined using the import_functions macro.\n")
        wf.write("                dd rva IAT__#lib\n")
        wf.write("                dd 0\n")
        wf.write("                dd 0\n")
        wf.write("                dd rva NAME__#lib  ; ptr into the library name table.\n")
        wf.write("                dd rva IAT__#lib\n")

        wf.write("        ; terminate IDT with an all-zero entry.\n")
        wf.write("        common\n")
        wf.write("                dd 5 dup(0)      \n")

        wf.write("        ; table of library name strings.\n")
        wf.write("        forward\n")
        wf.write("                NAME__#lib db `lib, \".DLL\", 0  \n")
        wf.write("}\n")

        wf.write("macro import_functions libname, [funcnames] {\n")
        wf.write("        ; define the hint/name table\n")
        wf.write("        forward\n")
        wf.write("        ; ensure entries are aligned on even address.\n")
        wf.write("        if $ & 1\n")
        wf.write("                db 0\n")
        wf.write("        end if\n")
        wf.write("        IMPORTNAME__#funcnames dw 0\n")
        wf.write("                                db `funcnames, 0\n")
        wf.write("        ; IAT definition\n")
        wf.write("        common\n")
        wf.write("                IAT__#libname:\n")
        wf.write("        ; each entry is a ptr into the previously defined hint/name table.\n")
        wf.write("        ; entries shall be overwritten by actual function addresses at runtime.\n")
        wf.write("        forward\n")
        wf.write("                funcnames dq rva IMPORTNAME__#funcnames\n")

        wf.write("        ; terminate the IAT with a null entry.\n")
        wf.write("        common\n")
        wf.write("                dq 0\n")
        wf.write("}\n")
        wf.write("\nentry start\n")
        wf.write("STD_OUTPUT_HANDLE=-11\n")
        wf.write("section '.text' code readable executable\n")

        wf.write("\n\nstart:\n")
        wf.write("sub     rsp,8*5         ; reserve stack for API use and make stack dqword aligned\n")
        wf.write("mov     rcx, STD_OUTPUT_HANDLE\n")
        wf.write("call    [GetStdHandle]\n")
        wf.write("mov     [std_handle], rax\n")

        wf.write(content["main"])

        wf.write("mov     ecx,eax\n")
        wf.write("call    [ExitProcess]\n")

        wf.write(content["procs"])

        wf.write("\ndump:\n")
        wf.write("mov     rbx, 10         ; divsor for div command\n")
        wf.write("push 10\n")
        wf.write("dump_loop:\n")
        wf.write("xor     rdx, rdx\n")

        wf.write("idiv    rbx             ; rax/rbx -> rax/10 \n")
        wf.write("add     rdx, 48         ; get ascii\n")

        wf.write("mov     [dump_char], dl\n")

        wf.write("mov     dl, [dump_char]\n")
        wf.write("push rdx\n")

        wf.write("cmp     rax, 0\n")
        wf.write("jne     dump_loop\n")

        wf.write("\nprint_loop:\n")
        wf.write("pop rax\n")
        wf.write("mov     [dump_char], al\n")

        wf.write("mov     r9d, 0\n")
        wf.write("mov     r8, 1\n")
        wf.write("lea     rdx,[dump_char]\n")
        wf.write("mov     rcx, [std_handle]\n")
        wf.write("call    [WriteConsoleA]\n")

        wf.write("mov     al, [dump_char]\n")

        wf.write("cmp     rax, 10\n")
        wf.write("jne     print_loop\n")

        wf.write("ret\n")

        wf.write("\nstrlen:\n")
        wf.write("push rdi\n")
        wf.write("push rcx\n")
        wf.write("sub  rcx, rcx\n")
        wf.write("mov rcx, -1\n")
        wf.write("sub al, al\n")
        wf.write("cld\n")
        wf.write("repne scasb\n")
        wf.write("neg rcx\n")
        wf.write("sub rcx, 1\n")
        wf.write("mov rax, rcx\n")
        wf.write("pop rcx\n")
        wf.write("pop rdi\n")
        wf.write("ret\n")


        wf.write("\nsection '.data' data readable writeable\n")

        wf.write(";   _caption db 'Win64 assembly program',0\n")
        wf.write(f"  mem rb {program.memory_capacity}\n")
        wf.write("  dump_char rb 1\n")
        wf.write("  bindStack rb 80\n")
        wf.write("  bindPtr rq 80\n")
        wf.write("  std_handle rq 1\n")
        for i in range(8):
            wf.write(f"  arg_{i} rq 1\n")
        wf.write(content["strs"]) 

        wf.write("section '.idata' import data readable writeable\n")

        for lib, funcs in SYSPORT_FUNCS.items():
            if len(SYSPORT_USED) != 0:
                wf.write(f"  import_directory_table {lib}\n")
                wf.write(f"  import_functions {lib}")
                for func in funcs:
                    if func in SYSPORT_USED:
                        wf.write(f", {func}")

            wf.write("\n")


def usage(program_token):
    print("Usage: %s [OPTIONS] <SUBCOMMAND> [ARGS]" % program_token)
    print("OPTIONS:")
    print("   -I <path>             Add the path to the include search list")
    print("   -u                    unsafe mode for no typechecking")
    print("SUBCOMMAND:")
    print("   com <file>  Compile the program")
    print(    "OPTIONS:")
    print("        -r                  Run the program after successful compilation")
    print("        -o <file|dir>       Customize the output path")
    print("        -ob                 Set output path to `./build`")

def callCmd(cmd):
    cmdStr = " ".join(cmd)
    print(f"[CMD] {cmdStr}")
    subprocess.call(cmd)


def main():
    argv : List[str] = sys.argv
    compilerPath, *argv = argv
    if len(sys.argv) < 2:
        usage(sys.argv[0])
        sys.exit("\n[ERROR] No subcommand Given")

    includePaths = [".", "./std/"]
    timed = False
    unsafe = False

    while len(argv) > 0:
        if argv[0] == "-I":
            argv = argv[1:]
            if len(argv) == 0:
                usage(compilerPath)
                sys.exit("[ERROR] no path is provided for `-I` flag", file=sys.stderr)

            includePath, *argv = argv
            includePaths.append(includePath)
        if argv[0] == "-t":
            timed = True
            argv = argv[1:]
        if argv[0] == "--unsafe" or argv[0] == "-u":
            unsafe = True
            argv = argv[1:]
        else:
            break
    
    if len(argv) < 1:
        usage(compilerPath)
        sys.exit("[ERROR] no subcommand is provided", file=sys.stderr)
    subcommand, *argv = argv 

    programPath = None

    if subcommand == "com":
        run = False
        outputPath = None
        while len(argv) > 0:
            arg, *argv = argv
            if arg == "-r":
                run = True
            elif arg == "-o":
                if len(argv) == 0:
                    usage(compilerPath)
                    sys.exit("[ERROR] no argument is provided for parameter -o", file=sys.stderr)
                outputPath, *argv = argv
            elif arg == "-ob":
                outputPath = "./build/"
            else:
                programPath = arg
                break
        if programPath == None:
            usage(compilerPath)
            sys.exit("[ERROR] no input file is provided for the compilation", file=sys.stderr)
        
        if outputPath == None:
            baseDir = getcwd()
            programFile = path.basename(programPath)
            programName = programFile.replace(".porth","")
            basePath = path.join(baseDir,programName)
        else:
            baseDir = outputPath
            if path.isdir(baseDir):
                programFile = path.basename(programPath)
                programName = programFile.replace(".porth","")
                basePath = path.join(baseDir,programName)
            else:
                usage(compilerPath)
                print(f"[ERROR] Invalid Path {baseDir} entered")
                exit(1)
        if timed:
            start = time.time()
        program = load_program(programPath, includePaths)
        print("[INFO] loaded program")
        if not unsafe:
            type_check_program(program)

        compile_program_fasm64(program, f"{basePath}.asm")
        print(f"[INFO] Generated {basePath}.asm")
        callCmd(["fasm", f"{basePath}.asm"])


        if timed:
            print(f"[TIME] Compile Time: {round(time.time() - start, 5)} secs")
            start = time.time()
        if run:
            callCmd([f"{basePath}.exe",*argv])
            if timed:
                print(f"[TIME] Run Time: {round(time.time() - start, 5)} secs")
    elif subcommand == "-h" or subcommand == "--help":
        usage(compilerPath)
    else:
        sys.exit(f"Error: Invalid subcommand provided `{subcommand}`. use flag -h")
    

if __name__ == "__main__":
    main()