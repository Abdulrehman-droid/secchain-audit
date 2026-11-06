"""
Bytecode Analyzer & Intermediate Representation (IR) Engine.
Parses class definitions, method bodies, opcodes, and constructs Basic Blocks for program analysis.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Any
import ast
import json
import re


@dataclass
class Instruction:
    index: int
    opcode: str               # INVOKE, ASSIGN, BRANCH, RETURN, FIELD_LOAD, FIELD_STORE, CONST
    target: Optional[str]     # Destination variable or register
    operands: List[str] = field(default_factory=list)
    method_signature: Optional[str] = None   # e.g. "TelephonyManager.getDeviceId"
    field_name: Optional[str] = None         # e.g. "consentGiven"
    constant_value: Any = None
    line_number: int = 0
    raw: str = ""

    def is_invoke(self) -> bool:
        return self.opcode.startswith("INVOKE")

    def is_branch(self) -> bool:
        return self.opcode in ("BRANCH", "IF_EQ", "IF_NE", "IF_TRUE", "IF_FALSE", "GOTO")


@dataclass
class BasicBlockIR:
    id: int
    instructions: List[Instruction] = field(default_factory=list)
    predecessors: List[int] = field(default_factory=list)
    successors: List[int] = field(default_factory=list)

    @property
    def entry_instruction(self) -> Optional[Instruction]:
        return self.instructions[0] if self.instructions else None

    @property
    def exit_instruction(self) -> Optional[Instruction]:
        return self.instructions[-1] if self.instructions else None


@dataclass
class MethodIR:
    class_name: str
    name: str
    signature: str = ""
    parameters: List[str] = field(default_factory=list)
    return_type: str = "void"
    is_static: bool = False
    is_constructor: bool = False
    instructions: List[Instruction] = field(default_factory=list)
    basic_blocks: List[BasicBlockIR] = field(default_factory=list)

    @property
    def full_name(self) -> str:
        return f"{self.class_name}.{self.name}"

    def get_invocations(self) -> List[Instruction]:
        return [inst for inst in self.instructions if inst.is_invoke()]


@dataclass
class ClassIR:
    name: str
    package: str
    super_class: str = "java.lang.Object"
    interfaces: List[str] = field(default_factory=list)
    fields: Dict[str, str] = field(default_factory=dict)  # field_name -> type
    methods: Dict[str, MethodIR] = field(default_factory=dict)

    def get_method(self, name: str) -> Optional[MethodIR]:
        return self.methods.get(name)


class BytecodeAnalyzer:
    """Disassembles and models class methods and instruction streams into IR."""

    @classmethod
    def from_json(cls, json_str: str) -> Dict[str, ClassIR]:
        """Parses structured JSON bytecode representation."""
        data = json.loads(json_str)
        classes: Dict[str, ClassIR] = {}

        for class_data in data.get("classes", []):
            c_name = class_data.get("name", "UnknownClass")
            pkg = class_data.get("package", "default.pkg")
            c_ir = ClassIR(
                name=c_name,
                package=pkg,
                super_class=class_data.get("super_class", "java.lang.Object"),
                interfaces=class_data.get("interfaces", []),
                fields=class_data.get("fields", {}),
            )

            for m_data in class_data.get("methods", []):
                m_name = m_data.get("name", "unnamed")
                m_sig = m_data.get("signature", f"{m_name}()")
                instructions: List[Instruction] = []
                for idx, inst_data in enumerate(m_data.get("instructions", [])):
                    inst = Instruction(
                        index=idx,
                        opcode=inst_data.get("opcode", "NOP"),
                        target=inst_data.get("target"),
                        operands=inst_data.get("operands", []),
                        method_signature=inst_data.get("method_signature"),
                        field_name=inst_data.get("field_name"),
                        constant_value=inst_data.get("constant_value"),
                        line_number=inst_data.get("line_number", idx + 1),
                        raw=inst_data.get("raw", ""),
                    )
                    instructions.append(inst)

                m_ir = MethodIR(
                    class_name=c_name,
                    name=m_name,
                    signature=m_sig,
                    parameters=m_data.get("parameters", []),
                    return_type=m_data.get("return_type", "void"),
                    is_static=m_data.get("is_static", False),
                    is_constructor=(m_name in ("<init>", "__init__")),
                    instructions=instructions,
                )
                m_ir.basic_blocks = cls._build_basic_blocks(instructions)
                c_ir.methods[m_name] = m_ir

            classes[c_name] = c_ir

        return classes

    @classmethod
    def from_python_code(cls, py_code: str, class_name: str = "TestSDK", package: str = "com.sdk") -> ClassIR:
        """Parses Python source code into ClassIR for lightweight modeling & simulation."""
        tree = ast.parse(py_code)
        c_ir = ClassIR(name=class_name, package=package)

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                m_name = node.name
                params = [arg.arg for arg in node.args.args]
                instructions = cls._ast_func_to_instructions(node)
                blocks = cls._build_basic_blocks(instructions)
                m_ir = MethodIR(
                    class_name=class_name,
                    name=m_name,
                    signature=f"{m_name}({', '.join(params)})",
                    parameters=params,
                    is_constructor=(m_name == "__init__"),
                    instructions=instructions,
                    basic_blocks=blocks,
                )
                c_ir.methods[m_name] = m_ir

        return c_ir

    @classmethod
    def _ast_func_to_instructions(cls, func_node: ast.FunctionDef) -> List[Instruction]:
        instructions = []
        idx = 0

        for stmt in func_node.body:
            if isinstance(stmt, ast.Assign):
                target = stmt.targets[0].id if isinstance(stmt.targets[0], ast.Name) else "var"
                if isinstance(stmt.value, ast.Call):
                    # Method invocation
                    call_sig = cls._get_call_signature(stmt.value)
                    args = [a.id for a in stmt.value.args if isinstance(a, ast.Name)]
                    instructions.append(Instruction(
                        index=idx,
                        opcode="INVOKE",
                        target=target,
                        operands=args,
                        method_signature=call_sig,
                        line_number=stmt.lineno,
                    ))
                elif isinstance(stmt.value, ast.Constant):
                    instructions.append(Instruction(
                        index=idx,
                        opcode="CONST",
                        target=target,
                        constant_value=stmt.value.value,
                        line_number=stmt.lineno,
                    ))
                else:
                    instructions.append(Instruction(
                        index=idx,
                        opcode="ASSIGN",
                        target=target,
                        line_number=stmt.lineno,
                    ))
                idx += 1

            elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                call_sig = cls._get_call_signature(stmt.value)
                args = [a.id for a in stmt.value.args if isinstance(a, ast.Name)]
                instructions.append(Instruction(
                    index=idx,
                    opcode="INVOKE",
                    target=None,
                    operands=args,
                    method_signature=call_sig,
                    line_number=stmt.lineno,
                ))
                idx += 1

            elif isinstance(stmt, ast.If):
                test_str = ast.unparse(stmt.test) if hasattr(ast, "unparse") else "test_condition"
                instructions.append(Instruction(
                    index=idx,
                    opcode="BRANCH",
                    target=None,
                    operands=[test_str],
                    line_number=stmt.lineno,
                ))
                idx += 1
                # Recurse into if body
                for sub_stmt in stmt.body:
                    if isinstance(sub_stmt, ast.Expr) and isinstance(sub_stmt.value, ast.Call):
                        call_sig = cls._get_call_signature(sub_stmt.value)
                        args = [a.id for a in sub_stmt.value.args if isinstance(a, ast.Name)]
                        instructions.append(Instruction(
                            index=idx,
                            opcode="INVOKE",
                            target=None,
                            operands=args,
                            method_signature=call_sig,
                            line_number=sub_stmt.lineno,
                        ))
                        idx += 1

            elif isinstance(stmt, ast.Return):
                ret_val = stmt.value.id if isinstance(stmt.value, ast.Name) else None
                instructions.append(Instruction(
                    index=idx,
                    opcode="RETURN",
                    target=None,
                    operands=[ret_val] if ret_val else [],
                    line_number=stmt.lineno,
                ))
                idx += 1

        return instructions

    @classmethod
    def _get_call_signature(cls, call_node: ast.Call) -> str:
        if isinstance(call_node.func, ast.Attribute):
            obj = call_node.func.value.id if isinstance(call_node.func.value, ast.Name) else "obj"
            return f"{obj}.{call_node.func.attr}"
        elif isinstance(call_node.func, ast.Name):
            return call_node.func.id
        return "unknown_call"

    @classmethod
    def _build_basic_blocks(cls, instructions: List[Instruction]) -> List[BasicBlockIR]:
        """Partitions instruction list into Basic Blocks with branch edges."""
        if not instructions:
            return []

        # Find leaders
        leaders: Set[int] = {0}
        for i, inst in enumerate(instructions):
            if inst.is_branch():
                if i + 1 < len(instructions):
                    leaders.add(i + 1)
                # target of branch would also be a leader

        leader_list = sorted(list(leaders))
        blocks: List[BasicBlockIR] = []

        for b_idx, start in enumerate(leader_list):
            end = leader_list[b_idx + 1] if b_idx + 1 < len(leader_list) else len(instructions)
            blk_insts = instructions[start:end]
            block = BasicBlockIR(id=b_idx, instructions=blk_insts)
            blocks.append(block)

        # Wire up simple sequential flow and branches
        for b_idx, blk in enumerate(blocks):
            if b_idx + 1 < len(blocks):
                # Sequential successor
                blk.successors.append(b_idx + 1)
                blocks[b_idx + 1].predecessors.append(b_idx)

        return blocks
