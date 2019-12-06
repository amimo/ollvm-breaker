from z3 import (
    UGT,
    ULE,
    ULT,
    UGE,
    And,
    Array,
    BitVec,
    BitVecSort,
    BitVecVal,
    Bool,
    BoolVal,
    Extract,
    Not,
    Or,
    Tactic,
    ZeroExt
)

from binaryninja import BinaryView, Variable, VariableSourceType, log_info, log_debug, TypeClass

from bnilvisitor import BNILVisitor


# Josh Watson's https://github.com/joshwatson/f-ing-around-with-binaryninja.git

def make_variable(var: Variable):
    if var.name == "":
        if var.source_type == VariableSourceType.RegisterVariableSourceType:
            var.name = var.function.arch.get_reg_by_index(var.storage)
        else:
            var.name = f'var_{abs(var.storage):x}'
    if var.type.width == 1:
        return Bool(var.name)
    else:
        return BitVec(var.name, var.type.width * 8)


class ConditionVisitor(BNILVisitor):
    def __init__(self, view: BinaryView):
        self.view = view
        super().__init__()
        addr_size = self.view.address_size
        self.mem = {
            1: Array("mem1", BitVecSort(addr_size*8), BitVecSort(8)),
            2: Array('mem2', BitVecSort(addr_size*8), BitVecSort(16)),
            4: Array('mem4', BitVecSort(addr_size*8), BitVecSort(32)),
            8: Array('mem8', BitVecSort(addr_size*8), BitVecSort(64)),
            16: Array('mem16', BitVecSort(addr_size*8), BitVecSort(128))
        }

    def simplify(self, condition):
        visit_result = self.visit(condition)

        if visit_result.sort().name() != "Bool":
            return visit_result

        result = Tactic("ctx-solver-simplify")(visit_result)[0]

        if len(result) == 0:
            return BoolVal(True)

        if len(result) < 2:
            return result[0]

        return And(*result)

    def visit_MLIL_CMP_E(self, expr):
        left = self.visit(expr.left)
        right = self.visit(expr.right)
        if right.size() != left.size():
            right = ZeroExt(left.size() - right.size(), right)
        return left == right

    def visit_MLIL_CMP_NE(self, expr):
        left = self.visit(expr.left)
        right = self.visit(expr.right)
        if right.size() != left.size():
            right = ZeroExt(left.size() - right.size(), right)
        return left != right

    def visit_MLIL_CMP_SLE(self, expr):
        left, right = self.visit_both_sides(expr)
        if right.size() != left.size():
            right = ZeroExt(left.size() - right.size(), right)
        return left <= right

    def visit_MLIL_CMP_SLT(self, expr):
        left, right = self.visit_both_sides(expr)
        if right.size() != left.size():
            right = ZeroExt(left.size() - right.size(), right)
        return left < right

    def visit_MLIL_CMP_SGT(self, expr):
        left, right = self.visit_both_sides(expr)
        if right.size() != left.size():
            right = ZeroExt(left.size() - right.size(), right)
        return left > right

    def visit_MLIL_CMP_SGE(self, expr):
        left, right = self.visit_both_sides(expr)
        if right.size() != left.size():
            right = ZeroExt(left.size() - right.size(), right)
        return left >= right

    def visit_MLIL_CMP_UGT(self, expr):
        left, right = self.visit_both_sides(expr)
        if right.size() != left.size():
            right = ZeroExt(left.size() - right.size(), right)
        return UGT(left, right)

    def visit_MLIL_CMP_UGE(self, expr):
        left, right = self.visit_both_sides(expr)
        if right.size() != left.size():
            right = ZeroExt(left.size() - right.size(), right)
        return UGE(left, right)

    def visit_MLIL_CMP_ULE(self, expr):
        left, right = self.visit_both_sides(expr)
        if right.size() != left.size():
            right = ZeroExt(left.size() - right.size(), right)
        return ULE(left, right)

    def visit_MLIL_CMP_ULT(self, expr):
        left, right = self.visit_both_sides(expr)
        if right.size() != left.size():
            right = ZeroExt(left.size() - right.size(), right)
        return ULT(left, right)

    def visit_MLIL_LOAD(self, expr):
        src = self.visit(expr.src)

        if src is not None:
            log_debug(f'{expr.src.size} {src.sort()}')
            return self.mem[expr.src.size][src]

    def visit_MLIL_VAR_FIELD(self, expr):
        src = make_variable(expr.src)
        offset = expr.offset
        size = expr.size

        return Extract(((offset + size) * 8) - 1, (offset * 8), src)

    def visit_MLIL_VAR(self, expr):
        return make_variable(expr.src)

    def visit_MLIL_CONST(self, expr):
        if expr.size == 0 and expr.constant in (0, 1):
            return BoolVal(True) if expr.constant else BoolVal(False)
        return BitVecVal(expr.constant, expr.size * 8)

    def visit_MLIL_NOT(self, expr):
        return Not(self.visit(expr.src))

    def visit_MLIL_AND(self, expr):
        left, right = self.visit_both_sides(expr)

        if right.size() != left.size():
            right = ZeroExt(left.size() - right.size(), right)

        return left & right

    def visit_MLIL_OR(self, expr):
        left, right = self.visit_both_sides(expr)

        if right.size() != left.size():
            right = ZeroExt(left.size() - right.size(), right)

        return left | right

    def visit_MLIL_ADD(self, expr):
        left, right = self.visit_both_sides(expr)
        if right.size() != left.size():
            right = ZeroExt(left.size() - right.size(), right)
        return left + right

    def visit_MLIL_ADDRESS_OF(self, expr):
        if expr.src.name:
            var_name = expr.src.name
        elif (expr.src.source_type ==
                VariableSourceType.StackVariableSourceType):
            var_name = f'var_{abs(expr.src.storage):x}'
        else:
            var_name = expr.function.arch.get_reg_by_index(expr.src.storage)

        log_debug(f'var_name: {repr(var_name)}')
        return BitVec(
            f"&{var_name}",
            (expr.size * 8)
            if expr.size
            else expr.function.source_function.view.address_size * 8,
        )

    def visit_MLIL_LSL(self, expr):
        left, right = self.visit_both_sides(expr)

        if right.size() != left.size():
            right = ZeroExt(left.size() - right.size(), right)

        return left << right

    def visit_both_sides(self, expr):
        return self.visit(expr.left), self.visit(expr.right)

    visit_MLIL_CONST_PTR = visit_MLIL_CONST
