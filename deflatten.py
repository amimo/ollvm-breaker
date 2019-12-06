from typing import List

import z3
from binaryninja import *

from condition_visitor import ConditionVisitor, make_variable

ARM64_INSTRUCTION_LENGTH = 4

idc = '''
from idc import *
base = 0x4000000
seg_size = 0x400000
address = base
add_segm_ex(base, base + seg_size, 0X1, 2, 1, 2, ADDSEG_NOSREG)
set_segm_name(base, "patch")
set_segm_class(base, "CODE")
set_segm_type(base, 2)
'''


# REF: https://github.com/RPISEC/llvm-deobfuscator.git
def rel(addr, base_addr):
    return hex(addr - base_addr).rstrip('L')


def safe_asm(bv, asm_str):
    return bv.arch.assemble(asm_str)


def get_func_containing(bv, addr):
    """ Finds the function, if any, containing the given address """
    funcs = bv.get_functions_containing(addr)
    return funcs[0] if funcs else None


def mlil_at(mlil, addr):
    for il_bb in mlil:
        if il_bb.source_block.start <= addr < il_bb.source_block.end:
            return il_bb
    return None


def get_state_value(state):
    return state.src.constant


def compute_reaching_states(bv, mlil, from_bb, to_bb, states):
    visitor = ConditionVisitor(bv)
    path = next(dfs_paths_backward(from_bb, to_bb))
    reaching_conditions = []
    cond = None
    for edge in path:
        terminator = edge.source[-1]
        # assert terminator.operation == MediumLevelILOperation.MLIL_IF
        if terminator.operation == MediumLevelILOperation.MLIL_IF:
            cond = terminator.condition
            if cond.operation == MediumLevelILOperation.MLIL_VAR:
                cond = mlil.get_var_definitions(cond.src)[0].src
            condition = visitor.visit(cond)
            if edge.type == BranchType.TrueBranch:
                reaching_conditions.append(condition)
            else:
                reaching_conditions.append(z3.Not(condition))

    solver = z3.Solver()
    for condition in reaching_conditions:
        solver.add(condition)

    reaching_states = set()
    if cond.operation == MediumLevelILOperation.MLIL_VAR:
        cond = mlil.get_var_definitions(cond.src)[0].src
    symbolic_state = make_variable(cond.left.src)
    for state in states:
        solver.push()
        solver.add(symbolic_state == state)
        if solver.check() == z3.sat:
            reaching_states.add(state)
        solver.pop()
    return list(reaching_states)


class StateVar(object):
    def __init__(self, bv: BinaryView, mlil: MediumLevelILFunction, definintion: MediumLevelILFunction,
                 dispatcher: MediumLevelILBasicBlock):
        self.defintion = definintion
        self._dispatcher = dispatcher
        self._bv = bv
        self._mlil = mlil
        self._related_vars = self.find_related_vars(mlil, definintion)
        self._block_to_definition = self._build_definition_map()
        self.states = self.get_states()
        self._branch_table = self.get_branch_table()

    def get_definition_at_block(self, block):
        return self._block_to_definition.get(block, None)

    def get_source_var(self, src: MediumLevelILInstruction):
        if src.operation == MediumLevelILOperation.MLIL_ZX:
            return self.get_source_var(src.src)
        elif src.operation == MediumLevelILOperation.MLIL_VAR_FIELD:
            return src.src
        elif src.operation == MediumLevelILOperation.MLIL_VAR:
            return src.src
        else:
            return src

    def find_related_vars(self, mlil, definition):
        related_vars = set()
        todo = [definition]
        related_vars.add(definition)
        while todo:
            var = todo.pop()
            for use in mlil.get_var_uses(var):
                if use.operation == MediumLevelILOperation.MLIL_SET_VAR:
                    source_var = self.get_source_var(use.src)
                    if source_var == definition or source_var in related_vars:
                        if use.dest not in related_vars:
                            related_vars.add(use.dest)
                            todo.append(use.dest)

        return related_vars

    def get_uses(self):
        for var in self._related_vars:
            uses = self._mlil.get_var_uses(var)
            for use in uses:
                yield use

    def get_definitions(self, constant=False):
        for var in self._related_vars:
            definitions = self._mlil.get_var_definitions(var)
            for definition in definitions:
                if constant:
                    if definition.src.operation != MediumLevelILOperation.MLIL_CONST:
                        continue
                yield definition

    def get_states(self):
        mlil = self._mlil
        states = set()
        for use in self.get_uses():

            bb = use.il_basic_block

            terminator = bb[-1]
            if terminator.operation != MediumLevelILOperation.MLIL_IF:
                continue

            cond = terminator.condition

            if cond.operation == MediumLevelILOperation.MLIL_VAR:
                cond = mlil.get_var_definitions(cond.src)[0].src

            if cond.operation not in (MediumLevelILOperation.MLIL_CMP_E, MediumLevelILOperation.MLIL_CMP_NE):
                continue

            # state var compare against a constant
            if cond.left.src in self._related_vars:
                if cond.right.operation == MediumLevelILOperation.MLIL_CONST:
                    states.add(cond.right.constant)

        for defn in self.get_definitions(True):
            if defn.src.operation == MediumLevelILOperation.MLIL_CONST:
                states.add(defn.src.constant)
        return states

    def _find_dom_definition(self, block: MediumLevelILBasicBlock):
        assert len(block.incoming_edges) == 1
        for edge in block.incoming_edges:
            pred = edge.source
            if pred in self._block_to_definition:
                return pred
            else:
                return self._find_dom_definition(pred)
        return None

    def is_alive(self, block: MediumLevelILBasicBlock):
        return block in self._block_to_definition

    def get_branch_table(self):
        mlil = self._mlil
        switch_table = {}
        visited_block = set()

        for use in self.get_uses():

            bb = use.il_basic_block
            if bb in visited_block:
                continue
            else:
                visited_block.add(bb)

            terminator = bb[-1]
            if terminator.operation != MediumLevelILOperation.MLIL_IF:
                continue

            cond = terminator.condition

            if cond.operation == MediumLevelILOperation.MLIL_VAR:
                # Handle condition is not a boolean expression but a boolean variable:
                #   bool cond:0_1 = var_4 == 0
                #   if (cond:0_1)
                # cond -> var_4 == 0
                cond = mlil.get_var_definitions(cond.src)[0].src
            defintion = self.get_definition_at_block(bb)
            if defintion:
                # It seems like if we have definition & use of state var in a same block,
                # the reaching state is always the constant in the compare expression
                if cond.right.operation == MediumLevelILOperation.MLIL_CONST:
                    state = cond.right.constant
                else:
                    reaching_state = compute_reaching_states(self._bv, mlil, bb, self._dispatcher, self.states)
                    assert len(reaching_state) == 1
                    state = reaching_state[0]
                if cond.operation == MediumLevelILOperation.MLIL_CMP_E:
                    # TODO: is clear path to dispatcher
                    if bb.outgoing_edges[0].target == self._dispatcher:
                        switch_table[state] = bb
                    else:
                        switch_table[state] = bb.outgoing_edges[0].target
                else:
                    switch_table[state] = bb.outgoing_edges[1].target
            else:
                # state_var compare against a constant
                if cond.right.operation != MediumLevelILOperation.MLIL_CONST:
                    continue
                # assert cond.right.operation == MediumLevelILOperation.MLIL_CONST
                state = cond.right.constant
                if cond.left.src in self._related_vars:
                    assert cond.right.operation == MediumLevelILOperation.MLIL_CONST
                    if cond.operation == MediumLevelILOperation.MLIL_CMP_E:
                        target = bb.outgoing_edges[0].target
                    else:
                        target = bb.outgoing_edges[1].target
                    # TODO: is clear path to dispatcher
                    if target == self._dispatcher:
                        target = self._find_dom_definition(bb)
                    switch_table[state] = target

        return switch_table

    def _build_definition_map(self):
        current_definition = {}
        for var in self.get_definitions():
            current_definition[var.il_basic_block] = var
        return current_definition

    def is_clear_path(self, reaching_path, definition):
        if len(reaching_path) == 1:
            return True
        for edge in reaching_path:
            if edge.target in self._block_to_definition and \
                    self._block_to_definition.get(edge.target).dest == definition.dest:
                return False
        return True

    def get_branch_target(self, definition):
        assert definition.src.constant in self._branch_table
        return self._branch_table[definition.src.constant]

    def is_target_reachable(self, definitions):
        for definition in definitions:
            if definition.src.operation != MediumLevelILOperation.MLIL_CONST:
                return False
            if definition.src.constant not in self._branch_table:
                return False
        else:
            return True


class AsmInst(object):
    def __init__(self, asm):
        items = list(filter(lambda x: len(x) > 0, re.split('[ ,]', asm)))
        self.operation = items[0]
        self.operands = items[1:]

    def is_jump(self):
        if self.operation in ["b", "br", "bl"]:
            return True
        else:
            return False

    def is_b_cond(self):
        if self.operation.startswith('b.'):
            return True
        else:
            return False

    def is_cbr(self):
        if self.operation in ["tbnz", "tbz", "cbz", "cbnz"]:
            return True
        else:
            return False

    def is_pcrel(self):
        if self.is_jump() or self.is_b_cond() or self.is_cbr():
            return True
        else:
            return False

    def is_csel(self):
        if self.operation in ["csel"]:
            return True
        else:
            return False


class CFGLink(object):
    def __init__(self, mlil, block, states, exit_path, targets, entry_paths):
        self.mlil = mlil
        self.block = block
        self.states = states
        self.enter_path = exit_path  # state definition block -> dispatcher
        self.exit_paths = entry_paths  # dispatcher -> targets
        self.targets = targets

    def gather_enter_dispatcher_insns(self, bv, base_addr):
        if len(self.enter_path) == 1:
            return b''
        insns = b''
        for path in self.enter_path[:-1]:
            source_block = path.target.source_block
            if source_block.instruction_count <= 1:
                continue
            # copy all instruction except terminator
            # TODO: Fix pcrel instructions
            insns += bv.read(source_block.start, (source_block.instruction_count - 1) * ARM64_INSTRUCTION_LENGTH)
        return insns

    def gather_leave_dispatcher_insns(self, bv, base_addr, target):
        insns = b''
        if len(self.exit_paths) == 0:
            return insns

        # return insns
        for path in self.exit_paths[target]:
            source_block = path.source.source_block
            if source_block.instruction_count <= 1:
                continue
            # TODO: Fix pcrel instructions
            insns += bv.read(source_block.start, (source_block.instruction_count - 1) * ARM64_INSTRUCTION_LENGTH)
        return insns

    def __str__(self):
        if len(self.states) == 1:
            s = 'BLOCK : %s , DEF: 0x%x \n' % (self.block.source_block, get_state_value(self.states[0]))
            s += 'LINK TO : BLOCK: %s \n' % self.targets[0].source_block
        else:
            s = 'BLOCK : %s , DEF: [0x%x, 0x%x] \n' % (self.block.source_block,
                                                       get_state_value(self.states[0]),
                                                       get_state_value(self.states[1]))
            s += 'LINK T: 0x%x TO BLOCK: %s  \n' % (get_state_value(self.states[0]), self.targets[0].source_block)
            s += 'LINK F: 0x%x TO BLOCK: %s  \n' % (get_state_value(self.states[1]), self.targets[1].source_block)

        s += 'TO DISPATCHER :   \n'
        for edge in self.enter_path:
            s += ' -> %s\n' % edge.target.source_block
        for idx, path in enumerate(self.exit_paths):
            s += 'TO TARGET :   %s\n' % self.targets[idx].source_block
            for edge in path:
                s += ' -> %s\n' % edge.target.source_block
        return s


# Found all simple (no loop) paths from start to goal
def dfs_paths_backward(start, goal):
    for start_edge in start.incoming_edges:
        stack = [(start_edge.source, [start_edge])]
        while stack:
            (current_block, current_path) = stack.pop()

            # found goal, return current path
            if current_block == goal:
                yield current_path
                continue

            for next_edge in current_block.incoming_edges:
                # detect loop
                for edge in current_path:
                    if next_edge.source == edge.target or next_edge.source == edge.source:
                        break
                else:
                    stack.append((next_edge.source, current_path + [next_edge]))


def dfs_paths(start, goal):
    for start_edge in start.outgoing_edges:
        stack = [(start_edge.target, [start_edge])]
        while stack:
            (current_block, current_path) = stack.pop()

            # found goal, return current path
            if current_block == goal:
                yield current_path
                continue

            for next_edge in current_block.outgoing_edges:
                # detect loop
                for edge in current_path:
                    if next_edge.target == edge.target or next_edge.target == edge.source:
                        break
                else:
                    stack.append((next_edge.target, current_path + [next_edge]))


def delete_overlap_edges(bv: BinaryView, paths):
    if len(paths) <= 1:
        return

    # Remove overlap edges
    for i, path in enumerate(paths):
        for n, edge in enumerate(path[:]):
            overlap = False
            for p in paths[i + 1:]:
                if edge == p[0]:
                    overlap = True
                    p.pop(0)

            if overlap:
                path.pop(0)
            else:
                break

    # Start block should ends with b or b.cond instruction
    for path in paths:
        for edge in path[:]:
            if edge == path[-1]:
                break
            terminator = edge.source[-1]
            inst = AsmInst(bv.get_disassembly(terminator.address))
            if not inst.is_b_cond() and not inst.is_jump():
                path.remove(edge)

    # Remove duplicate paths
    new_paths = []
    for path in paths:
        if path not in new_paths:
            new_paths.append(path)
    paths.clear()
    paths.extend(new_paths)


def get_var_definitions_at(mlil, variable, addr):
    result = []
    for var in mlil.get_var_definitions(variable):
        if var.address == addr:
            result.append(var)
    return result


def resolve_branch_condition(state):
    il_bb = state.il_basic_block
    assert len(il_bb.incoming_edges) <= 1
    if len(il_bb.incoming_edges) == 1:
        return il_bb.incoming_edges[0].type == BranchType.TrueBranch
    else:
        return True


class PatchWriter(object):
    def __init__(self, bv: BinaryView, address):
        self._address = address
        self._bv = bv
        self.size = 0
        self._changes = []

    def current_pos(self):
        return self._address

    def write(self, data):
        if len(data) == 0:
            return
        self.size += len(data)
        self._bv.write(self._address, data)
        self._changes.append((self._address, data))
        self._address += len(data)

    def write_at_addr(self, address, data):
        if len(data) == 0:
            return
        self._bv.write(address, data)
        self._changes.append((address, data))

    def export_ida(self, save_name):
        if len(self._changes) == 0:
            return

        with open(save_name, 'w') as fp:
            fp.write(idc)
            for change in self._changes:
                address, data = change
                for i, c in enumerate(data):
                    fp.write('patch_byte(0x%x, 0x%x)\n' % (address + i, c & 0xff))


def fix_link(bv: BinaryView, pw: PatchWriter, link: CFGLink):
    patch_code_addr = pw.current_pos()
    terminater = link.block[-1]
    if len(link.states) == 1:
        inst = AsmInst(bv.get_disassembly(terminater.address))
        if inst.operation in ['tbnz', 'tbz']:
            print('Fix %s 0x%x' % (inst.operation, terminater.address))
            # tbnz w8,  #0, to_dispatcher
            # cont:
            #
            # patch_code:
            # tbnz w8, #0, to_case_entry
            # b cont
            # to_case_entry:
            # patch_codes

            asm = '%s %s, %s, 0x8' % (inst.operation, inst.operands[0], inst.operands[1])
            patch_codes = safe_asm(bv, asm)
            pw.write(patch_codes)

            asm = 'b %s' % rel(terminater.address + 4, pw.current_pos())
            patch_codes = safe_asm(bv, asm)
            pw.write(patch_codes)
        elif inst.operation in ['cbnz', 'cbz']:
            print('Fix %s' % inst.operation)
            # cbnz w8,  #0, to_dispatcher
            # cont:
            #
            # cbnz w8,  #0, to_case_entry
            # b cont
            # to_case_entry:
            # patch_codes

            asm = '%s %s, 0x8' % (inst.operation, inst.operands[0])
            patch_codes = safe_asm(bv, asm)
            pw.write(patch_codes)

            asm = 'b %s' % rel(terminater.address + 4, pw.current_pos())
            patch_codes = safe_asm(bv, asm)
            pw.write(patch_codes)

        elif not inst.is_jump() and not inst.is_b_cond():
            # copy original instruction
            # TODO: fix pcrel instruction
            codes = bv.read(terminater.address, 4)
            pw.write(codes)

        # insert enter dispatcher codes

        patch_codes = link.gather_enter_dispatcher_insns(bv, pw.current_pos())
        pw.write(patch_codes)

        # insert leave dispatcher codes
        patch_codes = link.gather_leave_dispatcher_insns(bv, pw.current_pos(), 0)
        pw.write(patch_codes)

        # branch back to link.target (switch case entry)
        patch_codes = safe_asm(bv, "b %s" % rel(link.targets[0].source_block.start, pw.current_pos()))
        pw.write(patch_codes)

        # patch terminator to jump to patch code
        patch_codes = safe_asm(bv, "b %s" % rel(patch_code_addr, terminater.address))
        pw.write_at_addr(terminater.address, patch_codes)
        print('patch branch address 0x%x' % terminater.address)
    else:
        # csel    w7, w15, w14, eq
        # mov     w20, w0
        # b       to_dispatcher
        #
        # cset    w7, eq
        # mov     w20, w0
        # b       patch_code
        #
        # patch_code:
        # cbnz    w7, true_branch (0x8)
        # cbz     w7, false_branch
        # true_branch:
        # original instruction at patch point
        # collected instructions from this block to dispatcher
        # collected instructions from dispatcher to true target
        # b true_target
        # false_branch:
        # original instruction at patch point
        # collected instructions from this block to dispatcher
        # collected instructions from dispatcher to false target
        # b false_target

        patch_code_addr = pw.current_pos()
        def_il = link.states[0]
        inst = AsmInst(bv.get_disassembly(def_il.address))
        assert inst.is_csel()

        enter_codes = link.gather_enter_dispatcher_insns(bv, pw.current_pos())
        true_branch_codes = link.gather_leave_dispatcher_insns(bv, pw.current_pos(), 0)
        false_branch_codes = link.gather_leave_dispatcher_insns(bv, pw.current_pos(), 1)

        patch_codes = safe_asm(bv, "cbnz %s, 0x8" % (inst.operands[0]))
        pw.write(patch_codes)
        patch_codes = safe_asm(bv, "cbz %s, %d" % (inst.operands[0], 8 + len(true_branch_codes) + len(enter_codes)))
        pw.write(patch_codes)

        pw.write(enter_codes)
        pw.write(true_branch_codes)
        patch_codes = safe_asm(bv, "b %s" % (rel(link.targets[0].source_block.start, pw.current_pos())))
        pw.write(patch_codes)

        pw.write(enter_codes)
        pw.write(false_branch_codes)
        patch_codes = safe_asm(bv, "b %s" % (rel(link.targets[1].source_block.start, pw.current_pos())))
        pw.write(patch_codes)
        print('patch branch address 0x%x' % terminater.address)

        # patch terminator to jump to patch code
        patch_codes = safe_asm(bv, "cset %s, %s" % (inst.operands[0], inst.operands[-1]))
        pw.write_at_addr(def_il.address, patch_codes)

        patch_codes = safe_asm(bv, "b %s" % (rel(patch_code_addr, terminater.address)))
        pw.write_at_addr(terminater.address, patch_codes)


def deflatten_cfg(bv, pw, state_var_addr, dispatcher_addr):
    func = get_func_containing(bv, state_var_addr)
    mlil = func.medium_level_il
    def_il = func.get_low_level_il_at(state_var_addr).medium_level_il.dest
    dispatcher = mlil_at(mlil, dispatcher_addr)
    assert dispatcher
    state_var = StateVar(bv, mlil, def_il, dispatcher)
    tofix = []
    broken_blocks = set()
    visited_states = set()
    for definition in state_var.get_definitions(True):
        states = get_var_definitions_at(mlil, definition.dest, definition.address)
        if not state_var.is_target_reachable(states):
            print('unable to determine the successors of  %s@%x' % (definition, definition.address))
            broken_blocks.add(definition.il_basic_block)
            continue
        if len(states) == 2:
            # selection instructions like 'csel' in arm64, cmov in x86 define two state values.
            assert len(definition.il_basic_block.outgoing_edges) == 1
            if not resolve_branch_condition(states[0]):
                states = [states[1], states[0]]
            definition_block = definition.il_basic_block.outgoing_edges[0].target
            targets = list(map(state_var.get_branch_target, states))
        else:
            definition_block = definition.il_basic_block
            targets = [state_var.get_branch_target(definition)]

        if definition_block in visited_states:
            continue
        else:
            visited_states.add(definition_block)

        # DEF -> ENTER DISPATCHER -> DISPATCHER -> LEAVE DISPATCHER -> TARGET
        enter_paths = []
        for path in dfs_paths(definition_block, dispatcher):
            # skip path if there is a new state var definition on path
            if not state_var.is_clear_path(path, definition):
                continue
            enter_paths.append(path)

        exit_paths = []
        # Backward search is faster than forward
        for target in targets:
            if target == dispatcher:
                continue
            path = next(dfs_paths_backward(target, dispatcher))
            path.reverse()
            exit_paths.append(path)

        delete_overlap_edges(bv, enter_paths)
        for path in enter_paths:
            e = CFGLink(mlil, path[0].source, states, path, targets, exit_paths)
            tofix.append(e)

    patched_blocks = set()
    for link in tofix:
        if link.block not in patched_blocks:
            patched_blocks.add(link.block)
        else:
            raise Exception("Block has been patched")
        # print(link)
        fix_link(bv, pw, link)


if __name__ == "__main__":
    if len(sys.argv) == 1:
        print('%s <input.bndb>' % os.path.basename(sys.argv[0]))
        sys.exit(1)

    filename = sys.argv[1]
    bv = BinaryViewType.get_view_of_file(filename)
    patch_base = 0x4000000
    patch_max_size = 0x4000
    bv.add_user_segment(patch_base, patch_max_size, 0x0000087c, 0x3600,
                        SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable | SegmentFlag.SegmentWritable)
    pw = PatchWriter(bv, patch_base)
    # JNI_OnLoad
    # deflatten_cfg(bv, pw, 0x000704c0, 0x000704f0)  # vdog
    # deflatten_cfg(bv, pw, 0x000712e4, 0x00071304)  # vdog
    # deflatten_cfg(bv, pw, 0x000714ac, 0x000714ec)  # vdog
    # deflatten_cfg(bv, pw, 0x00070fb8, 0x000710a0)  # vdog
    # deflatten_cfg(bv, pw, 0x00071550, 0x00071574)  # vdog
    # deflatten_cfg(bv, pw, 0x00070690, 0x000706cc)  # vdog
    #
    # # crazy::GetPackageName
    # deflatten_cfg(bv, pw, 0x000620ac, 0x000620c8)  # vdog
    # deflatten_cfg(bv, pw, 0x00062188, 0x000621b4)  # vdog
    # deflatten_cfg(bv, pw, 0x00062434, 0x00062494)  # vdog
    #
    # # prevent_attach_one
    # deflatten_cfg(bv, pw, 0x0008d65c, 0x0008d674)  # vdog
    #
    # # attach_thread_scn
    # deflatten_cfg(bv, pw, 0x0008cd48, 0x0008cd64)  # vdog
    # deflatten_cfg(bv, pw, 0x0008d1c8, 0x0008d2b0)  # vdog
    #
    # # crazy::CheckDex
    # deflatten_cfg(bv, pw, 0x0008755c, 0x00087598)  # vdog
    # deflatten_cfg(bv, pw, 0x00087b48, 0x00087b40)  # vdog

    # sub_7abf0
    # deflatten_cfg(bv, pw, 0x0007ac78, 0x0007ac9c)
    # deflatten_cfg(bv, pw, 0x0007c92c, 0x0007c958)
    # deflatten_cfg(bv, pw, 0x0007c734, 0x0007c75c)
    # deflatten_cfg(bv, pw, 0x0007c81c, 0x0007c848)
    # deflatten_cfg(bv, pw, 0x0007b230, 0x0007b588)
    # deflatten_cfg(bv, pw, 0x0007be70, 0x0007be98)
    # deflatten_cfg(bv, pw, 0x0007c058, 0x0007c088)
    # deflatten_cfg(bv, pw, 0x0007b2a4, 0x0007b2f4)
    # deflatten_cfg(bv, pw, 0x0007b698, 0x0007b6dc)

    deflatten_cfg(bv, pw, 0x00000750, 0x00000768)  # cff

    # save_name = 'fix-' + os.path.basename(filename)
    # bv.create_database(save_name)

    save_name = 'fix-' + os.path.splitext(os.path.basename(filename))[0] + '.py'
    pw.export_ida(save_name)
    print('patch section size: 0x%x' % pw.size)
