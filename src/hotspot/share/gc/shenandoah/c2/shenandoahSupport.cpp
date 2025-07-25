/*
 * Copyright (c) 2015, 2021, Red Hat, Inc. All rights reserved.
 * Copyright (C) 2022 THL A29 Limited, a Tencent company. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 *
 */


#include "classfile/javaClasses.hpp"
#include "gc/shenandoah/c2/shenandoahBarrierSetC2.hpp"
#include "gc/shenandoah/c2/shenandoahSupport.hpp"
#include "gc/shenandoah/shenandoahBarrierSetAssembler.hpp"
#include "gc/shenandoah/shenandoahForwarding.hpp"
#include "gc/shenandoah/shenandoahHeap.hpp"
#include "gc/shenandoah/shenandoahHeapRegion.hpp"
#include "gc/shenandoah/shenandoahRuntime.hpp"
#include "gc/shenandoah/shenandoahThreadLocalData.hpp"
#include "opto/arraycopynode.hpp"
#include "opto/block.hpp"
#include "opto/callnode.hpp"
#include "opto/castnode.hpp"
#include "opto/movenode.hpp"
#include "opto/phaseX.hpp"
#include "opto/rootnode.hpp"
#include "opto/runtime.hpp"
#include "opto/subnode.hpp"

bool ShenandoahBarrierC2Support::expand(Compile* C, PhaseIterGVN& igvn) {
  ShenandoahBarrierSetC2State* state = ShenandoahBarrierSetC2::bsc2()->state();
  if (state->load_reference_barriers_count() > 0) {
    assert(C->post_loop_opts_phase(), "no loop opts allowed");
    C->reset_post_loop_opts_phase(); // ... but we know what we are doing
    C->clear_major_progress();
    PhaseIdealLoop::optimize(igvn, LoopOptsShenandoahExpand);
    if (C->failing()) return false;
    C->process_for_post_loop_opts_igvn(igvn);
    if (C->failing()) return false;

    C->set_post_loop_opts_phase(); // now for real!
  }
  return true;
}

bool ShenandoahBarrierC2Support::is_gc_state_test(Node* iff, int mask) {
  if (!UseShenandoahGC) {
    return false;
  }
  assert(iff->is_If(), "bad input");
  if (iff->Opcode() != Op_If) {
    return false;
  }
  Node* bol = iff->in(1);
  if (!bol->is_Bool() || bol->as_Bool()->_test._test != BoolTest::ne) {
    return false;
  }
  Node* cmp = bol->in(1);
  if (cmp->Opcode() != Op_CmpI) {
    return false;
  }
  Node* in1 = cmp->in(1);
  Node* in2 = cmp->in(2);
  if (in2->find_int_con(-1) != 0) {
    return false;
  }
  if (in1->Opcode() != Op_AndI) {
    return false;
  }
  in2 = in1->in(2);
  if (in2->find_int_con(-1) != mask) {
    return false;
  }
  in1 = in1->in(1);

  return is_gc_state_load(in1);
}

bool ShenandoahBarrierC2Support::is_heap_stable_test(Node* iff) {
  return is_gc_state_test(iff, ShenandoahHeap::HAS_FORWARDED);
}

bool ShenandoahBarrierC2Support::is_gc_state_load(Node *n) {
  if (!UseShenandoahGC) {
    return false;
  }
  if (n->Opcode() != Op_LoadB && n->Opcode() != Op_LoadUB) {
    return false;
  }
  Node* addp = n->in(MemNode::Address);
  if (!addp->is_AddP()) {
    return false;
  }
  Node* base = addp->in(AddPNode::Address);
  Node* off = addp->in(AddPNode::Offset);
  if (base->Opcode() != Op_ThreadLocal) {
    return false;
  }
  if (off->find_intptr_t_con(-1) != in_bytes(ShenandoahThreadLocalData::gc_state_offset())) {
    return false;
  }
  return true;
}

bool ShenandoahBarrierC2Support::has_safepoint_between(Node* start, Node* stop, PhaseIdealLoop *phase) {
  assert(phase->is_dominator(stop, start), "bad inputs");
  ResourceMark rm;
  Unique_Node_List wq;
  wq.push(start);
  for (uint next = 0; next < wq.size(); next++) {
    Node *m = wq.at(next);
    if (m == stop) {
      continue;
    }
    if (m->is_SafePoint() && !m->is_CallLeaf()) {
      return true;
    }
    if (m->is_Region()) {
      for (uint i = 1; i < m->req(); i++) {
        wq.push(m->in(i));
      }
    } else {
      wq.push(m->in(0));
    }
  }
  return false;
}

#ifdef ASSERT
bool ShenandoahBarrierC2Support::verify_helper(Node* in, Node_Stack& phis, VectorSet& visited, verify_type t, bool trace, Unique_Node_List& barriers_used) {
  assert(phis.size() == 0, "");

  while (true) {
    if (in->bottom_type() == TypePtr::NULL_PTR) {
      if (trace) {tty->print_cr("null");}
    } else if (!in->bottom_type()->make_ptr()->make_oopptr()) {
      if (trace) {tty->print_cr("Non oop");}
    } else {
      if (in->is_ConstraintCast()) {
        in = in->in(1);
        continue;
      } else if (in->is_AddP()) {
        assert(!in->in(AddPNode::Address)->is_top(), "no raw memory access");
        in = in->in(AddPNode::Address);
        continue;
      } else if (in->is_Con()) {
        if (trace) {
          tty->print("Found constant");
          in->dump();
        }
      } else if (in->Opcode() == Op_Parm) {
        if (trace) {
          tty->print("Found argument");
        }
      } else if (in->Opcode() == Op_CreateEx) {
        if (trace) {
          tty->print("Found create-exception");
        }
      } else if (in->Opcode() == Op_LoadP && in->adr_type() == TypeRawPtr::BOTTOM) {
        if (trace) {
          tty->print("Found raw LoadP (OSR argument?)");
        }
      } else if (in->Opcode() == Op_ShenandoahLoadReferenceBarrier) {
        if (t == ShenandoahOopStore) {
          return false;
        }
        barriers_used.push(in);
        if (trace) {tty->print("Found barrier"); in->dump();}
      } else if (in->is_Proj() && in->in(0)->is_Allocate()) {
        if (trace) {
          tty->print("Found alloc");
          in->in(0)->dump();
        }
      } else if (in->is_Proj() && (in->in(0)->Opcode() == Op_CallStaticJava || in->in(0)->Opcode() == Op_CallDynamicJava)) {
        if (trace) {
          tty->print("Found Java call");
        }
      } else if (in->is_Phi()) {
        if (!visited.test_set(in->_idx)) {
          if (trace) {tty->print("Pushed phi:"); in->dump();}
          phis.push(in, 2);
          in = in->in(1);
          continue;
        }
        if (trace) {tty->print("Already seen phi:"); in->dump();}
      } else if (in->Opcode() == Op_CMoveP || in->Opcode() == Op_CMoveN) {
        if (!visited.test_set(in->_idx)) {
          if (trace) {tty->print("Pushed cmovep:"); in->dump();}
          phis.push(in, CMoveNode::IfTrue);
          in = in->in(CMoveNode::IfFalse);
          continue;
        }
        if (trace) {tty->print("Already seen cmovep:"); in->dump();}
      } else if (in->Opcode() == Op_EncodeP || in->Opcode() == Op_DecodeN) {
        in = in->in(1);
        continue;
      } else {
        return false;
      }
    }
    bool cont = false;
    while (phis.is_nonempty()) {
      uint idx = phis.index();
      Node* phi = phis.node();
      if (idx >= phi->req()) {
        if (trace) {tty->print("Popped phi:"); phi->dump();}
        phis.pop();
        continue;
      }
      if (trace) {tty->print("Next entry(%d) for phi:", idx); phi->dump();}
      in = phi->in(idx);
      phis.set_index(idx+1);
      cont = true;
      break;
    }
    if (!cont) {
      break;
    }
  }
  return true;
}

void ShenandoahBarrierC2Support::report_verify_failure(const char* msg, Node* n1, Node* n2) {
  if (n1 != nullptr) {
    n1->dump(+10);
  }
  if (n2 != nullptr) {
    n2->dump(+10);
  }
  fatal("%s", msg);
}

void ShenandoahBarrierC2Support::verify(RootNode* root) {
  ResourceMark rm;
  Unique_Node_List wq;
  GrowableArray<Node*> barriers;
  Unique_Node_List barriers_used;
  Node_Stack phis(0);
  VectorSet visited;
  const bool trace = false;
  const bool verify_no_useless_barrier = false;

  wq.push(root);
  for (uint next = 0; next < wq.size(); next++) {
    Node *n = wq.at(next);
    if (n->is_Load()) {
      const bool trace = false;
      if (trace) {tty->print("Verifying"); n->dump();}
      if (n->Opcode() == Op_LoadRange || n->Opcode() == Op_LoadKlass || n->Opcode() == Op_LoadNKlass) {
        if (trace) {tty->print_cr("Load range/klass");}
      } else {
        const TypePtr* adr_type = n->as_Load()->adr_type();

        if (adr_type->isa_oopptr() && adr_type->is_oopptr()->offset() == oopDesc::mark_offset_in_bytes()) {
          if (trace) {tty->print_cr("Mark load");}
        } else if (adr_type->isa_instptr() &&
                   adr_type->is_instptr()->instance_klass()->is_subtype_of(Compile::current()->env()->Reference_klass()) &&
                   adr_type->is_instptr()->offset() == java_lang_ref_Reference::referent_offset()) {
          if (trace) {tty->print_cr("Reference.get()");}
        } else if (!verify_helper(n->in(MemNode::Address), phis, visited, ShenandoahLoad, trace, barriers_used)) {
          report_verify_failure("Shenandoah verification: Load should have barriers", n);
        }
      }
    } else if (n->is_Store()) {
      const bool trace = false;

      if (trace) {tty->print("Verifying"); n->dump();}
      if (n->in(MemNode::ValueIn)->bottom_type()->make_oopptr()) {
        Node* adr = n->in(MemNode::Address);
        bool verify = true;

        if (adr->is_AddP() && adr->in(AddPNode::Base)->is_top()) {
          adr = adr->in(AddPNode::Address);
          if (adr->is_AddP()) {
            assert(adr->in(AddPNode::Base)->is_top(), "");
            adr = adr->in(AddPNode::Address);
            if (adr->Opcode() == Op_LoadP &&
                adr->in(MemNode::Address)->in(AddPNode::Base)->is_top() &&
                adr->in(MemNode::Address)->in(AddPNode::Address)->Opcode() == Op_ThreadLocal &&
                adr->in(MemNode::Address)->in(AddPNode::Offset)->find_intptr_t_con(-1) == in_bytes(ShenandoahThreadLocalData::satb_mark_queue_buffer_offset())) {
              if (trace) {tty->print_cr("SATB prebarrier");}
              verify = false;
            }
          }
        }

        if (verify && !verify_helper(n->in(MemNode::ValueIn), phis, visited, ShenandoahValue, trace, barriers_used)) {
          report_verify_failure("Shenandoah verification: Store should have barriers", n);
        }
      }
      if (!verify_helper(n->in(MemNode::Address), phis, visited, ShenandoahStore, trace, barriers_used)) {
        report_verify_failure("Shenandoah verification: Store (address) should have barriers", n);
      }
    } else if (n->Opcode() == Op_CmpP) {
      const bool trace = false;

      Node* in1 = n->in(1);
      Node* in2 = n->in(2);
      if (in1->bottom_type()->isa_oopptr()) {
        if (trace) {tty->print("Verifying"); n->dump();}

        bool mark_inputs = false;
        if (in1->bottom_type() == TypePtr::NULL_PTR || in2->bottom_type() == TypePtr::NULL_PTR ||
            (in1->is_Con() || in2->is_Con())) {
          if (trace) {tty->print_cr("Comparison against a constant");}
          mark_inputs = true;
        } else if ((in1->is_CheckCastPP() && in1->in(1)->is_Proj() && in1->in(1)->in(0)->is_Allocate()) ||
                   (in2->is_CheckCastPP() && in2->in(1)->is_Proj() && in2->in(1)->in(0)->is_Allocate())) {
          if (trace) {tty->print_cr("Comparison with newly alloc'ed object");}
          mark_inputs = true;
        } else {
          assert(in2->bottom_type()->isa_oopptr(), "");

          if (!verify_helper(in1, phis, visited, ShenandoahStore, trace, barriers_used) ||
              !verify_helper(in2, phis, visited, ShenandoahStore, trace, barriers_used)) {
            report_verify_failure("Shenandoah verification: Cmp should have barriers", n);
          }
        }
        if (verify_no_useless_barrier &&
            mark_inputs &&
            (!verify_helper(in1, phis, visited, ShenandoahValue, trace, barriers_used) ||
             !verify_helper(in2, phis, visited, ShenandoahValue, trace, barriers_used))) {
          phis.clear();
          visited.reset();
        }
      }
    } else if (n->is_LoadStore()) {
      if (n->in(MemNode::ValueIn)->bottom_type()->make_ptr() &&
          !verify_helper(n->in(MemNode::ValueIn), phis, visited, ShenandoahValue, trace, barriers_used)) {
        report_verify_failure("Shenandoah verification: LoadStore (value) should have barriers", n);
      }

      if (n->in(MemNode::Address)->bottom_type()->make_oopptr() && !verify_helper(n->in(MemNode::Address), phis, visited, ShenandoahStore, trace, barriers_used)) {
        report_verify_failure("Shenandoah verification: LoadStore (address) should have barriers", n);
      }
    } else if (n->Opcode() == Op_CallLeafNoFP || n->Opcode() == Op_CallLeaf) {
      CallNode* call = n->as_Call();

      static struct {
        const char* name;
        struct {
          int pos;
          verify_type t;
        } args[6];
      } calls[] = {
        "array_partition_stub",
        { { TypeFunc::Parms, ShenandoahStore }, { TypeFunc::Parms+4, ShenandoahStore },   { -1, ShenandoahNone },
          { -1, ShenandoahNone },                { -1, ShenandoahNone },                  { -1, ShenandoahNone } },
        "arraysort_stub",
        { { TypeFunc::Parms, ShenandoahStore },  { -1, ShenandoahNone },                  { -1, ShenandoahNone },
          { -1,  ShenandoahNone},                 { -1,  ShenandoahNone},                 { -1,  ShenandoahNone} },
        "aescrypt_encryptBlock",
        { { TypeFunc::Parms, ShenandoahLoad },   { TypeFunc::Parms+1, ShenandoahStore },  { TypeFunc::Parms+2, ShenandoahLoad },
          { -1,  ShenandoahNone},                 { -1,  ShenandoahNone},                 { -1,  ShenandoahNone} },
        "aescrypt_decryptBlock",
        { { TypeFunc::Parms, ShenandoahLoad },   { TypeFunc::Parms+1, ShenandoahStore },  { TypeFunc::Parms+2, ShenandoahLoad },
          { -1,  ShenandoahNone},                 { -1,  ShenandoahNone},                 { -1,  ShenandoahNone} },
        "multiplyToLen",
        { { TypeFunc::Parms, ShenandoahLoad },   { TypeFunc::Parms+2, ShenandoahLoad },   { TypeFunc::Parms+4, ShenandoahStore },
          { -1,  ShenandoahNone},                 { -1,  ShenandoahNone},                 { -1,  ShenandoahNone} },
        "squareToLen",
        { { TypeFunc::Parms, ShenandoahLoad },   { TypeFunc::Parms+2, ShenandoahLoad },   { -1,  ShenandoahNone},
          { -1,  ShenandoahNone},                 { -1,  ShenandoahNone},                 { -1,  ShenandoahNone} },
        "montgomery_multiply",
        { { TypeFunc::Parms, ShenandoahLoad },   { TypeFunc::Parms+1, ShenandoahLoad },   { TypeFunc::Parms+2, ShenandoahLoad },
          { TypeFunc::Parms+6, ShenandoahStore }, { -1,  ShenandoahNone},                 { -1,  ShenandoahNone} },
        "montgomery_square",
        { { TypeFunc::Parms, ShenandoahLoad },   { TypeFunc::Parms+1, ShenandoahLoad },   { TypeFunc::Parms+5, ShenandoahStore },
          { -1,  ShenandoahNone},                 { -1,  ShenandoahNone},                 { -1,  ShenandoahNone} },
        "mulAdd",
        { { TypeFunc::Parms, ShenandoahStore },  { TypeFunc::Parms+1, ShenandoahLoad },   { -1,  ShenandoahNone},
          { -1,  ShenandoahNone},                 { -1,  ShenandoahNone},                 { -1,  ShenandoahNone} },
        "vectorizedMismatch",
        { { TypeFunc::Parms, ShenandoahLoad },   { TypeFunc::Parms+1, ShenandoahLoad },   { -1,  ShenandoahNone},
          { -1,  ShenandoahNone},                 { -1,  ShenandoahNone},                 { -1,  ShenandoahNone} },
        "updateBytesCRC32",
        { { TypeFunc::Parms+1, ShenandoahLoad }, { -1,  ShenandoahNone},                  { -1,  ShenandoahNone},
          { -1,  ShenandoahNone},                 { -1,  ShenandoahNone},                 { -1,  ShenandoahNone} },
        "updateBytesAdler32",
        { { TypeFunc::Parms+1, ShenandoahLoad }, { -1,  ShenandoahNone},                  { -1,  ShenandoahNone},
          { -1,  ShenandoahNone},                 { -1,  ShenandoahNone},                 { -1,  ShenandoahNone} },
        "updateBytesCRC32C",
        { { TypeFunc::Parms+1, ShenandoahLoad }, { TypeFunc::Parms+3, ShenandoahLoad},    { -1,  ShenandoahNone},
          { -1,  ShenandoahNone},                 { -1,  ShenandoahNone},                 { -1,  ShenandoahNone} },
        "counterMode_AESCrypt",
        { { TypeFunc::Parms, ShenandoahLoad },   { TypeFunc::Parms+1, ShenandoahStore },  { TypeFunc::Parms+2, ShenandoahLoad },
          { TypeFunc::Parms+3, ShenandoahStore }, { TypeFunc::Parms+5, ShenandoahStore }, { TypeFunc::Parms+6, ShenandoahStore } },
        "cipherBlockChaining_encryptAESCrypt",
        { { TypeFunc::Parms, ShenandoahLoad },   { TypeFunc::Parms+1, ShenandoahStore },  { TypeFunc::Parms+2, ShenandoahLoad },
          { TypeFunc::Parms+3, ShenandoahLoad },  { -1,  ShenandoahNone},                 { -1,  ShenandoahNone} },
        "cipherBlockChaining_decryptAESCrypt",
        { { TypeFunc::Parms, ShenandoahLoad },   { TypeFunc::Parms+1, ShenandoahStore },  { TypeFunc::Parms+2, ShenandoahLoad },
          { TypeFunc::Parms+3, ShenandoahLoad },  { -1,  ShenandoahNone},                 { -1,  ShenandoahNone} },
        "shenandoah_clone",
        { { TypeFunc::Parms, ShenandoahLoad },   { -1,  ShenandoahNone},                  { -1,  ShenandoahNone},
          { -1,  ShenandoahNone},                 { -1,  ShenandoahNone},                 { -1,  ShenandoahNone} },
        "ghash_processBlocks",
        { { TypeFunc::Parms, ShenandoahStore },  { TypeFunc::Parms+1, ShenandoahLoad },   { TypeFunc::Parms+2, ShenandoahLoad },
          { -1,  ShenandoahNone},                 { -1,  ShenandoahNone},                 { -1,  ShenandoahNone} },
        "sha1_implCompress",
        { { TypeFunc::Parms, ShenandoahLoad },  { TypeFunc::Parms+1, ShenandoahStore },   { -1, ShenandoahNone },
          { -1,  ShenandoahNone},                 { -1,  ShenandoahNone},                 { -1,  ShenandoahNone} },
        "sha256_implCompress",
        { { TypeFunc::Parms, ShenandoahLoad },  { TypeFunc::Parms+1, ShenandoahStore },   { -1, ShenandoahNone },
          { -1,  ShenandoahNone},                 { -1,  ShenandoahNone},                 { -1,  ShenandoahNone} },
        "sha512_implCompress",
        { { TypeFunc::Parms, ShenandoahLoad },  { TypeFunc::Parms+1, ShenandoahStore },   { -1, ShenandoahNone },
          { -1,  ShenandoahNone},                 { -1,  ShenandoahNone},                 { -1,  ShenandoahNone} },
        "sha1_implCompressMB",
        { { TypeFunc::Parms, ShenandoahLoad },  { TypeFunc::Parms+1, ShenandoahStore },   { -1, ShenandoahNone },
          { -1,  ShenandoahNone},                 { -1,  ShenandoahNone},                 { -1,  ShenandoahNone} },
        "sha256_implCompressMB",
        { { TypeFunc::Parms, ShenandoahLoad },  { TypeFunc::Parms+1, ShenandoahStore },   { -1, ShenandoahNone },
          { -1,  ShenandoahNone},                 { -1,  ShenandoahNone},                 { -1,  ShenandoahNone} },
        "sha512_implCompressMB",
        { { TypeFunc::Parms, ShenandoahLoad },  { TypeFunc::Parms+1, ShenandoahStore },   { -1, ShenandoahNone },
          { -1,  ShenandoahNone},                 { -1,  ShenandoahNone},                 { -1,  ShenandoahNone} },
        "encodeBlock",
        { { TypeFunc::Parms, ShenandoahLoad },  { TypeFunc::Parms+3, ShenandoahStore },   { -1, ShenandoahNone },
          { -1,  ShenandoahNone},                 { -1,  ShenandoahNone},                 { -1,  ShenandoahNone} },
        "decodeBlock",
        { { TypeFunc::Parms, ShenandoahLoad },  { TypeFunc::Parms+3, ShenandoahStore },   { -1, ShenandoahNone },
          { -1,  ShenandoahNone},                 { -1,  ShenandoahNone},                 { -1,  ShenandoahNone} },
        "intpoly_montgomeryMult_P256",
        { { TypeFunc::Parms, ShenandoahLoad },  { TypeFunc::Parms+1, ShenandoahLoad  },   { TypeFunc::Parms+2, ShenandoahStore },
          { -1,  ShenandoahNone},                 { -1,  ShenandoahNone},                 { -1,  ShenandoahNone} },
        "intpoly_assign",
        { { TypeFunc::Parms+1, ShenandoahStore }, { TypeFunc::Parms+2, ShenandoahLoad },  { -1, ShenandoahNone },
          { -1,  ShenandoahNone},                 { -1,  ShenandoahNone},                 { -1,  ShenandoahNone} },
      };

      if (call->is_call_to_arraycopystub()) {
        Node* dest = nullptr;
        const TypeTuple* args = n->as_Call()->_tf->domain();
        for (uint i = TypeFunc::Parms, j = 0; i < args->cnt(); i++) {
          if (args->field_at(i)->isa_ptr()) {
            j++;
            if (j == 2) {
              dest = n->in(i);
              break;
            }
          }
        }
        if (!verify_helper(n->in(TypeFunc::Parms), phis, visited, ShenandoahLoad, trace, barriers_used) ||
            !verify_helper(dest, phis, visited, ShenandoahStore, trace, barriers_used)) {
          report_verify_failure("Shenandoah verification: ArrayCopy should have barriers", n);
        }
      } else if (strlen(call->_name) > 5 &&
                 !strcmp(call->_name + strlen(call->_name) - 5, "_fill")) {
        if (!verify_helper(n->in(TypeFunc::Parms), phis, visited, ShenandoahStore, trace, barriers_used)) {
          report_verify_failure("Shenandoah verification: _fill should have barriers", n);
        }
      } else if (!strcmp(call->_name, "shenandoah_wb_pre")) {
        // skip
      } else {
        const int calls_len = sizeof(calls) / sizeof(calls[0]);
        int i = 0;
        for (; i < calls_len; i++) {
          if (!strcmp(calls[i].name, call->_name)) {
            break;
          }
        }
        if (i != calls_len) {
          const uint args_len = sizeof(calls[0].args) / sizeof(calls[0].args[0]);
          for (uint j = 0; j < args_len; j++) {
            int pos = calls[i].args[j].pos;
            if (pos == -1) {
              break;
            }
            if (!verify_helper(call->in(pos), phis, visited, calls[i].args[j].t, trace, barriers_used)) {
              report_verify_failure("Shenandoah verification: intrinsic calls should have barriers", n);
            }
          }
          for (uint j = TypeFunc::Parms; j < call->req(); j++) {
            if (call->in(j)->bottom_type()->make_ptr() &&
                call->in(j)->bottom_type()->make_ptr()->isa_oopptr()) {
              uint k = 0;
              for (; k < args_len && calls[i].args[k].pos != (int)j; k++);
              if (k == args_len) {
                fatal("arg %d for call %s not covered", j, call->_name);
              }
            }
          }
        } else {
          for (uint j = TypeFunc::Parms; j < call->req(); j++) {
            if (call->in(j)->bottom_type()->make_ptr() &&
                call->in(j)->bottom_type()->make_ptr()->isa_oopptr()) {
              fatal("%s not covered", call->_name);
            }
          }
        }
      }
    } else if (n->Opcode() == Op_ShenandoahLoadReferenceBarrier) {
      // skip
    } else if (n->is_AddP()
               || n->is_Phi()
               || n->is_ConstraintCast()
               || n->Opcode() == Op_Return
               || n->Opcode() == Op_CMoveP
               || n->Opcode() == Op_CMoveN
               || n->Opcode() == Op_Rethrow
               || n->is_MemBar()
               || n->Opcode() == Op_Conv2B
               || n->Opcode() == Op_SafePoint
               || n->is_CallJava()
               || n->Opcode() == Op_Unlock
               || n->Opcode() == Op_EncodeP
               || n->Opcode() == Op_DecodeN) {
      // nothing to do
    } else {
      static struct {
        int opcode;
        struct {
          int pos;
          verify_type t;
        } inputs[2];
      } others[] = {
        Op_FastLock,
        { { 1, ShenandoahLoad },                  { -1, ShenandoahNone} },
        Op_Lock,
        { { TypeFunc::Parms, ShenandoahLoad },    { -1, ShenandoahNone} },
        Op_ArrayCopy,
        { { ArrayCopyNode::Src, ShenandoahLoad }, { ArrayCopyNode::Dest, ShenandoahStore } },
        Op_StrCompressedCopy,
        { { 2, ShenandoahLoad },                  { 3, ShenandoahStore } },
        Op_StrInflatedCopy,
        { { 2, ShenandoahLoad },                  { 3, ShenandoahStore } },
        Op_AryEq,
        { { 2, ShenandoahLoad },                  { 3, ShenandoahLoad } },
        Op_StrIndexOf,
        { { 2, ShenandoahLoad },                  { 4, ShenandoahLoad } },
        Op_StrComp,
        { { 2, ShenandoahLoad },                  { 4, ShenandoahLoad } },
        Op_StrEquals,
        { { 2, ShenandoahLoad },                  { 3, ShenandoahLoad } },
        Op_VectorizedHashCode,
        { { 2, ShenandoahLoad },                  { -1, ShenandoahNone } },
        Op_EncodeISOArray,
        { { 2, ShenandoahLoad },                  { 3, ShenandoahStore } },
        Op_CountPositives,
        { { 2, ShenandoahLoad },                  { -1, ShenandoahNone} },
        Op_CastP2X,
        { { 1, ShenandoahLoad },                  { -1, ShenandoahNone} },
        Op_StrIndexOfChar,
        { { 2, ShenandoahLoad },                  { -1, ShenandoahNone } },
      };

      const int others_len = sizeof(others) / sizeof(others[0]);
      int i = 0;
      for (; i < others_len; i++) {
        if (others[i].opcode == n->Opcode()) {
          break;
        }
      }
      uint stop = n->is_Call() ? n->as_Call()->tf()->domain()->cnt() : n->req();
      if (i != others_len) {
        const uint inputs_len = sizeof(others[0].inputs) / sizeof(others[0].inputs[0]);
        for (uint j = 0; j < inputs_len; j++) {
          int pos = others[i].inputs[j].pos;
          if (pos == -1) {
            break;
          }
          if (!verify_helper(n->in(pos), phis, visited, others[i].inputs[j].t, trace, barriers_used)) {
            report_verify_failure("Shenandoah verification: intrinsic calls should have barriers", n);
          }
        }
        for (uint j = 1; j < stop; j++) {
          if (n->in(j) != nullptr && n->in(j)->bottom_type()->make_ptr() &&
              n->in(j)->bottom_type()->make_ptr()->make_oopptr()) {
            uint k = 0;
            for (; k < inputs_len && others[i].inputs[k].pos != (int)j; k++);
            if (k == inputs_len) {
              fatal("arg %d for node %s not covered", j, n->Name());
            }
          }
        }
      } else {
        for (uint j = 1; j < stop; j++) {
          if (n->in(j) != nullptr && n->in(j)->bottom_type()->make_ptr() &&
              n->in(j)->bottom_type()->make_ptr()->make_oopptr()) {
            fatal("%s not covered", n->Name());
          }
        }
      }
    }

    if (n->is_SafePoint()) {
      SafePointNode* sfpt = n->as_SafePoint();
      if (verify_no_useless_barrier && sfpt->jvms() != nullptr) {
        for (uint i = sfpt->jvms()->scloff(); i < sfpt->jvms()->endoff(); i++) {
          if (!verify_helper(sfpt->in(i), phis, visited, ShenandoahLoad, trace, barriers_used)) {
            phis.clear();
            visited.reset();
          }
        }
      }
    }
  }

  if (verify_no_useless_barrier) {
    for (int i = 0; i < barriers.length(); i++) {
      Node* n = barriers.at(i);
      if (!barriers_used.member(n)) {
        tty->print("XXX useless barrier"); n->dump(-2);
        ShouldNotReachHere();
      }
    }
  }
}
#endif

bool ShenandoahBarrierC2Support::is_anti_dependent_load_at_control(PhaseIdealLoop* phase, Node* maybe_load, Node* store,
                                                                   Node* control) {
  return maybe_load->is_Load() && phase->C->can_alias(store->adr_type(), phase->C->get_alias_index(maybe_load->adr_type())) &&
         phase->ctrl_or_self(maybe_load) == control;
}

void ShenandoahBarrierC2Support::maybe_push_anti_dependent_loads(PhaseIdealLoop* phase, Node* maybe_store, Node* control, Unique_Node_List &wq) {
  if (!maybe_store->is_Store() && !maybe_store->is_LoadStore()) {
    return;
  }
  Node* mem = maybe_store->in(MemNode::Memory);
  for (DUIterator_Fast imax, i = mem->fast_outs(imax); i < imax; i++) {
    Node* u = mem->fast_out(i);
    if (is_anti_dependent_load_at_control(phase, u, maybe_store, control)) {
      wq.push(u);
    }
  }
}

void ShenandoahBarrierC2Support::push_data_inputs_at_control(PhaseIdealLoop* phase, Node* n, Node* ctrl, Unique_Node_List &wq) {
  for (uint i = 0; i < n->req(); i++) {
    Node* in = n->in(i);
    if (in != nullptr && phase->has_ctrl(in) && phase->get_ctrl(in) == ctrl) {
      wq.push(in);
    }
  }
}

bool ShenandoahBarrierC2Support::is_dominator_same_ctrl(Node* c, Node* d, Node* n, PhaseIdealLoop* phase) {
  // That both nodes have the same control is not sufficient to prove
  // domination, verify that there's no path from d to n
  ResourceMark rm;
  Unique_Node_List wq;
  wq.push(d);
  for (uint next = 0; next < wq.size(); next++) {
    Node *m = wq.at(next);
    if (m == n) {
      return false;
    }
    if (m->is_Phi() && m->in(0)->is_Loop()) {
      assert(phase->ctrl_or_self(m->in(LoopNode::EntryControl)) != c, "following loop entry should lead to new control");
    } else {
      // Take anti-dependencies into account
      maybe_push_anti_dependent_loads(phase, m, c, wq);
      push_data_inputs_at_control(phase, m, c, wq);
    }
  }
  return true;
}

bool ShenandoahBarrierC2Support::is_dominator(Node* d_c, Node* n_c, Node* d, Node* n, PhaseIdealLoop* phase) {
  if (d_c != n_c) {
    return phase->is_dominator(d_c, n_c);
  }
  return is_dominator_same_ctrl(d_c, d, n, phase);
}

Node* next_mem(Node* mem, int alias) {
  Node* res = nullptr;
  if (mem->is_Proj()) {
    res = mem->in(0);
  } else if (mem->is_SafePoint() || mem->is_MemBar()) {
    res = mem->in(TypeFunc::Memory);
  } else if (mem->is_Phi()) {
    res = mem->in(1);
  } else if (mem->is_MergeMem()) {
    res = mem->as_MergeMem()->memory_at(alias);
  } else if (mem->is_Store() || mem->is_LoadStore() || mem->is_ClearArray()) {
    assert(alias == Compile::AliasIdxRaw, "following raw memory can't lead to a barrier");
    res = mem->in(MemNode::Memory);
  } else {
#ifdef ASSERT
    mem->dump();
#endif
    ShouldNotReachHere();
  }
  return res;
}

Node* ShenandoahBarrierC2Support::no_branches(Node* c, Node* dom, bool allow_one_proj, PhaseIdealLoop* phase) {
  Node* iffproj = nullptr;
  while (c != dom) {
    Node* next = phase->idom(c);
    assert(next->unique_ctrl_out_or_null() == c || c->is_Proj() || c->is_Region(), "multiple control flow out but no proj or region?");
    if (c->is_Region()) {
      ResourceMark rm;
      Unique_Node_List wq;
      wq.push(c);
      for (uint i = 0; i < wq.size(); i++) {
        Node *n = wq.at(i);
        if (n == next) {
          continue;
        }
        if (n->is_Region()) {
          for (uint j = 1; j < n->req(); j++) {
            wq.push(n->in(j));
          }
        } else {
          wq.push(n->in(0));
        }
      }
      for (uint i = 0; i < wq.size(); i++) {
        Node *n = wq.at(i);
        assert(n->is_CFG(), "");
        if (n->is_Multi()) {
          for (DUIterator_Fast jmax, j = n->fast_outs(jmax); j < jmax; j++) {
            Node* u = n->fast_out(j);
            if (u->is_CFG()) {
              if (!wq.member(u) && !u->as_Proj()->is_uncommon_trap_proj()) {
                return NodeSentinel;
              }
            }
          }
        }
      }
    } else  if (c->is_Proj()) {
      if (c->is_IfProj()) {
        if (c->as_Proj()->is_uncommon_trap_if_pattern() != nullptr) {
          // continue;
        } else {
          if (!allow_one_proj) {
            return NodeSentinel;
          }
          if (iffproj == nullptr) {
            iffproj = c;
          } else {
            return NodeSentinel;
          }
        }
      } else if (c->Opcode() == Op_JumpProj) {
        return NodeSentinel; // unsupported
      } else if (c->Opcode() == Op_CatchProj) {
        return NodeSentinel; // unsupported
      } else if (c->Opcode() == Op_CProj && next->is_NeverBranch()) {
        return NodeSentinel; // unsupported
      } else {
        assert(next->unique_ctrl_out() == c, "unsupported branch pattern");
      }
    }
    c = next;
  }
  return iffproj;
}

Node* ShenandoahBarrierC2Support::dom_mem(Node* mem, Node* ctrl, int alias, Node*& mem_ctrl, PhaseIdealLoop* phase) {
  ResourceMark rm;
  VectorSet wq;
  wq.set(mem->_idx);
  mem_ctrl = phase->ctrl_or_self(mem);
  while (!phase->is_dominator(mem_ctrl, ctrl) || mem_ctrl == ctrl) {
    mem = next_mem(mem, alias);
    if (wq.test_set(mem->_idx)) {
      return nullptr;
    }
    mem_ctrl = phase->ctrl_or_self(mem);
  }
  if (mem->is_MergeMem()) {
    mem = mem->as_MergeMem()->memory_at(alias);
    mem_ctrl = phase->ctrl_or_self(mem);
  }
  return mem;
}

Node* ShenandoahBarrierC2Support::find_bottom_mem(Node* ctrl, PhaseIdealLoop* phase) {
  Node* mem = nullptr;
  Node* c = ctrl;
  do {
    if (c->is_Region()) {
      for (DUIterator_Fast imax, i = c->fast_outs(imax); i < imax && mem == nullptr; i++) {
        Node* u = c->fast_out(i);
        if (u->is_Phi() && u->bottom_type() == Type::MEMORY) {
          if (u->adr_type() == TypePtr::BOTTOM) {
            mem = u;
          }
        }
      }
    } else {
      if (c->is_Call() && c->as_Call()->adr_type() != nullptr) {
        CallProjections projs;
        c->as_Call()->extract_projections(&projs, true, false);
        if (projs.fallthrough_memproj != nullptr) {
          if (projs.fallthrough_memproj->adr_type() == TypePtr::BOTTOM) {
            if (projs.catchall_memproj == nullptr) {
              mem = projs.fallthrough_memproj;
            } else {
              if (phase->is_dominator(projs.fallthrough_catchproj, ctrl)) {
                mem = projs.fallthrough_memproj;
              } else {
                assert(phase->is_dominator(projs.catchall_catchproj, ctrl), "one proj must dominate barrier");
                mem = projs.catchall_memproj;
              }
            }
          }
        } else {
          Node* proj = c->as_Call()->proj_out(TypeFunc::Memory);
          if (proj != nullptr &&
              proj->adr_type() == TypePtr::BOTTOM) {
            mem = proj;
          }
        }
      } else {
        for (DUIterator_Fast imax, i = c->fast_outs(imax); i < imax; i++) {
          Node* u = c->fast_out(i);
          if (u->is_Proj() &&
              u->bottom_type() == Type::MEMORY &&
              u->adr_type() == TypePtr::BOTTOM) {
              assert(c->is_SafePoint() || c->is_MemBar() || c->is_Start(), "");
              assert(mem == nullptr, "only one proj");
              mem = u;
          }
        }
        assert(!c->is_Call() || c->as_Call()->adr_type() != nullptr || mem == nullptr, "no mem projection expected");
      }
    }
    c = phase->idom(c);
  } while (mem == nullptr);
  return mem;
}

void ShenandoahBarrierC2Support::follow_barrier_uses(Node* n, Node* ctrl, Unique_Node_List& uses, PhaseIdealLoop* phase) {
  for (DUIterator_Fast imax, i = n->fast_outs(imax); i < imax; i++) {
    Node* u = n->fast_out(i);
    if (!u->is_CFG() && phase->get_ctrl(u) == ctrl && (!u->is_Phi() || !u->in(0)->is_Loop() || u->in(LoopNode::LoopBackControl) != n)) {
      uses.push(u);
    }
  }
}

static void hide_strip_mined_loop(OuterStripMinedLoopNode* outer, CountedLoopNode* inner, PhaseIdealLoop* phase) {
  OuterStripMinedLoopEndNode* le = inner->outer_loop_end();
  Node* new_outer = new LoopNode(outer->in(LoopNode::EntryControl), outer->in(LoopNode::LoopBackControl));
  phase->register_control(new_outer, phase->get_loop(outer), outer->in(LoopNode::EntryControl));
  Node* new_le = new IfNode(le->in(0), le->in(1), le->_prob, le->_fcnt);
  phase->register_control(new_le, phase->get_loop(le), le->in(0));
  phase->lazy_replace(outer, new_outer);
  phase->lazy_replace(le, new_le);
  inner->clear_strip_mined();
}

void ShenandoahBarrierC2Support::test_gc_state(Node*& ctrl, Node* raw_mem, Node*& test_fail_ctrl,
                                               PhaseIdealLoop* phase, int flags) {
  PhaseIterGVN& igvn = phase->igvn();
  Node* old_ctrl = ctrl;

  Node* thread          = new ThreadLocalNode();
  Node* gc_state_offset = igvn.MakeConX(in_bytes(ShenandoahThreadLocalData::gc_state_offset()));
  Node* gc_state_addr   = new AddPNode(phase->C->top(), thread, gc_state_offset);
  Node* gc_state        = new LoadBNode(old_ctrl, raw_mem, gc_state_addr,
                                        DEBUG_ONLY(phase->C->get_adr_type(Compile::AliasIdxRaw)) NOT_DEBUG(nullptr),
                                        TypeInt::BYTE, MemNode::unordered);
  Node* gc_state_and    = new AndINode(gc_state, igvn.intcon(flags));
  Node* gc_state_cmp    = new CmpINode(gc_state_and, igvn.zerocon(T_INT));
  Node* gc_state_bool   = new BoolNode(gc_state_cmp, BoolTest::ne);

  IfNode* gc_state_iff  = new IfNode(old_ctrl, gc_state_bool, PROB_UNLIKELY(0.999), COUNT_UNKNOWN);
  ctrl                  = new IfTrueNode(gc_state_iff);
  test_fail_ctrl        = new IfFalseNode(gc_state_iff);

  IdealLoopTree* loop = phase->get_loop(old_ctrl);
  phase->register_control(gc_state_iff,   loop, old_ctrl);
  phase->register_control(ctrl,           loop, gc_state_iff);
  phase->register_control(test_fail_ctrl, loop, gc_state_iff);

  phase->register_new_node(thread,        old_ctrl);
  phase->register_new_node(gc_state_addr, old_ctrl);
  phase->register_new_node(gc_state,      old_ctrl);
  phase->register_new_node(gc_state_and,  old_ctrl);
  phase->register_new_node(gc_state_cmp,  old_ctrl);
  phase->register_new_node(gc_state_bool, old_ctrl);

  phase->set_root_as_ctrl(gc_state_offset);

  assert(is_gc_state_test(gc_state_iff, flags), "Should match the shape");
}

void ShenandoahBarrierC2Support::test_null(Node*& ctrl, Node* val, Node*& null_ctrl, PhaseIdealLoop* phase) {
  Node* old_ctrl = ctrl;
  PhaseIterGVN& igvn = phase->igvn();

  const Type* val_t = igvn.type(val);
  if (val_t->meet(TypePtr::NULL_PTR) == val_t) {
    Node* null_cmp   = new CmpPNode(val, igvn.zerocon(T_OBJECT));
    Node* null_test  = new BoolNode(null_cmp, BoolTest::ne);

    IfNode* null_iff = new IfNode(old_ctrl, null_test, PROB_LIKELY(0.999), COUNT_UNKNOWN);
    ctrl             = new IfTrueNode(null_iff);
    null_ctrl        = new IfFalseNode(null_iff);

    IdealLoopTree* loop = phase->get_loop(old_ctrl);
    phase->register_control(null_iff,  loop, old_ctrl);
    phase->register_control(ctrl,      loop, null_iff);
    phase->register_control(null_ctrl, loop, null_iff);

    phase->register_new_node(null_cmp,  old_ctrl);
    phase->register_new_node(null_test, old_ctrl);
  }
}

void ShenandoahBarrierC2Support::test_in_cset(Node*& ctrl, Node*& not_cset_ctrl, Node* val, Node* raw_mem, PhaseIdealLoop* phase) {
  Node* old_ctrl = ctrl;
  PhaseIterGVN& igvn = phase->igvn();

  Node* raw_val        = new CastP2XNode(old_ctrl, val);
  Node* cset_idx       = new URShiftXNode(raw_val, igvn.intcon(ShenandoahHeapRegion::region_size_bytes_shift_jint()));

  // Figure out the target cset address with raw pointer math.
  // This avoids matching AddP+LoadB that would emit inefficient code.
  // See JDK-8245465.
  Node* cset_addr_ptr  = igvn.makecon(TypeRawPtr::make(ShenandoahHeap::in_cset_fast_test_addr()));
  Node* cset_addr      = new CastP2XNode(old_ctrl, cset_addr_ptr);
  Node* cset_load_addr = new AddXNode(cset_addr, cset_idx);
  Node* cset_load_ptr  = new CastX2PNode(cset_load_addr);

  Node* cset_load      = new LoadBNode(old_ctrl, raw_mem, cset_load_ptr,
                                       DEBUG_ONLY(phase->C->get_adr_type(Compile::AliasIdxRaw)) NOT_DEBUG(nullptr),
                                       TypeInt::BYTE, MemNode::unordered);
  Node* cset_cmp       = new CmpINode(cset_load, igvn.zerocon(T_INT));
  Node* cset_bool      = new BoolNode(cset_cmp, BoolTest::ne);

  IfNode* cset_iff     = new IfNode(old_ctrl, cset_bool, PROB_UNLIKELY(0.999), COUNT_UNKNOWN);
  ctrl                 = new IfTrueNode(cset_iff);
  not_cset_ctrl        = new IfFalseNode(cset_iff);

  IdealLoopTree *loop = phase->get_loop(old_ctrl);
  phase->register_control(cset_iff,      loop, old_ctrl);
  phase->register_control(ctrl,          loop, cset_iff);
  phase->register_control(not_cset_ctrl, loop, cset_iff);

  phase->set_root_as_ctrl(cset_addr_ptr);

  phase->register_new_node(raw_val,        old_ctrl);
  phase->register_new_node(cset_idx,       old_ctrl);
  phase->register_new_node(cset_addr,      old_ctrl);
  phase->register_new_node(cset_load_addr, old_ctrl);
  phase->register_new_node(cset_load_ptr,  old_ctrl);
  phase->register_new_node(cset_load,      old_ctrl);
  phase->register_new_node(cset_cmp,       old_ctrl);
  phase->register_new_node(cset_bool,      old_ctrl);
}

void ShenandoahBarrierC2Support::call_lrb_stub(Node*& ctrl, Node*& val, Node* load_addr,
                                               DecoratorSet decorators, PhaseIdealLoop* phase) {
  IdealLoopTree*loop = phase->get_loop(ctrl);
  const TypePtr* obj_type = phase->igvn().type(val)->is_oopptr();

  address calladdr = nullptr;
  const char* name = nullptr;
  bool is_strong  = ShenandoahBarrierSet::is_strong_access(decorators);
  bool is_weak    = ShenandoahBarrierSet::is_weak_access(decorators);
  bool is_phantom = ShenandoahBarrierSet::is_phantom_access(decorators);
  bool is_native  = ShenandoahBarrierSet::is_native_access(decorators);
  bool is_narrow  = UseCompressedOops && !is_native;
  if (is_strong) {
    if (is_narrow) {
      calladdr = CAST_FROM_FN_PTR(address, ShenandoahRuntime::load_reference_barrier_strong_narrow);
      name = "load_reference_barrier_strong_narrow";
    } else {
      calladdr = CAST_FROM_FN_PTR(address, ShenandoahRuntime::load_reference_barrier_strong);
      name = "load_reference_barrier_strong";
    }
  } else if (is_weak) {
    if (is_narrow) {
      calladdr = CAST_FROM_FN_PTR(address, ShenandoahRuntime::load_reference_barrier_weak_narrow);
      name = "load_reference_barrier_weak_narrow";
    } else {
      calladdr = CAST_FROM_FN_PTR(address, ShenandoahRuntime::load_reference_barrier_weak);
      name = "load_reference_barrier_weak";
    }
  } else {
    assert(is_phantom, "only remaining strength");
    if (is_narrow) {
      calladdr = CAST_FROM_FN_PTR(address, ShenandoahRuntime::load_reference_barrier_phantom_narrow);
      name = "load_reference_barrier_phantom_narrow";
    } else {
      calladdr = CAST_FROM_FN_PTR(address, ShenandoahRuntime::load_reference_barrier_phantom);
      name = "load_reference_barrier_phantom";
    }
  }
  Node* call = new CallLeafNode(ShenandoahBarrierSetC2::load_reference_barrier_Type(), calladdr, name, TypeRawPtr::BOTTOM);

  call->init_req(TypeFunc::Control, ctrl);
  call->init_req(TypeFunc::I_O, phase->C->top());
  call->init_req(TypeFunc::Memory, phase->C->top());
  call->init_req(TypeFunc::FramePtr, phase->C->top());
  call->init_req(TypeFunc::ReturnAdr, phase->C->top());
  call->init_req(TypeFunc::Parms, val);
  call->init_req(TypeFunc::Parms+1, load_addr);
  phase->register_control(call, loop, ctrl);
  ctrl = new ProjNode(call, TypeFunc::Control);
  phase->register_control(ctrl, loop, call);
  val = new ProjNode(call, TypeFunc::Parms);
  phase->register_new_node(val, call);
  val = new CheckCastPPNode(ctrl, val, obj_type);
  phase->register_new_node(val, ctrl);
}

void ShenandoahBarrierC2Support::collect_nodes_above_barrier(Unique_Node_List &nodes_above_barrier, PhaseIdealLoop* phase, Node* ctrl, Node* init_raw_mem) {
  nodes_above_barrier.clear();
  if (phase->has_ctrl(init_raw_mem) && phase->get_ctrl(init_raw_mem) == ctrl && !init_raw_mem->is_Phi()) {
    nodes_above_barrier.push(init_raw_mem);
  }
  for (uint next = 0; next < nodes_above_barrier.size(); next++) {
    Node* n = nodes_above_barrier.at(next);
    // Take anti-dependencies into account
    maybe_push_anti_dependent_loads(phase, n, ctrl, nodes_above_barrier);
    push_data_inputs_at_control(phase, n, ctrl, nodes_above_barrier);
  }
}

void ShenandoahBarrierC2Support::fix_ctrl(Node* barrier, Node* region, const MemoryGraphFixer& fixer, Unique_Node_List& uses, Unique_Node_List& nodes_above_barrier, uint last, PhaseIdealLoop* phase) {
  Node* ctrl = phase->get_ctrl(barrier);
  Node* init_raw_mem = fixer.find_mem(ctrl, barrier);

  // Update the control of all nodes that should be after the
  // barrier control flow
  uses.clear();
  // Every node that is control dependent on the barrier's input
  // control will be after the expanded barrier. The raw memory (if
  // its memory is control dependent on the barrier's input control)
  // must stay above the barrier.
  collect_nodes_above_barrier(nodes_above_barrier, phase, ctrl, init_raw_mem);
  for (DUIterator_Fast imax, i = ctrl->fast_outs(imax); i < imax; i++) {
    Node* u = ctrl->fast_out(i);
    if (u->_idx < last &&
        u != barrier &&
        !u->depends_only_on_test() && // preserve dependency on test
        !nodes_above_barrier.member(u) &&
        (u->in(0) != ctrl || (!u->is_Region() && !u->is_Phi())) &&
        (ctrl->Opcode() != Op_CatchProj || u->Opcode() != Op_CreateEx)) {
      Node* old_c = phase->ctrl_or_self(u);
      if (old_c != ctrl ||
          is_dominator_same_ctrl(old_c, barrier, u, phase) ||
          ShenandoahBarrierSetC2::is_shenandoah_state_load(u)) {
        phase->igvn().rehash_node_delayed(u);
        int nb = u->replace_edge(ctrl, region, &phase->igvn());
        if (u->is_CFG()) {
          if (phase->idom(u) == ctrl) {
            phase->set_idom(u, region, phase->dom_depth(region));
          }
        } else if (phase->get_ctrl(u) == ctrl) {
          assert(u != init_raw_mem, "should leave input raw mem above the barrier");
          uses.push(u);
        }
        assert(nb == 1, "more than 1 ctrl input?");
        --i, imax -= nb;
      }
    }
  }
}

static Node* create_phis_on_call_return(Node* ctrl, Node* c, Node* n, Node* n_clone, const CallProjections& projs, PhaseIdealLoop* phase) {
  Node* region = nullptr;
  while (c != ctrl) {
    if (c->is_Region()) {
      region = c;
    }
    c = phase->idom(c);
  }
  assert(region != nullptr, "");
  Node* phi = new PhiNode(region, n->bottom_type());
  for (uint j = 1; j < region->req(); j++) {
    Node* in = region->in(j);
    if (phase->is_dominator(projs.fallthrough_catchproj, in)) {
      phi->init_req(j, n);
    } else if (phase->is_dominator(projs.catchall_catchproj, in)) {
      phi->init_req(j, n_clone);
    } else {
      phi->init_req(j, create_phis_on_call_return(ctrl, in, n, n_clone, projs, phase));
    }
  }
  phase->register_new_node(phi, region);
  return phi;
}

void ShenandoahBarrierC2Support::pin_and_expand(PhaseIdealLoop* phase) {
  ShenandoahBarrierSetC2State* state = ShenandoahBarrierSetC2::bsc2()->state();

  Unique_Node_List uses;
  Node_Stack stack(0);
  Node_List clones;
  for (int i = state->load_reference_barriers_count() - 1; i >= 0; i--) {
    ShenandoahLoadReferenceBarrierNode* lrb = state->load_reference_barrier(i);

    Node* ctrl = phase->get_ctrl(lrb);
    Node* val = lrb->in(ShenandoahLoadReferenceBarrierNode::ValueIn);

    CallStaticJavaNode* unc = nullptr;
    Node* unc_ctrl = nullptr;
    Node* uncasted_val = val;

    for (DUIterator_Fast imax, i = lrb->fast_outs(imax); i < imax; i++) {
      Node* u = lrb->fast_out(i);
      if (u->Opcode() == Op_CastPP &&
          u->in(0) != nullptr &&
          phase->is_dominator(u->in(0), ctrl)) {
        const Type* u_t = phase->igvn().type(u);

        if (u_t->meet(TypePtr::NULL_PTR) != u_t &&
            u->in(0)->Opcode() == Op_IfTrue &&
            u->in(0)->as_Proj()->is_uncommon_trap_if_pattern() &&
            u->in(0)->in(0)->is_If() &&
            u->in(0)->in(0)->in(1)->Opcode() == Op_Bool &&
            u->in(0)->in(0)->in(1)->as_Bool()->_test._test == BoolTest::ne &&
            u->in(0)->in(0)->in(1)->in(1)->Opcode() == Op_CmpP &&
            u->in(0)->in(0)->in(1)->in(1)->in(1) == val &&
            u->in(0)->in(0)->in(1)->in(1)->in(2)->bottom_type() == TypePtr::NULL_PTR) {
          IdealLoopTree* loop = phase->get_loop(ctrl);
          IdealLoopTree* unc_loop = phase->get_loop(u->in(0));

          if (!unc_loop->is_member(loop)) {
            continue;
          }

          Node* branch = no_branches(ctrl, u->in(0), false, phase);
          assert(branch == nullptr || branch == NodeSentinel, "was not looking for a branch");
          if (branch == NodeSentinel) {
            continue;
          }

          Node* iff = u->in(0)->in(0);
          Node* bol = iff->in(1)->clone();
          Node* cmp = bol->in(1)->clone();
          cmp->set_req(1, lrb);
          bol->set_req(1, cmp);
          phase->igvn().replace_input_of(iff, 1, bol);
          phase->set_ctrl(lrb, iff->in(0));
          phase->register_new_node(cmp, iff->in(0));
          phase->register_new_node(bol, iff->in(0));
          break;
        }
      }
    }
    // Load barrier on the control output of a call
    if ((ctrl->is_Proj() && ctrl->in(0)->is_CallJava()) || ctrl->is_CallJava()) {
      CallJavaNode* call = ctrl->is_Proj() ? ctrl->in(0)->as_CallJava() : ctrl->as_CallJava();
      if (call->entry_point() == OptoRuntime::rethrow_stub()) {
        // The rethrow call may have too many projections to be
        // properly handled here. Given there's no reason for a
        // barrier to depend on the call, move it above the call
        stack.push(lrb, 0);
        do {
          Node* n = stack.node();
          uint idx = stack.index();
          if (idx < n->req()) {
            Node* in = n->in(idx);
            stack.set_index(idx+1);
            if (in != nullptr) {
              if (phase->has_ctrl(in)) {
                if (phase->is_dominator(call, phase->get_ctrl(in))) {
#ifdef ASSERT
                  for (uint i = 0; i < stack.size(); i++) {
                    assert(stack.node_at(i) != in, "node shouldn't have been seen yet");
                  }
#endif
                  stack.push(in, 0);
                }
              } else {
                assert(phase->is_dominator(in, call->in(0)), "no dependency on the call");
              }
            }
          } else {
            phase->set_ctrl(n, call->in(0));
            stack.pop();
          }
        } while(stack.size() > 0);
        continue;
      }
      CallProjections projs;
      call->extract_projections(&projs, false, false);

      // If this is a runtime call, it doesn't have an exception handling path
      if (projs.fallthrough_catchproj == nullptr) {
        assert(call->method() == nullptr, "should be runtime call");
        assert(projs.catchall_catchproj == nullptr, "runtime call should not have catch all projection");
        continue;
      }

      // Otherwise, clone the barrier so there's one for the fallthrough and one for the exception handling path
#ifdef ASSERT
      VectorSet cloned;
#endif
      Node* lrb_clone = lrb->clone();
      phase->register_new_node(lrb_clone, projs.catchall_catchproj);
      phase->set_ctrl(lrb, projs.fallthrough_catchproj);

      stack.push(lrb, 0);
      clones.push(lrb_clone);

      do {
        assert(stack.size() == clones.size(), "");
        Node* n = stack.node();
#ifdef ASSERT
        if (n->is_Load()) {
          Node* mem = n->in(MemNode::Memory);
          for (DUIterator_Fast jmax, j = mem->fast_outs(jmax); j < jmax; j++) {
            Node* u = mem->fast_out(j);
            assert(!u->is_Store() || !u->is_LoadStore() || phase->get_ctrl(u) != ctrl, "anti dependent store?");
          }
        }
#endif
        uint idx = stack.index();
        Node* n_clone = clones.at(clones.size()-1);
        if (idx < n->outcnt()) {
          Node* u = n->raw_out(idx);
          Node* c = phase->ctrl_or_self(u);
          if (phase->is_dominator(call, c) && phase->is_dominator(c, projs.fallthrough_proj)) {
            stack.set_index(idx+1);
            assert(!u->is_CFG(), "");
            stack.push(u, 0);
            assert(!cloned.test_set(u->_idx), "only one clone");
            Node* u_clone = u->clone();
            int nb = u_clone->replace_edge(n, n_clone, &phase->igvn());
            assert(nb > 0, "should have replaced some uses");
            phase->register_new_node(u_clone, projs.catchall_catchproj);
            clones.push(u_clone);
            phase->set_ctrl(u, projs.fallthrough_catchproj);
          } else {
            bool replaced = false;
            if (u->is_Phi()) {
              for (uint k = 1; k < u->req(); k++) {
                if (u->in(k) == n) {
                  if (phase->is_dominator(projs.catchall_catchproj, u->in(0)->in(k))) {
                    phase->igvn().replace_input_of(u, k, n_clone);
                    replaced = true;
                  } else if (!phase->is_dominator(projs.fallthrough_catchproj, u->in(0)->in(k))) {
                    phase->igvn().replace_input_of(u, k, create_phis_on_call_return(ctrl, u->in(0)->in(k), n, n_clone, projs, phase));
                    replaced = true;
                  }
                }
              }
            } else {
              if (phase->is_dominator(projs.catchall_catchproj, c)) {
                phase->igvn().rehash_node_delayed(u);
                int nb = u->replace_edge(n, n_clone, &phase->igvn());
                assert(nb > 0, "should have replaced some uses");
                replaced = true;
              } else if (!phase->is_dominator(projs.fallthrough_catchproj, c)) {
                if (u->is_If()) {
                  // Can't break If/Bool/Cmp chain
                  assert(n->is_Bool(), "unexpected If shape");
                  assert(stack.node_at(stack.size()-2)->is_Cmp(), "unexpected If shape");
                  assert(n_clone->is_Bool(), "unexpected clone");
                  assert(clones.at(clones.size()-2)->is_Cmp(), "unexpected clone");
                  Node* bol_clone = n->clone();
                  Node* cmp_clone = stack.node_at(stack.size()-2)->clone();
                  bol_clone->set_req(1, cmp_clone);

                  Node* nn = stack.node_at(stack.size()-3);
                  Node* nn_clone = clones.at(clones.size()-3);
                  assert(nn->Opcode() == nn_clone->Opcode(), "mismatch");

                  int nb = cmp_clone->replace_edge(nn, create_phis_on_call_return(ctrl, c, nn, nn_clone, projs, phase),
                                                   &phase->igvn());
                  assert(nb > 0, "should have replaced some uses");

                  phase->register_new_node(bol_clone, u->in(0));
                  phase->register_new_node(cmp_clone, u->in(0));

                  phase->igvn().replace_input_of(u, 1, bol_clone);

                } else {
                  phase->igvn().rehash_node_delayed(u);
                  int nb = u->replace_edge(n, create_phis_on_call_return(ctrl, c, n, n_clone, projs, phase), &phase->igvn());
                  assert(nb > 0, "should have replaced some uses");
                }
                replaced = true;
              }
            }
            if (!replaced) {
              stack.set_index(idx+1);
            }
          }
        } else {
          stack.pop();
          clones.pop();
        }
      } while (stack.size() > 0);
      assert(stack.size() == 0 && clones.size() == 0, "");
    }
  }

  for (int i = 0; i < state->load_reference_barriers_count(); i++) {
    ShenandoahLoadReferenceBarrierNode* lrb = state->load_reference_barrier(i);
    Node* ctrl = phase->get_ctrl(lrb);
    IdealLoopTree* loop = phase->get_loop(ctrl);
    Node* head = loop->head();
    if (head->is_OuterStripMinedLoop()) {
      // Expanding a barrier here will break loop strip mining
      // verification. Transform the loop so the loop nest doesn't
      // appear as strip mined.
      OuterStripMinedLoopNode* outer = head->as_OuterStripMinedLoop();
      hide_strip_mined_loop(outer, outer->unique_ctrl_out()->as_CountedLoop(), phase);
    }
    if (head->is_BaseCountedLoop() && ctrl->is_IfProj() && ctrl->in(0)->is_BaseCountedLoopEnd() &&
        head->as_BaseCountedLoop()->loopexit() == ctrl->in(0)) {
      Node* entry = head->in(LoopNode::EntryControl);
      Node* backedge = head->in(LoopNode::LoopBackControl);
      Node* new_head = new LoopNode(entry, backedge);
      phase->register_control(new_head, phase->get_loop(entry), entry);
      phase->lazy_replace(head, new_head);
    }
  }

  // Expand load-reference-barriers
  MemoryGraphFixer fixer(Compile::AliasIdxRaw, true, phase);
  Unique_Node_List nodes_above_barriers;
  for (int i = state->load_reference_barriers_count() - 1; i >= 0; i--) {
    ShenandoahLoadReferenceBarrierNode* lrb = state->load_reference_barrier(i);
    uint last = phase->C->unique();
    Node* ctrl = phase->get_ctrl(lrb);
    Node* val = lrb->in(ShenandoahLoadReferenceBarrierNode::ValueIn);

    Node* orig_ctrl = ctrl;

    Node* raw_mem = fixer.find_mem(ctrl, lrb);
    Node* raw_mem_for_ctrl = fixer.find_mem(ctrl, nullptr);

    IdealLoopTree *loop = phase->get_loop(ctrl);

    Node* heap_stable_ctrl = nullptr;
    Node* null_ctrl = nullptr;

    assert(val->bottom_type()->make_oopptr(), "need oop");
    assert(val->bottom_type()->make_oopptr()->const_oop() == nullptr, "expect non-constant");

    enum { _heap_stable = 1, _evac_path, _not_cset, PATH_LIMIT };
    Node* region = new RegionNode(PATH_LIMIT);
    Node* val_phi = new PhiNode(region, val->bottom_type()->is_oopptr());

    // Stable path.
    int flags = ShenandoahHeap::HAS_FORWARDED;
    if (!ShenandoahBarrierSet::is_strong_access(lrb->decorators())) {
      flags |= ShenandoahHeap::WEAK_ROOTS;
    }
    test_gc_state(ctrl, raw_mem, heap_stable_ctrl, phase, flags);
    IfNode* heap_stable_iff = heap_stable_ctrl->in(0)->as_If();

    // Heap stable case
    region->init_req(_heap_stable, heap_stable_ctrl);
    val_phi->init_req(_heap_stable, val);

    // Test for in-cset, unless it's a native-LRB. Native LRBs need to return null
    // even for non-cset objects to prevent resurrection of such objects.
    // Wires !in_cset(obj) to slot 2 of region and phis
    Node* not_cset_ctrl = nullptr;
    if (ShenandoahBarrierSet::is_strong_access(lrb->decorators())) {
      test_in_cset(ctrl, not_cset_ctrl, val, raw_mem, phase);
    }
    if (not_cset_ctrl != nullptr) {
      region->init_req(_not_cset, not_cset_ctrl);
      val_phi->init_req(_not_cset, val);
    } else {
      region->del_req(_not_cset);
      val_phi->del_req(_not_cset);
    }

    // Resolve object when orig-value is in cset.
    // Make the unconditional resolve for fwdptr.

    // Call lrb-stub and wire up that path in slots 4
    Node* result_mem = nullptr;

    Node* addr;
    {
      VectorSet visited;
      addr = get_load_addr(phase, visited, lrb);
    }
    if (addr->Opcode() == Op_AddP) {
      Node* orig_base = addr->in(AddPNode::Base);
      Node* base = new CheckCastPPNode(ctrl, orig_base, orig_base->bottom_type(), ConstraintCastNode::StrongDependency);
      phase->register_new_node(base, ctrl);
      if (addr->in(AddPNode::Base) == addr->in((AddPNode::Address))) {
        // Field access
        addr = addr->clone();
        addr->set_req(AddPNode::Base, base);
        addr->set_req(AddPNode::Address, base);
        phase->register_new_node(addr, ctrl);
      } else {
        Node* addr2 = addr->in(AddPNode::Address);
        if (addr2->Opcode() == Op_AddP && addr2->in(AddPNode::Base) == addr2->in(AddPNode::Address) &&
              addr2->in(AddPNode::Base) == orig_base) {
          addr2 = addr2->clone();
          addr2->set_req(AddPNode::Base, base);
          addr2->set_req(AddPNode::Address, base);
          phase->register_new_node(addr2, ctrl);
          addr = addr->clone();
          addr->set_req(AddPNode::Base, base);
          addr->set_req(AddPNode::Address, addr2);
          phase->register_new_node(addr, ctrl);
        }
      }
    }
    call_lrb_stub(ctrl, val, addr, lrb->decorators(), phase);
    region->init_req(_evac_path, ctrl);
    val_phi->init_req(_evac_path, val);

    phase->register_control(region, loop, heap_stable_iff);
    Node* out_val = val_phi;
    phase->register_new_node(val_phi, region);

    fix_ctrl(lrb, region, fixer, uses, nodes_above_barriers, last, phase);

    ctrl = orig_ctrl;

    phase->igvn().replace_node(lrb, out_val);

    follow_barrier_uses(out_val, ctrl, uses, phase);

    for(uint next = 0; next < uses.size(); next++ ) {
      Node *n = uses.at(next);
      assert(phase->get_ctrl(n) == ctrl, "bad control");
      assert(n != raw_mem, "should leave input raw mem above the barrier");
      phase->set_ctrl(n, region);
      follow_barrier_uses(n, ctrl, uses, phase);
    }
    fixer.record_new_ctrl(ctrl, region, raw_mem, raw_mem_for_ctrl);
  }
  // Done expanding load-reference-barriers.
  assert(ShenandoahBarrierSetC2::bsc2()->state()->load_reference_barriers_count() == 0, "all load reference barrier nodes should have been replaced");
}

Node* ShenandoahBarrierC2Support::get_load_addr(PhaseIdealLoop* phase, VectorSet& visited, Node* in) {
  if (visited.test_set(in->_idx)) {
    return nullptr;
  }
  switch (in->Opcode()) {
    case Op_Proj:
      return get_load_addr(phase, visited, in->in(0));
    case Op_CastPP:
    case Op_CheckCastPP:
    case Op_DecodeN:
    case Op_EncodeP:
      return get_load_addr(phase, visited, in->in(1));
    case Op_LoadN:
    case Op_LoadP:
      return in->in(MemNode::Address);
    case Op_CompareAndExchangeN:
    case Op_CompareAndExchangeP:
    case Op_GetAndSetN:
    case Op_GetAndSetP:
    case Op_ShenandoahCompareAndExchangeP:
    case Op_ShenandoahCompareAndExchangeN:
      // Those instructions would just have stored a different
      // value into the field. No use to attempt to fix it at this point.
      return phase->igvn().zerocon(T_OBJECT);
    case Op_CMoveP:
    case Op_CMoveN: {
      Node* t = get_load_addr(phase, visited, in->in(CMoveNode::IfTrue));
      Node* f = get_load_addr(phase, visited, in->in(CMoveNode::IfFalse));
      // Handle unambiguous cases: single address reported on both branches.
      if (t != nullptr && f == nullptr) return t;
      if (t == nullptr && f != nullptr) return f;
      if (t != nullptr && t == f)    return t;
      // Ambiguity.
      return phase->igvn().zerocon(T_OBJECT);
    }
    case Op_Phi: {
      Node* addr = nullptr;
      for (uint i = 1; i < in->req(); i++) {
        Node* addr1 = get_load_addr(phase, visited, in->in(i));
        if (addr == nullptr) {
          addr = addr1;
        }
        if (addr != addr1) {
          return phase->igvn().zerocon(T_OBJECT);
        }
      }
      return addr;
    }
    case Op_ShenandoahLoadReferenceBarrier:
      return get_load_addr(phase, visited, in->in(ShenandoahLoadReferenceBarrierNode::ValueIn));
    case Op_CallDynamicJava:
    case Op_CallLeaf:
    case Op_CallStaticJava:
    case Op_ConN:
    case Op_ConP:
    case Op_Parm:
    case Op_CreateEx:
      return phase->igvn().zerocon(T_OBJECT);
    default:
#ifdef ASSERT
      fatal("Unknown node in get_load_addr: %s", NodeClassNames[in->Opcode()]);
#endif
      return phase->igvn().zerocon(T_OBJECT);
  }

}

#ifdef ASSERT
static bool has_never_branch(Node* root) {
  for (uint i = 1; i < root->req(); i++) {
    Node* in = root->in(i);
    if (in != nullptr && in->Opcode() == Op_Halt && in->in(0)->is_Proj() && in->in(0)->in(0)->is_NeverBranch()) {
      return true;
    }
  }
  return false;
}
#endif

void MemoryGraphFixer::collect_memory_nodes() {
  Node_Stack stack(0);
  VectorSet visited;
  Node_List regions;

  // Walk the raw memory graph and create a mapping from CFG node to
  // memory node. Exclude phis for now.
  stack.push(_phase->C->root(), 1);
  do {
    Node* n = stack.node();
    int opc = n->Opcode();
    uint i = stack.index();
    if (i < n->req()) {
      Node* mem = nullptr;
      if (opc == Op_Root) {
        Node* in = n->in(i);
        int in_opc = in->Opcode();
        if (in_opc == Op_Return || in_opc == Op_Rethrow) {
          mem = in->in(TypeFunc::Memory);
        } else if (in_opc == Op_Halt) {
          if (in->in(0)->is_Region()) {
            Node* r = in->in(0);
            for (uint j = 1; j < r->req(); j++) {
              assert(!r->in(j)->is_NeverBranch(), "");
            }
          } else {
            Node* proj = in->in(0);
            assert(proj->is_Proj(), "");
            Node* in = proj->in(0);
            assert(in->is_CallStaticJava() || in->is_NeverBranch() || in->Opcode() == Op_Catch || proj->is_IfProj(), "");
            if (in->is_CallStaticJava()) {
              mem = in->in(TypeFunc::Memory);
            } else if (in->Opcode() == Op_Catch) {
              Node* call = in->in(0)->in(0);
              assert(call->is_Call(), "");
              mem = call->in(TypeFunc::Memory);
            } else if (in->is_NeverBranch()) {
              mem = collect_memory_for_infinite_loop(in);
            }
          }
        } else {
#ifdef ASSERT
          n->dump();
          in->dump();
#endif
          ShouldNotReachHere();
        }
      } else {
        assert(n->is_Phi() && n->bottom_type() == Type::MEMORY, "");
        assert(n->adr_type() == TypePtr::BOTTOM || _phase->C->get_alias_index(n->adr_type()) == _alias, "");
        mem = n->in(i);
      }
      i++;
      stack.set_index(i);
      if (mem == nullptr) {
        continue;
      }
      for (;;) {
        if (visited.test_set(mem->_idx) || mem->is_Start()) {
          break;
        }
        if (mem->is_Phi()) {
          stack.push(mem, 2);
          mem = mem->in(1);
        } else if (mem->is_Proj()) {
          stack.push(mem, mem->req());
          mem = mem->in(0);
        } else if (mem->is_SafePoint() || mem->is_MemBar()) {
          mem = mem->in(TypeFunc::Memory);
        } else if (mem->is_MergeMem()) {
          MergeMemNode* mm = mem->as_MergeMem();
          mem = mm->memory_at(_alias);
        } else if (mem->is_Store() || mem->is_LoadStore() || mem->is_ClearArray()) {
          assert(_alias == Compile::AliasIdxRaw, "");
          stack.push(mem, mem->req());
          mem = mem->in(MemNode::Memory);
        } else {
#ifdef ASSERT
          mem->dump();
#endif
          ShouldNotReachHere();
        }
      }
    } else {
      if (n->is_Phi()) {
        // Nothing
      } else if (!n->is_Root()) {
        Node* c = get_ctrl(n);
        _memory_nodes.map(c->_idx, n);
      }
      stack.pop();
    }
  } while(stack.is_nonempty());

  // Iterate over CFG nodes in rpo and propagate memory state to
  // compute memory state at regions, creating new phis if needed.
  Node_List rpo_list;
  visited.clear();
  _phase->rpo(_phase->C->root(), stack, visited, rpo_list);
  Node* root = rpo_list.pop();
  assert(root == _phase->C->root(), "");

  const bool trace = false;
#ifdef ASSERT
  if (trace) {
    for (int i = rpo_list.size() - 1; i >= 0; i--) {
      Node* c = rpo_list.at(i);
      if (_memory_nodes[c->_idx] != nullptr) {
        tty->print("X %d", c->_idx);  _memory_nodes[c->_idx]->dump();
      }
    }
  }
#endif
  uint last = _phase->C->unique();

#ifdef ASSERT
  uint16_t max_depth = 0;
  for (LoopTreeIterator iter(_phase->ltree_root()); !iter.done(); iter.next()) {
    IdealLoopTree* lpt = iter.current();
    max_depth = MAX2(max_depth, lpt->_nest);
  }
#endif

  bool progress = true;
  int iteration = 0;
  Node_List dead_phis;
  while (progress) {
    progress = false;
    iteration++;
    assert(iteration <= 2+max_depth || _phase->C->has_irreducible_loop() || has_never_branch(_phase->C->root()), "");
    if (trace) { tty->print_cr("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"); }

    for (int i = rpo_list.size() - 1; i >= 0; i--) {
      Node* c = rpo_list.at(i);

      Node* prev_mem = _memory_nodes[c->_idx];
      if (c->is_Region() && (_include_lsm || !c->is_OuterStripMinedLoop())) {
        Node* prev_region = regions[c->_idx];
        Node* unique = nullptr;
        for (uint j = 1; j < c->req() && unique != NodeSentinel; j++) {
          Node* m = _memory_nodes[c->in(j)->_idx];
          assert(m != nullptr || (c->is_Loop() && j == LoopNode::LoopBackControl && iteration == 1) || _phase->C->has_irreducible_loop() || has_never_branch(_phase->C->root()), "expect memory state");
          if (m != nullptr) {
            if (m == prev_region && ((c->is_Loop() && j == LoopNode::LoopBackControl) || (prev_region->is_Phi() && prev_region->in(0) == c))) {
              assert((c->is_Loop() && j == LoopNode::LoopBackControl) || _phase->C->has_irreducible_loop() || has_never_branch(_phase->C->root()), "");
              // continue
            } else if (unique == nullptr) {
              unique = m;
            } else if (m == unique) {
              // continue
            } else {
              unique = NodeSentinel;
            }
          }
        }
        assert(unique != nullptr, "empty phi???");
        if (unique != NodeSentinel) {
          if (prev_region != nullptr && prev_region->is_Phi() && prev_region->in(0) == c) {
            dead_phis.push(prev_region);
          }
          regions.map(c->_idx, unique);
        } else {
          Node* phi = nullptr;
          if (prev_region != nullptr && prev_region->is_Phi() && prev_region->in(0) == c && prev_region->_idx >= last) {
            phi = prev_region;
            for (uint k = 1; k < c->req(); k++) {
              Node* m = _memory_nodes[c->in(k)->_idx];
              assert(m != nullptr, "expect memory state");
              phi->set_req(k, m);
            }
          } else {
            for (DUIterator_Fast jmax, j = c->fast_outs(jmax); j < jmax && phi == nullptr; j++) {
              Node* u = c->fast_out(j);
              if (u->is_Phi() && u->bottom_type() == Type::MEMORY &&
                  (u->adr_type() == TypePtr::BOTTOM || _phase->C->get_alias_index(u->adr_type()) == _alias)) {
                phi = u;
                for (uint k = 1; k < c->req() && phi != nullptr; k++) {
                  Node* m = _memory_nodes[c->in(k)->_idx];
                  assert(m != nullptr, "expect memory state");
                  if (u->in(k) != m) {
                    phi = NodeSentinel;
                  }
                }
              }
            }
            if (phi == NodeSentinel) {
              phi = new PhiNode(c, Type::MEMORY, _phase->C->get_adr_type(_alias));
              for (uint k = 1; k < c->req(); k++) {
                Node* m = _memory_nodes[c->in(k)->_idx];
                assert(m != nullptr, "expect memory state");
                phi->init_req(k, m);
              }
            }
          }
          if (phi != nullptr) {
            regions.map(c->_idx, phi);
          } else {
            assert(c->unique_ctrl_out()->Opcode() == Op_Halt, "expected memory state");
          }
        }
        Node* current_region = regions[c->_idx];
        if (current_region != prev_region) {
          progress = true;
          if (prev_region == prev_mem) {
            _memory_nodes.map(c->_idx, current_region);
          }
        }
      } else if (prev_mem == nullptr || prev_mem->is_Phi() || ctrl_or_self(prev_mem) != c) {
        Node* m = _memory_nodes[_phase->idom(c)->_idx];
        assert(m != nullptr || c->Opcode() == Op_Halt, "expect memory state");
        if (m != prev_mem) {
          _memory_nodes.map(c->_idx, m);
          progress = true;
        }
      }
#ifdef ASSERT
      if (trace) { tty->print("X %d", c->_idx);  _memory_nodes[c->_idx]->dump(); }
#endif
    }
  }

  // Replace existing phi with computed memory state for that region
  // if different (could be a new phi or a dominating memory node if
  // that phi was found to be useless).
  while (dead_phis.size() > 0) {
    Node* n = dead_phis.pop();
    n->replace_by(_phase->C->top());
    n->destruct(&_phase->igvn());
  }
  for (int i = rpo_list.size() - 1; i >= 0; i--) {
    Node* c = rpo_list.at(i);
    if (c->is_Region() && (_include_lsm || !c->is_OuterStripMinedLoop())) {
      Node* n = regions[c->_idx];
      assert(n != nullptr || c->unique_ctrl_out()->Opcode() == Op_Halt, "expected memory state");
      if (n != nullptr && n->is_Phi() && n->_idx >= last && n->in(0) == c) {
        _phase->register_new_node(n, c);
      }
    }
  }
  for (int i = rpo_list.size() - 1; i >= 0; i--) {
    Node* c = rpo_list.at(i);
    if (c->is_Region() && (_include_lsm || !c->is_OuterStripMinedLoop())) {
      Node* n = regions[c->_idx];
      assert(n != nullptr || c->unique_ctrl_out()->Opcode() == Op_Halt, "expected memory state");
      for (DUIterator_Fast imax, i = c->fast_outs(imax); i < imax; i++) {
        Node* u = c->fast_out(i);
        if (u->is_Phi() && u->bottom_type() == Type::MEMORY &&
            u != n) {
          assert(c->unique_ctrl_out()->Opcode() != Op_Halt, "expected memory state");
          if (u->adr_type() == TypePtr::BOTTOM) {
            fix_memory_uses(u, n, n, c);
          } else if (_phase->C->get_alias_index(u->adr_type()) == _alias) {
            _phase->lazy_replace(u, n);
            --i; --imax;
          }
        }
      }
    }
  }
}

Node* MemoryGraphFixer::collect_memory_for_infinite_loop(const Node* in) {
  Node* mem = nullptr;
  Node* head = in->in(0);
  assert(head->is_Region(), "unexpected infinite loop graph shape");

  Node* phi_mem = nullptr;
  for (DUIterator_Fast jmax, j = head->fast_outs(jmax); j < jmax; j++) {
    Node* u = head->fast_out(j);
    if (u->is_Phi() && u->bottom_type() == Type::MEMORY) {
      if (_phase->C->get_alias_index(u->adr_type()) == _alias) {
        assert(phi_mem == nullptr || phi_mem->adr_type() == TypePtr::BOTTOM, "");
        phi_mem = u;
      } else if (u->adr_type() == TypePtr::BOTTOM) {
        assert(phi_mem == nullptr || _phase->C->get_alias_index(phi_mem->adr_type()) == _alias, "");
        if (phi_mem == nullptr) {
          phi_mem = u;
        }
      }
    }
  }
  if (phi_mem == nullptr) {
    ResourceMark rm;
    Node_Stack stack(0);
    stack.push(head, 1);
    do {
      Node* n = stack.node();
      uint i = stack.index();
      if (i >= n->req()) {
        stack.pop();
      } else {
        stack.set_index(i + 1);
        Node* c = n->in(i);
        assert(c != head, "should have found a safepoint on the way");
        if (stack.size() != 1 || _phase->is_dominator(head, c)) {
          for (;;) {
            if (c->is_Region()) {
              stack.push(c, 1);
              break;
            } else if (c->is_SafePoint() && !c->is_CallLeaf()) {
              Node* m = c->in(TypeFunc::Memory);
              if (m->is_MergeMem()) {
                m = m->as_MergeMem()->memory_at(_alias);
              }
              assert(mem == nullptr || mem == m, "several memory states");
              mem = m;
              break;
            } else {
              assert(c != c->in(0), "");
              c = c->in(0);
            }
          }
        }
      }
    } while (stack.size() > 0);
    assert(mem != nullptr, "should have found safepoint");
  } else {
    mem = phi_mem;
  }
  return mem;
}

Node* MemoryGraphFixer::get_ctrl(Node* n) const {
  Node* c = _phase->get_ctrl(n);
  if (n->is_Proj() && n->in(0) != nullptr && n->in(0)->is_Call()) {
    assert(c == n->in(0), "");
    CallNode* call = c->as_Call();
    CallProjections projs;
    call->extract_projections(&projs, true, false);
    if (projs.catchall_memproj != nullptr) {
      if (projs.fallthrough_memproj == n) {
        c = projs.fallthrough_catchproj;
      } else {
        assert(projs.catchall_memproj == n, "");
        c = projs.catchall_catchproj;
      }
    }
  }
  return c;
}

Node* MemoryGraphFixer::ctrl_or_self(Node* n) const {
  if (_phase->has_ctrl(n))
    return get_ctrl(n);
  else {
    assert (n->is_CFG(), "must be a CFG node");
    return n;
  }
}

bool MemoryGraphFixer::mem_is_valid(Node* m, Node* c) const {
  return m != nullptr && get_ctrl(m) == c;
}

Node* MemoryGraphFixer::find_mem(Node* ctrl, Node* n) const {
  assert(n == nullptr || _phase->ctrl_or_self(n) == ctrl, "");
  assert(!ctrl->is_Call() || ctrl == n, "projection expected");
#ifdef ASSERT
  if ((ctrl->is_Proj() && ctrl->in(0)->is_Call()) ||
      (ctrl->is_Catch() && ctrl->in(0)->in(0)->is_Call())) {
    CallNode* call = ctrl->is_Proj() ? ctrl->in(0)->as_Call() : ctrl->in(0)->in(0)->as_Call();
    int mems = 0;
    for (DUIterator_Fast imax, i = call->fast_outs(imax); i < imax; i++) {
      Node* u = call->fast_out(i);
      if (u->bottom_type() == Type::MEMORY) {
        mems++;
      }
    }
    assert(mems <= 1, "No node right after call if multiple mem projections");
  }
#endif
  Node* mem = _memory_nodes[ctrl->_idx];
  Node* c = ctrl;
  while (!mem_is_valid(mem, c) &&
         (!c->is_CatchProj() || mem == nullptr || c->in(0)->in(0)->in(0) != get_ctrl(mem))) {
    c = _phase->idom(c);
    mem = _memory_nodes[c->_idx];
  }
  if (n != nullptr && mem_is_valid(mem, c)) {
    while (!ShenandoahBarrierC2Support::is_dominator_same_ctrl(c, mem, n, _phase) && _phase->ctrl_or_self(mem) == ctrl) {
      mem = next_mem(mem, _alias);
    }
    if (mem->is_MergeMem()) {
      mem = mem->as_MergeMem()->memory_at(_alias);
    }
    if (!mem_is_valid(mem, c)) {
      do {
        c = _phase->idom(c);
        mem = _memory_nodes[c->_idx];
      } while (!mem_is_valid(mem, c) &&
               (!c->is_CatchProj() || mem == nullptr || c->in(0)->in(0)->in(0) != get_ctrl(mem)));
    }
  }
  assert(mem->bottom_type() == Type::MEMORY, "");
  return mem;
}

bool MemoryGraphFixer::has_mem_phi(Node* region) const {
  for (DUIterator_Fast imax, i = region->fast_outs(imax); i < imax; i++) {
    Node* use = region->fast_out(i);
    if (use->is_Phi() && use->bottom_type() == Type::MEMORY &&
        (_phase->C->get_alias_index(use->adr_type()) == _alias)) {
      return true;
    }
  }
  return false;
}

void MemoryGraphFixer::fix_mem(Node* ctrl, Node* new_ctrl, Node* mem, Node* mem_for_ctrl, Node* new_mem, Unique_Node_List& uses) {
  assert(_phase->ctrl_or_self(new_mem) == new_ctrl, "");
  const bool trace = false;
  DEBUG_ONLY(if (trace) { tty->print("ZZZ control is"); ctrl->dump(); });
  DEBUG_ONLY(if (trace) { tty->print("ZZZ mem is"); mem->dump(); });
  GrowableArray<Node*> phis;
  if (mem_for_ctrl != mem) {
    Node* old = mem_for_ctrl;
    Node* prev = nullptr;
    while (old != mem) {
      prev = old;
      if (old->is_Store() || old->is_ClearArray() || old->is_LoadStore()) {
        assert(_alias == Compile::AliasIdxRaw, "");
        old = old->in(MemNode::Memory);
      } else if (old->Opcode() == Op_SCMemProj) {
        assert(_alias == Compile::AliasIdxRaw, "");
        old = old->in(0);
      } else {
        ShouldNotReachHere();
      }
    }
    assert(prev != nullptr, "");
    if (new_ctrl != ctrl) {
      _memory_nodes.map(ctrl->_idx, mem);
      _memory_nodes.map(new_ctrl->_idx, mem_for_ctrl);
    }
    uint input = (uint)MemNode::Memory;
    _phase->igvn().replace_input_of(prev, input, new_mem);
  } else {
    uses.clear();
    _memory_nodes.map(new_ctrl->_idx, new_mem);
    uses.push(new_ctrl);
    for(uint next = 0; next < uses.size(); next++ ) {
      Node *n = uses.at(next);
      assert(n->is_CFG(), "");
      DEBUG_ONLY(if (trace) { tty->print("ZZZ ctrl"); n->dump(); });
      for (DUIterator_Fast imax, i = n->fast_outs(imax); i < imax; i++) {
        Node* u = n->fast_out(i);
        if (!u->is_Root() && u->is_CFG() && u != n) {
          Node* m = _memory_nodes[u->_idx];
          if (u->is_Region() && (!u->is_OuterStripMinedLoop() || _include_lsm) &&
              !has_mem_phi(u) &&
              u->unique_ctrl_out()->Opcode() != Op_Halt) {
            DEBUG_ONLY(if (trace) { tty->print("ZZZ region"); u->dump(); });
            DEBUG_ONLY(if (trace && m != nullptr) { tty->print("ZZZ mem"); m->dump(); });

            if (!mem_is_valid(m, u) || !m->is_Phi()) {
              bool push = true;
              bool create_phi = true;
              if (_phase->is_dominator(new_ctrl, u)) {
                create_phi = false;
              }
              if (create_phi) {
                Node* phi = new PhiNode(u, Type::MEMORY, _phase->C->get_adr_type(_alias));
                _phase->register_new_node(phi, u);
                phis.push(phi);
                DEBUG_ONLY(if (trace) { tty->print("ZZZ new phi"); phi->dump(); });
                if (!mem_is_valid(m, u)) {
                  DEBUG_ONLY(if (trace) { tty->print("ZZZ setting mem"); phi->dump(); });
                  _memory_nodes.map(u->_idx, phi);
                } else {
                  DEBUG_ONLY(if (trace) { tty->print("ZZZ NOT setting mem"); m->dump(); });
                  for (;;) {
                    assert(m->is_Mem() || m->is_LoadStore() || m->is_Proj(), "");
                    Node* next = nullptr;
                    if (m->is_Proj()) {
                      next = m->in(0);
                    } else {
                      assert(m->is_Mem() || m->is_LoadStore(), "");
                      assert(_alias == Compile::AliasIdxRaw, "");
                      next = m->in(MemNode::Memory);
                    }
                    if (_phase->get_ctrl(next) != u) {
                      break;
                    }
                    if (next->is_MergeMem()) {
                      assert(_phase->get_ctrl(next->as_MergeMem()->memory_at(_alias)) != u, "");
                      break;
                    }
                    if (next->is_Phi()) {
                      assert(next->adr_type() == TypePtr::BOTTOM && next->in(0) == u, "");
                      break;
                    }
                    m = next;
                  }

                  DEBUG_ONLY(if (trace) { tty->print("ZZZ setting to phi"); m->dump(); });
                  assert(m->is_Mem() || m->is_LoadStore(), "");
                  uint input = (uint)MemNode::Memory;
                  _phase->igvn().replace_input_of(m, input, phi);
                  push = false;
                }
              } else {
                DEBUG_ONLY(if (trace) { tty->print("ZZZ skipping region"); u->dump(); });
              }
              if (push) {
                uses.push(u);
              }
            }
          } else if (!mem_is_valid(m, u) &&
                     !(u->Opcode() == Op_CProj && u->in(0)->is_NeverBranch() && u->as_Proj()->_con == 1)) {
            uses.push(u);
          }
        }
      }
    }
    for (int i = 0; i < phis.length(); i++) {
      Node* n = phis.at(i);
      Node* r = n->in(0);
      DEBUG_ONLY(if (trace) { tty->print("ZZZ fixing new phi"); n->dump(); });
      for (uint j = 1; j < n->req(); j++) {
        Node* m = find_mem(r->in(j), nullptr);
        _phase->igvn().replace_input_of(n, j, m);
        DEBUG_ONLY(if (trace) { tty->print("ZZZ fixing new phi: %d", j); m->dump(); });
      }
    }
  }
  uint last = _phase->C->unique();
  MergeMemNode* mm = nullptr;
  int alias = _alias;
  DEBUG_ONLY(if (trace) { tty->print("ZZZ raw mem is"); mem->dump(); });
  // Process loads first to not miss an anti-dependency: if the memory
  // edge of a store is updated before a load is processed then an
  // anti-dependency may be missed.
  for (DUIterator i = mem->outs(); mem->has_out(i); i++) {
    Node* u = mem->out(i);
    if (u->_idx < last && u->is_Load() && _phase->C->get_alias_index(u->adr_type()) == alias) {
      Node* m = find_mem(_phase->get_ctrl(u), u);
      if (m != mem) {
        DEBUG_ONLY(if (trace) { tty->print("ZZZ setting memory of use"); u->dump(); });
        _phase->igvn().replace_input_of(u, MemNode::Memory, m);
        --i;
      }
    }
  }
  for (DUIterator i = mem->outs(); mem->has_out(i); i++) {
    Node* u = mem->out(i);
    if (u->_idx < last) {
      if (u->is_Mem()) {
        if (_phase->C->get_alias_index(u->adr_type()) == alias) {
          Node* m = find_mem(_phase->get_ctrl(u), u);
          if (m != mem) {
            DEBUG_ONLY(if (trace) { tty->print("ZZZ setting memory of use"); u->dump(); });
            _phase->igvn().replace_input_of(u, MemNode::Memory, m);
            --i;
          }
        }
      } else if (u->is_MergeMem()) {
        MergeMemNode* u_mm = u->as_MergeMem();
        if (u_mm->memory_at(alias) == mem) {
          MergeMemNode* newmm = nullptr;
          for (DUIterator_Fast jmax, j = u->fast_outs(jmax); j < jmax; j++) {
            Node* uu = u->fast_out(j);
            assert(!uu->is_MergeMem(), "chain of MergeMems?");
            if (uu->is_Phi()) {
              assert(uu->adr_type() == TypePtr::BOTTOM, "");
              Node* region = uu->in(0);
              int nb = 0;
              for (uint k = 1; k < uu->req(); k++) {
                if (uu->in(k) == u) {
                  Node* m = find_mem(region->in(k), nullptr);
                  if (m != mem) {
                    DEBUG_ONLY(if (trace) { tty->print("ZZZ setting memory of phi %d", k); uu->dump(); });
                    newmm = clone_merge_mem(u, mem, m, _phase->ctrl_or_self(m), i);
                    if (newmm != u) {
                      _phase->igvn().replace_input_of(uu, k, newmm);
                      nb++;
                      --jmax;
                    }
                  }
                }
              }
              if (nb > 0) {
                --j;
              }
            } else {
              Node* m = find_mem(_phase->ctrl_or_self(uu), uu);
              if (m != mem) {
                DEBUG_ONLY(if (trace) { tty->print("ZZZ setting memory of use"); uu->dump(); });
                newmm = clone_merge_mem(u, mem, m, _phase->ctrl_or_self(m), i);
                if (newmm != u) {
                  _phase->igvn().replace_input_of(uu, uu->find_edge(u), newmm);
                  --j, --jmax;
                }
              }
            }
          }
        }
      } else if (u->is_Phi()) {
        assert(u->bottom_type() == Type::MEMORY, "what else?");
        if (_phase->C->get_alias_index(u->adr_type()) == alias || u->adr_type() == TypePtr::BOTTOM) {
          Node* region = u->in(0);
          bool replaced = false;
          for (uint j = 1; j < u->req(); j++) {
            if (u->in(j) == mem) {
              Node* m = find_mem(region->in(j), nullptr);
              Node* nnew = m;
              if (m != mem) {
                if (u->adr_type() == TypePtr::BOTTOM) {
                  mm = allocate_merge_mem(mem, m, _phase->ctrl_or_self(m));
                  nnew = mm;
                }
                DEBUG_ONLY(if (trace) { tty->print("ZZZ setting memory of phi %d", j); u->dump(); });
                _phase->igvn().replace_input_of(u, j, nnew);
                replaced = true;
              }
            }
          }
          if (replaced) {
            --i;
          }
        }
      } else if ((u->adr_type() == TypePtr::BOTTOM && u->Opcode() != Op_StrInflatedCopy) ||
                 u->adr_type() == nullptr) {
        assert(u->adr_type() != nullptr ||
               u->Opcode() == Op_Rethrow ||
               u->Opcode() == Op_Return ||
               u->Opcode() == Op_SafePoint ||
               (u->is_CallStaticJava() && u->as_CallStaticJava()->uncommon_trap_request() != 0) ||
               (u->is_CallStaticJava() && u->as_CallStaticJava()->_entry_point == OptoRuntime::rethrow_stub()) ||
               u->Opcode() == Op_CallLeaf, "");
        Node* m = find_mem(_phase->ctrl_or_self(u), u);
        if (m != mem) {
          mm = allocate_merge_mem(mem, m, _phase->get_ctrl(m));
          _phase->igvn().replace_input_of(u, u->find_edge(mem), mm);
          --i;
        }
      } else if (_phase->C->get_alias_index(u->adr_type()) == alias) {
        Node* m = find_mem(_phase->ctrl_or_self(u), u);
        if (m != mem) {
          DEBUG_ONLY(if (trace) { tty->print("ZZZ setting memory of use"); u->dump(); });
          _phase->igvn().replace_input_of(u, u->find_edge(mem), m);
          --i;
        }
      } else if (u->adr_type() != TypePtr::BOTTOM &&
                 _memory_nodes[_phase->ctrl_or_self(u)->_idx] == u) {
        Node* m = find_mem(_phase->ctrl_or_self(u), u);
        assert(m != mem, "");
        // u is on the wrong slice...
        assert(u->is_ClearArray(), "");
        DEBUG_ONLY(if (trace) { tty->print("ZZZ setting memory of use"); u->dump(); });
        _phase->igvn().replace_input_of(u, u->find_edge(mem), m);
        --i;
      }
    }
  }
#ifdef ASSERT
  assert(new_mem->outcnt() > 0, "");
  for (int i = 0; i < phis.length(); i++) {
    Node* n = phis.at(i);
    assert(n->outcnt() > 0, "new phi must have uses now");
  }
#endif
}

void MemoryGraphFixer::record_new_ctrl(Node* ctrl, Node* new_ctrl, Node* mem, Node* mem_for_ctrl) {
  if (mem_for_ctrl != mem && new_ctrl != ctrl) {
    _memory_nodes.map(ctrl->_idx, mem);
    _memory_nodes.map(new_ctrl->_idx, mem_for_ctrl);
  }
}

MergeMemNode* MemoryGraphFixer::allocate_merge_mem(Node* mem, Node* rep_proj, Node* rep_ctrl) const {
  MergeMemNode* mm = MergeMemNode::make(mem);
  mm->set_memory_at(_alias, rep_proj);
  _phase->register_new_node(mm, rep_ctrl);
  return mm;
}

MergeMemNode* MemoryGraphFixer::clone_merge_mem(Node* u, Node* mem, Node* rep_proj, Node* rep_ctrl, DUIterator& i) const {
  MergeMemNode* newmm = nullptr;
  MergeMemNode* u_mm = u->as_MergeMem();
  Node* c = _phase->get_ctrl(u);
  if (_phase->is_dominator(c, rep_ctrl)) {
    c = rep_ctrl;
  } else {
    assert(_phase->is_dominator(rep_ctrl, c), "one must dominate the other");
  }
  if (u->outcnt() == 1) {
    if (u->req() > (uint)_alias && u->in(_alias) == mem) {
      _phase->igvn().replace_input_of(u, _alias, rep_proj);
      --i;
    } else {
      _phase->igvn().rehash_node_delayed(u);
      u_mm->set_memory_at(_alias, rep_proj);
    }
    newmm = u_mm;
    _phase->set_ctrl_and_loop(u, c);
  } else {
    // can't simply clone u and then change one of its input because
    // it adds and then removes an edge which messes with the
    // DUIterator
    newmm = MergeMemNode::make(u_mm->base_memory());
    for (uint j = 0; j < u->req(); j++) {
      if (j < newmm->req()) {
        if (j == (uint)_alias) {
          newmm->set_req(j, rep_proj);
        } else if (newmm->in(j) != u->in(j)) {
          newmm->set_req(j, u->in(j));
        }
      } else if (j == (uint)_alias) {
        newmm->add_req(rep_proj);
      } else {
        newmm->add_req(u->in(j));
      }
    }
    if ((uint)_alias >= u->req()) {
      newmm->set_memory_at(_alias, rep_proj);
    }
    _phase->register_new_node(newmm, c);
  }
  return newmm;
}

bool MemoryGraphFixer::should_process_phi(Node* phi) const {
  if (phi->adr_type() == TypePtr::BOTTOM) {
    Node* region = phi->in(0);
    for (DUIterator_Fast jmax, j = region->fast_outs(jmax); j < jmax; j++) {
      Node* uu = region->fast_out(j);
      if (uu->is_Phi() && uu != phi && uu->bottom_type() == Type::MEMORY && _phase->C->get_alias_index(uu->adr_type()) == _alias) {
        return false;
      }
    }
    return true;
  }
  return _phase->C->get_alias_index(phi->adr_type()) == _alias;
}

void MemoryGraphFixer::fix_memory_uses(Node* mem, Node* replacement, Node* rep_proj, Node* rep_ctrl) const {
  uint last = _phase-> C->unique();
  MergeMemNode* mm = nullptr;
  assert(mem->bottom_type() == Type::MEMORY, "");
  for (DUIterator i = mem->outs(); mem->has_out(i); i++) {
    Node* u = mem->out(i);
    if (u != replacement && u->_idx < last) {
      if (u->is_MergeMem()) {
        MergeMemNode* u_mm = u->as_MergeMem();
        if (u_mm->memory_at(_alias) == mem) {
          MergeMemNode* newmm = nullptr;
          for (DUIterator_Fast jmax, j = u->fast_outs(jmax); j < jmax; j++) {
            Node* uu = u->fast_out(j);
            assert(!uu->is_MergeMem(), "chain of MergeMems?");
            if (uu->is_Phi()) {
              if (should_process_phi(uu)) {
                Node* region = uu->in(0);
                int nb = 0;
                for (uint k = 1; k < uu->req(); k++) {
                  if (uu->in(k) == u && _phase->is_dominator(rep_ctrl, region->in(k))) {
                    if (newmm == nullptr) {
                      newmm = clone_merge_mem(u, mem, rep_proj, rep_ctrl, i);
                    }
                    if (newmm != u) {
                      _phase->igvn().replace_input_of(uu, k, newmm);
                      nb++;
                      --jmax;
                    }
                  }
                }
                if (nb > 0) {
                  --j;
                }
              }
            } else {
              if (rep_ctrl != uu && ShenandoahBarrierC2Support::is_dominator(rep_ctrl, _phase->ctrl_or_self(uu), replacement, uu, _phase)) {
                if (newmm == nullptr) {
                  newmm = clone_merge_mem(u, mem, rep_proj, rep_ctrl, i);
                }
                if (newmm != u) {
                  _phase->igvn().replace_input_of(uu, uu->find_edge(u), newmm);
                  --j, --jmax;
                }
              }
            }
          }
        }
      } else if (u->is_Phi()) {
        assert(u->bottom_type() == Type::MEMORY, "what else?");
        Node* region = u->in(0);
        if (should_process_phi(u)) {
          bool replaced = false;
          for (uint j = 1; j < u->req(); j++) {
            if (u->in(j) == mem && _phase->is_dominator(rep_ctrl, region->in(j))) {
              Node* nnew = rep_proj;
              if (u->adr_type() == TypePtr::BOTTOM) {
                if (mm == nullptr) {
                  mm = allocate_merge_mem(mem, rep_proj, rep_ctrl);
                }
                nnew = mm;
              }
              _phase->igvn().replace_input_of(u, j, nnew);
              replaced = true;
            }
          }
          if (replaced) {
            --i;
          }

        }
      } else if ((u->adr_type() == TypePtr::BOTTOM && u->Opcode() != Op_StrInflatedCopy) ||
                 u->adr_type() == nullptr) {
        assert(u->adr_type() != nullptr ||
               u->Opcode() == Op_Rethrow ||
               u->Opcode() == Op_Return ||
               u->Opcode() == Op_SafePoint ||
               (u->is_CallStaticJava() && u->as_CallStaticJava()->uncommon_trap_request() != 0) ||
               (u->is_CallStaticJava() && u->as_CallStaticJava()->_entry_point == OptoRuntime::rethrow_stub()) ||
               u->Opcode() == Op_CallLeaf, "%s", u->Name());
        if (ShenandoahBarrierC2Support::is_dominator(rep_ctrl, _phase->ctrl_or_self(u), replacement, u, _phase)) {
          if (mm == nullptr) {
            mm = allocate_merge_mem(mem, rep_proj, rep_ctrl);
          }
          _phase->igvn().replace_input_of(u, u->find_edge(mem), mm);
          --i;
        }
      } else if (_phase->C->get_alias_index(u->adr_type()) == _alias) {
        if (ShenandoahBarrierC2Support::is_dominator(rep_ctrl, _phase->ctrl_or_self(u), replacement, u, _phase)) {
          _phase->igvn().replace_input_of(u, u->find_edge(mem), rep_proj);
          --i;
        }
      }
    }
  }
}

ShenandoahLoadReferenceBarrierNode::ShenandoahLoadReferenceBarrierNode(Node* ctrl, Node* obj, DecoratorSet decorators)
: Node(ctrl, obj), _decorators(decorators) {
  ShenandoahBarrierSetC2::bsc2()->state()->add_load_reference_barrier(this);
}

DecoratorSet ShenandoahLoadReferenceBarrierNode::decorators() const {
  return _decorators;
}

uint ShenandoahLoadReferenceBarrierNode::size_of() const {
  return sizeof(*this);
}

static DecoratorSet mask_decorators(DecoratorSet decorators) {
  return decorators & (ON_STRONG_OOP_REF | ON_WEAK_OOP_REF | ON_PHANTOM_OOP_REF | ON_UNKNOWN_OOP_REF | IN_NATIVE);
}

uint ShenandoahLoadReferenceBarrierNode::hash() const {
  uint hash = Node::hash();
  hash += mask_decorators(_decorators);
  return hash;
}

bool ShenandoahLoadReferenceBarrierNode::cmp( const Node &n ) const {
  return Node::cmp(n) && n.Opcode() == Op_ShenandoahLoadReferenceBarrier &&
         mask_decorators(_decorators) == mask_decorators(((const ShenandoahLoadReferenceBarrierNode&)n)._decorators);
}

const Type* ShenandoahLoadReferenceBarrierNode::bottom_type() const {
  if (in(ValueIn) == nullptr || in(ValueIn)->is_top()) {
    return Type::TOP;
  }
  const Type* t = in(ValueIn)->bottom_type();
  if (t == TypePtr::NULL_PTR) {
    return t;
  }

  if (ShenandoahBarrierSet::is_strong_access(decorators())) {
    return t;
  }

  return t->meet(TypePtr::NULL_PTR);
}

const Type* ShenandoahLoadReferenceBarrierNode::Value(PhaseGVN* phase) const {
  // Either input is TOP ==> the result is TOP
  const Type *t2 = phase->type(in(ValueIn));
  if( t2 == Type::TOP ) return Type::TOP;

  if (t2 == TypePtr::NULL_PTR) {
    return t2;
  }

  if (ShenandoahBarrierSet::is_strong_access(decorators())) {
    return t2;
  }

  return t2->meet(TypePtr::NULL_PTR);
}

Node* ShenandoahLoadReferenceBarrierNode::Identity(PhaseGVN* phase) {
  Node* value = in(ValueIn);
  if (!needs_barrier(phase, value)) {
    return value;
  }
  return this;
}

bool ShenandoahLoadReferenceBarrierNode::needs_barrier(PhaseGVN* phase, Node* n) {
  Unique_Node_List visited;
  return needs_barrier_impl(phase, n, visited);
}

bool ShenandoahLoadReferenceBarrierNode::needs_barrier_impl(PhaseGVN* phase, Node* n, Unique_Node_List &visited) {
  if (n == nullptr) return false;
  if (visited.member(n)) {
    return false; // Been there.
  }
  visited.push(n);

  if (n->is_Allocate()) {
    // tty->print_cr("optimize barrier on alloc");
    return false;
  }
  if (n->is_Call()) {
    // tty->print_cr("optimize barrier on call");
    return false;
  }

  const Type* type = phase->type(n);
  if (type == Type::TOP) {
    return false;
  }
  if (type->make_ptr()->higher_equal(TypePtr::NULL_PTR)) {
    // tty->print_cr("optimize barrier on null");
    return false;
  }
  if (type->make_oopptr() && type->make_oopptr()->const_oop() != nullptr) {
    // tty->print_cr("optimize barrier on constant");
    return false;
  }

  switch (n->Opcode()) {
    case Op_AddP:
      return true; // TODO: Can refine?
    case Op_LoadP:
    case Op_ShenandoahCompareAndExchangeN:
    case Op_ShenandoahCompareAndExchangeP:
    case Op_CompareAndExchangeN:
    case Op_CompareAndExchangeP:
    case Op_GetAndSetN:
    case Op_GetAndSetP:
      return true;
    case Op_Phi: {
      for (uint i = 1; i < n->req(); i++) {
        if (needs_barrier_impl(phase, n->in(i), visited)) return true;
      }
      return false;
    }
    case Op_CheckCastPP:
    case Op_CastPP:
      return needs_barrier_impl(phase, n->in(1), visited);
    case Op_Proj:
      return needs_barrier_impl(phase, n->in(0), visited);
    case Op_ShenandoahLoadReferenceBarrier:
      // tty->print_cr("optimize barrier on barrier");
      return false;
    case Op_Parm:
      // tty->print_cr("optimize barrier on input arg");
      return false;
    case Op_DecodeN:
    case Op_EncodeP:
      return needs_barrier_impl(phase, n->in(1), visited);
    case Op_LoadN:
      return true;
    case Op_CMoveN:
    case Op_CMoveP:
      return needs_barrier_impl(phase, n->in(2), visited) ||
             needs_barrier_impl(phase, n->in(3), visited);
    case Op_CreateEx:
      return false;
    default:
      break;
  }
#ifdef ASSERT
  tty->print("need barrier on?: ");
  tty->print_cr("ins:");
  n->dump(2);
  tty->print_cr("outs:");
  n->dump(-2);
  ShouldNotReachHere();
#endif
  return true;
}
