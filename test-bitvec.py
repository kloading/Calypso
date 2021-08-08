from z3 import *


s = Solver()
z3_formula = """
(declare-const x (_ BitVec 8))
(assert (<= x #b00000000))
(check-sat)
             """
s.from_string(z3_formula)
z3_sat = s.check()
print(z3_sat)
