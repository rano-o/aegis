| Variant | Scored Files | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| full_locked | 290 | 514 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| no_auth_lifting | 290 | 425 | 84 | 89 | 83.5% | 82.68% | 83.09% |
| no_nonce_lifting | 290 | 378 | 115 | 136 | 76.67% | 73.54% | 75.07% |
| no_hash_binding_lifting | 290 | 420 | 72 | 94 | 85.37% | 81.71% | 83.5% |
| no_caller_binding_lifting | 290 | 420 | 81 | 94 | 83.83% | 81.71% | 82.76% |
| no_return_path_semantics | 290 | 375 | 71 | 139 | 84.08% | 72.96% | 78.12% |
| no_profile_binding | 290 | 420 | 171 | 94 | 71.07% | 81.71% | 76.02% |
| structural_only | 290 | 338 | 311 | 176 | 52.08% | 65.76% | 58.13% |

Parity check (full FP=0): expected=0, actual=0, match=True
