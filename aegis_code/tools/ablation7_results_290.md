| Variant | Scored Files | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| full | 248 | 360 | 1 | 93 | 99.72% | 79.47% | 88.45% |
| no_auth_lifting | 248 | 365 | 12 | 88 | 96.82% | 80.57% | 87.95% |
| no_nonce_lifting | 248 | 318 | 43 | 135 | 88.09% | 70.2% | 78.13% |
| no_hash_binding_lifting | 248 | 360 | 1 | 93 | 99.72% | 79.47% | 88.45% |
| no_caller_binding_lifting | 248 | 360 | 10 | 93 | 97.3% | 79.47% | 87.48% |
| no_return_path_semantics | 248 | 330 | 1 | 123 | 99.7% | 72.85% | 84.18% |
| no_profile_binding | 248 | 360 | 97 | 93 | 78.77% | 79.47% | 79.12% |
| structural_only | 248 | 293 | 237 | 160 | 55.28% | 64.68% | 59.61% |