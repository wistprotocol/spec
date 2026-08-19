# Manual derivation — decay-table (2026-08-19)
Exemplar: t=0, t=37, t=855, t=100, t=80
Prose sections used: WIST-4 §6 (Reputation)
Derivation: floor(exp(-t/180)*1e9), python3:
  math.floor(math.exp(-0/180)*1e9) -> 1000000000
  math.floor(math.exp(-37/180)*1e9) -> 814194860
  math.floor(math.exp(-855/180)*1e9) -> 8651695
  math.floor(math.exp(-100/180)*1e9) -> 573753420
  math.floor(math.exp(-80/180)*1e9) -> 641180388
Result: match
