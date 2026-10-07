import sys
from pathlib import Path

# 정본 파이프라인은 scripts/pipeline. 최상위 legacy pipeline/ 보다 먼저 잡히게 한다.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
