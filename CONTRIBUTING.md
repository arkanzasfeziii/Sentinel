# Contributing to Sentinel

## Setup

```bash
git clone https://github.com/arkanzasfeziii/Sentinel.git
cd Sentinel
pip install -r requirements.txt
pip install ruff pytest
make test
```

## Adding a New Module

1. Create `sentinel/modules/your_module.py` extending `BaseModule`
2. Implement `run(es, **kwargs) -> List[AttackResult]`
3. Register in `sentinel/cli.py: MODULE_REGISTRY`
4. Update `sentinel/modules/__init__.py`
5. Add tests
