# Runner Action Step Support

**Priority:** Medium
**Area:** runner

## Description

The Python runner recognizes `uses:` steps (GitHub Actions-style) in workflow definitions but doesn't execute them.

## Current State

`runner/workflow.py:213`:
```python
elif "uses" in step:
    # TODO: Implement action support
    normalized["type"] = "action"
    normalized["uses"] = step["uses"]
```

## What's Needed

Implement action resolution and execution:
- Parse action references (e.g., `uses: actions/checkout@v4`)
- Download/cache action definitions
- Execute action entrypoints within the runner sandbox

## Files

- `runner/workflow.py`
