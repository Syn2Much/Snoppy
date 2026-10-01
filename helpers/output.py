"""Persist tool results in Snoopy's target-keyed JSON format."""

import json
from pathlib import Path


def write_result(output_path, target, module, result):
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if output_path.exists():
        with output_path.open("r", encoding="utf8") as input_file:
            results = json.load(input_file)
    else:
        results = {"targets": {}}

    results.setdefault("targets", {})
    results["targets"].setdefault(target, {})[module] = result

    with output_path.open("w", encoding="utf8") as output_file:
        json.dump(results, output_file, indent=2, sort_keys=True)
        output_file.write("\n")
