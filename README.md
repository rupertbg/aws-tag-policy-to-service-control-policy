# Convert AWS Tag Policies into Service Control Policies
Writing Tag Policies is easy. Denying access to create resources that are missing tags is not. This should help.

## Usage

1. Put your JSON-formatted Tag Policies in the `tag-policies` directory.
2. Run `index.py`.
3. Take SCP files from `service-control-policies` directory.

## TODO

- `resources-syntax-map.json` needs more mappings in it.