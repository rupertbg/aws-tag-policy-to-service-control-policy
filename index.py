import json
import os

TAG_POLICY_DIR = "tag-policies"
SCP_DIR = "service-control-policies"
RESOURCE_TO_ACTION_MAP = "resource-syntax-map.json"
resource_action_map = {}

try:
    with open(os.path.join(".", RESOURCE_TO_ACTION_MAP)) as json_file:
        resource_action_map = json.load(json_file)
except:
    print("IAM Action to Resources map file not found")
    quit()


def valid_tag_resource(resource):
    if "Dedupe" in resource:
        return False
    elif "Condition" not in resource:
        return False
    elif "Action" not in resource or len(resource["Action"]) == 0:
        return False
    return True


def deduplicate_matching_statements_remove_empty(resource_map):
    deduped = {}
    print("||| Deduplicating generated statements")
    # Dedupe statements
    for resource in resource_map:
        if not valid_tag_resource(resource_map[resource]):
            continue
        for compare in resource_map:
            if resource == compare:
                continue
            elif not valid_tag_resource(resource_map[compare]):
                continue
            elif resource_map[resource]["Condition"] == resource_map[compare]["Condition"]:
                if isinstance(resource_map[resource]["Action"], str):
                    resource_map[resource]["Action"] = [
                        resource_map[resource]["Action"]]
                if isinstance(resource_map[compare]["Action"], str):
                    resource_map[compare]["Action"] = [
                        resource_map[compare]["Action"]]
                resource_map[resource]["Action"].extend(
                    resource_map[compare]["Action"])
                resource_map[compare]["Dedupe"] = True
        deduped[resource] = resource_map[resource]
    # Dedupe actions
    for resource in deduped:
        deduped[resource]["Action"] = list(dict.fromkeys(deduped[resource]["Action"]))
    return deduped


def generate_statement_from_resource_map(tag_condition_keys, resource_map):
    print(f"--- Generating SCP statement")
    statement = []
    resources = deduplicate_matching_statements_remove_empty(resource_map)
    for idx, r in enumerate(resources):
        statement.append({
            "Sid": f"DenyMissingTags{idx}",
            "Effect": "Deny",
            "Action": resources[r]["Action"],
            "Resource": "*",
            "Condition": resources[r]["Condition"],
        })
    return statement


def convert_tag_policy_to_scp_statements(tag_policy):
    tag_condition_keys = []
    resource_map = resource_action_map.copy()
    print(f"--- Reading enforced actions")
    for tag_name in tag_policy["tags"]:
        if "enforced_for" in tag_policy["tags"][tag_name]:
            resource_map = add_tag_conditions_to_resource_map(
                tag_name,
                tag_policy["tags"][tag_name],
                resource_map
            )
            print(f"||| Read enforced actions for {tag_name}")
    return generate_statement_from_resource_map(tag_condition_keys, resource_map)


def add_tag_conditions_to_resource_map(tag_name, tag_statement, resource_map):
    inheritance_operators = ["@@assign", "@@append"]
    for io in inheritance_operators:
        if io in tag_statement["enforced_for"]:
            for resource in tag_statement["enforced_for"][io]:
                if resource in resource_map.keys():
                    if "Condition" not in resource_map[resource]:
                        resource_map[resource]["Condition"] = {
                            "Null": {}}
                    resource_map[resource]["Condition"][
                        "Null"][f"aws:RequestTag/{tag_name}"] = "true"
                elif resource.endswith(':*'):
                    wildcard_resources = [r for r in resource_map.keys(
                    ) if r.startswith(resource.split(':')[0])]
                    for wildcard_resource in wildcard_resources:
                        if "Condition" not in resource_map[wildcard_resource]:
                            resource_map[wildcard_resource]["Condition"] = {
                                "Null": {}}
                        resource_map[wildcard_resource]["Condition"][
                            "Null"][f"aws:RequestTag/{tag_name}"] = "true"
    return resource_map


def convert_tag_policy_to_scp(filename, tag_policy):
    statements = convert_tag_policy_to_scp_statements(tag_policy)
    print(f"Converted {filename} to SCP")
    return {"Version": "2012-10-17", "Statement": statements}


def write_scp_to_disk(filename, scp):
    print(f"Writing SCP: {filename}")
    with open(os.path.join(SCP_DIR, filename), "w") as scp_file:
        json.dump(scp, scp_file, indent=2)


def main():
    print("--- Reading tag policies")
    tag_policy_files = [f for f in os.listdir(
        TAG_POLICY_DIR) if f.endswith(".json")]
    for filename in tag_policy_files:
        print(f"||| Reading tag policy: {filename}")
        with open(os.path.join(TAG_POLICY_DIR, filename)) as json_file:
            tag_policy = json.load(json_file)
            scp = convert_tag_policy_to_scp(filename, tag_policy)
            write_scp_to_disk(filename, scp)


if __name__ == "__main__":
    main()
