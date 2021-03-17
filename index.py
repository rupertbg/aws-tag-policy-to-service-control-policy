import json
import os

TAG_POLICY_DIR = "tag-policies"
SCP_DIR = "service-control-policies"
RESOURCE_TO_ACTION_MAP = "resource-syntax-map.json"


def valid_statement(statement):
    if "Dedupe" in statement:
        return False
    elif "Condition" not in statement:
        return False
    elif "Action" not in statement or len(statement["Action"]) == 0:
        return False
    return True


def optimize_statment_packing(statements):
    deduped = []
    print("||| Optimizing generated statements")
    for s in statements:
        if not valid_statement(s):
            continue
        for compare in statements:
            if s == compare:
                continue
            elif not valid_statement(compare):
                continue

            for attr in ["Action", "Resource"]:
                # Process matching condition statements
                if s["Condition"] == compare["Condition"]:
                    if isinstance(s[attr], str):
                        s[attr] = [s[attr]]
                    if isinstance(compare[attr], str):
                        compare[attr] = [compare[attr]]
                    # s[attr].extend(
                    #     compare[attr]
                    # )
                    # compare["Dedupe"] = True
        deduped.append(s)

    print("||| Deduplicating generated action lists")
    for s in deduped:
        s["Action"] = list(
            dict.fromkeys(s["Action"]))
        s["Resource"] = list(
            dict.fromkeys(s["Resource"]))
    return deduped


def tag_and_resource_to_statement(sid, tag_name, resource_name, resource):
    print(f"--- Generating SCP statement for {tag_name} / {resource_name}")
    statement_action = resource["Action"]
    if len(resource["Action"]) == 1:
        statement_action = resource["Action"][0]
    statement_resource = resource["Resource"]
    if len(resource["Resource"]) == 1:
        statement_resource = resource["Resource"][0]
    return {
        "Sid": sid,
        "Effect": "Deny",
        "Action": statement_action,
        "Resource": statement_resource,
        "Condition": {
            "StringNotLike": {
                f"aws:RequestTag/{tag_name}": "?*",
            }
        }
    }


def convert_tag_policy_to_scp_statements(tag_policy):
    print(f"--- Reading IAM / Tag Policy Resource Map")
    try:
        with open(os.path.join(".", RESOURCE_TO_ACTION_MAP)) as json_file:
            resource_map = json.load(json_file)
    except Exception as e:
        print(
            f"!!! Error reading IAM Action to Resources map: {RESOURCE_TO_ACTION_MAP}")
        print(e)
        quit()
    print(f"--- Reading enforced resources")

    statements = []
    inheritance_operators = ["@@assign", "@@append"]
    itr = 0
    for tag_name in tag_policy["tags"]:
        if "enforced_for" in tag_policy["tags"][tag_name]:
            print(f"||| Enforced resources for {tag_name}:")
            for io in inheritance_operators:
                if io in tag_policy["tags"][tag_name]["enforced_for"]:
                    for resource_name in tag_policy["tags"][tag_name]["enforced_for"][io]:
                        # Tag / Resource match for enforcement
                        if resource_name in resource_map.keys():
                            itr += 1
                            s = tag_and_resource_to_statement(
                                f"tag{itr}", tag_name, resource_name, resource_map[resource_name])
                            statements.append(s)
                        # Handle wildcard resources in resource map
                        elif resource_name.endswith(':*'):
                            wildcard_resources = [r for r in resource_map.keys(
                            ) if r.startswith(resource_name.split(':')[0])]
                            for wildcard_resource_name in wildcard_resources:
                                s = tag_and_resource_to_statement(
                                    f"tag{itr}", tag_name, wildcard_resource_name, resource_map[wildcard_resource_name])
                                statements.append(s)
    return statements


def create_statements_for_tag(tag_name, tag_statement, resource_map):
    statements = []

    return statements


def convert_tag_policy_to_scp(filename, tag_policy):
    statements = convert_tag_policy_to_scp_statements(tag_policy)
    print(f"--- Converted {filename} to SCP")
    return {"Version": "2012-10-17", "Statement": statements}


def write_scp_to_disk(filename, scp):
    print(f"--- Writing SCP: {filename}")
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
