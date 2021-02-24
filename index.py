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


def tag_to_statements(tag_name, tag_policy):
    statements = []
    if "enforced_for" in tag_policy:
        value_setters = ["@@assign", "@@append"]
        for value_setter in value_setters:
            if value_setter in tag_policy["enforced_for"]:
                for resource in tag_policy["enforced_for"][value_setter]:
                    if resource in resource_action_map.keys():
                        statements.append(
                            {
                                "Sid": f"Deny Missing {tag_name} on {resource}",
                                "Effect": "Deny",
                                "Action": resource_action_map[resource]["Actions"],
                                "Resource": resource_action_map[resource]["Resources"],
                                "Condition": {
                                    "StringNotLike": {
                                        f"aws:RequestTag/{tag_name}": "?*"
                                    },
                                },
                            }
                        )
    return statements


def convert_tag_policy_to_scp_statements(tag_policy):
    for tag_name in tag_policy["tags"]:
        return tag_to_statements(tag_name, tag_policy["tags"][tag_name])


def convert_tag_policy_to_scp(tag_policy):
    statements = convert_tag_policy_to_scp_statements(tag_policy)
    return {"Version": "2012-10-17", "Statement": statements}


def write_scp_to_disk(filename, scp):
    with open(os.path.join(SCP_DIR, filename), "w") as scp_file:
        json.dump(scp, scp_file, indent=2)


def main():
    tag_policy_files = [f for f in os.listdir(TAG_POLICY_DIR) if f.endswith(".json")]
    for filename in tag_policy_files:
        with open(os.path.join(TAG_POLICY_DIR, filename)) as json_file:
            tag_policy = json.load(json_file)
            scp = convert_tag_policy_to_scp(tag_policy)
            write_scp_to_disk(filename, scp)


if __name__ == "__main__":
    main()