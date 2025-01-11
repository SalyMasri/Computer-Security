#!/usr/bin/env python3

def filter_text(content):
    rules_dict = {}
    for line in content.split("\n"):
        if line.startswith("#"):
            rule_key, rule_value = map(str.strip, line[1:].split("="))
            rules_dict[rule_key] = rule_value

    # Ensure that no rule creates a self-reference or unsafe expansion
    for rule_key in rules_dict.keys():
        for substitution in rules_dict.values():
            if rule_key in substitution:
                return False

    return True