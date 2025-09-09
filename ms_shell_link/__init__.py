from .lnk import LNKStructure
import json

def parse_lnk(path):
    target = LNKStructure(path)
    result = target.get_notion_data()

    print(json.dumps(result, indent=4))