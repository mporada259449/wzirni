import json

#Shamelessly stolen from https://hackersandslackers.com/extract-data-from-complex-json-python/
#(With minor tweaks)
def json_extract(obj, key):
    """Recursively fetch values from nested JSON."""
    arr = []

    def extract(obj, arr, key):
        """Recursively search for values of key in JSON tree."""
        if isinstance(obj, dict):
            for k, v in obj.items():
                #print("k: " + str(k) + " v: " + str(v))
                if k == key:
                    arr.append(v)
                if isinstance(v, (dict, list)):
                    extract(v, arr, key)
        elif isinstance(obj, list):
            for item in obj:
                extract(item, arr, key)
        return arr

    values = extract(obj, arr, key)
    return values

def assign_analysis_results(network, last_analysis_results):
    analysis_results = {}

    for i in range(len(network)):
        engines = last_analysis_results[i]
        result_entry = {}

        for engine_name, engine_data in engines.items():
            result_entry[engine_name] = engine_data['result']

        analysis_results[network[i]] = result_entry

    return analysis_results
""" def extract_engine_and_result(data):
    analysis_results = {}

    for entry in data:
        for engine_name, result in entry.items():
            analysis_results[engine_name] = result['result']
            
    return analysis_results """


# read JSON data
with open("./output/results_full.json") as input_file:
    old_data = json.load(input_file)

ip_list = json_extract(old_data, "id")
last_analysis_results = json_extract(old_data, "last_analysis_results")

result = assign_analysis_results(ip_list, last_analysis_results)

with open('./output/analysis_results.json', 'w') as file:
    json.dump(result, file, indent=2)