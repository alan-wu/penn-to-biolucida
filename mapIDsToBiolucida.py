import requests
from config import Config
import json

log_file = open('mapIDs.txt', 'a')

bp_list = []


def get_biolucida_token():
    url_bl_auth = f"{Config.BIOLUCIDA_ENDPOINT}/authenticate"
    response = requests.post(url_bl_auth,
                        data=dict(
                            username=Config.BIOLUCIDA_USERNAME,
                            password=Config.BIOLUCIDA_PASSWORD,
                            token=''))
    if response.status_code == requests.codes.ok:
        content = response.json()
        if content['status'] == 'success':
            return content['token']
    return None


def map_file_to_bl(token, penn_id, published_id, package_id, image_id):
    print(f"Mapping {penn_id}, {published_id}, {package_id}, {image_id}")
    log_file.write(f"Mapping {penn_id}, {published_id}, {package_id}, {image_id}")
    # see https://documenter.getpostman.com/view/8986837/SWLh5mQL
    # see also https://github.com/nih-sparc/sparc-app/blob/0ca1c33e245b39b0f07485a990e3862af085013e/nuxt.config.js#L101
    BL_SERVER_URL = Config.BIOLUCIDA_ENDPOINT
    #token = None
    if token:
      log_file.write(f"imagemap: ")
      if image_id:
          url_bl_ima = f"{BL_SERVER_URL}/imagemap/add"
          resp_img = requests.post(url_bl_ima,
                              data=dict(
                                  imageId=image_id,
                                  sourceId=package_id,
                                  blackfynn_datasetId=penn_id,
                                  discover_datasetId=published_id),
                                  headers=dict(token=token))
          if resp_img.status_code == requests.codes.ok:
            content = resp_img.json()
            print(content)
            if content['status='] == 'success':
                log_file.write("Successful\n")
            else:
                log_file.write("Fail\n")
          else:
              log_file.write("Fail\n")
    else:
        log_file.write("Fail to get authentication token")
    

def get_keys_value(element, *keys):
    _element = element
    for key in keys:
        try:
            _element = _element[key]
        except KeyError:
            return None
    return _element


def process_dataset(dataset_id):
    files = []
    sparc_dataset = f"{Config.SPARC_API}/dataset_info/using_multiple_discoverIds/?discoverIds={dataset_id}"
    response = requests.get(sparc_dataset)
    penn_datasetId = None
    if response.status_code == requests.codes.ok:
      content = response.json()
      results = content.get("results")
      result = results[0] if len(results) > 0 else None
      if result:
        b2d = result.get("biolucida-2d", [])
        b3d = result.get("biolucida-3d", [])
        bList = b2d + b3d
        if len(bList) > 0:
          penn_datasetId = bList[0]["dataset"]["identifier"]
          for item in bList:
            bioID = get_keys_value(item, "biolucida", "identifier")
            if bioID:
              fileID = get_keys_value(item, "identifier")
              if fileID:
                files.append({
                  "bioID": bioID,
                  "fileID": fileID
                })
    return {
      "files": files,
      "penn_datasetId": penn_datasetId
    }

    #for warg in wargs:
    #    upload_to_bl(**warg, secrets=secrets, username=bioluc_username)

def main():
    dataset_id = "403"
    dataset_info = process_dataset(dataset_id)
    token = get_biolucida_token()
    files, penn_datasetId = dataset_info.values()
    for file in files:
      map_file_to_bl(token, penn_datasetId, dataset_id, file['fileID'], file['bioID'])
    #log_file.close()
    #with open('output.json', 'w') as f:
    #    json.dump(bp_list, f)



if __name__ == "__main__":
    main()
