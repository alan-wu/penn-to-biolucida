import math
import base64
import pathlib
import boto3  # sigh
import requests
from config import Config
import json

log_file = open('test_log.txt', 'a')

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

def initiate_biolucida_upload(filename, filesize, chunk_size, token):
    url_bl_uinit = f"{Config.BIOLUCIDA_ENDPOINT}/upload/init"
    response = requests.post(url_bl_uinit,
                        data=dict(
                            filename=filename,
                            filesize=filesize,
                            chunk_size=chunk_size),
                            headers=dict(token=token))
    if response.status_code == requests.codes.ok:
        content = response.json()
        if content['status'] == 'success':
            return content['upload_key'], content['total_chunks']
    return None

def cancel_biolucida_upload(upload_key):
    url_bl_ucancel = f"{Config.BIOLUCIDA_ENDPOINT}/upload/cancel"
    response = requests.post(url_bl_ucancel,
                        data=dict(
                            upload_key=upload_key
                        ))
    if response.status_code == requests.codes.ok:
        content = response.json()
        if content['status'] == 'success':
            return content['filepath'], content['files']
    return None

def finalise_biolucida_upload(upload_key):
    url_bl_ufin = f"{Config.BIOLUCIDA_ENDPOINT}/upload/finish"
    response = requests.post(url_bl_ufin,
                    data=dict(upload_key=upload_key))
    if response.status_code == requests.codes.ok:
        log_file.write(f"Upload for {filename} completed\n")
        content = response.json()
        if content['status'] == 'success':
            content = response.json()
            log_file.write(f"Finish api biolucida id: {content['img_id']}\n")
            return content['img_id']
    else:
        log_file.write(f"Finish api for upload for {filename} failed\n")
    return None

def get_biolucida_id(filename):
    url_bl_search = f"{Config.BIOLUCIDA_ENDPOINT}/search/{filename}"
    response = requests.get(url_bl_search)
    if response.status_code == requests.codes.ok:
        content = response.json()
        if content['status'] == 'success':
            images = content['images']
            for image in images:
                if image['original_name'] == filename:
                    return image['url'] #this is the id

    return None, None

def upload_to_bl(dataset_id, published_id, package_id, s3url, filename, filesize, chunk_size=1048576):
    print(f"Uploading {published_id}, {s3url}, {filename}")
    log_file.write(f"Upload {published_id}, {dataset_id}, {package_id}, {s3url}, {filename}, {filesize}\n")
    # see https://documenter.getpostman.com/view/8986837/SWLh5mQL
    # see also https://github.com/nih-sparc/sparc-app/blob/0ca1c33e245b39b0f07485a990e3862af085013e/nuxt.config.js#L101
    BL_SERVER_URL = Config.BIOLUCIDA_ENDPOINT
     # filesize chunk_size filename -> upload_key
    # chunk_size is after decoded from base64
    # chunk_id means we can go in parallel in principle
    url_bl_ucont = f"{BL_SERVER_URL}/upload/continue" # upload_key upload_data chunk_id
    url_bl_ima = f"{BL_SERVER_URL}/imagemap/add"  # imageid sourceid blackfynn_datasetId discover_datasetId

    token = get_biolucida_token()
    item = {
        "package_id": package_id,
        "filename": filename,
        "discover_id": published_id,
        "status": "failed"
    }

    if token:
        upload_key, expect_chunks = initiate_biolucida_upload(filename, filesize, chunk_size, token)
        log_file.write(f"{upload_key}, {expect_chunks}\n")
        # see https://documenter.getpostman.com/view/8986837/SWLh5mQL

        if upload_key:
            resp_s3 = requests.get(s3url, stream=True)
            for i, chunk in enumerate(resp_s3.iter_content(chunk_size=chunk_size)):
                log_file.write(f"Chunk {i} of {expect_chunks}: ")
                b64chunk = base64.encodebytes(chunk)
                resp_cont = requests.post(url_bl_ucont,
                                        data=dict(
                                            upload_key=upload_key,
                                            upload_data=b64chunk,
                                            chunk_id=i))
                if resp_cont.status_code == requests.codes.ok:                           
                    content = resp_cont.json()
                    if content['status'] == 'success':
                        log_file.write("Successful\n")
                    else:
                        log_file.write("Fail\n")
                else:
                    log_file.write("Fail\n")

            imageid = finalise_biolucida_upload(upload_key)

            if not imageid:
                log_file.write(f"Alternate way to get biolucida id: ")                     
                imageid = get_biolucida_id(filename)
            
            log_file.write(f"Biolucida id: {imageid}\n")

            if imageid:
                item['image_id'] = imageid
                resp_img = requests.post(url_bl_ima,
                                    data=dict(
                                        imageId=imageid,
                                        sourceId=package_id,
                                        blackfynn_datasetId=dataset_id,
                                        discover_datasetId=published_id),
                                    headers=dict(token=token))
                if resp_img.status_code == requests.codes.ok:   
                    if content['status'] == 'success':
                        log_file.write("Successful\n")
                        item['status'] = 'sucessful'
                    else:
                        log_file.write("Fail\n")
                else:
                    log_file.write("Fail\n")
        else:
            log_file.write("Fail to get upload key")
    else:
        log_file.write("Fail to get authentication token")
    bp_list.append(item)
    print(item['status'])

def make_pennsieve_session():
    api_key = Config.PENNSIEVE_API_TOKEN
    api_secret = Config.PENNSIEVE_API_SECRET

    r = requests.get(f"{Config.PENNSIEVE_API_HOST}/authentication/cognito-config")
    r.raise_for_status()

    cognito_app_client_id = r.json()["tokenPool"]["appClientId"]
    cognito_region = r.json()["region"]

    cognito_idp_client = boto3.client(
        "cognito-idp",
        region_name=cognito_region,
        aws_access_key_id="",
        aws_secret_access_key="",
    )

    login_response = cognito_idp_client.initiate_auth(
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": api_key, "PASSWORD": api_secret},
        ClientId=cognito_app_client_id,
    )

    api_token = login_response["AuthenticationResult"]["AccessToken"]

    session = requests.Session()
    session.headers.update({"Authorization": f"Bearer {api_token}"})
    return session

def get_download_details(pennsieve_session):
    dataset_id = Config.TEST_DATASET_ID # f001
    package_id = Config.TEST_PACKAGE_ID
    #packagee_url = "https://api.pennsieve.io/packages/" + package_id + "/files/" + file_id
    package_view = "https://api.pennsieve.io/packages/" + package_id + "/view"
    resp = pennsieve_session.get(package_view)
    data = resp.json()[0]['content']
    filename = data['filename']
    filesize = data['size']
    file_id = str(data['id'])
    packagee_url = "https://api.pennsieve.io/packages/" + package_id + "/files/" + file_id
    resp = pennsieve_session.get(packagee_url)
    s3url = resp.json()['url']
    return dict(
        dataset_id=dataset_id,
        published_id="99999",
        package_id=package_id,
        s3url=s3url,
        filename=filename,
        filesize=filesize
    )

def test_uploads():
    pennsieve_session = make_pennsieve_session()
    detail = get_download_details(pennsieve_session)
    upload_to_bl(**detail)

def main():
    test_uploads()
    log_file.close()
    with open('test_output.json', 'w') as f:
        json.dump(bp_list, f)

if __name__ == "__main__":
    main()
