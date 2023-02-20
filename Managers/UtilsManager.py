# Import built-in libraries
import hashid
import base64

# Import conntector related libraries
from Conf import HASH


def get_type_of_hash(hash_value):
    """
    Get type of the given hash
    :param hash_value: hash value
    :return: type of hash
    """

    # initializing instance of hashid
    hash_object = hashid.HashID()

    # identifying type of hash value
    prop = hash_object.identifyHash(hash_value)

    for i in prop:
        type_of_hash = i[0]
        if "SHA-1" in type_of_hash:
            return HASH.SHA1
        elif "MD" in type_of_hash:
            return HASH.MD5
        elif "256" in type_of_hash:
            return HASH.SHA256

    return None


def csv_to_list(csv):
    """
    Convert comma seperated string to array
    :param csv: comma seperated string value
    :return: array which contrains parsed strings
    """
    return csv.split(",")


def binary_to_base64(data):
    """
    Encode given binary with base64
    :param data: binary data
    :return: base64 encoded string of given data
    """
    return base64.b64encode(data).decode()


def build_analysis_archive_download_url(base_url, download_url):
    """
    Concat base url and download url to build analysis arcive download link
    :param base_url: base url form VMRay API endpoint
    :param download_url: url path to download analysis archive
    :return: concatted download url string
    """
    if base_url[-1] == "/":
        return base_url + download_url[1:]
    else:
        return base_url + download_url