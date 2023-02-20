# Import built-in libraries
import io
from vmray.rest_api import VMRayRESTAPI

# Import conntector related libraries
from UtilsManager import get_type_of_hash
from Conf import IOC_KEY_MAPPINGS, VTI_KEY_MAPPINGS, MITRE_ATTACK_KEY_MAPPINGS, SUBMISSION_KEY_MAPPINGS

class VMRay:
    """
    Wrapper class for VMRayRESTAPI modules and functions.
    Import this class to submit samples and retrieve reports.
    """

    def __init__(self, log, config):
        """
        Initialize, authenticate and healthcheck the VMRay instance, use VMRayConfig as configuration
        :param log: logger instance
        :return void
        """
        self.api = None
        self.log = log
        self.config = config

    def healthcheck(self):
        """
        Healtcheck for VMRay REST API, uses system_info endpoint
        :raise: When healtcheck error occured during the connection wih REST API
        :return: boolean status of VMRay REST API
        """
        self.log.info("healthcheck function is invoked")

        method = "GET"
        url = "/rest/system_info"

        try:
            self.api.call(method, url)
            self.log.info("VMRAY Healthcheck is successfull.")
            return True
        except Exception as err:
            self.log.error("Healthcheck failed. Error: %s" % (err))
            raise

    def authenticate(self):
        """
        Authenticate the VMRay REST API
        :raise: When API Key is not properly configured
        :return: void
        """
        self.log.info("authenticate function is invoked")

        try:
            self.api = VMRayRESTAPI(self.config.URL, self.config.API_KEY, self.config.SSL_VERIFY, self.config.USER_AGENT)
            self.log.info("Successfully authenticated the VMRay API")
        except Exception as err:
            self.log.error("Authentication failed. Error: %s" % (err))
            raise

    def get_sample(self, identifier, sample_id=False):
        """
        Retrieve sample summary from VMRay database with sample_id or hash value
        :param identifier: sample_id or hash value to identify submitted sample
        :param sample_id: boolean value to determine which value (sample_id or hash) is passed to function
        :return: dict object which contains summary data about sample
        """
        self.log.info("get_sample function is invoked")

        method = "GET"
        if sample_id:
            url = "/rest/sample/" + str(identifier)
        else:
            hash_type = get_type_of_hash(identifier)
            url = "/rest/sample/%s/%s" % (hash_type, str(identifier))

        try:
            response = self.api.call(method, url)
            if len(response) == 0:
                self.log.warn("Sample %s couldn't find in VMRay database." % (identifier))
                return None
            else:
                self.log.info("Sample %s retrieved from VMRay" % identifier)
                return response
        except Exception as err:
            self.log.error("Sample %s couldn't find in VMRay database. Error: %s" % (identifier, err))
            return None

    def parse_sample_data(self, sample):
        """
        Parse and extract summary data about the sample with keys below
        :param sample: dict object which contains raw data about the sample
        :return sample_data: dict objects which contains parsed data about the sample
        """
        self.log.info("parse_sample_data function is invoked")

        sample_data = {}
        keys = [
            "sample_id",
            "sample_verdict",
            "sample_vti_score",
            "sample_severity",
            "sample_md5hash",
            "sample_sha1hash",
            "sample_sha256hash",
            "sample_webif_url",
            "sample_classifications",
            "sample_threat_names"
        ]
        if sample is not None:
            if type(sample) == type([]):
                sample = sample[0]
            for key in keys:
                if key in sample:
                    sample_data[key] = sample[key]
        return sample_data

    def get_sample_iocs(self, sample_id):
        """
        Retrieve IOC values from VMRay
        :param sample_id: str value to identify submitted sample
        :return iocs: dict object which contains IOC values according to the verdict
        """
        self.log.info("get_sample_iocs function is invoked")

        method = "GET"
        url = "/rest/sample/%s/iocs/verdict/%s"

        iocs = {}
        
        for key in self.config.SELECTED_IOC_VERDICTS:
            try:
                response = self.api.call(method, url % (sample_id, key))
                iocs[key] = response
                self.log.info("%s IOC reports for %s retrieved from VMRay" % (key,sample_id))
            except Exception as err:
                self.log.error(err)
        
        if len(iocs.keys()) == 0:
            return None
        
        return iocs
    
    def parse_sample_iocs(self, sample_iocs):
        """
        Parse and extract IOC values about the sample
        :param sample_iocs: dict object which contains raw IOC data about the sample
        :return parsed_sample_iocs: dict object which contains parsed/extracted IOC values
        """
        self.log.info("parse_sample_iocs function is invoked")
        
        parsed_sample_iocs = {}
        
        for verdict in sample_iocs:
            iocs_by_verdict = {}
    
            for ioc_type in self.config.SELECTED_IOC_TYPES:
                if ioc_type in IOC_KEY_MAPPINGS:
                    parsed_iocs = self.parse_ioc_dict(sample_iocs[verdict]["iocs"][ioc_type], ioc_type)
                    if len(parsed_iocs) > 0:
                        iocs_by_verdict[ioc_type] = parsed_iocs
    
            parsed_sample_iocs[verdict] = iocs_by_verdict
    
        return parsed_sample_iocs
    
    def parse_ioc_dict(self, iocs, ioc_type):
        """
        Parse and extract IOC values from specific raw IOC dict based on ioc_type and ioc_key_mappings
        :param iocs: dict object which contains specific raw IOC data about the sample
        :return parsed_iocs: dict object which contains parsed/extracted IOC values
        """
        self.log.info("parse_sample_iocs function is invoked with parameter %s" % ioc_type)
        
        parsed_iocs = []
    
        for ioc in iocs:
            ioc_dict = {}
            for key in IOC_KEY_MAPPINGS[ioc_type]:
                if key in ioc:
                    ioc_dict[key] = ioc[key]
            parsed_iocs.append(ioc_dict)
    
        return parsed_iocs
    
    def get_sample_vtis(self, sample_id):
        """
        Retrieve VTI's (VMRay Threat Identifier) values about the sample
        :param sample_id: id value of the sample
        :return: dict object which contains VTI information about the sample
        """
        self.log.info("get_sample_vtis function is invoked")

        method = "GET"
        url = "/rest/sample/%s/vtis" % str(sample_id)

        try:
            response = self.api.call(method, url)
            self.log.info("Sample %s VTI's successfully retrieved from VMRay" % sample_id)
            return response
        except Exception as err:
            self.log.error("Sample %s VTI's couldn't retrieved from VMRay database. Error: %s" % (sample_id, err))
            return None
    
    def parse_sample_vtis(self, vtis):
        """
        Parse and extract VTI details about the sample with keys below
        :param vtis: dict object which contains raw VTI data about the sample
        :return parsed_vtis: dict object which contains parsed VTI data about the sample
        """
        self.log.info("parse_sample_vtis function is invoked")

        parsed_vtis = {}

        for vti in vtis["threat_indicators"]:
            if vti["score"] >= self.config.MIN_VTI_SCORE:
                if vti["category"] not in parsed_vtis:
                    parsed_vtis[vti["category"]] = []
                
                vti_dict = {}
                for key in VTI_KEY_MAPPINGS:
                    vti_dict[key] = vti[key]
                
                parsed_vtis[vti["category"]].append(vti_dict)
                
        return parsed_vtis
    
    def get_sample_mitre_attack_techniques(self, sample_id):
        """
        Retrieve Mitre Att&ck Techniques and related VTI values about the sample
        :param sample_id: id value of the sample
        :return: dict object which contains raw techniques about the sample
        """
        self.log.info("get_sample_mitre_attack_techniques function is invoked")
    
        method = "GET"
        url = "/rest/sample/%s/mitre_attack" % str(sample_id)
    
        try:
            response = self.api.call(method, url)
            self.log.info("Sample %s Mitre Att&ck techniques successfully retrieved from VMRay" % sample_id)
            return response
        except Exception as err:
            self.log.error("Sample %s Mitre Att&ck techniques couldn't retrieved from VMRay database. Error: %s" % (
                sample_id, err))
        
        return None
    
    def parse_sample_mitre_attack_techniques(self, techniques):
        """
        Parse and extract Mitre Att&ck techniques about the sample
        :param techniques: dict object which contains raw Mitre Att&ck Technique data about the sample
        :return parsed_techniques: dict object which contains parsed Mitre Att&ck Technique data about the sample
        """
        self.log.info("parse_sample_mitre_attack_techniques function is invoked")

        parsed_attack_techniques = []

        for technique in techniques["mitre_attack_techniques"]:
            parsed_technique = {}

            for key in MITRE_ATTACK_KEY_MAPPINGS:
                parsed_technique[key] = technique[key]

            if len(technique["threat_indicators"]) > 0:
                parsed_technique["vtis"] = {}

                for vti in technique["threat_indicators"]:

                    if vti["category"] not in parsed_technique["vtis"]:
                        parsed_technique["vtis"][vti["category"]] = []

                    vti_dict = {}
                    for key in VTI_KEY_MAPPINGS:
                        vti_dict[key] = vti[key]

                    parsed_technique["vtis"][vti["category"]].append(vti_dict)

            parsed_attack_techniques.append(parsed_technique)
        
        return parsed_attack_techniques
    
    def get_sample_report(self, sample_id):
        """
        Retrieve PDF report for given sample
        :param sample_id: id value of the sample
        :return: object which contains pdf report of sample
        """
        self.log.info("get_sample_report function is invoked")

        method = "GET"
        url = "/rest/sample/%s/report" % str(sample_id)

        try:
            response = self.api.call(method, url, raw_data=True)
            self.log.info("Sample %s report successfully retrieved from VMRay" % sample_id)
            return response.data
        except Exception as err:
            self.log.error("Sample %s report couldn't retrieved from VMRay database. Error: %s" % (sample_id, err))
        
        return None
    
    def get_sample_submissions(self, sample_id):
        """
        Retrieve submissions of the given sample id
        :param sample_id: id value of the sample
        :return: object which contains submissions of sample
        """
        self.log.info("get_sample_submissions function is invoked")

        method = "GET"
        url = "/rest/submission/sample/%s" % str(sample_id)

        try:
            response = self.api.call(method, url)
            self.log.info("Sample %s submissions successfully retrieved from VMRay" % sample_id)
            return response
        except Exception as err:
            self.log.error("Sample %s submissions couldn't retrieved from VMRay database. Error: %s" % (sample_id, err))

        return None
    
    def get_submission_analyses(self, submission_id):
        """
        Retrieve analysis' details of submission
        :param submission_id: id value of the submission
        :return: dict object which contains analysis information about the submission
        """
        self.log.info("get_submission_analyses function is invoked")

        method = "GET"
        url = "/rest/analysis/submission/%s" % str(submission_id)
        try:
            response = self.api.call(method, url)
            self.log.info("Submission %s analyses successfully retrieved from VMRay" % submission_id)
            return response
        except Exception as err:
            self.log.error("Submission %s analyses couldn't retrieved from VMRay. Error: %s" % (submission_id, err))
        
        return None

    def get_analysis_archive(self, analysis_id):
        """
        Retrieve the archive file of given analysis
        :param analysis_id: id value of the analysis
        :return: archive file of analysis
        """
        self.log.info("get_analysis_archive function is invoked")

        method = "GET"
        url = "/rest/analysis/%s/archive" % str(analysis_id)

        try:
            response = self.api.call(method, url, raw_data=True)
            self.log.info("Analysis %s archive successfully retrieved from VMRay" % analysis_id)
            return response.data
        except Exception as err:
            self.log.error("Analysis %s archive couldn't retrieved from VMRay database. Error: %s" % (analysis_id, err))

        return None
    
    def submit_url(self, sample_url):
        """
        Submit given url to VMRay
        :param sample_url: url to be analyzed
        :return: dict object which contains submission and sample info
        """
        self.log.info("submit_url function is invoked")
        
        method = "POST"
        url = "/rest/sample/submit"
        
        params = {}
        params["sample_url"] = sample_url
        params["comment"] = self.config.SUBMISSION_COMMENT
        params["tags"] = ",".join(self.config.SUBMISSION_TAGS)
        params["user_config"] = """{"timeout":%d}""" % self.config.ANALYSIS_TIMEOUT
        params["analyzer_mode"] = self.config.ANALYZER_MODE
        
        try:
            response = self.api.call(method, url, params)
            if len(response["errors"]) == 0:
                submission_id = response["submissions"][0]["submission_id"]
                sample_id = response["samples"][0]["sample_id"]
                self.log.info("Url %s submitted to VMRay" % sample_url)
                return {"submission_id": submission_id, "sample_id": sample_id}
            else:
                [self.log.error(str(error)) for error in response["errors"]]
        except Exception as err:
            self.log.error(err)
        
        return None
        
    def submit_sample(self, sample_file_path, archive_password):
        """
        Submit given sample to VMRay
        :param sample_file_path: file to be analyzed
        :param archive_password: password of submitted archive file
        :return: dict object which contains submission and sample info
        """
        self.log.info("submit_sample function is invoked")

        method = "POST"
        url = "/rest/sample/submit"

        params = {}
        params["comment"] = self.config.SUBMISSION_COMMENT
        params["tags"] = ",".join(self.config.SUBMISSION_TAGS)
        params["user_config"] = """{"timeout":%d}""" % self.config.ANALYSIS_TIMEOUT
        params["analyzer_mode"] = self.config.ANALYZER_MODE
        
        if archive_password is not None and len(archive_password) > 0:
            params["archive_password"] = archive_password

        try:
            with io.open(sample_file_path, "rb") as file_object:
                params["sample_file"] = file_object
                
                try:
                    response = self.api.call(method, url, params)
                    if len(response["errors"]) == 0:
                        submission_id = response["submissions"][0]["submission_id"]
                        sample_id = response["samples"][0]["sample_id"]
                        self.log.info("File %s submitted to VMRay" % sample_file_path)
                        return {"submission_id": submission_id, "sample_id": sample_id}
                    else:
                        [self.log.error(str(error)) for error in response["errors"]]
                except Exception as err:
                    self.log.error(err)
        except Exception as err:
            self.log.error(err)

        return None
    
    def get_submission(self, submission_id):
        """
        Retrieve the result of the sumission
        :param submission_id: identifier value of the submission
        :return: submission status and dict object which contains submission info
        """
        self.log.info("get_submission_result function is invoked")

        method = "GET"
        url = "/rest/submission/%s"

        try:
            response = self.api.call(method, url % submission_id)
            return response
        except Exception as err:
            self.log.error(err)

        return None

    def parse_submission(self, submission):
        """
        Parse and extract fields from submission result
        :param submission: dict object which contains info about submission
        :return parsed_submission_result: dict object which contains parsed/extracted submission data
        """
        self.log.info("parse_submission_result function is invoked")

        parsed_submission_result = {}

        for key in SUBMISSION_KEY_MAPPINGS:
            if key in submission:
                parsed_submission_result[key] = submission[key]
        
        return parsed_submission_result

    def is_submission_finished(self, submission_id):
        """
        Check status of the sumission
        :param submission_id: identifier value of the submission
        :return: submission status and dict object which contains submission info
        """
        self.log.info("is_submission_finished function is invoked")
        
        method = "GET"
        url = "/rest/submission/%s"
        
        try:
            response = self.api.call(method, url % submission_id)
            if response["submission_finished"]:
                self.log.info("Submission %s finished." % submission_id)
                return True, response
            else:
                self.log.info("Submission %s is running." % submission_id)
                return False, None
        except Exception as err:
            self.log.error(err)
        
        return None, None
    
    def unlock_reports(self, sample_id):
        """
        Unlock reports for Verdict Api Keys
        :param sample_id: id value of the sample
        :return status: boolean value of status
        """
        self.log.info("unlock_reports function is invoked")
        
        method = "POST"
        url = "/rest/sample/%s/unlock_reports" % str(sample_id)

        try:
            response = self.api.call(method, url)
            reports_ids = response["unlocked_analysis_ids"]
            if len(reports_ids) > 0:
                self.log.info("Sample %s reports(%s) unlocked." % (sample_id, ",".join(reports_ids)))
            return True
        except Exception as err:
            self.log.error(err)
        
        return False

    def get_child_samples(self, sample_id):
        """
        Retrieve child samples for given sample
        :param sample_id: id value of the sample
        :return child_samples: array of dictionaries which contains metadata of child samples
        """
        self.log.info("get_child_samples function is invoked")

        method = "GET"
        url = "/rest/sample/%s"

        child_samples = []
        processed_sample_ids = []

        try:
            response = self.api.call(method, url % sample_id)
            for child_relation in response["sample_child_relations"]:
                if child_relation["relation_child_sample_id"] not in processed_sample_ids:
                    child_samples.append({
                        "sample_id": child_relation["relation_child_sample_id"],
                        "verdict": child_relation["relation_child_sample_verdict"],
                        "relation_type": child_relation["relation_type"]
                    })
                    processed_sample_ids.append(child_relation["relation_child_sample_id"])
            return child_samples
        except Exception as err:
            self.log.error(err)

        return None