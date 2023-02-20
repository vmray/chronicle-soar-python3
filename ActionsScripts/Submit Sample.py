# Import built-in libraries
import json
import sys

# Import Siemplify libraries
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_INPROGRESS

# Import conntector related libraries
from Conf import VMRayConfig, INTEGRATION_NAME, SUBMIT_SAMPLE_SCRIPT_NAME
from UtilsManager import csv_to_list
from VMRayApiManager import VMRay


def start_operation(siemplify, vmray, sample_file_path, archive_password):
    """
    Submit given sample to the VMRay
    :param siemplify: instance of SiemplifyAction to interact Siemplify REST API
    :param vmray: instance of VMRayApiManager to interact VMRay REST API
    :param sample_file_path: file path of the sample which will be submitted
    :param archive_password: password of the archived sample which will be submitted
    :raise: when an error occurred on sample submission request
    :return result_value: dict or boolean object which store submission status and result
    :return status: SiemplifyAction status to define current status of action
    :return output_message: human-readable message to define action result
    """
    
    siemplify.LOGGER.info("start_operation function is invoked")
    
    try:
        # submit sample with file path and archive password parameters
        submission = vmray.submit_sample(sample_file_path, archive_password)

        # check submission object to handle API related errors
        if submission is not None:
            
            # set result_value - dict which contains submission status and necessary identifiers (for using in the next iterations)
            result_value = json.dumps({"is_finished":False, "submission_id":submission["submission_id"], "sample_id":submission["sample_id"]})

            # set output_message - string which contains success message
            output_message = "File submitted successfully."

            # set status - inprogress, because sample just uploaded, we need to wait for it to finish
            status = EXECUTION_STATE_INPROGRESS

            return result_value, status, output_message
        else:
            # there is an error about submission
            siemplify.LOGGER.error("Couldn't retrieved results for file: %s" % sample_file_path)

            # set necessary variables with error codes and messages
            output_message = "Couldn't retrieved submission results."
            result_value = False
            status = EXECUTION_STATE_FAILED

            return result_value, status, output_message
    except Exception as err:
        # we got an exception when submitting the sample
        siemplify.LOGGER.error("Couldn't submitted the file: %s" % sample_file_path)
        siemplify.LOGGER.exception(err)

        # set necessary variables with error codes and messages
        output_message = "File submission failed. Error: %s" % err
        result_value = False
        status = EXECUTION_STATE_FAILED

        return result_value, status, output_message


def query_operation_status(siemplify, vmray, result_data):
    """
    Query result of the submission
    :param siemplify: instance of SiemplifyAction to interact Siemplify REST API
    :param vmray: instance of VMRayApiManager to interact VMRay REST API
    :param result_data: dict object which store submission status and result (from the iteration before)
    :raise: when an error occurred on querying submission status
    :return result_value: dict or boolean object which store submission status and result
    :return status: SiemplifyAction status to define current status of action
    :return output_message: human-readable message to define action result
    """
    
    siemplify.LOGGER.info("query_operation_status function is invoked")
    
    # get submission_id from result_data
    submission_id = result_data["submission_id"]

    try:
        # retrieve submission status with submission_id
        status, result = vmray.is_submission_finished(submission_id)

        if status is None:
            # check status object to handle API related errors
            siemplify.LOGGER.error("Status check failed for submission %s." % submission_id)

            # set necessary variables with error codes and messages
            output_message = "Status check failed for submission %s." % submission_id
            result_value = False
            status = EXECUTION_STATE_FAILED
            
            return result_value, status, output_message
        
        if status:
            # submission finished successfully
            siemplify.LOGGER.info("Submission %s finished." % submission_id)

            # retrieve verdict from submission result
            result_data["verdict"] = result["submission_verdict"]
            
            # set submission status as finished
            result_data["is_finished"] = True

            # set necessary variables with success codes and messages
            output_message = "Submission %s finished." % submission_id
            result_value = True
            status = EXECUTION_STATE_COMPLETED
            
            # add result_data dict to action result
            siemplify.result.add_result_json(json.dumps(result_data))

            return result_value, status, output_message
    
        else:
            # submission still in progress
            siemplify.LOGGER.info("Submission %s is running." % submission_id)

            # set necessary variables with status codes and messages
            output_message = "Submission %s is running." % submission_id
            result_value = json.dumps(result_data)
            status = EXECUTION_STATE_INPROGRESS

            # add result_value dict to action result
            siemplify.result.add_result_json(result_value)
            
            return result_value, status, output_message

    except Exception as err:
        # we got an exception when querying the result of the sample
        siemplify.LOGGER.error("Couldn't check the status of submission: %s" % submission_id)
        siemplify.LOGGER.exception(err)

        # set necessary variables with error codes and messages
        output_message = "Query operation failed for submission %s. Error %s" % (submission_id, err)
        result_value = False
        status = EXECUTION_STATE_FAILED
        
        return result_value, status, output_message


@output_handler
def main(is_first_run):
    siemplify = SiemplifyAction()
    siemplify.script_name = SUBMIT_SAMPLE_SCRIPT_NAME

    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    # initializing integration parameters for Submit Sample Action
    api_key = siemplify.extract_configuration_param(provider_name=INTEGRATION_NAME, 
                                                    param_name="API_KEY",
                                                    input_type=str,
                                                    is_mandatory=True,
                                                    print_value=False)
    url = siemplify.extract_configuration_param(provider_name=INTEGRATION_NAME,
                                                param_name="URL",
                                                input_type=str,
                                                is_mandatory=True,
                                                print_value=True)
    ssl_verify = siemplify.extract_configuration_param(provider_name=INTEGRATION_NAME, 
                                                       param_name="SSL_VERIFY",
                                                       input_type=bool,
                                                       is_mandatory=True,
                                                       print_value=True)
    
    # initializing action specific parameters for Submit Sample Action
    sample_file_path = siemplify.extract_action_param(param_name="FILE_PATH",
                                                input_type=str,
                                                is_mandatory=True,
                                                print_value=True)
    archive_password = siemplify.extract_action_param(param_name="ARCHIVE_PASSWORD",
                                                input_type=str,
                                                is_mandatory=False,
                                                print_value=True)
    submission_comment = siemplify.extract_action_param(param_name="SUBMISSION_COMMENT",
                                                input_type=str,
                                                is_mandatory=False,
                                                print_value=True)
    tags = siemplify.extract_action_param(param_name="TAGS",
                                                input_type=str,
                                                is_mandatory=False,
                                                print_value=True)
    analysis_timeout = siemplify.extract_action_param(param_name="ANALYSIS_TIMEOUT",
                                                input_type=str,
                                                is_mandatory=False,
                                                print_value=True)
    analyzer_mode = siemplify.extract_action_param(param_name="ANALYZER_MODE",
                                                input_type=str,
                                                is_mandatory=False,
                                                print_value=True)

    VMRayConfig.API_KEY = api_key
    VMRayConfig.URL = url
    VMRayConfig.SSL_VERIFY = ssl_verify
    
    # check and initialize given parameters to config
    if submission_comment is not None and len(submission_comment) > 0:
        VMRayConfig.SUBMISSION_COMMENT = submission_comment
    
    if tags is not None and len(csv_to_list(tags)) > 0:
        VMRayConfig.SUBMISSION_TAGS =  csv_to_list(tags)
    
    if analysis_timeout is not None and analysis_timeout.isnumeric():
        VMRayConfig.ANALYSIS_TIMEOUT =  int(analysis_timeout)
        
    if analyzer_mode is not None and len(analyzer_mode) > 0:
        VMRayConfig.ANALYZER_MODE =  analyzer_mode

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    # set default values to status variables
    output_message = ""
    result_value = False
    status = EXECUTION_STATE_INPROGRESS

    # Initializing VMRay API Instance
    vmray = VMRay(siemplify.LOGGER, VMRayConfig)

    try:
        # Authenticating VMRay API
        vmray.authenticate()

        # Doing healtcheck for VMRay API endpoint
        vmray.healthcheck()

        if is_first_run:
            # If it is the first run of the action, we need to sumbit file
            result_value, status, output_message = start_operation(siemplify, vmray, sample_file_path, archive_password)
        
        if status == EXECUTION_STATE_INPROGRESS:
            # If the action has started and is still running, the sample has already been sent

            # so we need to retrieve result from the iteration before with using additional_data parameter
            result_data = result_value if result_value else siemplify.extract_action_param(param_name="additional_data", default_value='{}')

            # query status of submission
            result_value, status, output_message = query_operation_status(siemplify, vmray, json.loads(result_data))

    except Exception as err:
        # we got an exception when doing API requests
        siemplify.LOGGER.error("Error executing action %s." % SUBMIT_SAMPLE_SCRIPT_NAME)
        siemplify.LOGGER.exception(err)
        
        # set necessary variables with error codes and messages
        output_message = "Error executing action %s. Reason: %s" % (SUBMIT_SAMPLE_SCRIPT_NAME, str(err))
        result_value = False
        status = EXECUTION_STATE_FAILED

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")

    siemplify.LOGGER.info("\n  status: %s\n  result_value: %s\n  output_message: %s" % (status, result_value, output_message))
    siemplify.end(output_message, result_value, status)

if __name__ == "__main__":
    is_first_run = len(sys.argv) < 3 or sys.argv[2] == "True"
    main(is_first_run)