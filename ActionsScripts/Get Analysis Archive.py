# Import built-in libraries
import json
import sys

# Import Siemplify libraries
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED

# Import conntector related libraries
from Conf import VMRayConfig, INTEGRATION_NAME, GET_ANALYSIS_ARCHIVE_SCRIPT_NAME
from VMRayApiManager import VMRay
from UtilsManager import binary_to_base64, build_analysis_archive_download_url


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_ANALYSIS_ARCHIVE_SCRIPT_NAME
    
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")
    
    # Initializing integration parameters for Get Analysis Archive Action
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
    
    # initializing action specific parameters for Get Analysis Archive Action
    sample_id = siemplify.extract_action_param(param_name="SAMPLE_ID",
                                                input_type=str,
                                                is_mandatory=False,
                                                print_value=True)
    analysis_id = siemplify.extract_action_param(param_name="ANALYSIS_ID",
                                                input_type=str,
                                                is_mandatory=False,
                                                print_value=True)
                                                
    VMRayConfig.API_KEY = api_key
    VMRayConfig.URL = url
    VMRayConfig.SSL_VERIFY = ssl_verify
    
    is_analysis_id_set = False
    is_sample_id_set = False
    
    # check and initialize given parameters
    if analysis_id is not None and len(analysis_id) > 0:
        is_analysis_id_set = True
    
    if sample_id is not None and len(sample_id) > 0:
        is_sample_id_set = True
        
    if not is_sample_id_set and not is_analysis_id_set:
        # used to flag back to siemplify system, the action final status
        status = EXECUTION_STATE_FAILED  
    
        # human readable message, showed in UI as the action result
        output_message = "One of SAMPLE_ID or ANALYSIS_ID parameter must be set to run this action."
    
        # Set a simple result value, used for playbook if\else and placeholders.
        result_value = False
        
        siemplify.LOGGER.info("%s action failed." % GET_ANALYSIS_ARCHIVE_SCRIPT_NAME)
        siemplify.LOGGER.info("\n  status: %s\n  result_value: %s\n  output_message: %s" % (status, result_value, output_message))
        
        siemplify.end(output_message, result_value, status)
    
    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    
    # Initializing VMRay API Instance
    vmray = VMRay(siemplify.LOGGER, VMRayConfig)
    
    try:
        # Authenticating VMRay API
        vmray.authenticate()
        
        # Doing healtcheck for VMRay API endpoint
        vmray.healthcheck()
        
        if is_analysis_id_set:
            analysis_archive = vmray.get_analysis_archive(analysis_id)

            if analysis_archive is None:
                # used to flag back to siemplify system, the action final status
                status = EXECUTION_STATE_FAILED

                # human readable message, showed in UI as the action result
                output_message = "Error occured when retrieving analysis archive for analysis %s" % analysis_id

                # Set a simple result value, used for playbook if\else and placeholders.
                result_value = False

                siemplify.LOGGER.error("%s action finished with error." % GET_ANALYSIS_ARCHIVE_SCRIPT_NAME)
            else:
                siemplify.result.add_link("Download Analysis Archive",
                                      build_analysis_archive_download_url(vmray.config.URL, vmray.config.ANALYSIS_ARCHIVE_DOWNLOAD_URL % analysis_id))

                if sys.getsizeof(analysis_archive) / 1000000 < 5:
                    siemplify.result.add_attachment(title="Analysis Archive", 
                                                    filename="analysis_archive_%s.zip" % analysis_id, 
                                                    file_contents=binary_to_base64(analysis_archive))
                    
                    # used to flag back to siemplify system, the action final status
                    status = EXECUTION_STATE_COMPLETED  
                
                    # human readable message, showed in UI as the action result
                    output_message = "Analysis archive retrieved successfully for %s." % analysis_id
                
                    # Set a simple result value, used for playbook if\else and placeholders.
                    result_value = True
            
                    siemplify.LOGGER.info("%s action finished successfully." % GET_ANALYSIS_ARCHIVE_SCRIPT_NAME)
                else:
                    # used to flag back to siemplify system, the action final status
                    status = EXECUTION_STATE_COMPLETED  
                
                    # human readable message, showed in UI as the action result
                    output_message = "Analysis archive retrieved successfully for %s. But file size is bigger than 5MB." % analysis_id
                
                    # Set a simple result value, used for playbook if\else and placeholders.
                    result_value = True
            
                    siemplify.LOGGER.info("%s action finished successfully." % GET_ANALYSIS_ARCHIVE_SCRIPT_NAME)
        else:
            # Retrieving sample submissions with given sample_id
            sample_submissions = vmray.get_sample_submissions(sample_id)
            
            # Checking and parsing sample IOCs
            if sample_submissions is not None:
                
                # Find latest finished and suitable submsission
                last_submission = None
                for submission in sample_submissions:
                    if submission["submission_finished"] and submission['submission_verdict'] in vmray.config.SELECTED_VERDICTS:
                        last_submission = submission
                        break
                
                if last_submission is not None:
                    submission_id = last_submission["submission_id"]
                    sample_analyses = vmray.get_submission_analyses(submission_id)
                    
                    if sample_analyses is not None:
                        last_analysis = sample_analyses[0]
                        analysis_id = last_analysis["analysis_id"]
                        analysis_archive = vmray.get_analysis_archive(analysis_id)

                        if analysis_archive is None:
                            # used to flag back to siemplify system, the action final status
                            status = EXECUTION_STATE_FAILED

                            # human readable message, showed in UI as the action result
                            output_message = "Error occured when retrieving analysis archive for analysis %s" % analysis_id

                            # Set a simple result value, used for playbook if\else and placeholders.
                            result_value = False

                            siemplify.LOGGER.error("%s action finished with error." % GET_ANALYSIS_ARCHIVE_SCRIPT_NAME)
                        
                        else:
                            siemplify.result.add_link("Download Analysis Archive",
                                      build_analysis_archive_download_url(vmray.config.URL, vmray.config.ANALYSIS_ARCHIVE_DOWNLOAD_URL % analysis_id))

                            if sys.getsizeof(analysis_archive) / 1000000 < 5:
                                siemplify.result.add_attachment(title="Analysis Archive", 
                                                                filename="analysis_archive_%s" % analysis_id, 
                                                                file_contents=binary_to_base64(analysis_archive))
                        
                                # used to flag back to siemplify system, the action final status
                                status = EXECUTION_STATE_COMPLETED  
                            
                                # human readable message, showed in UI as the action result
                                output_message = "Analysis archive retrieved successfully for %s." % analysis_id
                            
                                # Set a simple result value, used for playbook if\else and placeholders.
                                result_value = True

                                siemplify.LOGGER.info("%s action finished successfully." % GET_ANALYSIS_ARCHIVE_SCRIPT_NAME)
                            
                            else:
                                # used to flag back to siemplify system, the action final status
                                status = EXECUTION_STATE_COMPLETED  
                            
                                # human readable message, showed in UI as the action result
                                output_message = "Analysis archive retrieved successfully for %s. But file size is bigger than 5MB." % analysis_id
                            
                                # Set a simple result value, used for playbook if\else and placeholders.
                                result_value = True
                        
                                siemplify.LOGGER.info("%s action finished successfully." % GET_ANALYSIS_ARCHIVE_SCRIPT_NAME)
                    else:
                        # used to flag back to siemplify system, the action final status
                        status = EXECUTION_STATE_FAILED  
                    
                        # human readable message, showed in UI as the action result
                        output_message = "No analyses was found for submission %s" % submission_id
                    
                        # Set a simple result value, used for playbook if\else and placeholders.
                        result_value = False
                        
                        siemplify.LOGGER.info("%s action failed." % GET_ANALYSIS_ARCHIVE_SCRIPT_NAME)
                else:
                    # used to flag back to siemplify system, the action final status
                    status = EXECUTION_STATE_FAILED  
                
                    # human readable message, showed in UI as the action result
                    output_message = "No suitable submission was found for sample %s" % sample_id
                
                    # Set a simple result value, used for playbook if\else and placeholders.
                    result_value = False
                    
                    siemplify.LOGGER.info("%s action failed." % GET_ANALYSIS_ARCHIVE_SCRIPT_NAME)
                
            else:
                # used to flag back to siemplify system, the action final status
                status = EXECUTION_STATE_FAILED  
            
                # human readable message, showed in UI as the action result
                output_message = "No submission was found for sample %s" % sample_id
            
                # Set a simple result value, used for playbook if\else and placeholders.
                result_value = False
                
                siemplify.LOGGER.info("%s action failed." % GET_ANALYSIS_ARCHIVE_SCRIPT_NAME)
    except Exception as err:
        # used to flag back to siemplify system, the action final status
        status = EXECUTION_STATE_FAILED
        
        # human readable message, showed in UI as the action result
        output_message = "Error occured when retrieving analysis archive for sample %s. Error: %s" % (sample_id, err)
        
        # Set a simple result value, used for playbook if\else and placeholders.
        result_value = False
        
        siemplify.LOGGER.error("%s action finished with error." % GET_ANALYSIS_ARCHIVE_SCRIPT_NAME)
        siemplify.LOGGER.exception(err)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")

    siemplify.LOGGER.info("\n  status: %s\n  result_value: %s\n  output_message: %s" % (status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
