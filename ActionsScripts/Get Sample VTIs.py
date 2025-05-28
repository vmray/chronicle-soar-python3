# Import built-in libraries
import json

# Import Siemplify libraries
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from SiemplifyDataModel import InsightSeverity, InsightType
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED

# Import conntector related libraries
from Conf import VMRayConfig, INTEGRATION_NAME, GET_SAMPLE_VTI_SCRIPT_NAME
from VMRayApiManager import VMRay
from UtilsManager import csv_to_list

def prepare_vtis_for_insight(response_dict, sample_id):
    message = "<br>"
    for key in response_dict:
        message += "<strong>%s</strong>\n" % key
        for vti in response_dict[key]:
            vti_text = "&emsp;<strong>Operation</strong>: %s\n" % vti["operation"]
            vti_text += "&emsp;<strong>Score</strong>: %s\n" % vti["score"]
            if len(vti["classifications"]) > 0:
                vti_text += "&emsp;<strong>Classifications</strong>: %s\n" % ",".join(vti["classifications"])
            message += vti_text + "<hr>"
        
    return message


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_SAMPLE_VTI_SCRIPT_NAME
    
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")
    
    # Initializing integration parameters for Get Sample VTI Action
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
    
    # initializing action specific parameters for Get Sample VTI Action
    sample_id = siemplify.extract_action_param(param_name="SAMPLE_ID",
                                                input_type=str,
                                                is_mandatory=True,
                                                print_value=True)
    min_vti_score = siemplify.extract_action_param(param_name="MIN_VTI_SCORE",
                                                input_type=str,
                                                is_mandatory=False,
                                                print_value=True)
    create_insight = siemplify.extract_action_param(param_name="CREATE_INSIGHT",
                                                input_type=bool,
                                                is_mandatory=False,
                                                print_value=True)
                                                
    VMRayConfig.API_KEY = api_key
    VMRayConfig.URL = url
    VMRayConfig.SSL_VERIFY = ssl_verify
    
    # check and initialize given parameters to config
    if min_vti_score is not None and min_vti_score.isnumeric():
        VMRayConfig.MIN_VTI_SCORE = int(min_vti_score)
    
    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    
    # Initializing VMRay API Instance
    vmray = VMRay(siemplify.LOGGER, VMRayConfig)
    
    try:
        # Authenticating VMRay API
        vmray.authenticate()
        
        # Doing healtcheck for VMRay API endpoint
        vmray.healthcheck()
        
        # Retrieving sample VTIs with given sample_id
        sample_vtis = vmray.get_sample_vtis(sample_id)
        
        # Checking and parsing sample vtis
        if sample_vtis is not None:
            
            # Parsing sample VTI values
            parsed_vtis = vmray.parse_sample_vtis(sample_vtis)
            
            # used to flag back to siemplify system, the action final status
            status = EXECUTION_STATE_COMPLETED  
        
            # human readable message, showed in UI as the action result
            output_message = f"Sample VTIs retrieved successfully for {sample_id}"
        
            # Set a simple result value, used for playbook if\else and placeholders.
            result_value = True
            
            # Adding sample metadata to result json
            siemplify.result.add_result_json(json.dumps({"sample_vtis":parsed_vtis}))
            
            if create_insight:
                siemplify.LOGGER.info("Creating case insight for found VTI's.")
                
                title = f"VMRay Threat Identifiers for Sample {sample_id}"
                
                try:
                    message = prepare_vtis_for_insight(parsed_vtis, sample_id)
                
                    siemplify.create_case_insight(triggered_by=INTEGRATION_NAME,
                                      title=title,
                                      content=message,
                                      entity_identifier="",
                                      severity=1,
                                      insight_type=InsightType.General)
                except Exception as err:
                    siemplify.LOGGER.error("Insight creation failed. Error: %s" % err)
            
            siemplify.LOGGER.info("%s action finished successfully." % GET_SAMPLE_VTI_SCRIPT_NAME)
        else:
            # used to flag back to siemplify system, the action final status
            status = EXECUTION_STATE_FAILED  
        
            # human readable message, showed in UI as the action result
            output_message = f"No VTI for {sample_id} was found in VMRay database."
        
            # Set a simple result value, used for playbook if\else and placeholders.
            result_value = False
            
            siemplify.LOGGER.info("%s action failed." % GET_SAMPLE_VTI_SCRIPT_NAME)
    except Exception as err:
        # used to flag back to siemplify system, the action final status
        status = EXECUTION_STATE_FAILED
        
        # human readable message, showed in UI as the action result
        output_message = "No VTI for %s was found in VMRay database. Error: %s" % (sample_id, err)
        
        # Set a simple result value, used for playbook if\else and placeholders.
        result_value = False
        
        siemplify.LOGGER.error("%s action finished with error." % GET_SAMPLE_VTI_SCRIPT_NAME)
        siemplify.LOGGER.exception(err)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")

    siemplify.LOGGER.info("\n  status: %s\n  result_value: %s\n  output_message: %s" % (status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
