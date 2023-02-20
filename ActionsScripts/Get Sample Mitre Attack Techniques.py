# Import built-in libraries
import json

# Import Siemplify libraries
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from SiemplifyDataModel import InsightSeverity, InsightType
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED

# Import conntector related libraries
from Conf import VMRayConfig, INTEGRATION_NAME, GET_SAMPLE_ATTACK_SCRIPT_NAME
from VMRayApiManager import VMRay


def prepare_techniques_for_insight(response_dict):
    message = "<br>"
    for technique in response_dict:
        technique_text = "<strong>%s - %s</strong>\n" % (technique["technique_id"],technique["technique"])
        technique_text += "<strong>Tactics</strong>: %s\n" % ",".join(technique["tactics"])
        technique_text += "<strong>VTI's</strong>: %s\n" % ",".join(technique["vtis"].keys())
        message += technique_text + "<hr>"
    return message


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_SAMPLE_ATTACK_SCRIPT_NAME
    
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")
    
    # Initializing integration parameters for Get Sample Mitre Att&ck Techniques Action
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
    
    # initializing action specific parameters for Get Sample Mitre Att&ck Techniques Action
    sample_id = siemplify.extract_action_param(param_name="SAMPLE_ID",
                                                input_type=str,
                                                is_mandatory=True,
                                                print_value=True)
    create_insight = siemplify.extract_action_param(param_name="CREATE_INSIGHT",
                                                input_type=bool,
                                                is_mandatory=False,
                                                print_value=True)
                                                
    VMRayConfig.API_KEY = api_key
    VMRayConfig.URL = url
    VMRayConfig.SSL_VERIFY = ssl_verify
    
    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    
    # Initializing VMRay API Instance
    vmray = VMRay(siemplify.LOGGER, VMRayConfig)
    
    try:
        # Authenticating VMRay API
        vmray.authenticate()
        
        # Doing healtcheck for VMRay API endpoint
        vmray.healthcheck()
        
        # Retrieving sample attack techniques with given sample_id
        sample_attack_techniques = vmray.get_sample_mitre_attack_techniques(sample_id)
        
        # Checking and parsing sample attack techniques
        if sample_attack_techniques is not None:
            
            # Parsing sample attack techniques
            parsed_attack_techniques = vmray.parse_sample_mitre_attack_techniques(sample_attack_techniques)
            
            # used to flag back to siemplify system, the action final status
            status = EXECUTION_STATE_COMPLETED  
        
            # human readable message, showed in UI as the action result
            output_message = "Sample Mitre ATT&CK techniques retrieved successfully for %s" % sample_id
        
            # Set a simple result value, used for playbook if\else and placeholders.
            result_value = True
            
            # Adding sample metadata to result json
            siemplify.result.add_result_json(json.dumps({"sample_technqiues":parsed_attack_techniques}))
            
            if create_insight:
                siemplify.LOGGER.info("Creating case insight for found MITRE ATT&CK Techniques.")
                
                title = "MITRE ATT&CK Techniques for Sample %s" % sample_id
                
                try:
                    message = prepare_techniques_for_insight(parsed_attack_techniques)
                
                    siemplify.create_case_insight(triggered_by=INTEGRATION_NAME,
                                      title=title,
                                      content=message,
                                      entity_identifier="",
                                      severity=1,
                                      insight_type=InsightType.General)
                except Exception as err:
                    siemplify.LOGGER.error("Insight creation failed. Error: %s" % err)
            
            siemplify.LOGGER.info("%s action finished successfully." % GET_SAMPLE_ATTACK_SCRIPT_NAME)
        else:
            # used to flag back to siemplify system, the action final status
            status = EXECUTION_STATE_FAILED  
        
            # human readable message, showed in UI as the action result
            output_message = "No attack techniques for %s was found in VMRay database." % sample_id
        
            # Set a simple result value, used for playbook if\else and placeholders.
            result_value = False
            
            siemplify.LOGGER.info("%s action failed." % GET_SAMPLE_ATTACK_SCRIPT_NAME)
    except Exception as err:
        # used to flag back to siemplify system, the action final status
        status = EXECUTION_STATE_FAILED
        
        # human readable message, showed in UI as the action result
        output_message = "No attack techniques for %s was found in VMRay database. Error: %s" % (sample_id, err)
        
        # Set a simple result value, used for playbook if\else and placeholders.
        result_value = False
        
        siemplify.LOGGER.error("%s action finished with error." % GET_SAMPLE_ATTACK_SCRIPT_NAME)
        siemplify.LOGGER.exception(err)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")

    siemplify.LOGGER.info("\n  status: %s\n  result_value: %s\n  output_message: %s" % (status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
