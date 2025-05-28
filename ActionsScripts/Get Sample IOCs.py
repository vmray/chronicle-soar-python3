# Import built-in libraries
import json

# Import Siemplify libraries
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from SiemplifyDataModel import InsightSeverity, InsightType
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED

# Import conntector related libraries
from Conf import VMRayConfig, INTEGRATION_NAME, GET_SAMPLE_IOC_SCRIPT_NAME
from UtilsManager import csv_to_list
from VMRayApiManager import VMRay

def prepare_iocs_for_insight(response_dict):
    message = ""
    for verdict in response_dict:
        message += "<br><span style=\"color:red;\"><strong>%s IOC's</strong></span>\n" % verdict.upper()
    
        ioc_data = response_dict[verdict]
    
        for ioc_type in ioc_data:
            message += "<br><strong>%s (%d)</strong>\n" % (ioc_type.upper(), len(ioc_data[ioc_type]))
    
            iocs = ioc_data[ioc_type]
    
            for ioc in iocs:
                message += "<hr>"
                for key in ioc:
                    if key == "categories" or key == "classifications" or key == "threat_names":
                        if len(ioc[key]) > 0:
                            message += "&emsp;<strong>%s</strong>: %s\n" % (key.upper(), ",".join(ioc[key]))
                    elif type(ioc[key]) == list:
                        if len(ioc[key]) > 0:
                            message += "&emsp;<strong>%s</strong>\n" % key.upper()
                            for value in ioc[key]:
                                if type(value) == dict:
                                    for k in value:
                                        message += "&emsp;&emsp;<strong>%s</strong>: %s\n" % (k, value[k])
                                else:
                                    message += "&emsp;&emsp;%s\n" % value
                    elif type(ioc[key]) == str:
                        if len(ioc[key]) > 0:
                            message += "&emsp;<strong>%s</strong>: %s\n" % (key.upper(), ioc[key])
    return message

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_SAMPLE_IOC_SCRIPT_NAME
    
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")
    
    # Initializing integration parameters for Get Sample IOC Action
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
    
    # initializing action specific parameters for Get Sample IOC Action
    sample_id = siemplify.extract_action_param(param_name="SAMPLE_ID",
                                                input_type=str,
                                                is_mandatory=True,
                                                print_value=True)
    selected_ioc_verdicts = siemplify.extract_action_param(param_name="SELECTED_IOC_VERDICTS",
                                                input_type=str,
                                                is_mandatory=False,
                                                print_value=True)
    selected_ioc_types = siemplify.extract_action_param(param_name="SELECTED_IOC_TYPES",
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
    if selected_ioc_verdicts is not None and len(selected_ioc_verdicts) > 0:
        VMRayConfig.SELECTED_IOC_VERDICTS = csv_to_list(selected_ioc_verdicts)
    
    if selected_ioc_types is not None and len(selected_ioc_types) > 0:
        VMRayConfig.SELECTED_IOC_TYPES = csv_to_list(selected_ioc_types)
    
    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    
    # Initializing VMRay API Instance
    vmray = VMRay(siemplify.LOGGER, VMRayConfig)
    
    try:
        # Authenticating VMRay API
        vmray.authenticate()
        
        # Doing healtcheck for VMRay API endpoint
        vmray.healthcheck()
        
        # Retrieving sample IOCs with given sample_id
        sample_iocs = vmray.get_sample_iocs(sample_id)
        
        # Checking and parsing sample IOCs
        if sample_iocs is not None:
            
            # Parsing sample IOCs values
            parsed_iocs = vmray.parse_sample_iocs(sample_iocs)
            
            # used to flag back to siemplify system, the action final status
            status = EXECUTION_STATE_COMPLETED  
        
            # human readable message, showed in UI as the action result
            output_message = f"Sample IOCs retrieved successfully for {sample_id}"
        
            # Set a simple result value, used for playbook if\else and placeholders.
            result_value = True
            
            # Adding sample metadata to result json
            siemplify.result.add_result_json(json.dumps({"sample_iocs":parsed_iocs}))
            
            if create_insight:
                siemplify.LOGGER.info("Creating case insight for found IOC's.")
                
                title = "VMRay Indicator of Compromise Values for Sample %s" % sample_id
                
                try:
                    message = prepare_iocs_for_insight(parsed_iocs)
                    
                    siemplify.create_case_insight(triggered_by=INTEGRATION_NAME,
                                      title=title,
                                      content=message,
                                      entity_identifier="",
                                      severity=1,
                                      insight_type=InsightType.General)
                except Exception as err:
                    siemplify.LOGGER.error("Insight creation failed. Error: %s" % err)
    
            siemplify.LOGGER.info("%s action finished successfully." % GET_SAMPLE_IOC_SCRIPT_NAME)
        else:
            # used to flag back to siemplify system, the action final status
            status = EXECUTION_STATE_FAILED  
        
            # human readable message, showed in UI as the action result
            output_message = "No IOC for %s was found in VMRay database." % sample_id
        
            # Set a simple result value, used for playbook if\else and placeholders.
            result_value = False
            
            siemplify.LOGGER.info("%s action failed." % GET_SAMPLE_IOC_SCRIPT_NAME)
    except Exception as err:
        # used to flag back to siemplify system, the action final status
        status = EXECUTION_STATE_FAILED
        
        # human readable message, showed in UI as the action result
        output_message = "No IOC for %s was found in VMRay database. Error: %s" % (sample_id, err)
        
        # Set a simple result value, used for playbook if\else and placeholders.
        result_value = False
        
        siemplify.LOGGER.error("%s action finished with error." % GET_SAMPLE_IOC_SCRIPT_NAME)
        siemplify.LOGGER.exception(err)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")

    siemplify.LOGGER.info("\n  status: %s\n  result_value: %s\n  output_message: %s" % (status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
