# Import built-in libraries
import json
import os

# Import Siemplify libraries
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from SiemplifyDataModel import InsightSeverity, InsightType
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED

# Import conntector related libraries
from Conf import VMRayConfig, INTEGRATION_NAME, GET_SAMPLE_REPORT_SCRIPT_NAME
from UtilsManager import binary_to_base64
from VMRayApiManager import VMRay

def prepare_report_for_insight(sample_report):
    return """<object width="100%" height="100%" data="data:application/pdf;base64,""" + sample_report + """></object>"""

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_SAMPLE_REPORT_SCRIPT_NAME
    
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")
    
    # Initializing integration parameters for Get Sample Report Action
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
    
    # initializing action specific parameters for Get Sample Report Action
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
        
        # Retrieving sample report with given sample_id
        sample_report = vmray.get_sample_report(sample_id)
        
        # Checking and parsing sample IOCs
        if sample_report is not None:
            
            siemplify.result.add_attachment(title="Sample PDF Report", 
                                            filename="sample_%s.pdf" % sample_id, 
                                            file_contents=binary_to_base64(sample_report))
            
            if create_insight:
                siemplify.LOGGER.info("Creating case insight for PDF report.")
             
                try:
                    tmp_file_path = "/tmp/sample_%s.pdf" % sample_id
                
                    file = open(tmp_file_path, "wb")
                    file.write(sample_report)
                    file.close()
                
                    description = "PDF report for sample %s" % sample_id
                    result = siemplify.add_attachment(tmp_file_path, description=description, is_favorite=True)
                    
                    siemplify.LOGGER.info("Result of add_attachment function %s" % result)
                except Exception as err:
                    siemplify.LOGGER.error("Insight creation failed. Error: %s" % err)
            
            # used to flag back to siemplify system, the action final status
            status = EXECUTION_STATE_COMPLETED  
        
            # human readable message, showed in UI as the action result
            output_message = "Sample report retrieved successfully for %s" % sample_id
        
            # Set a simple result value, used for playbook if\else and placeholders.
            result_value = True
    
            siemplify.LOGGER.info("%s action finished successfully." % GET_SAMPLE_REPORT_SCRIPT_NAME)
        else:
            # used to flag back to siemplify system, the action final status
            status = EXECUTION_STATE_FAILED  
        
            # human readable message, showed in UI as the action result
            output_message = "Report for %s couldn't generated." % sample_id
        
            # Set a simple result value, used for playbook if\else and placeholders.
            result_value = False
            
            siemplify.LOGGER.info("%s action failed." % GET_SAMPLE_REPORT_SCRIPT_NAME)
    except Exception as err:
        # used to flag back to siemplify system, the action final status
        status = EXECUTION_STATE_FAILED
        
        # human readable message, showed in UI as the action result
        output_message = "Report for %s couldn't generated. Error: %s" % (sample_id, err)
        
        # Set a simple result value, used for playbook if\else and placeholders.
        result_value = False
        
        siemplify.LOGGER.error("%s action finished with error." % GET_SAMPLE_REPORT_SCRIPT_NAME)
        siemplify.LOGGER.exception(err)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")

    siemplify.LOGGER.info("\n  status: %s\n  result_value: %s\n  output_message: %s" % (status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
