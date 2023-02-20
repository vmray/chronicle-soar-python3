# Import Siemplify libraries
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED

# Import conntector related libraries
from Conf import VMRayConfig, INTEGRATION_NAME, PING_SCRIPT_NAME
from VMRayApiManager import VMRay


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = PING_SCRIPT_NAME
    
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")
    
    # Initializing integration parameters for Ping Action
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
        
        # used to flag back to siemplify system, the action final status
        status = EXECUTION_STATE_COMPLETED  
        
        # human readable message, showed in UI as the action result
        output_message = "Authentication and Healthcheck successfully completed."
        
        # Set a simple result value, used for playbook if\else and placeholders.
        result_value = True
        
        siemplify.LOGGER.info("%s action finished successfully." % PING_SCRIPT_NAME)
    except Exception as err:
        # used to flag back to siemplify system, the action final status
        status = EXECUTION_STATE_FAILED
        
        # human readable message, showed in UI as the action result
        output_message = "Authentication and Healthcheck failed. Error: %s" % (err)
        
        # Set a simple result value, used for playbook if\else and placeholders.
        result_value = False
        
        siemplify.LOGGER.error("%s action finished with error." % PING_SCRIPT_NAME)
        siemplify.LOGGER.exception(err)
    
    siemplify.LOGGER.info("----------------- Main - Finished -----------------")

    siemplify.LOGGER.info("\n  status: %s\n  result_value: %s\n  output_message: %s" % (status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
