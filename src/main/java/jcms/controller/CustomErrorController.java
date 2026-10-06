package jcms.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import jcms.error.DebugError;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.boot.webmvc.error.ErrorAttributes;
import org.springframework.boot.webmvc.error.ErrorController;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.context.request.ServletWebRequest;

import java.util.Map;

/**
 * Controller for unhandled errors (such as unhandled route errors).
 * Based off of Joni Karppinen's Github gist (https://gist.github.com/jonikarppinen/662c38fb57a23de61c8b)
 */
@Controller
public class CustomErrorController implements ErrorController{
    private final static String ERROR_PATH = "/error";

    @Value("${debugMode}")
	private boolean isDebugMode;

    @Autowired
	private ErrorAttributes errorAttributes;

    @RequestMapping(value = ERROR_PATH)
    public String error(Model model, HttpServletRequest request, HttpServletResponse response) {
    	int httpErrorStatus = response.getStatus();

        model.addAttribute("errorStatus", httpErrorStatus);
        model.addAttribute("errorMessage", "Oops, looks like something went wrong.");

        model.addAttribute("isDebugMode", isDebugMode);
// 1. To INCLUDE the stack trace:
		ErrorAttributeOptions optionsWithTrace = ErrorAttributeOptions.defaults()
			.including(ErrorAttributeOptions.Include.STACK_TRACE, ErrorAttributeOptions.Include.MESSAGE);
		WebRequest webRequest = new ServletWebRequest(request);
		Map<String, Object> attributesWithTrace = errorAttributes.getErrorAttributes(webRequest, optionsWithTrace);

// 2. To EXCLUDE the stack trace completely:
		ErrorAttributeOptions optionsNoTrace = ErrorAttributeOptions.defaults()
			.excluding(ErrorAttributeOptions.Include.STACK_TRACE);

        if (isDebugMode) {
        	model.addAttribute(
        		"debugError",
				new DebugError(httpErrorStatus, getErrorAttributes(webRequest, optionsNoTrace))
			);
		}
        return "error";
    }

	private Map<String, Object> getErrorAttributes(WebRequest webRequest, ErrorAttributeOptions optionsNoTrace) {
//		RequestAttributes requestAttributes = new ServletRequestAttributes(request);
		return errorAttributes.getErrorAttributes(webRequest, optionsNoTrace);
	}

//    @Override
    public String getErrorPath() {
        return ERROR_PATH;
    }
}
