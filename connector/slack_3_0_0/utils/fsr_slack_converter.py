
from .slack_templates import *
from datetime import date


def convert(input_details):
    data_type = input_details.get('dataType')
    input_type = input_details.get('formType')
    label = input_details.get('label')
    default_value = input_details.get('defaultValue',"")
    required = input_details.get('required',False)
    if required:
        label = label+ " *(required)"
    name = input_details.get('name')
    options = input_details.get('options', [])
    text_inputs = ["filehash", "domain", "ipv4", "ipv6", "text", "phone"]
    if input_type in text_inputs:
        return convert_text_input(name, label, default_value)
    elif input_type == 'email':
        return convert_email_input(name, label, default_value)
    elif input_type == 'integer':
        return convert_integer_input(name, label, default_value)
    elif input_type == 'decimal':
        return convert_decimal_input(name, label, default_value)
    elif input_type == 'url':
        return convert_url_input(name, label, default_value)
    elif input_type == 'checkbox':
        return convert_checkboxes(name, label, default_value)
    elif input_type == 'dynamicList':
        return convert_dynamic_list(name, label, options)
    elif input_type == 'datetime' or input_type == 'date':
        return convert_datetime_input(name, label, default_value=date.today().strftime('%Y-%m-%d'), input_type="datetime")
    elif input_type == 'textarea':
        return convert_textarea_input(name, label, default_value)
    else:
        return []


def convert_input(input_schema, response_options, manual_input_context):
    title_section = {
			"type": "section",
			"text": {
				"type": "mrkdwn",
				"text": ""
			}
		}
    input_variables = input_schema['inputVariables']
    slack_inputs = []
    title_text = "*"+input_schema['title']+"*\n"+input_schema['description']
    title_section['text']['text'] = title_text
    slack_inputs.append(title_section)
    for input_variable in input_variables:
        slack_input = convert(input_variable)
        if type(slack_input) is list:
            slack_inputs.extend(slack_input)
        else:
            slack_inputs.append(slack_input)
    for response_input in response_options:
        slack_input = convert_button_action(response_input.get(
            'option'), response_input.get('step_iri'), manual_input_context)
        slack_inputs.append(slack_input)
    return slack_inputs
