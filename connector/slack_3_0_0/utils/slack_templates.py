blank = {
    "blocks": []
}


def convert_text_input(name, label, default_value=''):
    if not default_value:
        default_value = ''
    return {
        "type": "input",
        "element": {
            "type": "plain_text_input",
            "action_id": name,
            "initial_value": default_value
        },
        "label": {
            "type": "plain_text",
            "text": label,
            "emoji": True
        }
    }


def convert_dynamic_list(name, label, options):
    all_option = []
    for item in options:
        all_option.append(
            {
                "text": {
                    "type": "plain_text",
                    "text": item,
                    "emoji": True
                },
                "value": item
            })

    return {
        "type": "input",
        "element": {
            "type": "static_select",
            "placeholder": {
                "type": "plain_text",
                "text": "Select an item",
                "emoji": True
            },
            "options": all_option,
            "action_id": name
        },
        "label": {
            "type": "plain_text",
            "text": label,
            "emoji": True
        }
    }


def convert_url_input(name, label, default_value=''):
    return {
        "type": "input",
        "element": {
            "type": "url_text_input",
            "action_id": name
        },
        "label": {
            "type": "plain_text",
            "text": label,
            "emoji": True
        }
    }


def convert_textarea_input(name, label, default_value=''):
    return {
        "type": "input",
        "element": {
            "type": "plain_text_input",
            "multiline": True,
            "action_id": name
        },
        "label": {
            "type": "plain_text",
            "text": label,
            "emoji": True
        }
    }

def convert_integer_input(name, label, default_value=''):
    return {
        "type": "input",
        "element": {
            "type": "number_input",
            "is_decimal_allowed": False,
            "action_id": name
        },
        "label": {
            "type": "plain_text",
            "text": label,
            "emoji": True
        }
    }

def convert_decimal_input(name, label, default_value=''):
    return {
        "type": "input",
        "element": {
            "type": "number_input",
            "is_decimal_allowed": True,
            "action_id": name
        },
        "label": {
            "type": "plain_text",
            "text": label,
            "emoji": True
        }
    }

def convert_email_input(name, label, default_value=''):
    return {
        "type": "input",
        "label": {
                "type": "plain_text",
                "text": label
        },
        "element": {
            "type": "email_text_input",
            "action_id": name,
            "placeholder": {
                    "type": "plain_text",
                    "text": "Enter an email"
            }
        }
    }


def convert_datetime_input(name, label, default_value='', input_type='datetime'):
    if not default_value:
        default_value = ''
    if input_type == 'datetime':
        return {
            "type": "input",
            "element": {
                "type": "datetimepicker",
                "action_id": name,
                "initial_date_time": 1628633820
            },
            "label": {
                "type": "plain_text",
                "text": label,
                "emoji": True
            }
        }

    if input_type == 'date':
        return {
            "type": "input",
            "element": {
                "type": "datepicker",
                "action_id": name,
                "initial_value": default_value
            },
            "label": {
                "type": "plain_text",
                "text": label,
                "emoji": True
            }
        }


def convert_button_action(button_text, button_value, manual_input_context):
    return {
        "type": "actions",
        "elements": [
            {
                "type": "button",
                "text": {
                    "type": "plain_text",
                    "text": button_text,
                    "emoji": True
                },
                "value": button_value,
                "action_id": manual_input_context
            }
        ]
    }


def convert_checkboxes(name, label, default_value=False):
    return {
        "type": "input",
        "element": {
            "type": "checkboxes",
            "options": [
                {
                    "value": label,
                    "text": {
                        "type": "plain_text",
                        "text": label,
                        "emoji": True
                    }
                }
            ],
            "initial_options": [{
                "value": label,
                "text": {
                    "type": "plain_text",
                    "text": label
                }
            }],
            "action_id": name
        },
        "label": {
            "type": "plain_text",
            "text": "Label",
            "emoji": True
        }
    }
