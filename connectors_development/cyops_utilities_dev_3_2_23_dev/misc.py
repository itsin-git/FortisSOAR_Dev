import ipaddress
import arrow
from logging.handlers import RotatingFileHandler

from django.template import engines
from json2html import *
from connectors.core.connector import get_logger, ConnectorError
try:
    from connectors.core.connector import CustomConnectorException
    useCustomException = True
except:
    useCustomException = False

from .errors.error_constants import *

SYSTEM_HTML_TEMPLATES = ['stylized with row selection', 'cyops']

logger = get_logger(__name__)


def ip_cidr_check(ip_address, cidr, *args, **kwargs):
    cidr_ranges = cidr
    matched_cidr_ip = dict()
    unmatched_ips = dict()
    if type(cidr_ranges) == str:
        cidr_ranges = cidr_ranges.split(',')
    if type(ip_address) == str:
        ip_address = ip_address.split(',')
    for ip in ip_address:
        for each_cidr in cidr_ranges:
            if ipaddress.ip_address(str(ip).strip()) in ipaddress.ip_network(str(each_cidr).strip(), strict=False):
                if each_cidr in matched_cidr_ip.keys():
                    matched_cidr_ip[each_cidr].append(ip)
                else:
                    matched_cidr_ip[each_cidr] = [ip]
                break
            else:
                if each_cidr in unmatched_ips.keys():
                    unmatched_ips[each_cidr].append(ip)
                else:
                    unmatched_ips[each_cidr] = [ip]
    if len(ip_address) == 1 and len(matched_cidr_ip) > 0:
        result = {'matched_cidr_ip': matched_cidr_ip, 'unmatched_ips': unmatched_ips, 'ip_matched': True}
    else:
        result = {'matched_cidr_ip': matched_cidr_ip, 'unmatched_ips': unmatched_ips, 'ip_matched': False}
    return result


def arrow_timestamp_diff(time_stamp_1, time_stamp_2, *args, **kwargs):
    """
    Tries to get diff between arrow timestamps

    Gives diff in minutes

    """
    try:
        ctime = arrow.get(time_stamp_1)
        rtime = arrow.get(time_stamp_2)
    except Exception as e:
        logger.error("{0} ERROR : {1}".format(cs_connector_utility_11, str(e)).format("yyyy-MM-dd'T'HH:mm:ss.SSS"))
        raise ConnectorError(cs_connector_utility_11.format("yyyy-MM-dd'T'HH:mm:ss.SSS"))
    diff = abs(ctime - rtime)
    days = diff.days
    hours, remainder = divmod(diff.seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    microseconds = diff.microseconds

    return {
        'hours': hours,
        'minutes': minutes,
        'seconds': seconds,
        'days': days,
        'microseconds': microseconds
    }


arrow_timestamp_diff.__str__ = lambda: 'Arrow TimeStamp Diff'


def no_op(*args, **kwargs):
    """
    This function does nothing
    """
    pass


def raise_exception(msg='', *args, **kwargs):
    """
    Aborts

   :param str msg: A message to display
   :raises CustomConnectorException: SDK 6.4+
   :raises Exception: SDK versions <6.4
    """
    if useCustomException:
        raise CustomConnectorException(msg)
    else:
        raise Exception(msg)


def format_richtext(value, *args, **kwargs):
    return {"formatted_string": value}


def _json_to_html(data, *args, **kwargs):
    return json2html.convert(json=data)


jinja2 = engines['jinja2']


def json_to_html(data, styling=False, *args, **kwargs):
    if styling:
        return json_to_html_with_style(data, kwargs.get('row_fields', []), kwargs.get('table_style', {}),
                                       kwargs.get('display', ''))
    else:
        return json_to_html_without_style(data, kwargs.get('row_fields', []),
                                          kwargs.get('template', SYSTEM_HTML_TEMPLATES[0]),
                                          kwargs.get('display', 'horizontal'))


def _append_button(data, template, button_template):
    if len(data) > 5:
        template = template.replace('button_template', button_template)
    else:
        template = template.replace('button_template','')
    return template


def json_to_html_without_style(data, row_fields=None, template=SYSTEM_HTML_TEMPLATES[0], display='horizontal',
                               *args, **kwargs):
    if not template.lower() in SYSTEM_HTML_TEMPLATES:
        return _json_to_html(data)

    if not isinstance(data, list) and isinstance(data, dict):
        data = [data]

    if not row_fields:
        row_fields = data[0].keys()

    formatted_template_string_horizontal = '''
        <table class="cs-data-table">
            <tr>
                {% for each_field in row_fields %}
                    <th>{{each_field}}</th>
                {% endfor %}
            </tr>
            {% for obj in data %}
                <tr>
                    {% for fields in row_fields %}
                            <td>{{ obj[fields] }}</td>
                    {% endfor %}
                </tr>
            {% endfor %}
            <tr style="display:block !important; background:none; border:none; resize:none;padding-left:0; padding-top:5px;" >
                <td style="border:none; resize:none; padding-left:0; padding-top:0;">
                    <button class="cs-datatable-btn btn-link cs-datatable-showmore-btn" type="button" onclick="this.closest('table').classList += ' cs-data-table-show-more'; event.target.nextElementSibling.style.display = 'block'; event.target.style.display = 'none'; event.stopPropagation();"> Show more </button><button class="cs-datatable-btn btn-link cs-datatable-showless-btn" type="button" onclick="this.closest('table').classList = 'cs-data-table'; event.target.previousElementSibling.style.display = 'block'; event.target.style.display = 'none'; event.stopPropagation();"> Show less </button>
                </td>
            </tr>
        </table>
    '''

    formatted_template_string_vertical = '''
        <table class="cs-data-table">
            {% for each_field in row_fields %}
                <tr>
                  <th>{{each_field}}</th>
                  {% for obj in data %}
                      <td>{{ obj[each_field] }}</td>
                  {% endfor %}
                </tr>
            {% endfor %}
            <tr style="display:block !important; background:none; border:none; resize:none;padding-left:0; padding-top:5px;" >
                <td style="border:none; resize:none; padding-left:0; padding-top:0;">
                    <button class="cs-datatable-btn btn-link cs-datatable-showmore-btn" type="button" onclick="this.closest('table').classList += ' cs-data-table-show-more'; event.target.nextElementSibling.style.display = 'block'; event.target.style.display = 'none'; event.stopPropagation();"> Show more </button><button class="cs-datatable-btn btn-link cs-datatable-showless-btn" type="button" onclick="this.closest('table').classList = 'cs-data-table'; event.target.previousElementSibling.style.display = 'block'; event.target.style.display = 'none'; event.stopPropagation();"> Show less </button>
                </td>
            </tr>

        </table>
    '''
    template_string_vertical = '<table class="cs-data-table"> {% for each_field in row_fields %}<tr><th>{{each_field}}</th> {% for obj in data %}<td>{{ obj[each_field] }}</td> {% endfor %}</tr> {% endfor %}button_template</table>'

    template_string_horizontal = '<table class="cs-data-table"><tr> {% for each_field in row_fields %}<th>{{each_field}}</th> {% endfor %}</tr> {% for obj in data %}<tr> {% for fields in row_fields %}<td>{{ obj[fields] }}</td> {% endfor %}</tr> {% endfor %}button_template</table>'

    template_string_button = '<tr style="display:block !important; background:none; border:none; resize:none;padding-left:0; padding-top:5px;" ><td style="border:none; resize:none; padding-left:0; padding-top:0;"> <button class="cs-datatable-btn btn-link cs-datatable-showmore-btn" type="button" onclick="this.closest(\'table\').className += \' cs-data-table-show-more\'; event.target.nextElementSibling.style.display = \'block\'; event.target.style.display = \'none\'; event.stopPropagation();"> Show more </button><button class="cs-datatable-btn btn-link cs-datatable-showless-btn" type="button" onclick="this.closest(\'table\').className = this.closest(\'table\').className.replace(/\\bcs-data-table-show-more\\b/g,\'\'); event.target.previousElementSibling.style.display = \'block\'; event.target.style.display = \'none\'; event.stopPropagation();"> Show less </button></td></tr>'
    if display.lower() == 'vertical':
        template_string_vertical = _append_button(row_fields, template_string_vertical, template_string_button)
        template = jinja2.from_string(template_string_vertical)
    else:
        template_string_horizontal = _append_button(data, template_string_horizontal, template_string_button)
        template = jinja2.from_string(template_string_horizontal)

    context = {
        'data': data,
        'row_fields': row_fields
    }

    ret = template.render(context=context)
    return ret


class Table:
    def __init__(self, data, style, title, display):
        self.data = data
        self.title = title
        self.style = style
        self.display = display
        self.template_string_button = '<tr style="display:block !important; background:none; border:none; resize:none;padding-left:0; padding-top:5px;" ><td style="border:none; resize:none; padding-left:0; padding-top:0;"> <button class="cs-datatable-btn btn-link cs-datatable-showmore-btn" type="button" onclick="this.closest(\'table\').className += \' cs-data-table-show-more\'; event.target.nextElementSibling.style.display = \'block\'; event.target.style.display = \'none\'; event.stopPropagation();"> Show more </button><button class="cs-datatable-btn btn-link cs-datatable-showless-btn" type="button" onclick="this.closest(\'table\').className = this.closest(\'table\').className.replace(/\\bcs-data-table-show-more\\b/g,\'\'); event.target.previousElementSibling.style.display = \'block\'; event.target.style.display = \'none\'; event.stopPropagation();"> Show less </button></td></tr>'
        self.html = self._build_html()

    def _build_html(self):
        if isinstance(self.data, dict):
            tr_tag = ""
            tr_tag2 = ""
            if self.display.lower() == 'horizontal':
                for key, value in self.data.items():
                    if not isinstance(value, str):
                        value = str(value)
                    tr_tag = tr_tag + self._apply_style("th") + key + "</th>"
                    tr_tag2 = tr_tag2 + self._apply_style("td") + value + "</td>"
                tr_tag = self._apply_style("tr") + tr_tag + "</tr>"
                tr_tag2 = self._apply_style("tr") + tr_tag2 + "</tr>"
            elif self.display.lower() == 'vertical' or self.display == '':
                for key, value in self.data.items():
                    if not isinstance(value, str):
                        value = str(value)
                    tr_tag = tr_tag + self._apply_style("tr") + self._apply_style("th") + key + "</th>" + self._apply_style("td") + value + "</td></tr>"
            html_template = self._apply_style("table class='cs-data-table'") + tr_tag + tr_tag2 + "button_template</table>"
            return _append_button(self.data.keys(), html_template, self.template_string_button)

        elif isinstance(self.data, list):
            if not self.title:
                self.title = self.data[0].keys()
            tr_tag = ""
            th_tag = ""
            if self.display.lower() == 'horizontal' or self.display == '':
                for item in self.title:
                    th_tag = th_tag + self._apply_style("th") + item + "</th>"
                tr_tag = tr_tag + self._apply_style("tr") + th_tag + "</tr>"

                for items in self.data:
                    td_tag = ""
                    for item in self.title:
                        if item in items.keys():
                            td_tag = td_tag + self._apply_style("td") + str(items[item]) + "</td>"
                        else:
                            td_tag = td_tag + self._apply_style("td") + "Key Not Available</td>"
                    tr_tag = tr_tag + self._apply_style("tr") + td_tag + "</tr>"
            elif self.display.lower() == 'vertical':
                for item in self.title:
                    th_tag = self._apply_style("th") + item + "</th>"
                    for dict_item in self.data:
                        for key, value in dict_item.items():
                            if key == item:
                                td_tag = self._apply_style("td") + value + "</td>"
                                th_tag += td_tag
                                continue
                    tr_tag = tr_tag + self._apply_style("tr") + th_tag + "</tr>"
            html_template = self._apply_style("table class='cs-data-table'") + tr_tag + "button_template</table>"
            return _append_button(self.data, html_template, self.template_string_button)

    def _apply_style(self, elem):
        if self.style:
            if elem in self.style:
                return "<{} style='{}'>".format(elem, self.style[elem])
            else:
                return "<{}>".format(elem)
        else:
            return "<{}>".format(elem)


def json_to_html_with_style(data, row_fields=[], table_style={}, display='', *args, **kwargs):
    if not isinstance(data, (list, dict)):
        logger.exception("Data should be either in JSON format or List of JSON")
        raise ConnectorError("Data should be either in JSON format or List of JSON")

    if table_style and not isinstance(table_style, dict):
        logger.exception("Table style should be in dict format.")
        raise ConnectorError("Table style should be in dict format.")

    if row_fields and not isinstance(row_fields, list):
        logger.exception("Row Fields should be a list.")
        raise ConnectorError("Row Fields should be a list.")

    table = Table(data, table_style, row_fields, display=display)

    return table.html
