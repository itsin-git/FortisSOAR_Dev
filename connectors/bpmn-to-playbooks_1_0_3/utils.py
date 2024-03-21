from xml.dom.minidom import parseString
from connectors.core.connector import get_logger, ConnectorError
import json

logger = get_logger('bpmntoplaybooks')

def _parse(dom):

    try:
        obj = {}
        if dom.nodeType == 1:
            # element do attributes
            if dom.attributes.length > 0:
                obj['@attributes'] = {}
                for j in range(dom.attributes.length):
                    attribute = dom.attributes.item(j)
                    obj['@attributes'][attribute.nodeName] = str(attribute.nodeValue)

        elif dom.nodeType == 3:

            # text
            obj = dom.nodeValue

        # do children
        # If just one text node inside
        if dom.hasChildNodes() and len(dom.childNodes) == 1 and dom.childNodes[0].nodeType == 3:
            obj = dom.childNodes[0].nodeValue
        elif dom.hasChildNodes():
            for i in range(dom.childNodes.length):

                item = dom.childNodes.item(i)
                nodeName = item.nodeName

                if nodeName == '#cdata-section':
                    obj[nodeName] = item.data
                elif nodeName not in obj:
                    obj[nodeName] = _parse(item)
                else:
                    if isinstance(obj[nodeName], (dict, str)):
                        old = obj[nodeName]
                        obj[nodeName] = []
                        obj[nodeName].append(old)

                    obj[nodeName].append(_parse(item))

        return obj
    except Exception as e:
        logger.exception("Error converting XML to JSON : {}".format(e))
        raise ConnectorError("Error converting XML to JSON : {}".format(e))


def xmlToJson(xml):
    try:
        dom = _parse(parseString(xml))
        return dom
    except Exception as e:
        logger.exception("BPMN XML format is incorrect : {}".format(e))
        raise ConnectorError("BPMN XML format is incorrect : {}".format(e))




