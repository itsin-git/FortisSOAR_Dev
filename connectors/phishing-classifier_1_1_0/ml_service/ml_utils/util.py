from ml_utils import log
import json
logger = log.get_logger(__name__)


def timeit(fn):
    from time import perf_counter
    def timeit(*args, **kwargs):
        start_time = perf_counter()
        result = fn(*args, **kwargs)
        end_time = perf_counter()
        execution_time = end_time - start_time
        logger.debug('{0} took {1:.8f}s to execute'.format(fn.__name__, execution_time))
        return result

    return timeit


def get_fsr_version():
    version_json="/opt/cyops-integrations/web/static/version.json"
    try:
        with open(version_json) as file:
            version=json.loads(file.read())
            fsr_version=version.get("version").split('-')[0]
    except Exception as err:
        logger.error("Could not fetch FSR version")
        return None
    logger.debug("FSR-version: " + fsr_version)
    return fsr_version


def version_compare(version_1,version_2):
    i_result = 0
    a_version_1 = version_1.split('.')
    a_version_2 = version_2.split('.')
    if len(a_version_1) != len(a_version_2):
        logger.error("Cannot compare unequal length versions")
        return None
    for i in range(len(a_version_1)):
        if a_version_1[i] == a_version_2[i]:
            continue
        if a_version_1[i] > a_version_2[i]:
            i_result = 1
            break
        else:
            i_result = 2
            break
    return i_result