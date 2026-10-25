"""Interpret explicit school operation authorization failures without replaying them."""

# The school's H5 client handles these operation-ticket errors by requiring its
# official mini-program entry. They do not mean the CAS password is incorrect.
SCHOOL_CLIENT_CODES = frozenset((46001, 46002, 46003))
SCHOOL_CLIENT_REASON = 'school_client_required'
SCHOOL_CLIENT_MESSAGE = '请在微信中打开「成电智慧学工」小程序，进入打卡应用完成签到，再回来同步学校记录。'


def requires_school_client(details):
    return (isinstance(details, dict) and details.get('outcome') == 'rejected'
            and details.get('httpStatus') == 200
            and type(details.get('apiCode')) is int
            and details['apiCode'] in SCHOOL_CLIENT_CODES
            and details.get('stage') == 'checkin_post')


def submission_rejection(details):
    if not isinstance(details, dict) or details.get('outcome') != 'rejected':
        return None
    result = {'result': 'submission_rejected', 'reason': details.get('reason', 'business_error')}
    result.update({k: details[k] for k in ('stage', 'apiCode', 'httpStatus', 'schoolMessage') if k in details})
    if requires_school_client(details):
        result['reason'] = SCHOOL_CLIENT_REASON
    return result


def explain_result(value):
    """Correct legacy presentation while retaining the stored historical evidence."""
    if not isinstance(value, dict) or value.get('result') != 'submission_unknown':
        return value
    rejected = submission_rejection(value.get('submission'))
    if not rejected:
        return value
    return {k: v for k, v in {**value, **rejected}.items()
            if k not in ('retryExhausted', 'retryUnavailable', 'retryAt')}
